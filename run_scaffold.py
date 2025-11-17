import os
import re
import sys
import shutil
import subprocess
import hashlib
from pathlib import Path
import json
import uuid
from tqdm import tqdm
import asyncio
import warnings
from logger import logging
import time

# Suppress asyncio/event loop cleanup warnings (harmless during multi-threaded async execution)
warnings.filterwarnings(
    "ignore", category=RuntimeWarning, message=".*coroutine.*was never awaited.*"
)
warnings.filterwarnings("ignore", message=".*Event loop is closed.*")
warnings.filterwarnings(
    "ignore", category=SyntaxWarning, message=".*invalid escape sequence.*"
)

# Add project root to PYTHONPATH for subprocesses
_PROJECT_ROOT = str(Path(__file__).resolve().parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
current_pythonpath = os.environ.get("PYTHONPATH", "")
if current_pythonpath:
    os.environ["PYTHONPATH"] = f"{_PROJECT_ROOT}{os.pathsep}{current_pythonpath}"
else:
    os.environ["PYTHONPATH"] = _PROJECT_ROOT

from agent.agents import FinderAgent, GeneratorAgent, SetupAgent, FixerAgent
from agent.report_generator import generate_comprehensive_report, save_report
from agent.settings import MAX_SUBAGENT_TURNS, MAX_DEPTH
from logger.mongo_logger import (
    log_execution_pending,
    log_execution_in_progress,
    log_execution_complete,
    log_execution_failed,
)


BASE_INSTRUCTION = "You must start your search for exploits now. Pay attention to the instructions in the codebase, especially the ones in the README.md file."
SETUP_INSTRUCTION = "You must start setting up the repository now"


def _project_root() -> str:
    return str(Path(__file__).resolve().parent)


def _repos_root() -> str:
    root = os.path.join(_project_root(), "repos")
    os.makedirs(root, exist_ok=True)
    return root


def _repo_slug(repo_url: str) -> str:
    # Derive a filesystem-safe slug from repo name + short hash of URL
    name = Path(re.sub(r"\.git$", "", repo_url.split("/")[-1])).stem or "repo"
    short_hash = hashlib.sha1(repo_url.encode("utf-8")).hexdigest()[:8]
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "-", name)
    return f"{safe_name}-{short_hash}"


def _repo_path(repo_url: str) -> str:
    return os.path.join(_repos_root(), _repo_slug(repo_url))


def clone_repo(repo_url: str) -> str:
    """Clone the repository into a deterministic folder and return its absolute path."""
    dest = _repo_path(repo_url)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    subprocess.run(["git", "clone", repo_url, dest], check=True)
    return dest


async def run_finder_agent(
    repo_url: str, num_turns: int, model_name: str, use_openai: bool = False
):
    """Run the FinderAgent against the cloned repo for the requested number of user turns (async)."""
    print("🔍 Starting FinderAgent...")
    repo_path = _repo_path(repo_url)
    if not os.path.exists(repo_path):
        print(f"⬇️  Cloning to {repo_path}...")
        repo_path = clone_repo(repo_url)
    else:
        print(f"✅ Using existing repo at {repo_path}")

    print("🤖 Initializing agent...")
    agent = FinderAgent(
        repo_path=repo_path,
        model=model_name,
        max_tool_turns=num_turns,
        use_openai=use_openai,
    )
    print("✅ Agent ready, starting chat...")

    # Log execution start with pending status
    # Use agent_id as execution_id for the main agent
    execution_id = agent.agent_id
    try:
        log_execution_pending(execution_id, repo_url, model_name)
    except Exception:
        pass  # Don't fail if logging fails

    response = None
    exception_occurred = False
    try:
        response = await agent.chat(BASE_INSTRUCTION)

        # Log execution completion
        try:
            log_execution_complete(execution_id, "completed")
        except Exception:
            pass

    except Exception as e:
        print(f"❌ ERROR: {type(e).__name__}: {str(e)}")
        import traceback

        traceback.print_exc()
        exception_occurred = True

        # Log execution failure
        try:
            log_execution_failed(execution_id, str(e))
        except Exception:
            pass

    finally:
        # Always close the agent to clean up resources
        try:
            await agent.close()
        except Exception:
            pass

    # Save conversation ONLY for the main finder agent (depth 0)
    # Sub-agents save their own conversations in finder_tools.py
    if agent.depth == 0:
        save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url))
        prefix = "error_convo" if exception_occurred else "convo"
        agent.save_conversation(save_folder=save_folder, prefix=prefix)

    # Generate comprehensive report ONLY if agent completed successfully (no exception)
    # This ensures all sub-agents have finished before report generation
    if not exception_occurred and agent.depth == 0:
        hyperparams = {
            "main_agent_turns": num_turns,  # Actual turns used for main agent
            "MAX_SUBAGENT_TURNS": MAX_SUBAGENT_TURNS,
            "MAX_DEPTH": MAX_DEPTH,
            "model": model_name,
            "use_openai": use_openai,
        }

        try:
            report = generate_comprehensive_report(
                repo_slug=_repo_slug(repo_url),
                output_dir=os.path.join(_project_root(), "output"),
                hyperparams=hyperparams,
            )
            report_path = save_report(
                report=report,
                output_dir=os.path.join(_project_root(), "output"),
                repo_slug=_repo_slug(repo_url),
            )
            print(f"\n📊 Comprehensive report saved to: {report_path}")
            print(f"   Total cost: ${report['summary']['total_combined_cost']:.4f}")
            print(f"   Total time: {report['summary']['total_combined_time']}")
            print(f"   Total exploits: {report['summary']['total_combined_exploits']}")
            print(f"   Total agents: {report['summary']['total_agents']}")
        except Exception as e:
            print(f"\n⚠️  Warning: Failed to generate report: {e}")

    return {
        "response": response,
        "estimated_cost": agent.estimated_cost,
        "total_tokens": agent.total_tokens,
    }


async def run_setup_agent(
    repo_url: str, num_turns: int, model_name: str, use_openai: bool = False
):
    """Run the SetupAgent against the cloned repo for the requested number of user turns (async)."""
    repo_path = _repo_path(repo_url)
    agent = SetupAgent(
        repo_path=repo_path,
        model=model_name,
        max_tool_turns=num_turns,
        use_openai=use_openai,
    )

    response = None
    try:
        response = await agent.chat(SETUP_INSTRUCTION)
        prefix = "setup"
    except Exception:
        prefix = "error_setup"
    finally:
        # Always close the agent to clean up resources
        try:
            await agent.close()
        except Exception:
            pass

    # Save conversation under a per-repo folder inside output/conversations
    save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url))
    agent.save_conversation(save_folder=save_folder, prefix=prefix)

    return {
        "response": response,
        "estimated_cost": agent.estimated_cost,
        "total_tokens": agent.total_tokens,
    }


async def run_generator_agent(
    repo_url: str, num_turns: int, model_name: str, use_openai: bool = False
):
    """
    Run the generator agent for all exploits in the exploits.json file in the repo path (async)
    """
    repo_path = _repo_path(repo_url)

    GENERATOR_INSTRUCTION = """
Here is the exploit:
<exploit>
{exploit}
</exploit>

Start exploring the codebase and generate a test script for the exploit.
"""

    exploits = json.load(open(os.path.join(repo_path, "exploits.json")))
    total_cost = 0.0

    for exploit in tqdm(exploits, desc="Generating exploits"):
        # Initialize the generator agent
        agent = GeneratorAgent(
            repo_path=repo_path,
            max_tool_turns=num_turns,
            model=model_name,
            use_openai=use_openai,
        )

        try:
            # Construct the instruction
            instruction = GENERATOR_INSTRUCTION.format(exploit=json.dumps(exploit))

            # Generate the test script
            response = await agent.chat(instruction)

            # Save conversation under a per-repo folder inside output/conversations
            save_folder = os.path.join(
                _project_root(),
                "output",
                _repo_slug(repo_url),
                "generator_conversations",
            )
            os.makedirs(save_folder, exist_ok=True)
            agent.save_conversation(
                save_folder=save_folder, prefix=f"generator_exploit_{exploit['id']}"
            )

            total_cost += agent.estimated_cost
        finally:
            # Always close the agent to clean up resources
            try:
                await agent.close()
            except Exception:
                pass

    return {"total_cost": total_cost, "exploits_processed": len(exploits)}


async def run_fixer_agent(
    repo_url: str, num_turns: int, model_name: str, use_openai: bool = False
):
    """
    Run the fixer agent for all exploits in the exploits.json file in the repo path (async)
    """
    repo_path = _repo_path(repo_url)

    FIXER_INSTRUCTION = """
Here is the exploit:
<exploit>
{exploit}
</exploit>

Start exploring the codebase and fix the exploit.
"""

    exploits = json.load(open(os.path.join(repo_path, "exploits.json")))
    total_cost = 0.0

    for exploit in tqdm(exploits, desc="Fixing exploits"):
        agent = FixerAgent(
            repo_path=repo_path,
            max_tool_turns=num_turns,
            model=model_name,
            use_openai=use_openai,
        )

        try:
            # Construct the instruction
            instruction = FIXER_INSTRUCTION.format(exploit=json.dumps(exploit))

            # Fix the exploit
            response = await agent.chat(instruction)

            # Save the suggested fix in a suggested_fixes.json file
            # the format should be {exploit_id: suggested_fix}
            # the suggested_fixes.json file should be a list of dicts, with the key being the exploit_id and the value being the suggested_fix
            try:
                with open(os.path.join(repo_path, "suggested_fixes.json"), "r") as f:
                    suggested_fixes = json.load(f)
            except:
                suggested_fixes = []
            suggested_fixes.append({exploit["id"]: response.suggest_fix})
            with open(os.path.join(repo_path, "suggested_fixes.json"), "w") as f:
                json.dump(suggested_fixes, f, indent=2)

            # Save conversation under a per-repo folder inside output/conversations
            save_folder = os.path.join(
                _project_root(), "output", _repo_slug(repo_url), "fixer_conversations"
            )
            os.makedirs(save_folder, exist_ok=True)
            agent.save_conversation(
                save_folder=save_folder, prefix=f"fixer_exploit_{exploit['id']}"
            )

            total_cost += agent.estimated_cost
        finally:
            # Always close the agent to clean up resources
            try:
                await agent.close()
            except Exception:
                pass

    return {"total_cost": total_cost, "exploits_fixed": len(exploits)}


async def main():
    print("🚀 Starting exploit agent...")
    # repo_url = "https://github.com/gmsol-labs/gmx-solana.git"
    repo_url = "https://github.com/fatihbugrakdogan/publicis-trigger.git"
    num_turns = 4
    use_openai = False
    model_name = "gpt-5-2025-08-07" if use_openai else "z-ai/glm-4.6"
    user_id = "fatihbugrakdogan"
    task_id = "1234567890"

    print(f"📂 Repo: {repo_url}")
    print(f"🤖 Model: {model_name}")
    print(f"🔄 Max turns: {num_turns}")

    finder_result = await run_finder_agent(repo_url, num_turns, model_name, use_openai)
    # setup_result = await run_setup_agent(repo_url, num_turns, model_name, use_openai)
    # generator_result = await run_generator_agent(repo_url, num_turns, model_name, use_openai)
    # fixer_result = await run_fixer_agent(repo_url, num_turns, model_name, use_openai)

    return {
        "finder": finder_result,
        # "setup": setup_result,
        # "generator": generator_result,
        # "fixer": fixer_result
    }


if __name__ == "__main__":
    asyncio.run(main())
