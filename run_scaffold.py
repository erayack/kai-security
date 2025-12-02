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
import argparse
from typing import Optional

# Suppress asyncio/event loop cleanup warnings (harmless during multi-threaded async execution)
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*coroutine.*was never awaited.*")
warnings.filterwarnings("ignore", message=".*Event loop is closed.*")
warnings.filterwarnings("ignore", category=SyntaxWarning, message=".*invalid escape sequence.*")

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
from agent.settings import MAX_DEPTH, FIXER_BATCH_SIZE
from agent import settings as agent_settings
from agent.schemas import Role


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
    repo_url: str,
    num_turns: int,
    model_name: str,
    use_openai: bool = False,
    repo_path_override: Optional[str] = None,
    max_subagent_depth: Optional[int] = None,
):
    """
    Run the FinderAgent against the cloned repo for the requested number of user turns (async).

    Args:
        repo_url: Repository identifier/URL.
        num_turns: Turn budget for the finder.
        model_name: Model to use.
        use_openai: Whether to route via OpenAI API.
        repo_path_override: Optional pre-materialized repo path.
        max_subagent_depth: Optional override for finder sub-agent recursion depth.
    """
    repo_path = repo_path_override or _repo_path(repo_url)
    if repo_path_override:
        print(f"Using pre-materialized repo path: {repo_path}")
    # Clone repo if it doesn't exist (finder now runs before setup)
    if not os.path.exists(repo_path):
        if repo_path_override:
            raise FileNotFoundError(f"Materialized repo not found at {repo_path_override}")
        print(f"Cloning repository: {repo_url}")
        repo_path = clone_repo(repo_url)
    max_depth = max_subagent_depth if max_subagent_depth is not None else MAX_DEPTH

    agent = FinderAgent(
        repo_path=repo_path, 
        model=model_name, 
        max_tool_turns=num_turns,
        use_openai=use_openai,
        max_depth=max_depth
    )

    response = None
    exception_occurred = False
    try:
        response = await agent.chat(BASE_INSTRUCTION)
    except Exception:
        exception_occurred = True
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
            "MAX_SUBAGENT_TURNS": agent_settings.MAX_SUBAGENT_TURNS,
            "MAX_DEPTH": MAX_DEPTH,
            "model": model_name,
            "use_openai": use_openai
        }
        
        try:
            report = generate_comprehensive_report(
                repo_slug=_repo_slug(repo_url),
                output_dir=os.path.join(_project_root(), "output"),
                hyperparams=hyperparams
            )
            report_path = save_report(
                report=report,
                output_dir=os.path.join(_project_root(), "output"),
                repo_slug=_repo_slug(repo_url)
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
    repo_url: str, 
    num_turns: int, 
    model_name: str,
    use_openai: bool = False,
    repo_path_override: Optional[str] = None,
):
    """Run the SetupAgent against the cloned repo for the requested number of user turns (async)."""
    repo_path = repo_path_override or _repo_path(repo_url)
    if repo_path_override:
        print(f"Using pre-materialized repo path: {repo_path}")
    if not os.path.exists(repo_path):
        if repo_path_override:
            raise FileNotFoundError(f"Materialized repo not found at {repo_path_override}")
        print(f"Cloning repository: {repo_url}")
        repo_path = clone_repo(repo_url)
    agent = SetupAgent(
        repo_path=repo_path, 
        model=model_name, 
        max_tool_turns=num_turns,
        use_openai=use_openai
    )

    response = None
    exception_occurred = False
    exception_msg = ""
    try:
        response = await agent.chat(SETUP_INSTRUCTION)
        prefix = "setup"
    except Exception as e:
        exception_occurred = True
        exception_msg = str(e)
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
    
    # Check if setup was successful
    # Setup is successful if: no exception occurred AND agent completed (not ran out of turns)
    setup_successful = not exception_occurred and response is not None
    
    # Additionally, check if agent actually completed with <done>
    if response and not exception_occurred:
        done_present = False
        if agent.messages:
            # Find the last assistant message (ignore tool/user/system messages)
            for message in reversed(agent.messages):
                try:
                    role = message.role
                    content = message.content
                except AttributeError:
                    # Fallback if message is stored as dict/str
                    role = getattr(message, "role", None)
                    content = getattr(message, "content", str(message))

                if role == Role.ASSISTANT:
                    if "<done>" in content and "</done>" in content:
                        done_present = True
                    break

        if not done_present:
            setup_successful = False
            if not exception_msg:
                exception_msg = "Setup agent did not complete successfully (no <done> tag found)"
    
    return {
        "response": response,
        "estimated_cost": agent.estimated_cost,
        "total_tokens": agent.total_tokens,
        "success": setup_successful,
        "error_message": exception_msg if not setup_successful else None
    }

async def run_generator_agent(
    repo_url: str,
    num_turns: int,
    model_name: str,
    use_openai: bool = False,
    max_subagent_depth: Optional[int] = None,
):
    """
    Run the generator agent to locate all exploits.json files and validate the exploits 
    they contain by generating and running test scripts (async).
    
    Args:
        repo_url: Repository identifier/URL.
        num_turns: Turn budget for the generator.
        model_name: Model to use.
        use_openai: Whether to route via OpenAI API.
        max_subagent_depth: Optional override for generator sub-agent recursion.
    """
    repo_path = _repo_path(repo_url)
    # Repo should already be cloned by setup agent
    if not os.path.exists(repo_path):
        raise ValueError(f"Repository not found at {repo_path}. Setup agent should have cloned it.")
    
    GENERATOR_INSTRUCTION = """
Your task is to VALIDATE exploits in this repository by generating passing test scripts.

IMPORTANT: The finder agent has already found exploits and created exploits.json files. Your job is to validate these existing exploits, NOT to find new ones.

Workflow:
1. FIRST, read the README.md file(s) in the repository to understand the codebase structure, testing framework, and how to build/run tests
2. Use get_exploits_jsons(".") to locate all exploits.json files in the repository
3. For each exploits.json file, use await process_exploits_json(path) to validate all exploits in that file
4. You can also use await delegate_to_sub_agent(path, task) to delegate large directories to sub-agents
5. Sub-agents can recursively validate exploits in their assigned scopes

DO NOT print anything to stdout. Work silently and let the progress bars show your progress.

Start by reading the README, then explore the repository and validate all the exploits that were already found.
"""
    
    # Initialize the main generator agent
    max_depth = max_subagent_depth if max_subagent_depth is not None else MAX_DEPTH

    agent = GeneratorAgent(
        repo_path=repo_path,
        max_tool_turns=num_turns,
        model=model_name,
        use_openai=use_openai,
        depth=0,
        max_depth=max_depth
    )
    
    response = None
    exception_occurred = False
    try:
        response = await agent.chat(GENERATOR_INSTRUCTION)
    except Exception:
        exception_occurred = True
    finally:
        # Always close the agent to clean up resources
        try:
            await agent.close()
        except Exception:
            pass
    
    # Save conversation ONLY for the main generator agent (depth 0)
    if agent.depth == 0:
        save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url))
        prefix = "error_generator_convo" if exception_occurred else "generator_convo"
        agent.save_conversation(save_folder=save_folder, prefix=prefix)
    
    return {
        "response": response,
        "estimated_cost": agent.estimated_cost,
        "total_tokens": agent.total_tokens,
        "exception_occurred": exception_occurred
    }

async def run_generator_validation(
    repo_url: str,
    model_name: str,
    use_openai: bool = False,
    repo_path_override: Optional[str] = None,
    max_subagent_depth: Optional[int] = None,
):
    """
    Directly validate all exploits by processing exploits.json files in batches.
    No LLM orchestration - just mechanical batch processing.
    
    Args:
        repo_url: Repository URL
        model_name: Model name for validation agents
        use_openai: Whether to use OpenAI API (default False)
        repo_path_override: Optional path to a pre-materialized repository
        max_subagent_depth: Optional recursion cap for validation sub-agents
    
    Returns:
        Dictionary with validation results including total_cost, total_time, etc.
    """
    from agent.generator_utils import get_exploits_jsons, process_exploits_json
    from agent.settings import GENERATOR_BATCH_SIZE
    from scripts.generate_generator_report import generate_generator_report, save_report
    
    repo_path = repo_path_override or _repo_path(repo_url)
    if repo_path_override:
        print(f"Using pre-materialized repo path: {repo_path}")
    repo_slug = _repo_slug(repo_url)
    
    if not os.path.exists(repo_path):
        if repo_path_override:
            raise FileNotFoundError(f"Materialized repo not found at {repo_path_override}")
        raise ValueError(f"Repository not found at {repo_path}. Setup agent should have cloned it.")
    
    # Find all exploits.json files
    print("\n🔍 Searching for exploits.json files...")
    exploits_files = get_exploits_jsons(repo_path)
    
    if not exploits_files:
        print("   No exploits.json files found in repository")
        return {
            "total_cost": 0.0,
            "total_time": 0.0,
            "total_exploits": 0,
            "verified_exploits": 0,
            "removed_exploits": 0,
            "success_rate": 0.0
        }
    
    print(f"   Found {len(exploits_files)} exploits.json file(s)")
    
    # Split into batches
    batches = [exploits_files[i:i + GENERATOR_BATCH_SIZE] 
               for i in range(0, len(exploits_files), GENERATOR_BATCH_SIZE)]
    
    print(f"   Processing in {len(batches)} batch(es) of {GENERATOR_BATCH_SIZE}")
    print()
    
    # Process batches
    all_results = []
    total_cost = 0.0
    total_time = 0.0
    total_exploits = 0
    verified_exploits = 0
    removed_exploits = 0
    
    for batch_idx, batch in enumerate(batches, 1):
        print(f"📦 Batch {batch_idx}/{len(batches)}: Processing {len(batch)} file(s)")
        
        # Process batch in parallel
        tasks = [
            process_exploits_json(
                exploits_path=exploit_file,
                repo_path=repo_path,
                model=model_name,
                use_openai=use_openai,
                use_vllm=False,
                max_subagent_depth=max_subagent_depth
            )
            for exploit_file in batch
        ]
        
        batch_results = await asyncio.gather(*tasks)
        all_results.extend(batch_results)
        
        # Aggregate batch statistics
        for result in batch_results:
            if "error" not in result:
                total_cost += result.get("total_cost", 0.0)
                total_time += result.get("total_time", 0.0)
                total_exploits += result.get("total_exploits", 0)
                verified_exploits += result.get("verified_exploits", 0)
                removed_exploits += result.get("removed_exploits", 0)
        
        print()
    
    # Calculate success rate
    success_rate = (verified_exploits / total_exploits * 100) if total_exploits > 0 else 0.0
    
    # Generate comprehensive report
    print("📊 Generating comprehensive report...")
    try:
        output_dir = os.path.join(_project_root(), "output")
        report = generate_generator_report(
            repo_slug=repo_slug,
            output_dir=output_dir
        )
        report_path = save_report(
            report=report,
            output_dir=output_dir,
            repo_slug=repo_slug
        )
        print(f"   Report saved to: {report_path}")
    except Exception as e:
        print(f"   ⚠️  Warning: Failed to generate report: {e}")
    
    # Print summary
    print("\n" + "="*80)
    print("VALIDATION SUMMARY")
    print("="*80)
    print(f"Exploits.json files processed: {len(exploits_files)}")
    print(f"Total exploits processed: {total_exploits}")
    print(f"Verified exploits: {verified_exploits}")
    print(f"Removed exploits: {removed_exploits}")
    print(f"Success rate: {success_rate:.1f}%")
    print(f"Total cost: ${total_cost:.4f}")
    print(f"Total time: {total_time:.1f}s ({total_time/60:.1f}m)")
    if verified_exploits > 0:
        print(f"Cost per verified exploit: ${total_cost/verified_exploits:.4f}")
        print(f"Time per verified exploit: {total_time/verified_exploits:.1f}s")
    print("="*80)
    
    return {
        "total_cost": total_cost,
        "total_time": total_time,
        "total_exploits": total_exploits,
        "verified_exploits": verified_exploits,
        "removed_exploits": removed_exploits,
        "success_rate": success_rate,
        "all_results": all_results
    }


async def run_fixer_agent(
    repo_url: str, 
    num_turns: int, 
    model_name: str,
    use_openai: bool = False,
    repo_path_override: Optional[str] = None,
):
    """
    Run the fixer agent for all exploits in the exploits.json file in the repo path (async)
    """
    from agent.fixer_utils import process_fix_exploits
    from scripts.generate_fixer_report import generate_fixer_report, save_report
    
    repo_path = repo_path_override or _repo_path(repo_url)
    repo_slug = _repo_slug(repo_url)
    
    if not os.path.exists(repo_path):
        if repo_path_override:
            raise FileNotFoundError(f"Materialized repo not found at {repo_path_override}")
        raise ValueError(f"Repository not found at {repo_path}. Finder agent should have cloned it.")
    
    # Find all exploits.json files
    print("\n🔍 Searching for exploits.json files...")
    from agent.generator_utils import get_exploits_jsons
    exploits_files = get_exploits_jsons(repo_path)
    
    if not exploits_files:
        print("   No exploits.json files found in repository")
        return {
            "total_cost": 0.0,
            "total_time": 0.0,
            "total_exploits": 0,
            "fixed_exploits": 0,
            "failed_exploits": 0,
            "success_rate": 0.0
        }
    
    print(f"   Found {len(exploits_files)} exploits.json file(s)")
    
    # Process files in batches
    batch_size = max(1, FIXER_BATCH_SIZE)
    batches = [
        exploits_files[i:i + batch_size]
        for i in range(0, len(exploits_files), batch_size)
    ]
    
    print(f"   Processing in {len(batches)} batch(es) of {batch_size}")
    
    all_results = []
    total_cost = 0.0
    total_time = 0.0
    total_exploits = 0
    fixed_exploits = 0
    failed_exploits = 0
    
    for batch_idx, batch in enumerate(batches, 1):
        print(f"📦 Batch {batch_idx}/{len(batches)}: Processing {len(batch)} file(s)")
        
        tasks = [
            process_fix_exploits(
                exploits_path=exploit_file,
                repo_path=repo_path,
                model=model_name,
                use_openai=use_openai,
                use_vllm=False
            )
            for exploit_file in batch
        ]
        
        batch_results = await asyncio.gather(*tasks)
        
        for result in batch_results:
            if "error" not in result:
                total_cost += result.get("total_cost", 0.0)
                total_time += result.get("total_time", 0.0)
                total_exploits += result.get("total_exploits", 0)
                fixed_exploits += result.get("fixed_exploits", 0)
                failed_exploits += result.get("failed_exploits", 0)
                all_results.append(result)
        
        print()
            
    # Calculate success rate
    success_rate = (fixed_exploits / total_exploits * 100) if total_exploits > 0 else 0.0
    
    # Generate comprehensive report
    print("📊 Generating fixer report...")
    try:
        output_dir = os.path.join(_project_root(), "output")
        report = generate_fixer_report(
            repo_slug=repo_slug,
            output_dir=output_dir
        )
        report_path = save_report(
            report=report,
            output_dir=output_dir,
            repo_slug=repo_slug
        )
        print(f"   Report saved to: {report_path}")
    except Exception as e:
        print(f"   ⚠️  Warning: Failed to generate report: {e}")
    
    # Print summary
    print("\n" + "="*80)
    print("FIXER SUMMARY")
    print("="*80)
    print(f"Exploits.json files processed: {len(exploits_files)}")
    print(f"Total exploits processed: {total_exploits}")
    print(f"Fixed exploits: {fixed_exploits}")
    print(f"Failed exploits: {failed_exploits}")
    print(f"Success rate: {success_rate:.1f}%")
    print(f"Total cost: ${total_cost:.4f}")
    print(f"Total time: {total_time:.1f}s ({total_time/60:.1f}m)")
    if fixed_exploits > 0:
        print(f"Cost per fixed exploit: ${total_cost/fixed_exploits:.4f}")
        print(f"Time per fixed exploit: {total_time/fixed_exploits:.1f}s")
    print("="*80)
    
    return {
        "total_cost": total_cost,
        "total_time": total_time,
        "total_exploits": total_exploits,
        "fixed_exploits": fixed_exploits,
        "failed_exploits": failed_exploits,
        "success_rate": success_rate,
        "all_results": all_results
    }

async def main():
    """Main function with configurable agent execution."""
    parser = argparse.ArgumentParser(
        description='Run exploit-agent scaffold with configurable agent execution',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all agents (default: finder → setup → generator)
  python run_scaffold.py
  
  # Run only finder agent
  python run_scaffold.py --finder-only
  
  # Run only setup agent
  python run_scaffold.py --setup-only
  
  # Run finder and generator (skip setup)
  python run_scaffold.py --skip-setup
  
  # Run only generator (assumes finder and setup already completed)
  python run_scaffold.py --generator-only
  
  # Run only fixer (assumes exploits already found)
  python run_scaffold.py --fixer-only
  
  # Custom repository and model
  python run_scaffold.py --repo https://github.com/user/repo.git --model gpt-4
  
  # Custom number of turns
  python run_scaffold.py --turns 50
        """
    )
    
    # Repository configuration
    parser.add_argument('--repo', type=str, 
                       default="https://github.com/code-423n4/2025-09-monad.git",
                       help='Repository URL to analyze')
    parser.add_argument('--turns', type=int, default=32,
                       help='Number of turns for each agent (default: 32)')
    parser.add_argument('--subagent-turns', type=int,
                       default=agent_settings.MAX_SUBAGENT_TURNS,
                       help='Turn budget allocated to each sub-agent (default: %(default)s)')
    
    # Model configuration
    parser.add_argument('--model', type=str, default="z-ai/glm-4.6",
                       help='Model name for finder and generator agents')
    parser.add_argument('--setup-model', type=str, default="anthropic/claude-sonnet-4.5",
                       help='Model name for setup agent (default: claude-sonnet-4.5)')
    parser.add_argument('--use-openai', action='store_true',
                       help='Use OpenAI API instead of OpenRouter')
    
    # Agent selection (mutually exclusive group for convenience)
    agent_group = parser.add_mutually_exclusive_group()
    agent_group.add_argument('--setup-only', action='store_true',
                            help='Run only the setup agent')
    agent_group.add_argument('--finder-only', action='store_true',
                            help='Run only the finder agent (requires setup to be done)')
    agent_group.add_argument('--generator-only', action='store_true',
                            help='Run only the generator agent (requires setup and finder to be done)')
    agent_group.add_argument('--fixer-only', action='store_true',
                            help='Run only the fixer agent (requires exploits to be found)')
    
    # Fine-grained control (can be combined)
    parser.add_argument('--skip-setup', action='store_true',
                       help='Skip the setup agent')
    parser.add_argument('--skip-finder', action='store_true',
                       help='Skip the finder agent')
    parser.add_argument('--skip-generator', action='store_true',
                       help='Skip the generator agent')
    parser.add_argument('--skip-fixer', action='store_true',
                       help='Skip the fixer agent')
    
    args = parser.parse_args()
    
    if args.subagent_turns <= 0:
        parser.error("subagent-turns must be greater than zero.")
    applied_subagent_turns = agent_settings.set_max_subagent_turns(args.subagent_turns)
    
    # Determine which agents to run
    run_setup = True
    run_finder = True
    run_generator = True
    run_fixer = True
    
    # Handle mutually exclusive options
    if args.setup_only:
        run_setup = True
        run_finder = False
        run_generator = False
        run_fixer = False
    elif args.finder_only:
        run_setup = False
        run_finder = True
        run_generator = False
        run_fixer = False
    elif args.generator_only:
        run_setup = False
        run_finder = False
        run_generator = True
        run_fixer = False
    elif args.fixer_only:
        run_setup = False
        run_finder = False
        run_generator = False
        run_fixer = True
    
    # Handle skip options
    if args.skip_setup:
        run_setup = False
    if args.skip_finder:
        run_finder = False
    if args.skip_generator:
        run_generator = False
    if args.skip_fixer:
        run_fixer = False
    
    # Validate that at least one agent is enabled
    if not (run_setup or run_finder or run_generator or run_fixer):
        parser.error("At least one agent must be enabled. Cannot skip all agents.")
    
    # Configuration
    repo_url = args.repo
    num_turns = args.turns
    use_openai = args.use_openai
    model_name = args.model
    setup_model = args.setup_model
    setup_use_openai = False  # Use OpenRouter for Claude (setup agent)
    
    # Print configuration
    print("\n" + "="*80)
    print("EXPLOIT-AGENT CONFIGURATION")
    print("="*80)
    print(f"Repository: {repo_url}")
    print(f"Turns per agent: {num_turns}")
    print(f"Main model: {model_name}")
    print(f"Setup model: {setup_model}")
    print(f"Sub-agent turns: {applied_subagent_turns}")
    print(f"Agents to run: {', '.join([a for a, enabled in [('Finder', run_finder), ('Setup', run_setup), ('Generator', run_generator), ('Fixer', run_fixer)] if enabled])}")
    print("="*80)
    
    results = {}
    total_cost = 0.0
    step_num = 1
    total_steps = sum([run_setup, run_finder, run_generator, run_fixer])
    
    # Execution order: finder → setup → generator → fixer
    # Finder agent explores the raw codebase and creates exploits.json files
    # Setup agent prepares the environment (installs dependencies, builds, etc.)
    # Generator agent validates exploits by generating and running tests
    # Fixer agent suggests fixes for verified exploits
    
    if run_finder:
        print("\n" + "="*80)
        print(f"STEP {step_num}/{total_steps}: Running Finder Agent (Model: {model_name})")
        print("="*80)
        finder_result = await run_finder_agent(repo_url, num_turns, model_name, use_openai)
        print(f"✅ Finder agent completed. Cost: ${finder_result['estimated_cost']:.4f}")
        results['finder'] = finder_result
        total_cost += finder_result['estimated_cost']
        step_num += 1
    elif run_setup or run_generator or run_fixer:
        print("\n⚠️  Skipping finder agent - assuming exploits.json files already exist")
    
    if run_setup:
        print("\n" + "="*80)
        print(f"STEP {step_num}/{total_steps}: Running Setup Agent (Model: {setup_model})")
        print("="*80)
        setup_result = await run_setup_agent(repo_url, num_turns, setup_model, setup_use_openai)
        
        # Check if setup was successful
        if not setup_result.get('success', False):
            error_msg = setup_result.get('error_message', 'Unknown error')
            print(f"\n❌ SETUP FAILED: {error_msg}")
            print(f"   Cost: ${setup_result['estimated_cost']:.4f}")
            print("\n" + "="*80)
            print("ABORTING: Setup must complete successfully before proceeding to generator")
            print("="*80)
            raise RuntimeError(f"Setup agent failed: {error_msg}")
        
        print(f"✅ Setup agent completed successfully. Cost: ${setup_result['estimated_cost']:.4f}")
        results['setup'] = setup_result
        total_cost += setup_result['estimated_cost']
        step_num += 1
    elif run_generator or run_fixer:
        print("\n⚠️  Skipping setup agent - assuming repository is already set up")
    
    if run_generator:
        print("\n" + "="*80)
        print(f"STEP {step_num}/{total_steps}: Running Generator Validation (Model: {model_name})")
        print("="*80)
        generator_result = await run_generator_validation(repo_url, model_name, use_openai)
        print(f"✅ Generator validation completed. Cost: ${generator_result['total_cost']:.4f}")
        results['generator'] = generator_result
        total_cost += generator_result['total_cost']
        step_num += 1
    
    # Fixer agent
    if run_fixer:
        print("\n" + "="*80)
        print(f"STEP {step_num}/{total_steps}: Running Fixer Agent (Model: {model_name})")
        print("="*80)
        fixer_result = await run_fixer_agent(repo_url, num_turns, model_name, use_openai)
        print(f"✅ Fixer agent completed. Cost: ${fixer_result['total_cost']:.4f}")
        results['fixer'] = fixer_result
        total_cost += fixer_result['total_cost']
        step_num += 1
    
    # Final summary
    print("\n" + "="*80)
    agents_run = [a for a, enabled in [('Finder', run_finder), ('Setup', run_setup), ('Generator', run_generator), ('Fixer', run_fixer)] if enabled]
    print(f"{'ALL ' if len(agents_run) == 4 else ''}AGENTS COMPLETED SUCCESSFULLY")
    print("="*80)
    print(f"Agents run: {', '.join(agents_run)}")
    print(f"Total cost: ${total_cost:.4f}")
    print("="*80)
    
    return results

if __name__ == "__main__":
    asyncio.run(main())