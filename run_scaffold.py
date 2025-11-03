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


BASE_INSTRUCTION = "You must start your search for exploits now"
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


def delete_repo(repo_url: str) -> None:
    """Delete the deterministic clone folder for the given repository URL if it exists."""
    dest = _repo_path(repo_url)
    if os.path.exists(dest):
        shutil.rmtree(dest)


def run_finder_agent(
    repo_url: str, 
    num_turns: int, 
    model_name: str,
    use_openai: bool = False
):
    """Run the FinderAgent against the cloned repo for the requested number of user turns."""
    repo_path = _repo_path(repo_url)
    if not os.path.exists(repo_path):
        repo_path = clone_repo(repo_url)
    agent = FinderAgent(
        repo_path=repo_path, 
        model=model_name, 
        max_tool_turns=num_turns,
        use_openai=use_openai
    )

    try:
        response = agent.chat(BASE_INSTRUCTION)
        prefix = "convo"
    except Exception as e:
        print(f"Error in finder agent: {e}")
        prefix = "error_convo"

    # Save conversation under a per-repo folder inside output/conversations
    save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url))
    agent.save_conversation(save_folder=save_folder, prefix=prefix)

def run_setup_agent(
    repo_url: str, 
    num_turns: int, 
    model_name: str,
    use_openai: bool = False
):
    """Run the SetupAgent against the cloned repo for the requested number of user turns."""
    repo_path = _repo_path(repo_url)
    agent = SetupAgent(
        repo_path=repo_path, 
        model=model_name, 
        max_tool_turns=num_turns,
        use_openai=use_openai
    )

    try:
        response = agent.chat(SETUP_INSTRUCTION)
        prefix = "setup"
    except Exception as e:
        print(f"Error in setup agent: {e}")
        prefix = "error_setup"
    
    # Save conversation under a per-repo folder inside output/conversations
    save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url))
    agent.save_conversation(save_folder=save_folder, prefix=prefix)

def run_generator_agent(
    repo_url: str, 
    num_turns: int, 
    model_name: str,
    use_openai: bool = False
):
    """
    Run the generator agent for all exploits in the exploits.json file in the repo path
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
    for exploit in tqdm(exploits, desc="Generating exploits"):
        # Initialize the generator agent
        agent = GeneratorAgent(
            repo_path=repo_path,
            max_tool_turns=num_turns,
            model=model_name,
            use_openai=use_openai
        )
        
        # Construct the instruction
        instruction = GENERATOR_INSTRUCTION.format(exploit=json.dumps(exploit))
        
        # Generate the test script
        response = agent.chat(instruction)
        
        # Save conversation under a per-repo folder inside output/conversations
        save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url), "generator_conversations")
        os.makedirs(save_folder, exist_ok=True)
        agent.save_conversation(save_folder=save_folder, prefix=f"generator_exploit_{exploit['id']}")

def run_fixer_agent(
    repo_url: str, 
    num_turns: int, 
    model_name: str,
    use_openai: bool = False
):
    """
    Run the fixer agent for all exploits in the exploits.json file in the repo path
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
    for exploit in tqdm(exploits, desc="Fixing exploits"):
        agent = FixerAgent(
            repo_path=repo_path, 
            max_tool_turns=num_turns, 
            model=model_name,
            use_openai=use_openai
        )

        # Construct the instruction
        instruction = FIXER_INSTRUCTION.format(exploit=json.dumps(exploit))
        
        # Fix the exploit
        response = agent.chat(instruction)
        
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
        save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url), "fixer_conversations")
        os.makedirs(save_folder, exist_ok=True)
        agent.save_conversation(save_folder=save_folder, prefix=f"fixer_exploit_{exploit['id']}")

def main():
    repo_url = "https://github.com/gmsol-labs/gmx-solana.git"
    num_turns = 32
    use_openai = False
    model_name = "gpt-5-2025-08-07" if use_openai else "z-ai/glm-4.6"

    run_finder_agent(repo_url, num_turns, model_name, use_openai)
    print("Finder agent finished")
    #run_setup_agent(repo_url, num_turns, model_name, use_openai)
    print("Setup agent finished")
    #run_generator_agent(repo_url, num_turns, model_name, use_openai)
    print("Generator agent finished")
    #run_fixer_agent(repo_url, num_turns, model_name, use_openai)
    print("Fixer agent finished")

if __name__ == "__main__":
    main()