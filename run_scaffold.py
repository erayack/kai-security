import os
import re
import shutil
import subprocess
import hashlib
from pathlib import Path
import json
import uuid
from tqdm import tqdm

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


def run_finder_agent(repo_url: str, num_turns: int, model_name: str):
    """Run the FinderAgent against the cloned repo for the requested number of user turns."""
    repo_path = _repo_path(repo_url)
    if not os.path.exists(repo_path):
        repo_path = clone_repo(repo_url)
    agent = FinderAgent(repo_path=repo_path, model=model_name, max_tool_turns=num_turns)

    response = agent.chat(BASE_INSTRUCTION)

    # Save conversation under a per-repo folder inside output/conversations
    save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url))
    agent.save_conversation(save_folder=save_folder)

def run_setup_agent(repo_url: str, num_turns: int, model_name: str):
    """Run the SetupAgent against the cloned repo for the requested number of user turns."""
    repo_path = _repo_path(repo_url)
    agent = SetupAgent(repo_path=repo_path, model=model_name, max_tool_turns=num_turns)

    response = agent.chat(SETUP_INSTRUCTION)

    # Save conversation under a per-repo folder inside output/conversations
    save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url))
    agent.save_conversation(save_folder=save_folder, prefix="setup")

def run_generator_agent(repo_url: str, num_turns: int, model_name: str):
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
            model=model_name
        )
        
        # Construct the instruction
        instruction = GENERATOR_INSTRUCTION.format(exploit=json.dumps(exploit))
        
        # Generate the test script
        response = agent.chat(instruction)
        
        # Save the conversation
        agent.save_conversation(save_folder="generator_conversations", prefix=f"exploit_{exploit['id']}")

def run_fixer_agent(repo_url: str, num_turns: int, model_name: str):
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
            model=model_name
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

        agent.save_conversation(save_folder="fixer_conversations", prefix=f"exploit_{exploit['id']}")

def main():
    repo_url = "https://github.com/code-423n4/2025-10-hybra-finance"
    num_turns = 64
    model_name = "anthropic/claude-sonnet-4.5"
    run_finder_agent(repo_url, num_turns, model_name)
    print("Finder agent finished")
    run_setup_agent(repo_url, num_turns, model_name)
    print("Setup agent finished")
    run_generator_agent(repo_url, num_turns, model_name)
    print("Generator agent finished")
    run_fixer_agent(repo_url, num_turns, model_name)
    print("Fixer agent finished")

if __name__ == "__main__":
    main()