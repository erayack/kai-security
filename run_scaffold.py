import os
import re
import shutil
import subprocess
import hashlib
from pathlib import Path
import json
import uuid
from agent.agent import Agent
from agent.utils import AgentType
from agent.verifier import generate_test_script


BASE_INSTRUCTION = "You must start your search for exploits now"


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
    """Run the Agent against the cloned repo for the requested number of user turns."""
    repo_path = _repo_path(repo_url)
    if not os.path.exists(repo_path):
        repo_path = clone_repo(repo_url)
    agent = Agent(repo_path=repo_path, model=model_name, max_tool_turns=num_turns)

    response = agent.chat(BASE_INSTRUCTION)

    # Save conversation under a per-repo folder inside output/conversations
    save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url))
    agent.save_conversation(save_folder=save_folder)

def run_generator_agent(repo_url: str, num_turns: int, model_name: str):
    """
    Run the generator agent for all exploits in the exploits.json file in the repo path
    """
    repo_path = _repo_path(repo_url)
    agent = Agent(repo_path=repo_path, model=model_name, max_tool_turns=num_turns, agent_type=AgentType.TEST_GENERATOR)
    for exploit in json.load(open(os.path.join(repo_path, "exploits.json"))):
        test_script = generate_test_script(exploit, repo_path)
        if test_script:
            try:
                test_dir = "test_scripts"
                os.makedirs(test_dir, exist_ok=True)
                test_file_path = os.path.join(test_dir, f"{exploit['id']}.t.sol")
                with open(test_file_path, "w") as f:
                    f.write(test_script)
            except Exception as e:
                print(f"Error writing test script for exploit {exploit['id']}: {e}")

def main():
    repo_url = "https://github.com/CodeHawks-Contests/2025-07-last-man-standing.git"
    num_turns = 16
    model_name = "google/gemini-2.5-flash-preview-09-2025"
    run_finder_agent(repo_url, num_turns, model_name)
    print("Finder agent finished")
    run_generator_agent(repo_url, num_turns, model_name)
    print("Generator agent finished")

if __name__ == "__main__":
    main()