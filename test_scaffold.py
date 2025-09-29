import os
import re
import shutil
import subprocess
import hashlib
from pathlib import Path
import json
import uuid
from agent.agent import Agent


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


def test_agent(repo_url: str, num_turns: int, model_name: str):
    """Run the Agent against the cloned repo for the requested number of user turns."""
    repo_path = clone_repo(repo_url)
    agent = Agent(repo_path=repo_path, model=model_name)

    response = agent.chat(BASE_INSTRUCTION)

    # Save conversation under a per-repo folder inside output/conversations
    save_folder = os.path.join(_project_root(), "output", _repo_slug(repo_url))
    report_folder = os.path.join(save_folder, "reports")
    os.makedirs(report_folder, exist_ok=True)
    agent.save_conversation(save_folder=save_folder)

    # Get the reply from the response
    reply = response.reply
    # Parse the reply as a JSON object
    reply = json.loads(reply)
    # Save the reply to the report folder
    report_name = f"report_{uuid.uuid4()}.json"
    try:
        with open(os.path.join(report_folder, report_name), "w") as f:
            json.dump(reply, f)
    except Exception as e:
        print(f"Error saving report: {e}")

    delete_repo(repo_url)
    return save_folder

def main():
    repo_url = "https://github.com/firstbatchxyz/mem-agent-mcp.git"
    num_turns = 32
    model_name = "google/gemini-2.5-flash-preview-09-2025"
    test_agent(repo_url, num_turns, model_name)

if __name__ == "__main__":
    main()