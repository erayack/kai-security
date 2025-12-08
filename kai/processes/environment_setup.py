import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from kai.agents.agent_types import SetupAgent
from kai.schemas import MasterContext, AgentResponse


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _inputs_root(repo_slug: str) -> Path:
    # Test expects testbed/<slug>/inputs
    path = _project_root() / repo_slug / "inputs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _master_root(repo_slug: str) -> Path:
    # Test expects testbed/<slug>/master
    path = _project_root() / repo_slug / "master"
    path.mkdir(parents=True, exist_ok=True)
    return path


_REPO_COMMIT_CACHE = {}


def _get_repo_commit_hash(repo_url: str) -> Optional[str]:
    """Resolve the repository's HEAD commit hash for slug generation."""
    if repo_url in _REPO_COMMIT_CACHE:
        return _REPO_COMMIT_CACHE[repo_url]

    commit_hash = None
    is_local_repo = os.path.isdir(repo_url)
    command = (
        ["git", "-C", repo_url, "rev-parse", "HEAD"]
        if is_local_repo
        else ["git", "ls-remote", repo_url, "HEAD"]
    )

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        output = result.stdout.strip()
        if output:
            commit_hash = output if is_local_repo else output.split()[0]
    except Exception:
        commit_hash = None

    if commit_hash:
        commit_hash = commit_hash[:8]

    _REPO_COMMIT_CACHE[repo_url] = commit_hash
    return commit_hash


def _repo_slug(repo_url: str) -> str:
    # Derive a filesystem-safe slug from repo name + commit hash (fallback to URL hash)
    name = Path(re.sub(r"\\.git$", "", repo_url.split("/")[-1])).stem or "repo"
    short_hash = _get_repo_commit_hash(repo_url) or "unknown"
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "-", name)
    return f"{safe_name}-{short_hash}"


def clone_repo(repo_url: str, dest: Path) -> Path:
    """Clone the repository into a deterministic folder and return its absolute path."""
    if dest.exists():
        shutil.rmtree(dest)
    subprocess.run(["git", "clone", repo_url, str(dest)], check=True)
    return dest


def copy_to_master(inputs_path: Path, master_path: Path) -> Path:
    if master_path.exists():
        shutil.rmtree(master_path)
    shutil.copytree(inputs_path, master_path)
    return master_path


def make_read_only(path: Path) -> None:
    """Recursively mark a directory tree as read-only."""
    try:
        path.chmod(path.stat().st_mode & ~0o222)
    except Exception:
        pass
    for root, dirs, files in os.walk(path):
        for d in dirs:
            dir_path = Path(root) / d
            dir_path.chmod(dir_path.stat().st_mode & ~0o222)
        for f in files:
            file_path = Path(root) / f
            try:
                file_path.chmod(file_path.stat().st_mode & ~0o222)
            except PermissionError:
                # If chmod fails (e.g., on symlinks), skip silently
                pass


def _normalize_master_context_paths(
    master_context: MasterContext, master_repo_path: Path
) -> MasterContext:
    """
    Convert relative or placeholder paths in MasterContext to absolute paths rooted at master_repo_path.
    """

    def _normalize_path(value: Optional[str]) -> str:
        if not value or value in (".", "./"):
            return str(master_repo_path)
        p = Path(value)
        if p.is_absolute():
            return str(p)
        return str(master_repo_path / p)

    master_context.root_path = _normalize_path(master_context.root_path)
    master_context.artifacts_path = _normalize_path(master_context.artifacts_path)
    master_context.src_path = _normalize_path(master_context.src_path)
    master_context.lib_path = _normalize_path(master_context.lib_path)
    master_context.test_path = _normalize_path(master_context.test_path)
    return master_context


async def run_environment_setup(
    repo_url: str,
    num_turns: int,
    model_name: str,
    use_openai: bool = False,
    execution_id: Optional[str] = None,
    repo_path_override: Optional[str] = None,
) -> dict:
    """
    Clone/copy the repository into master, run SetupAgent, and return MasterContext.
    """
    repo_slug = _repo_slug(repo_url)
    inputs_root = _inputs_root(repo_slug)
    master_root = _master_root(repo_slug)

    inputs_repo_path = Path(repo_path_override) if repo_path_override else inputs_root
    master_repo_path = master_root

    if repo_path_override:
        if not inputs_repo_path.exists():
            raise FileNotFoundError(
                f"Materialized repo not found at {repo_path_override}"
            )
    else:
        clone_repo(repo_url, inputs_repo_path)

    copy_to_master(inputs_repo_path, master_repo_path)

    agent = SetupAgent(
        repo_path=str(master_repo_path),
        model=model_name,
        max_tool_turns=num_turns,
        use_openai=use_openai,
        execution_id=execution_id,
    )

    response: Optional[AgentResponse] = None
    exception_occurred = False
    exception_msg = ""
    try:
        response = await agent.chat("You must start setting up the repository now")
        prefix = "setup"
    except Exception as e:
        exception_occurred = True
        exception_msg = str(e)
        prefix = "error_setup"
    finally:
        try:
            await agent.close()
        except Exception:
            pass

    # Save conversation under output/<repo_slug>
    save_folder = _project_root() / "output" / repo_slug
    agent.save_conversation(save_folder=str(save_folder), prefix=prefix)

    master_context = response.master_context if response else None
    if master_context:
        master_context = _normalize_master_context_paths(
            master_context, master_repo_path
        )

    # Mark master as read-only to enforce golden master contract
    try:
        make_read_only(master_repo_path)
    except Exception:
        pass

    setup_successful = (
        not exception_occurred
        and response is not None
        and response.master_context is not None
    )

    if not setup_successful and not exception_msg:
        exception_msg = "Setup agent did not produce a MasterContext"

    return {
        "response": response,
        "master_context": master_context,
        "estimated_cost": agent.estimated_cost,
        "total_tokens": agent.total_tokens,
        "success": setup_successful,
        "error_message": exception_msg if not setup_successful else None,
        "master_repo_path": str(master_repo_path),
        "repo_slug": repo_slug,
    }
