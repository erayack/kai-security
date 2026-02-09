import os
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List

# Expose common repo inspection + file editing tools to SetupAgent.
# The setup prompt expects these primitives for exploration and patching.
from kai.agents.tools.tools import (
    read_file,
    list_files,
    update_file,
    create_file,
    _get_current_agent as _get_agent,
)
from kai.schemas import MasterContext
from kai.utils.tool_adapters import get_tool_adapter

__all__ = [
    "read_file",
    "list_files",
    "update_file",
    "create_file",
    "write_setup_script",
    "run_setup_script",
    "git_submodule_update",
    "convert_ssh_to_https_in_gitmodules",
    "install_dependencies",
    "write_and_compile",
    "run_test",
    "register_master_context",
]


def _get_current_agent():
    """
    Get the current agent instance from the global registry.
    First checks contextvars (via _get_agent), then falls back to stack inspection.
    """
    # Try the preferred contextvar method first
    agent = _get_agent()
    if agent is not None:
        return agent

    try:
        # Try to get from local scope first (passed via execute_sandboxed_code)
        import inspect

        frame = inspect.currentframe()
        while frame:
            if "_agent_instance" in frame.f_locals:
                return frame.f_locals["_agent_instance"]
            frame = frame.f_back
    except Exception:
        pass
    return None


def _resolve_working_dir(working_dir: Optional[str] = None) -> str:
    """
    Resolve working_dir relative to agent's working_dir if available.
    If working_dir is None, returns agent's working_dir or current directory.
    """
    if working_dir is None:
        try:
            agent = _get_current_agent()
            return agent.working_dir if agent else os.getcwd()
        except (NameError, TypeError):
            return os.getcwd()
    else:
        # Resolve relative paths relative to agent's working_dir
        if not os.path.isabs(working_dir):
            try:
                agent = _get_current_agent()
                if agent:
                    return os.path.join(agent.working_dir, working_dir)
            except (NameError, TypeError):
                pass
        return working_dir


def _detect_framework(workspace: Path) -> str:
    """
    Best-effort detect a supported tool framework for compilation/testing.

    Uses the centralized FrameworkDetector. Falls back to "foundry" if detection fails.
    """
    from kai.utils.framework_detector import detect_framework_safe

    return detect_framework_safe(workspace, fallback="foundry")


def write_setup_script(
    working_dir: Optional[str] = None,
    subdir: Optional[str] = None,
    primary: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Write a cross-framework bootstrap script to scripts/setup_all.sh.

    The script is idempotent and can:
    - Install assist dependencies across Node/Foundry/Python/Cargo
    - Build and test only the primary framework (auto-detected or overridden via PRIMARY=...)

    Args:
        working_dir: Base working directory (defaults to agent working_dir)
        subdir: Optional subdirectory under working_dir to write the script in
        primary: Optional primary framework hint (e.g., "foundry", "javascript", "python", "cargo", "cmake").

    Returns:
        Dict with {written: bool, path: str, content: str}
    """
    try:
        wd = _resolve_working_dir(working_dir)
        workspace = Path(wd)
        # Determine destination directory for script.
        # If subdir is provided, use it as-is; otherwise, default to "scripts".
        # Avoid accidental nesting like scripts/scripts when callers pass "scripts".
        scripts_dir = workspace / (subdir or "scripts")
        scripts_dir.mkdir(parents=True, exist_ok=True)

        script_path = scripts_dir / "setup_all.sh"
        script_content = """#!/usr/bin/env bash
set -euo pipefail

ROOT="${SETUP_SUBDIR:-.}"
cd "$ROOT"

have(){ command -v "$1" >/dev/null 2>&1; }

pkg_manager() {
  if [ -f pnpm-lock.yaml ] && have pnpm; then echo pnpm; return; fi
  if [ -f yarn.lock ] && have yarn; then echo yarn; return; fi
  if [ -f package-lock.json ] && have npm; then echo npm; return; fi
  if have pnpm; then echo pnpm; elif have yarn; then echo yarn; else echo npm; fi
}

node_install() {
  [ -f package.json ] || return 0
  PM="$(pkg_manager)"
  case "$PM" in
    pnpm) pnpm install --frozen-lockfile || pnpm install ;;
    yarn) yarn install --frozen-lockfile || yarn install ;;
    npm) npm ci || npm install ;;
  esac
}

foundry_install() {
  [ -f foundry.toml ] || return 0
  if ! command -v forge >/dev/null 2>&1; then echo "forge not found in PATH"; return 1; fi
  git submodule update --init --recursive || true
  forge install || true
}

python_install() {
  # Use uv sync ONLY when a pyproject.toml exists in this repo.
  if [ -f pyproject.toml ]; then
    if command -v uv >/dev/null 2>&1; then uv sync || true; return 0; fi
  fi
  # For requirements.txt-only repos, provision a local venv and install there.
  if [ -f requirements.txt ]; then
    python3 -m venv .venv || true
    if [ -f .venv/bin/activate ]; then . .venv/bin/activate; fi
    python3 -m pip install -U pip wheel || true
    pip install -r requirements.txt || true
  fi
}

cargo_install() {
  [ -f Cargo.toml ] || return 0
  if ! command -v cargo >/dev/null 2>&1; then echo "cargo not found in PATH"; return 1; fi
  cargo fetch || true
}

primary_detect() {
  if [ "${PRIMARY:-auto}" != "auto" ]; then echo "$PRIMARY"; return; fi
  if [ -f foundry.toml ]; then echo foundry; return; fi
  if ls hardhat.config.* >/dev/null 2>&1 || [ -f package.json ]; then echo javascript; return; fi
  if [ -f Cargo.toml ]; then echo cargo; return; fi
  if [ -f CMakeLists.txt ]; then echo cmake; return; fi
  if [ -f pyproject.toml ] || [ -f requirements.txt ]; then echo python; return; fi
  echo foundry
}

build_primary() {
  local P; P="$(primary_detect)"
  # Assist installs for common cross-deps
  if [ "$P" = "foundry" ] && [ -f package.json ]; then node_install; fi
  if [ "$P" = "javascript" ] && [ -f foundry.toml ]; then foundry_install; fi
  if [ "$P" = "python" ] && [ -f Cargo.toml ]; then cargo_install; fi

  case "$P" in
    foundry) forge build ;;
    javascript) npx hardhat compile || { command -v tsc >/dev/null 2>&1 && tsc -p .; } || true ;;
    cargo) cargo test --no-run ;;
    cmake) cmake -S . -B build && cmake --build build ;;
    python) echo "Python: syntax-only; run tests to validate" ;;
  esac
}

test_primary() {
  local P; P="$(primary_detect)"
  case "$P" in
    foundry) forge test -vv ;;
    javascript) npx hardhat test || npm test || true ;;
    cargo) cargo test ;;
    cmake) ctest --test-dir build || true ;;
    python)
      if [ -f .venv/bin/activate ]; then . .venv/bin/activate; fi
      pytest -q || true
      ;;
  esac
}

case "${1:-all}" in
  install) node_install; foundry_install; python_install; cargo_install ;;
  build) build_primary ;;
  test) test_primary ;;
  all) node_install; foundry_install; python_install; cargo_install; build_primary; test_primary ;;
esac
"""

        script_path.write_text(script_content, encoding="utf-8")
        # Make executable
        try:
            os.chmod(script_path, 0o755)
        except Exception:
            # Non-fatal if chmod not permitted on some filesystems
            pass

        rel_path = script_path.relative_to(workspace)
        result = {
            "written": True,
            "path": rel_path.as_posix(),
            "content": script_content,
        }
        if primary:
            result["primary_hint"] = str(primary)
        return result
    except Exception as e:
        return {"written": False, "error": str(e)}


def run_setup_script(
    phase: str = "install",
    working_dir: Optional[str] = None,
    timeout: int = 600,
) -> Dict[str, Any]:
    """
    Execute the generated scripts/setup_all.sh with the given phase.

    Args:
        phase: One of install, build, test, all
        working_dir: Directory to run in (defaults to agent working_dir)
        timeout: Command timeout in seconds

    Returns:
        Dict with {success: bool, stdout: str, stderr: str, returncode: int, script_path: str}
    """
    agent = _get_current_agent()
    if agent is None:
        return {"success": False, "error": "No agent context available"}

    wd = _resolve_working_dir(working_dir)
    workspace = Path(wd)

    # Prefer scripts/setup_all.sh; tolerate older scripts/scripts/setup_all.sh
    candidates = [
        workspace / "scripts" / "setup_all.sh",
        workspace / "scripts" / "scripts" / "setup_all.sh",
    ]
    script_path = None
    for c in candidates:
        if c.exists():
            script_path = c
            break
    if script_path is None:
        return {"success": False, "error": "setup_all.sh not found"}

    try:
        # Ensure executable
        try:
            os.chmod(script_path, 0o755)
        except Exception:
            pass

        result = subprocess.run(
            ["bash", str(script_path), str(phase)],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=int(timeout),
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "script_path": str(script_path.relative_to(workspace)),
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"setup_all.sh {phase} timed out after {timeout}s",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def git_submodule_update(
    working_dir: Optional[str] = None,
    init: bool = True,
    recursive: bool = True,
    additional_args: Optional[str] = None,
) -> str:
    """
    Update git submodules in the repository.

    Many projects (especially C++ projects) use git submodules for dependencies.
    This command initializes and updates them.

    Args:
        working_dir: The directory containing the .git folder.
                    If None, uses the current working directory.
        init: If True, initializes submodules (--init flag).
        recursive: If True, recursively updates nested submodules (--recursive flag).
        additional_args: Any additional git submodule update arguments.

    Returns:
        A string containing the output of the git submodule update command.

    Examples:
        # Initialize and update all submodules recursively
        git_submodule_update()

        # Update submodules in a specific directory
        git_submodule_update(working_dir="monad")

        # Update without initialization
        git_submodule_update(init=False)
    """
    try:
        command = ["git", "submodule", "update"]

        if init:
            command.append("--init")

        if recursive:
            command.append("--recursive")

        if additional_args:
            command.extend(additional_args.split())

        resolved_dir = _resolve_working_dir(working_dir)
        result = subprocess.run(
            command, check=True, capture_output=True, text=True, cwd=resolved_dir
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"


def convert_ssh_to_https_in_gitmodules(working_dir: Optional[str] = None) -> str:
    """
    Convert SSH URLs to HTTPS URLs in .gitmodules files to work around SSH authentication issues.

    Many git submodules use SSH URLs (git@github.com:user/repo.git) which require SSH keys.
    This tool converts them to HTTPS URLs (https://github.com/user/repo.git) which work
    without authentication for public repositories.

    This is useful when git submodule update fails due to SSH permission errors.

    Args:
        working_dir: The directory containing the .gitmodules file.
                    If None, uses the current working directory.

    Returns:
        A string describing what was converted and the result.

    Examples:
        # Convert SSH to HTTPS in the main .gitmodules
        result = convert_ssh_to_https_in_gitmodules()

        # Convert in a subdirectory
        result = convert_ssh_to_https_in_gitmodules(working_dir="monad")
    """
    try:
        resolved_dir = _resolve_working_dir(working_dir)
        gitmodules_path = os.path.join(resolved_dir, ".gitmodules")

        if not os.path.exists(gitmodules_path):
            return f"No .gitmodules file found in {resolved_dir}"

        # Read the file
        with open(gitmodules_path, "r") as f:
            content = f.read()

        original_content = content

        # Convert SSH URLs to HTTPS
        # Pattern: git@github.com:user/repo.git -> https://github.com/user/repo.git
        import re

        content = re.sub(
            r"git@github\.com:([^/\s]+)/([^\s]+)", r"https://github.com/\1/\2", content
        )

        # Also handle gitlab and other common hosts
        content = re.sub(
            r"git@gitlab\.com:([^/\s]+)/([^\s]+)", r"https://gitlab.com/\1/\2", content
        )

        if content == original_content:
            return "No SSH URLs found in .gitmodules - nothing to convert"

        # Write back
        with open(gitmodules_path, "w") as f:
            f.write(content)

        # Count conversions
        conversions = len(re.findall(r"git@[^:]+:", original_content))

        return f"Successfully converted {conversions} SSH URLs to HTTPS in {gitmodules_path}"

    except Exception as e:
        return f"Error: {str(e)}"


def install_dependencies(
    packages: Optional[List[str]] = None,
    working_dir: Optional[str] = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    DEPRECATED for guided usage via prompts. Prefer `write_setup_script(...)` and
    invoking the generated scripts/setup_all.sh to provision dependencies and build/test.

    This function remains for backward compatibility and direct calls. It installs
    project dependencies using detected tool adapters and aggregates results.

    For Foundry projects, this uses `forge install` to install Solidity libraries.
    If no packages are specified, it automatically detects dependencies from .gitmodules.
    On mixed repos (e.g., Foundry + Node), it will also run JS installs when package.json is present.

    Args:
        packages: Optional list of packages to install. Format depends on framework:
                  - Foundry: ["OpenZeppelin/openzeppelin-contracts", "foundry-rs/forge-std"]
                  - If None, automatically parses .gitmodules to find packages.
        working_dir: The directory to run installation from.
                    If None, uses the agent's working directory.
        timeout: Installation timeout in seconds (default 300).

    Returns:
        A dict containing:
        - success (bool): Whether installation succeeded
        - installed (List[str]): List of successfully installed packages
        - errors (List[str]): List of error messages for failed packages
        - raw_output (str): Raw command output

    Examples:
        # Auto-detect and install all dependencies from .gitmodules
        result = install_dependencies()

        # Install specific packages
        result = install_dependencies(packages=["OpenZeppelin/openzeppelin-contracts"])

        # Install in a subdirectory (for monorepos)
        result = install_dependencies(working_dir="packages/contracts")
    """
    agent = _get_current_agent()
    if agent is None:
        return {"success": False, "error": "No agent context available"}

    wd = _resolve_working_dir(working_dir)
    workspace = Path(wd)
    framework = _detect_framework(workspace)
    adapter = get_tool_adapter(framework)

    # Convert packages to list if provided as string
    pkg_list: Optional[List[str]] = None
    if packages is not None:
        if isinstance(packages, str):
            pkg_list = [packages]
        else:
            pkg_list = list(packages)

    install_result = adapter.install_dependencies(
        workspace_path=workspace,
        packages=pkg_list,
        timeout=int(timeout),
    )

    if not hasattr(agent, "_setup_install_attempts"):
        agent._setup_install_attempts = 0
    agent._setup_install_attempts += 1

    payload = install_result.to_dict()
    payload["attempt"] = agent._setup_install_attempts
    payload["workspace"] = str(workspace)
    payload["framework"] = framework
    return payload


def write_and_compile(
    file_path: str,
    content: str,
    working_dir: Optional[str] = None,
    timeout: int = 120,
) -> Dict[str, Any]:
    """
    Write a minimal smoke test/harness into the repo and compile via the detected tool adapter.

    Args:
        file_path: Test file path/name (adapter-normalized). Example: "kai_setup/Smoke.t.sol"
        content: Full file contents.
        working_dir: Optional subdirectory to run compilation from (useful for monorepos).
        timeout: Compilation timeout seconds.
    """
    agent = _get_current_agent()
    if agent is None:
        return {"written": False, "error": "No agent context available"}

    wd = _resolve_working_dir(working_dir)
    workspace = Path(wd)
    framework = _detect_framework(workspace)
    adapter = get_tool_adapter(framework)

    abs_path = adapter.normalize_test_path(file_path, workspace)
    rel_path = abs_path.relative_to(workspace)

    try:
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(content, encoding="utf-8")
    except Exception as e:
        return {"written": False, "error": f"Failed to write file: {e}"}

    # Remember match_path for run_test convenience
    setattr(agent, "_last_setup_match_path", rel_path.as_posix())

    compile_result = adapter.compile(workspace_path=workspace, timeout=int(timeout))

    if not hasattr(agent, "_setup_compile_attempts"):
        agent._setup_compile_attempts = 0
    agent._setup_compile_attempts += 1

    return {
        "written": True,
        "path": rel_path.as_posix(),
        "workspace": str(workspace),
        "framework": framework,
        "match_path": rel_path.as_posix(),
        "compiled": compile_result.success,
        "errors": compile_result.errors,
        "warnings": compile_result.warnings,
        "raw_output": compile_result.raw_output,
        "attempt": agent._setup_compile_attempts,
    }


def run_test(
    match_contract: Optional[str] = None,
    match_test: Optional[str] = None,
    verbosity: int = 2,
    additional_args: Optional[str] = None,
    framework_kwargs: Optional[Dict[str, Any]] = None,
    working_dir: Optional[str] = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """
    Run tests via the detected tool adapter.

    For Foundry, this supports `framework_kwargs={"match_path": "<relpath>"}` and will
    default to the last match_path produced by write_and_compile.
    """
    agent = _get_current_agent()
    if agent is None:
        return {"success": False, "error": "No agent context available"}

    wd = _resolve_working_dir(working_dir)
    workspace = Path(wd)
    framework = _detect_framework(workspace)
    adapter = get_tool_adapter(framework)

    fw = dict(framework_kwargs or {})
    if "match_path" not in fw:
        last_mp = getattr(agent, "_last_setup_match_path", None)
        if isinstance(last_mp, str) and last_mp.strip():
            fw["match_path"] = last_mp.strip()

    test_result = adapter.run_test(
        workspace_path=workspace,
        match_contract=match_contract,
        match_test=match_test,
        verbosity=int(verbosity),
        timeout=int(timeout),
        additional_args=additional_args,
        framework_kwargs=fw or None,
    )

    if not hasattr(agent, "_setup_test_attempts"):
        agent._setup_test_attempts = 0
    agent._setup_test_attempts += 1

    payload = test_result.to_dict()
    payload["attempt"] = agent._setup_test_attempts
    payload["workspace"] = str(workspace)
    payload["framework"] = framework
    payload["framework_kwargs"] = fw
    return payload


def register_master_context(master_context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Register the final MasterContext for the repository.
    Call this tool once you have successfully built and analyzed the repository.

    The master_context dict must follow the MasterContext schema:
    - root_path (str): Absolute path to the repository root.
    - compile_success (bool): Whether the project compiled successfully.
    - frameworks (List[str], optional): List of detected frameworks (e.g., ["foundry"]).
    - artifacts_path (str, optional): Path to build artifacts.
    - src_path (str, optional): Path to source contracts.
    - lib_path (str, optional): Path to libraries/dependencies.
    - test_path (str, optional): Path to tests.
    - build_script_path (str, optional): Repo-relative path to build script.
    - build_script (str, optional): Full build script contents.
    - test_script_path (str, optional): Repo-relative path to test script.
    - test_script (str, optional): Full test script contents.
    - adapter (str, optional): Domain adapter, default "solidity".

    Example:
        register_master_context({
            "root_path": "/path/to/repo",
            "compile_success": True,
            "frameworks": ["foundry"],
            "src_path": "src",
            "test_path": "test"
        })
    """
    agent = _get_current_agent()
    if agent is None:
        return {"registered": False, "error": "No active agent context found."}

    try:
        # Validate using Pydantic model
        mc = MasterContext(**master_context)
        # Store on agent instance
        agent._registered_master_context = mc
        return {
            "registered": True,
            "message": "MasterContext registered successfully. You may now stop.",
        }
    except Exception as e:
        return {"registered": False, "error": f"Validation failed: {str(e)}"}
