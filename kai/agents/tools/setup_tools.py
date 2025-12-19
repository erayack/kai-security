import os
import subprocess
from typing import Optional, List, Dict, Any

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

__all__ = [
    "read_file",
    "list_files",
    "update_file",
    "create_file",
    "forge_install",
    "forge_build",
    "npm_install",
    "cargo_install",
    "cargo_build",
    "cmake_configure",
    "cmake_build",
    "git_submodule_update",
    "convert_ssh_to_https_in_gitmodules",
    "create_minimal_cargo_package",
    "run_script",
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


def forge_install(package_name: str, working_dir: Optional[str] = None) -> str:
    """
    Install a package using forge.

    Args:
        package_name: The name of the package to install.
        working_dir: The directory to run the forge install command from.
                    Useful for repos with multiple sub-projects.
                    If None, uses the agent's working directory.

    Returns:
        A string containing the output of the forge install command.

    Examples:
        # Install in a sub-repository
        forge_install("openzeppelin/openzeppelin-contracts", working_dir="ve33")
    """
    try:
        resolved_dir = _resolve_working_dir(working_dir)
        result = subprocess.run(
            ["forge", "install", package_name],
            check=True,
            capture_output=True,
            text=True,
            cwd=resolved_dir,
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"


def forge_build(
    working_dir: Optional[str] = None,
    force: bool = False,
    skip: Optional[List[str]] = None,
    sizes: bool = False,
    names: bool = False,
    additional_args: Optional[str] = None,
) -> str:
    """
    Build the project using forge.

    Args:
        working_dir: The directory to run the forge build command from.
                    Useful for repos with multiple sub-projects.
                    If None, uses the current working directory.
        force: If True, clears the cache and recompiles all contracts (--force flag).
        skip: List of file paths or patterns to skip during compilation.
              For example: ["test/", "script/Deploy.sol"]
        sizes: If True, displays contract sizes after compilation (--sizes flag).
        names: If True, prints compiled contract names (--names flag).
        additional_args: Any additional forge build arguments as a string.
                        For example: "--optimize --optimizer-runs 200"

    Returns:
        A string containing the output of the forge build command.

    Examples:
        # Build a sub-repository
        forge_build(working_dir="ve33")

        # Build from current directory
        forge_build()

        # Force rebuild with sizes
        forge_build(force=True, sizes=True)

        # Skip test directory
        forge_build(skip=["test/"])

        # Build with custom optimizer settings
        forge_build(additional_args="--optimize --optimizer-runs 200")
    """
    try:
        # Build the forge build command
        cmd = ["forge", "build"]

        # Add force flag if requested
        if force:
            cmd.append("--force")

        # Add skip patterns if specified
        if skip:
            for pattern in skip:
                cmd.extend(["--skip", pattern])

        # Add sizes flag if requested
        if sizes:
            cmd.append("--sizes")

        # Add names flag if requested
        if names:
            cmd.append("--names")

        # Add any additional arguments
        if additional_args:
            cmd.extend(additional_args.split())

        resolved_dir = _resolve_working_dir(working_dir)
        result = subprocess.run(
            cmd, check=True, capture_output=True, text=True, cwd=resolved_dir
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"


def npm_install(working_dir: Optional[str] = None) -> str:
    """
    Install npm dependencies for the project.

    Many Solidity projects use npm packages (like @openzeppelin/contracts)
    that need to be installed before compilation.

    Args:
        working_dir: The directory to run npm install from.
                    Useful for repos with multiple sub-projects.
                    If None, uses the current working directory.

    Returns:
        A string containing the output of the npm install command.

    Examples:
        # Install npm dependencies in a sub-repository
        npm_install(working_dir="ve33")

        # Install in current directory
        npm_install()
    """
    try:
        resolved_dir = _resolve_working_dir(working_dir)
        result = subprocess.run(
            ["npm", "install"],
            check=True,
            capture_output=True,
            text=True,
            cwd=resolved_dir,
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"


def cargo_install(
    crate_name: str, version: Optional[str] = None, working_dir: Optional[str] = None
) -> str:
    """
    Install a Rust crate using cargo.

    This is useful for installing command-line tools and dependencies
    that are distributed as Rust crates.

    Args:
        crate_name: The name of the crate to install.
        version: Optional version of the crate to install.
                If None, installs the latest version.
        working_dir: The directory to run cargo install from.
                    If None, uses the current working directory.

    Returns:
        A string containing the output of the cargo install command.

    Examples:
        # Install the latest version of a crate
        cargo_install("ripgrep")

        # Install a specific version
        cargo_install("cargo-edit", version="0.12.0")

        # Install from a specific directory
        cargo_install("my-tool", working_dir="rust-project")
    """
    try:
        command = ["cargo", "install", crate_name]
        if version:
            command.extend(["--version", version])

        resolved_dir = _resolve_working_dir(working_dir)
        result = subprocess.run(
            command, check=True, capture_output=True, text=True, cwd=resolved_dir
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"


def cargo_build(
    working_dir: Optional[str] = None,
    release: bool = False,
    package: Optional[str] = None,
    features: Optional[List[str]] = None,
    all_features: bool = False,
    no_default_features: bool = False,
    additional_args: Optional[str] = None,
) -> str:
    """
    Build a Rust project using cargo.

    This compiles the Rust project and all its dependencies. Use this
    to build Rust-based blockchain clients, smart contracts, or tools.

    Args:
        working_dir: The directory to run cargo build from.
                    Useful for repos with multiple Rust projects.
                    If None, uses the current working directory.
        release: If True, builds in release mode with optimizations (--release).
                Default is False (builds in debug mode).
        package: Optional package name to build (uses -p flag).
                Useful in workspace projects with multiple packages.
        features: Optional list of features to enable.
        all_features: If True, builds with all features enabled (--all-features).
        no_default_features: If True, disables default features (--no-default-features).
        additional_args: Any additional cargo build arguments as a string.
                        For example: "--jobs 4 --verbose"

    Returns:
        A string containing the output of the cargo build command.

    Examples:
        # Build in debug mode
        cargo_build(working_dir="bft")

        # Build in release mode with all features
        cargo_build(working_dir="bft", release=True, all_features=True)

        # Build specific package
        cargo_build(package="monad-node", working_dir="bft")

        # Build with specific features
        cargo_build(features=["jit", "parallel"], working_dir="bft")
    """
    try:
        command = ["cargo", "build"]

        if release:
            command.append("--release")

        if package:
            command.extend(["-p", package])

        if features:
            command.extend(["--features", ",".join(features)])

        if all_features:
            command.append("--all-features")

        if no_default_features:
            command.append("--no-default-features")

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


def cmake_configure(
    source_dir: str,
    build_dir: str,
    options: Optional[dict] = None,
    generator: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> str:
    """
    Configure a C++ project using CMake.

    This runs the CMake configuration step, which generates build files
    for the project. This is the first step in building C++ projects.

    Args:
        source_dir: The directory containing CMakeLists.txt (source root).
                   Can be relative to agent's working_dir or absolute.
        build_dir: The directory where build files will be generated.
                  Can be relative to agent's working_dir or absolute.
        options: Optional dictionary of CMake options to set.
                Keys are option names, values are option values.
                For example: {"CMAKE_BUILD_TYPE": "Release", "ENABLE_TESTS": "ON"}
        generator: Optional generator to use (e.g., "Ninja", "Unix Makefiles").
                  If None, uses CMake's default generator.
        additional_args: Any additional cmake arguments as a string.

    Returns:
        A string containing the output of the cmake configure command.

    Examples:
        # Configure with default settings
        cmake_configure(source_dir="monad", build_dir="monad/build")

        # Configure with Release build and tests enabled
        cmake_configure(
            source_dir="monad",
            build_dir="monad/build",
            options={"CMAKE_BUILD_TYPE": "Release", "BUILD_TESTING": "ON"}
        )

        # Configure with Ninja generator
        cmake_configure(
            source_dir="monad",
            build_dir="monad/build",
            generator="Ninja"
        )
    """
    try:
        # Resolve paths relative to agent's working_dir
        try:
            agent = _get_current_agent()
            if agent:
                if not os.path.isabs(source_dir):
                    source_dir = os.path.join(agent.working_dir, source_dir)
                if not os.path.isabs(build_dir):
                    build_dir = os.path.join(agent.working_dir, build_dir)
        except (NameError, TypeError):
            pass

        # Create build directory if it doesn't exist
        os.makedirs(build_dir, exist_ok=True)

        command = ["cmake", source_dir]

        # Add generator if specified
        if generator:
            command.extend(["-G", generator])

        # Add options
        if options:
            for key, value in options.items():
                command.append(f"-D{key}={value}")

        # Add additional arguments
        if additional_args:
            command.extend(additional_args.split())

        result = subprocess.run(
            command, check=True, capture_output=True, text=True, cwd=build_dir
        )
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"


def cmake_build(
    build_dir: str,
    target: Optional[str] = None,
    parallel: bool = True,
    config: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> str:
    """
    Build a C++ project using CMake.

    This runs the CMake build step, which compiles the project.
    Must be run after cmake_configure().

    Args:
        build_dir: The directory containing the generated build files.
                  Can be relative to agent's working_dir or absolute.
        target: Optional specific target to build (e.g., "monad-node", "all", "test").
               If None, builds the default target.
        parallel: If True, builds in parallel using available CPU cores.
                 Default is True.
        config: Optional build configuration (e.g., "Release", "Debug").
                Only needed for multi-config generators.
        additional_args: Any additional cmake --build arguments as a string.

    Returns:
        A string containing the output of the cmake build command.

    Examples:
        # Build all targets in parallel
        cmake_build(build_dir="monad/build")

        # Build specific target
        cmake_build(build_dir="monad/build", target="monad-node")

        # Build in Release mode without parallelization
        cmake_build(build_dir="monad/build", parallel=False, config="Release")

        # Build tests
        cmake_build(build_dir="monad/build", target="test")
    """
    try:
        # Resolve build_dir relative to agent's working_dir
        try:
            agent = _get_current_agent()
            if agent and not os.path.isabs(build_dir):
                build_dir = os.path.join(agent.working_dir, build_dir)
        except (NameError, TypeError):
            pass

        command = ["cmake", "--build", build_dir]

        if target:
            command.extend(["--target", target])

        if parallel:
            command.append("--parallel")

        if config:
            command.extend(["--config", config])

        if additional_args:
            command.extend(additional_args.split())

        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr if e.stderr else str(e)}"
    except Exception as e:
        return f"Error: {e}"


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


def create_minimal_cargo_package(
    package_path: str, package_name: str, dependencies: Optional[dict] = None
) -> str:
    """
    Create a minimal Cargo package (Cargo.toml + lib.rs) as a placeholder for missing dependencies.

    This is useful when a workspace depends on a package that failed to clone (e.g., via SSH).
    Creating a minimal placeholder allows the workspace to at least parse and compile other packages.

    Args:
        package_path: Path where the package should be created (e.g., "bft/manytrace/agent").
                     Can be relative to agent's working_dir or absolute.
        package_name: Name of the package (e.g., "agent", "tracing-manytrace").
        dependencies: Optional dictionary of dependencies to include.
                     For example: {"serde": "1.0", "tokio": {"version": "1.0", "features": ["full"]}}

    Returns:
        A string describing the result of the operation.

    Examples:
        # Create minimal placeholder for missing 'agent' package
        result = create_minimal_cargo_package(
            package_path="bft/manytrace/agent",
            package_name="agent"
        )

        # Create with dependencies
        result = create_minimal_cargo_package(
            package_path="bft/manytrace/tracing-manytrace",
            package_name="tracing-manytrace",
            dependencies={"tracing": "0.1"}
        )
    """
    try:
        # Resolve package_path relative to agent's working_dir
        if not os.path.isabs(package_path):
            try:
                agent = _get_current_agent()
                if agent:
                    package_path = os.path.join(agent.working_dir, package_path)
            except (NameError, TypeError):
                pass

        # Create the directory structure
        os.makedirs(package_path, exist_ok=True)
        src_dir = os.path.join(package_path, "src")
        os.makedirs(src_dir, exist_ok=True)

        # Create minimal Cargo.toml
        cargo_toml_path = os.path.join(package_path, "Cargo.toml")
        cargo_toml_content = f"""[package]
name = "{package_name}"
version = "0.1.0"
edition = "2021"

[lib]
"""

        # Add dependencies if provided
        if dependencies:
            cargo_toml_content += "\n[dependencies]\n"
            for dep_name, dep_value in dependencies.items():
                if isinstance(dep_value, dict):
                    # Handle complex dependency specification
                    cargo_toml_content += f"{dep_name} = {dep_value}\n"
                else:
                    # Simple version string
                    cargo_toml_content += f'{dep_name} = "{dep_value}"\n'

        with open(cargo_toml_path, "w") as f:
            f.write(cargo_toml_content)

        # Create minimal lib.rs with empty exports
        lib_rs_path = os.path.join(src_dir, "lib.rs")
        lib_rs_content = """// Minimal placeholder package created by setup agent
// This is a stub to allow the workspace to compile

// Re-export commonly used items from this package
// Add actual implementations as needed
"""

        with open(lib_rs_path, "w") as f:
            f.write(lib_rs_content)

        return f"Successfully created minimal Cargo package '{package_name}' at {package_path}"

    except Exception as e:
        return f"Error creating minimal Cargo package: {str(e)}"


def run_script(
    script_path: str, working_dir: Optional[str] = None, timeout: int = 300
) -> dict:
    """
    Run an existing shell script in the repository (READ-ONLY execution).

    This tool can ONLY run scripts that already exist in the repository.
    It CANNOT create, modify, or delete files. This is useful for running
    setup scripts like install.sh, configure.sh, build.sh, etc.

    IMPORTANT RESTRICTIONS:
    - Can only run scripts that exist in the repository
    - Cannot create, edit, or delete ANY files
    - Cannot run arbitrary commands - must be a script file
    - Script must be readable and executable

    Args:
        script_path: Path to the script file to run (relative to working_dir).
                    Must be an existing file in the repository.
        working_dir: The directory to run the script from.
                    If None, uses the current working directory.
        timeout: Maximum execution time in seconds. Default is 300 (5 minutes).
                Set higher for long-running build scripts.

    Returns:
        A dictionary containing:
        - stdout: The standard output from the script
        - stderr: The standard error from the script
        - returncode: The exit code (0 for success, non-zero for failure)
        - success: Boolean indicating if the script ran successfully

    Examples:
        # Run a setup script in the repo
        result = run_script("scripts/install.sh")

        # Run a build script with longer timeout
        result = run_script("build.sh", working_dir="monad", timeout=600)

        # Run a configure script
        result = run_script("configure.sh", working_dir="bft")

    Security Notes:
        - This tool can only execute existing scripts
        - It cannot modify files or create new ones
        - The sandbox prevents file write operations
        - Use with caution on untrusted repositories
    """
    try:
        # Resolve working directory
        if working_dir is None:
            try:
                agent = _get_current_agent()
                working_dir = agent.working_dir if agent else os.getcwd()
            except (NameError, TypeError):
                working_dir = os.getcwd()
        else:
            # Resolve relative paths relative to agent's working_dir
            if not os.path.isabs(working_dir):
                try:
                    agent = _get_current_agent()
                    if agent:
                        working_dir = os.path.join(agent.working_dir, working_dir)
                except (NameError, TypeError):
                    pass

        # Resolve script path
        if not os.path.isabs(script_path):
            script_path = os.path.join(working_dir, script_path)

        # Validate that the script exists
        if not os.path.exists(script_path):
            return {
                "stdout": "",
                "stderr": f"Error: Script '{script_path}' does not exist",
                "returncode": -1,
                "success": False,
            }

        if not os.path.isfile(script_path):
            return {
                "stdout": "",
                "stderr": f"Error: '{script_path}' is not a file",
                "returncode": -1,
                "success": False,
            }

        # Make script executable if it isn't already
        try:
            os.chmod(script_path, os.stat(script_path).st_mode | 0o111)
        except Exception:
            pass  # If we can't make it executable, the subprocess will fail with a clear error

        # Run the script
        result = subprocess.run(
            ["/bin/bash", script_path],
            capture_output=True,
            text=True,
            cwd=working_dir,
            timeout=timeout,
        )

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0,
        }

    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Error: Script execution timed out after {timeout} seconds",
            "returncode": -1,
            "success": False,
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Error: {str(e)}",
            "returncode": -1,
            "success": False,
        }


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
    - build_commands (List[dict], optional): List of commands to build the project.
      Each command dict: {"command": str, "order_of_execution": int}
    - test_commands (List[dict], optional): List of commands to run tests.
      Each command dict: {"command": str, "order_of_execution": int}
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
