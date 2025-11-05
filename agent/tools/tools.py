"""
Common tools shared across all agents.

This module contains utility functions that are used by multiple agents
to avoid code duplication and ensure consistency.
"""

import os
import json
import subprocess
import uuid
from typing import Optional, Union
from agent.utils import load_gitignore_spec, should_ignore_path


def read_file(file_path: str, start_line: Optional[int] = None, end_line: Optional[int] = None) -> str:
    """
    Read a file with a given path, optionally specifying a line range.

    Args:
        file_path: The path to the file.
        start_line: Optional starting line number (1-indexed, inclusive).
        end_line: Optional ending line number (1-indexed, inclusive).

    Returns:
        The content of the file (or specified line range), or an error message if the file cannot be read.
        
    Examples:
        read_file("foo.rs")              # Full file
        read_file("foo.rs", 100, 150)    # Lines 100-150 only
    """
    try:
        # Scope validation (if _get_current_agent is available)
        try:
            agent = _get_current_agent()
            if agent and hasattr(agent, 'restricted_scope') and agent.restricted_scope:
                abs_path = os.path.abspath(file_path)
                if not any(abs_path.startswith(allowed) for allowed in agent.allowed_paths):
                    return f"Error: Access denied. File '{file_path}' is outside assigned scope."
        except (NameError, TypeError):
            # _get_current_agent not defined or returns None, skip scope validation
            pass
        
        # Ensure the file path is properly resolved
        if not os.path.exists(file_path):
            return f"Error: File {file_path} does not exist"
        
        if not os.path.isfile(file_path):
            return f"Error: {file_path} is not a file"
        
        with open(file_path, "r") as f:
            if start_line is None and end_line is None:
                # Read entire file
                return f.read()
            else:
                # Read specific line range
                lines = f.readlines()
                total_lines = len(lines)
                
                # Validate line numbers
                if start_line is not None and (start_line < 1 or start_line > total_lines):
                    return f"Error: start_line {start_line} is out of range (file has {total_lines} lines)"
                if end_line is not None and (end_line < 1 or end_line > total_lines):
                    return f"Error: end_line {end_line} is out of range (file has {total_lines} lines)"
                if start_line is not None and end_line is not None and start_line > end_line:
                    return f"Error: start_line {start_line} cannot be greater than end_line {end_line}"
                
                # Extract line range (convert to 0-indexed)
                start_idx = (start_line - 1) if start_line else 0
                end_idx = end_line if end_line else total_lines
                
                return "".join(lines[start_idx:end_idx])
                
    except PermissionError:
        return f"Error: Permission denied accessing {file_path}"
    except Exception as e:
        return f"Error: {e}"


def list_files(depth: int, path: Optional[str] = None) -> str:
    """
    Display all files and directories in the current working directory as a tree structure. 
    If given a path, display the files and directories in the given path.
    
    Example output:
    ```
    ./
    ├── user.md
    └── entities/
        ├── 452_willow_creek_dr.md
        └── frank_miller_plumbing.md
    ```

    Args:
        depth: Maximum depth to traverse.
           depth=0 shows only the root directory contents,
           depth=1 shows root and one level of subdirectories, etc.
        path: The path to the directory to display.

    Returns:
        A string representation of the directory tree.
    """
    try:
        # Use agent's working_dir if available and no path specified, otherwise os.getcwd()
        if path is None:
            try:
                agent = _get_current_agent()
                dir_path = agent.working_dir if agent else os.getcwd()
            except (NameError, TypeError):
                dir_path = os.getcwd()
        else:
            dir_path = path
        
        # Scope validation (if _get_current_agent is available)
        try:
            agent = _get_current_agent()
            if agent and hasattr(agent, 'restricted_scope') and agent.restricted_scope:
                abs_path = os.path.abspath(dir_path)
                if not any(abs_path.startswith(allowed) for allowed in agent.allowed_paths):
                    return f"Error: Access denied. Directory '{dir_path}' is outside assigned scope."
        except (NameError, TypeError):
            # _get_current_agent not defined or returns None, skip scope validation
            pass
        
        # Load gitignore patterns
        gitignore_spec = load_gitignore_spec(dir_path)
        
        def build_tree(start_path, prefix="", is_last=True, current_depth=0):
            """Recursively build tree structure"""
            entries = []
            try:
                items = sorted(os.listdir(start_path))
                # Filter out hidden files, __pycache__, and gitignored items
                filtered_items = []
                for item in items:
                    if item.startswith('.') or item == '__pycache__':
                        continue
                    item_path = os.path.join(start_path, item)
                    if should_ignore_path(item_path, dir_path, gitignore_spec):
                        continue
                    filtered_items.append(item)
                items = filtered_items
            except PermissionError:
                return f"{prefix}[Permission Denied]\n"
            
            if not items:
                return ""
            
            for i, item in enumerate(items):
                item_path = os.path.join(start_path, item)
                is_last_item = i == len(items) - 1
                
                # Choose the right prefix characters
                if is_last_item:
                    current_prefix = prefix + "└── "
                    extension = prefix + "    "
                else:
                    current_prefix = prefix + "├── "
                    extension = prefix + "│   "
                
                if os.path.isdir(item_path):
                    # Check if we've reached the depth limit
                    if depth is not None and current_depth >= depth:
                        entries.append(f"{current_prefix}{item}/ [...]\n")
                    else:
                        # Check if directory is empty (considering gitignore)
                        try:
                            dir_contents = []
                            for f in os.listdir(item_path):
                                if f.startswith('.') or f == '__pycache__':
                                    continue
                                f_path = os.path.join(item_path, f)
                                if should_ignore_path(f_path, dir_path, gitignore_spec):
                                    continue
                                dir_contents.append(f)
                            
                            if not dir_contents:
                                entries.append(f"{current_prefix}{item}/ (empty)\n")
                            else:
                                entries.append(f"{current_prefix}{item}/\n")
                                # Recursively add subdirectory contents
                                entries.append(build_tree(item_path, extension, is_last_item, current_depth + 1))
                        except PermissionError:
                            entries.append(f"{current_prefix}{item}/ [Permission Denied]\n")
                else:
                    entries.append(f"{current_prefix}{item}\n")
            
            return "".join(entries)
        
        # Start with the root directory
        tree = f"./\n{build_tree(dir_path)}"
        return tree.rstrip()  # Remove trailing newline
        
    except Exception as e:
        return f"Error: {e}"


def grep(args: str):
    """
    Run system grep with the provided CLI-style arg string.
    Prints output passthrough; returns grep's exit code (0/1/2).
    
    Common build/dependency directories are always excluded for faster searches.
    Output is limited to 100KB to prevent context overflow.
    
    If the agent has a restricted scope, grep will only search within the allowed paths.

    Args:
        args: The arguments to pass to grep.
    Returns:
        A GrepResponse with exit_code, stdout, and stderr.
    """
    try:
        from agent.settings import SANDBOX_TIMEOUT
        from agent.schemas import GrepResponse
        
        # Scope validation: restrict grep to allowed paths if scope is restricted
        search_path = "."
        try:
            agent = _get_current_agent()
            if agent and hasattr(agent, 'restricted_scope') and agent.restricted_scope:
                # Use the first allowed path as the search root
                if agent.allowed_paths:
                    search_path = agent.allowed_paths[0]
                    # Make path relative to current directory if possible
                    try:
                        search_path = os.path.relpath(search_path)
                    except ValueError:
                        pass  # Keep absolute path if relpath fails
        except (NameError, TypeError):
            # _get_current_agent not defined or returns None, skip scope validation
            pass
        
        # Comprehensive exclusions for build artifacts, dependencies, and caches
        # This prevents grep from returning millions of lines from these directories
        exclude_dirs = [
            # Rust
            "target",           # Rust build artifacts (includes debug/release/deps)
            
            # JavaScript/TypeScript
            "node_modules",     # Node.js dependencies
            "bower_components", # Bower dependencies
            ".npm",             # npm cache
            ".yarn",            # Yarn cache
            ".pnp",             # Yarn PnP
            
            # Python
            "venv",             # Python virtual environment
            ".venv",            # Python virtual environment (hidden)
            "env",              # Python virtual environment
            ".env",             # Python virtual environment (hidden)
            "virtualenv",       # virtualenv directory
            ".virtualenv",      # virtualenv directory (hidden)
            "__pycache__",      # Python cache
            ".pytest_cache",    # Pytest cache
            ".mypy_cache",      # Mypy cache
            ".tox",             # Tox test environments
            "site-packages",    # Python packages
            "dist-packages",    # Python packages (Debian/Ubuntu)
            ".eggs",            # Python eggs
            "*.egg-info",       # Python egg info
            
            # Build outputs
            "build",            # General build directory
            "dist",             # Distribution directory
            "out",              # Solidity/Foundry/general build artifacts
            "bin",              # Binary directory (sometimes)
            "obj",              # Object files (C/C++)
            
            # Caches
            "cache",            # Various caches
            ".cache",           # Hidden caches
            "tmp",              # Temporary files
            ".tmp",             # Hidden temporary files
            
            # Version control
            ".git",             # Git directory
            ".svn",             # SVN directory
            ".hg",              # Mercurial directory
            
            # IDEs and editors
            ".idea",            # IntelliJ IDEA
            ".vscode",          # VS Code
            ".vs",              # Visual Studio
            
            # Other
            "vendor",           # Vendored dependencies (Go, PHP, etc.)
            ".bundle",          # Ruby bundler
        ]
        exclude_flags = " ".join([f"--exclude-dir={d}" for d in exclude_dirs])
        
        # Determine working directory for grep
        grep_cwd = None
        try:
            agent = _get_current_agent()
            if agent and hasattr(agent, 'working_dir'):
                grep_cwd = agent.working_dir
        except (NameError, TypeError):
            pass
        
        # Run grep with timeout, locale optimization (LC_ALL=C), and optional exclusions
        # Add search path at the end
        cmd = f"LC_ALL=C grep {exclude_flags} {args} {search_path}".strip()
        p = subprocess.run(
            cmd, 
            shell=True, 
            text=True, 
            capture_output=True,
            timeout=SANDBOX_TIMEOUT,
            cwd=grep_cwd
        )
        
        # Limit output size to prevent context overflow (100KB max)
        # This prevents grep from returning millions of characters that crash the model
        MAX_GREP_OUTPUT_SIZE = 100_000  # 100KB
        stdout = p.stdout
        stderr = p.stderr
        
        if len(stdout) > MAX_GREP_OUTPUT_SIZE:
            line_count = stdout.count('\n')
            truncated_stdout = stdout[:MAX_GREP_OUTPUT_SIZE]
            # Try to end at a line boundary
            last_newline = truncated_stdout.rfind('\n')
            if last_newline > 0:
                truncated_stdout = truncated_stdout[:last_newline]
            
            truncation_msg = f"\n\n... [TRUNCATED: Output too large. Showing first {len(truncated_stdout):,} of {len(stdout):,} characters, ~{line_count:,} total matches. Use more specific patterns or -m flag to limit results.]"
            stdout = truncated_stdout + truncation_msg
        
        # Return a GrepResponse object
        return GrepResponse(exit_code=p.returncode, stdout=stdout, stderr=stderr)
    except subprocess.TimeoutExpired:
        from agent.schemas import GrepResponse
        return GrepResponse(exit_code=1, stdout="", stderr=f"Error: grep exceeded timeout of {SANDBOX_TIMEOUT} seconds. Try narrowing your search or using more specific patterns.")
    except Exception as e:
        from agent.schemas import GrepResponse
        return GrepResponse(exit_code=1, stdout="", stderr=f"Error: {e}")


def forge_test(
    test_script_path: Optional[str] = None,
    working_dir: Optional[str] = None,
    match_contract: Optional[str] = None,
    match_test: Optional[str] = None,
    additional_args: Optional[str] = None,
    output_json: bool = True
) -> dict:
    """
    Run forge test with flexible parameters to support various repository structures.
    
    This function supports repositories with multiple sub-repositories and test directories.
    You can specify the working directory where forge should run, and use various
    matching patterns to target specific tests.

    Args:
        test_script_path: The path pattern to match test files (uses --match-path).
                         Can be a glob pattern like "test/*.t.sol" or specific file.
        working_dir: The directory to run the forge command from. Useful when the repo
                    has multiple sub-repos with their own foundry.toml files.
                    If None, uses the current working directory.
        match_contract: Contract name pattern to match (uses --match-contract).
        match_test: Test function name pattern to match (uses --match-test).
        additional_args: Any additional forge test arguments as a string.
        output_json: Whether to output JSON format (default True, uses --json flag).

    Returns:
        A dictionary containing the test results. If JSON parsing fails, returns
        {"stdout": <output>, "stderr": <errors>} with the raw output.
        
    Examples:
        # Run test in a sub-repository
        forge_test(test_script_path="test/MyTest.t.sol", working_dir="ve33")
        
        # Run specific test function
        forge_test(match_test="test_exploit", working_dir="cl")
        
        # Run with multiple filters
        forge_test(
            test_script_path="test/*.t.sol",
            match_contract="ExploitTest",
            working_dir="ve33"
        )
    """
    try:
        # Build the forge test command
        cmd_parts = ["forge", "test"]
        
        # Add match patterns
        if test_script_path:
            cmd_parts.extend(["--match-path", test_script_path])
        if match_contract:
            cmd_parts.extend(["--match-contract", match_contract])
        if match_test:
            cmd_parts.extend(["--match-test", match_test])
        
        # Add JSON output flag if requested
        if output_json:
            cmd_parts.append("--json")
        
        # Add any additional arguments
        if additional_args:
            cmd_parts.append(additional_args)
        
        # Join command parts
        cmd = " ".join(cmd_parts)
        
        # Run the command, optionally in a specific directory
        if working_dir:
            p = subprocess.run(
                cmd,
                shell=True,
                text=True,
                capture_output=True,
                cwd=working_dir
            )
        else:
            p = subprocess.run(
                cmd,
                shell=True,
                text=True,
                capture_output=True
            )
        
        # Try to parse JSON output if requested
        if output_json:
            try:
                return json.loads(p.stdout)
            except json.JSONDecodeError:
                # If JSON parsing fails, return raw output
                return {
                    "stdout": p.stdout,
                    "stderr": p.stderr,
                    "returncode": p.returncode,
                    "error": "Failed to parse JSON output"
                }
        else:
            # Return raw output for non-JSON mode
            return {
                "stdout": p.stdout,
                "stderr": p.stderr,
                "returncode": p.returncode
            }
            
    except Exception as e:
        return {"error": str(e)}


def cargo_test(
    working_dir: Optional[str] = None,
    package: Optional[str] = None,
    test_name: Optional[str] = None,
    release: bool = False,
    additional_args: Optional[str] = None,
    output_json: bool = False
) -> dict:
    """
    Run cargo test with flexible parameters to support various Rust project structures.
    
    This function supports Rust workspaces with multiple packages and can run specific
    tests or all tests in a package.

    Args:
        working_dir: The directory to run the cargo command from. Useful when the repo
                    has multiple sub-projects or you want to run from a specific location.
                    If None, uses the current working directory.
        package: Package name to test (uses -p or --package flag).
                For example: "sp1-prover", "recursion-circuit", etc.
        test_name: Optional specific test name or pattern to run.
                  If None, runs all tests.
        release: Whether to run tests in release mode (optimized).
                Default is False (runs in debug mode).
        additional_args: Any additional cargo test arguments as a string.
                        For example: "--no-fail-fast", "--test-threads=1", etc.
        output_json: Whether to request JSON output format (uses --format json).
                    Note: This requires nightly Rust or the test to support it.

    Returns:
        A dictionary containing the test results:
        - stdout: The standard output from cargo test
        - stderr: The standard error from cargo test
        - returncode: The exit code (0 for success, non-zero for failure)
        - If JSON output is requested and parsing succeeds, returns parsed JSON.
        
    Examples:
        # Run all tests in a workspace
        result = cargo_test()
        
        # Run tests for a specific package
        result = cargo_test(package="sp1-prover")
        
        # Run a specific test in a package
        result = cargo_test(package="sp1-prover", test_name="test_uninitialized_memory")
        
        # Run tests in release mode with specific package
        result = cargo_test(package="recursion-circuit", release=True)
        
        # Run from a specific directory
        result = cargo_test(working_dir="crates/prover")
        
        # Run with additional flags
        result = cargo_test(package="sp1-prover", additional_args="--no-fail-fast --test-threads=1")
    """
    try:
        # Build the cargo test command
        cmd_parts = ["cargo", "test"]
        
        # Add package filter if specified
        if package:
            cmd_parts.extend(["-p", package])
        
        # Add test name filter if specified
        if test_name:
            cmd_parts.append(test_name)
        
        # Add release flag if requested
        if release:
            cmd_parts.append("--release")
        
        # Add JSON output flag if requested
        if output_json:
            cmd_parts.extend(["--", "--format", "json"])
        
        # Add any additional arguments
        if additional_args:
            # If additional_args contains test-specific flags (after --), handle carefully
            if "--" in additional_args:
                # Split and add appropriately
                cmd_parts.extend(additional_args.split())
            else:
                cmd_parts.extend(additional_args.split())
        
        # Run the command
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            cwd=working_dir
        )
        
        # Try to parse JSON output if requested
        if output_json:
            try:
                return {
                    "parsed_json": json.loads(result.stdout),
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode
                }
            except json.JSONDecodeError:
                # If JSON parsing fails, return raw output with error note
                return {
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                    "error": "Failed to parse JSON output"
                }
        else:
            # Return raw output for non-JSON mode
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
            
    except Exception as e:
        return {
            "error": str(e),
            "stdout": "",
            "stderr": "",
            "returncode": -1
        }


def anchor_test(
    working_dir: Optional[str] = None,
    test_name: Optional[str] = None,
    skip_build: bool = False,
    skip_deploy: bool = False,
    skip_local_validator: bool = False,
    additional_args: Optional[str] = None
) -> dict:
    """
    Run anchor test for Solana programs using the Anchor framework.
    
    This function executes integration tests for Solana programs. By default, the 'anchor test'
    command starts a local validator, builds the program, deploys it, runs tests, and then
    stops the validator. You can skip individual steps using the flags.

    Args:
        working_dir: The directory to run the anchor command from. Useful when the repo
                    has multiple Anchor projects or you want to run from a specific location.
                    If None, uses the current working directory.
        test_name: Optional specific test name or pattern to run.
                  If None, runs all tests.
        skip_build: Whether to skip building the program (uses --skip-build).
                   Default is False.
        skip_deploy: Whether to skip deploying the program (uses --skip-deploy).
                    Default is False. Useful if program is already deployed.
        skip_local_validator: Whether to skip starting local validator (uses --skip-local-validator).
                             Default is False. Use this if you have a validator already running.
        additional_args: Any additional anchor test arguments as a string.
                        For example: "--detach" to keep validator running after tests.

    Returns:
        A dictionary containing the test results:
        - stdout: The standard output from anchor test
        - stderr: The standard error from anchor test
        - returncode: The exit code (0 for success, non-zero for failure)
        
    Examples:
        # Run all tests (starts validator, builds, deploys, tests, stops validator)
        result = anchor_test()
        
        # Run tests with existing validator
        result = anchor_test(skip_local_validator=True)
        
        # Run specific test
        result = anchor_test(test_name="test_initialize")
        
        # Run from specific directory
        result = anchor_test(working_dir="programs/my-program")
        
        # Skip build and deploy (useful for quick test iterations)
        result = anchor_test(skip_build=True, skip_deploy=True)
        
        # Run with additional flags
        result = anchor_test(additional_args="--detach")
    """
    try:
        # Build the anchor test command
        cmd_parts = ["anchor", "test"]
        
        # Add skip flags if requested
        if skip_build:
            cmd_parts.append("--skip-build")
        if skip_deploy:
            cmd_parts.append("--skip-deploy")
        if skip_local_validator:
            cmd_parts.append("--skip-local-validator")
        
        # Add test name filter if specified
        if test_name:
            cmd_parts.append(test_name)
        
        # Add any additional arguments
        if additional_args:
            cmd_parts.extend(additional_args.split())
        
        # Run the command
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            cwd=working_dir
        )
        
        # Return raw output
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
            
    except Exception as e:
        return {
            "error": str(e),
            "stdout": "",
            "stderr": "",
            "returncode": -1
        }


def update_file(file_path: str, old_content: str, new_content: str) -> Union[bool, str]:
    """
    Simple find-and-replace update method for files.

    This is an easier alternative to write_to_file() that doesn't require
    creating git-style diffs. It performs a simple string replacement.

    Parameters
    ----------
    file_path : str
        Path to the file to update.
    old_content : str
        The exact text to find and replace in the file.
    new_content : str
        The text to replace old_content with.

    Returns
    -------
    Union[bool, str]
        True if successful, error message string if failed.

    Examples
    --------
    # Add a new row to a table
    old = "| TKT-1056  | 2024-09-25 | Late Delivery   | Resolved |"
    new = "| TKT-1056  | 2024-09-25 | Late Delivery   | Resolved |\\n| TKT-1057  | 2024-11-11 | Damaged Item    | Open     |"
    result = update_file("user.md", old, new)
    """
    try:
        # Read the current file content
        if not os.path.exists(file_path):
            return f"Error: File '{file_path}' does not exist"

        if not os.path.isfile(file_path):
            return f"Error: '{file_path}' is not a file"

        with open(file_path, "r") as f:
            current_content = f.read()

        # Check if old_content exists in the file
        if old_content not in current_content:
            # Provide helpful context about what wasn't found
            preview_length = 50
            preview = old_content[:preview_length] + "..." if len(old_content) > preview_length else old_content
            return f"Error: Could not find the specified content in the file. Looking for: '{preview}'"

        # Count occurrences (multiple matches handled by replacing first only)
        occurrences = current_content.count(old_content)
        # Note: If multiple matches exist, only first one is replaced

        # Perform the replacement (only first occurrence)
        updated_content = current_content.replace(old_content, new_content, 1)

        # Check if replacement actually changed anything
        if updated_content == current_content:
            return "Error: No changes were made to the file"

        # Write the updated content back
        with open(file_path, "w") as f:
            f.write(updated_content)

        return True

    except PermissionError:
        return f"Error: Permission denied writing to '{file_path}'"
    except Exception as e:
        return f"Error: Unexpected error - {str(e)}"


def create_file(file_path: str, content: str = "") -> bool:
    """
    Create a new file in the file system with the given content (if any).
    If the file already exists, overwrite it with the new content.

    Args:
        file_path: The path to the file.
        content: The content of the file.

    Returns:
        True if the file was created successfully, False otherwise.
    """
    temp_file_path = None
    try:
        # Create parent directories if they don't exist
        parent_dir = os.path.dirname(file_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
        
        # Create a unique temporary file name in the same directory as the target file
        # This ensures the temp file is within the sandbox's allowed path
        target_dir = os.path.dirname(os.path.abspath(file_path)) or "."
        temp_file_path = os.path.join(target_dir, f"temp_{uuid.uuid4().hex[:8]}.txt")
        
        with open(temp_file_path, "w") as f:
            f.write(content)
        
        # Move the content to the final destination
        with open(file_path, "w") as f:
            f.write(content)
        os.remove(temp_file_path)
        return True
    except Exception as e:
        # Clean up temp file if it exists
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception as e:
                raise Exception(f"Error removing temp file {temp_file_path}: {e}")
        raise Exception(f"Error creating file {file_path}: {e}")

