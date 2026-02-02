"""
Build and test tools for various frameworks.

This module contains test runners for different build systems:
- forge_test: Foundry/Solidity tests
- cargo_test: Rust/Cargo tests
- anchor_test: Solana/Anchor tests
- ctest: CMake/C++ tests
"""

import json
import os
import shlex
import subprocess
from typing import Any, Dict, List, Optional

from .shared import get_current_agent


def forge_test(
    test_script_path: Optional[str] = None,
    working_dir: Optional[str] = None,
    match_contract: Optional[str] = None,
    match_test: Optional[str] = None,
    additional_args: Optional[str] = None,
    output_json: bool = True,
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
        # Default working dir for agent-driven runs.
        # Blackbox (native tool calling) frequently omits `working_dir` or passes "".
        wd = (working_dir or "").strip() if isinstance(working_dir, str) else ""
        if not wd:
            agent = get_current_agent()
            if agent is not None:
                wd = (getattr(agent, "repo_path", None) or "") or (
                    getattr(agent, "working_dir", None) or ""
                )
        if not wd:
            wd = os.getcwd()

        # Build the forge test command
        cmd_parts: List[str] = ["forge", "test"]

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
            # Use shlex.split to preserve quoted args.
            cmd_parts.extend(shlex.split(additional_args))

        # Run the command
        p = subprocess.run(cmd_parts, text=True, capture_output=True, cwd=wd)

        # Always include metadata so callers can reason about failures.
        # Keep the payload lightweight (truncate large outputs).
        stdout = p.stdout or ""
        stderr = p.stderr or ""
        meta: Dict[str, Any] = {
            "returncode": p.returncode,
            "stdout": stdout[:8000] if len(stdout) > 8000 else stdout,
            "stderr": stderr[:8000] if len(stderr) > 8000 else stderr,
            "cwd": wd,
            "command": cmd_parts,
        }

        # Try to parse JSON output if requested
        if output_json:
            try:
                parsed = json.loads(stdout)
                # Preserve the original JSON structure for agents, but also provide
                # returncode/stdout/stderr for reliability and debugging.
                if isinstance(parsed, dict):
                    parsed.update(meta)
                    parsed["json_parsed"] = True
                    return parsed
                return {
                    "parsed_json": parsed,
                    "json_parsed": True,
                    **meta,
                }
            except json.JSONDecodeError:
                # If JSON parsing fails, return raw output
                return {
                    "error": "Failed to parse JSON output",
                    "json_parsed": False,
                    **meta,
                }
        else:
            # Return raw output for non-JSON mode
            return meta

    except Exception as e:
        return {"error": str(e), "stdout": "", "stderr": "", "returncode": -1}


def cargo_test(
    working_dir: Optional[str] = None,
    package: Optional[str] = None,
    test_name: Optional[str] = None,
    release: bool = False,
    additional_args: Optional[str] = None,
    output_json: bool = False,
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

        # Resolve working_dir relative to agent's working_dir
        resolved_dir = working_dir
        if working_dir is not None:
            try:
                agent = get_current_agent()
                if agent and not os.path.isabs(working_dir):
                    resolved_dir = os.path.join(agent.working_dir, working_dir)
            except (NameError, TypeError):
                pass
        else:
            try:
                agent = get_current_agent()
                resolved_dir = agent.working_dir if agent else os.getcwd()
            except (NameError, TypeError):
                resolved_dir = os.getcwd()

        # Run the command
        result = subprocess.run(
            cmd_parts, capture_output=True, text=True, cwd=resolved_dir
        )

        # Try to parse JSON output if requested
        if output_json:
            try:
                return {
                    "parsed_json": json.loads(result.stdout),
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                }
            except json.JSONDecodeError:
                # If JSON parsing fails, return raw output with error note
                return {
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                    "error": "Failed to parse JSON output",
                }
        else:
            # Return raw output for non-JSON mode
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }

    except Exception as e:
        return {"error": str(e), "stdout": "", "stderr": "", "returncode": -1}


def anchor_test(
    working_dir: Optional[str] = None,
    test_name: Optional[str] = None,
    skip_build: bool = False,
    skip_deploy: bool = False,
    skip_local_validator: bool = False,
    additional_args: Optional[str] = None,
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

        # Resolve working_dir relative to agent's working_dir
        resolved_dir = working_dir
        if working_dir is not None:
            try:
                agent = get_current_agent()
                if agent and not os.path.isabs(working_dir):
                    resolved_dir = os.path.join(agent.working_dir, working_dir)
            except (NameError, TypeError):
                pass
        else:
            try:
                agent = get_current_agent()
                resolved_dir = agent.working_dir if agent else os.getcwd()
            except (NameError, TypeError):
                resolved_dir = os.getcwd()

        # Run the command
        result = subprocess.run(
            cmd_parts, capture_output=True, text=True, cwd=resolved_dir
        )

        # Return raw output
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    except Exception as e:
        return {"error": str(e), "stdout": "", "stderr": "", "returncode": -1}


def ctest(
    build_dir: str,
    test_regex: Optional[str] = None,
    parallel: bool = True,
    verbose: bool = False,
    additional_args: Optional[str] = None,
) -> dict:
    """
    Run tests for a C++ project using CTest.

    CTest is CMake's test runner. Tests must be registered with CMake (add_test() in CMakeLists.txt)
    and the project must be built before running tests.

    Args:
        build_dir: The directory containing the CMake build files (where you ran cmake_build).
        test_regex: Optional regex pattern to filter tests by name.
                   For example: "unit_.*" to run only unit tests.
        parallel: If True, runs tests in parallel using available CPU cores.
                 Default is True.
        verbose: If True, enables verbose output (shows test output even for passing tests).
                Default is False.
        additional_args: Any additional ctest arguments as a string.
                        For example: "--rerun-failed --output-on-failure"

    Returns:
        A dictionary containing the test results:
        - stdout: The standard output from ctest
        - stderr: The standard error from ctest
        - returncode: The exit code (0 for success, non-zero for failure)

    Examples:
        # Run all tests in parallel
        result = ctest(build_dir="monad/build")

        # Run specific test pattern with verbose output
        result = ctest(build_dir="monad/build", test_regex="unit_.*", verbose=True)

        # Run tests serially (no parallelization)
        result = ctest(build_dir="monad/build", parallel=False)

        # Run with custom flags
        result = ctest(build_dir="monad/build", additional_args="--output-on-failure --timeout 300")
    """
    try:
        # Build the ctest command
        cmd_parts = ["ctest"]

        # Add test regex filter if specified
        if test_regex:
            cmd_parts.extend(["-R", test_regex])

        # Add parallel flag if requested
        if parallel:
            cmd_parts.append("--parallel")

        # Add verbose flag if requested
        if verbose:
            cmd_parts.append("--verbose")

        # Add any additional arguments
        if additional_args:
            cmd_parts.extend(additional_args.split())

        # Resolve build_dir relative to agent's working_dir
        resolved_build_dir = build_dir
        try:
            agent = get_current_agent()
            if agent and not os.path.isabs(build_dir):
                resolved_build_dir = os.path.join(agent.working_dir, build_dir)
        except (NameError, TypeError):
            pass

        # Run the command from the build directory
        result = subprocess.run(
            cmd_parts, capture_output=True, text=True, cwd=resolved_build_dir
        )

        # Return raw output
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    except Exception as e:
        return {"error": str(e), "stdout": "", "stderr": "", "returncode": -1}
