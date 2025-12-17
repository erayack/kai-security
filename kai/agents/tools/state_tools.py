"""
Tools for StateAgent - finding state/ordering vulnerabilities.

Provides:
- Graph tools for understanding code (reused from shared tools)
- write_and_compile: Write file + immediate compilation feedback
- forge_test: Run tests with parsed output
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any

# Import shared tools
from kai.agents.tools.tools import (
    dependency_graph_loc,
    dependency_graph_slice,
    dependency_graph_paths,
    dependency_graph_neighbors,
    dependency_graph_resolve,
    dependency_graph_snippet,
    dependency_graph_callers,
    dependency_graph_callees,
    dependency_graph_explain,
    dependency_graph_protocol_entrypoints,
    _get_current_agent,
    _normalize_agent_path,
)


def _find_forge() -> str:
    """
    Find the forge binary, checking common installation paths.

    Returns the path to forge or raises FileNotFoundError.
    """
    # First try shutil.which (uses PATH)
    forge_path = shutil.which("forge")
    if forge_path:
        return forge_path

    # Common Foundry installation paths
    home = Path.home()
    common_paths = [
        home / ".foundry" / "bin" / "forge",
        home / ".cargo" / "bin" / "forge",
        Path("/usr/local/bin/forge"),
        Path("/opt/homebrew/bin/forge"),
    ]

    for path in common_paths:
        if path.exists() and path.is_file():
            return str(path)

    raise FileNotFoundError("forge not found - is Foundry installed?")


def write_and_compile(file_path: str, content: str) -> Dict[str, Any]:
    """
    Write a test file to the agent workspace and compile it.

    Tests are written to the provisioned workspace's test/ directory.
    The workspace has remappings to access the main repo's contracts.

    Args:
        file_path: Test file name (e.g., "MyExploit.t.sol")
        content: The Solidity test file content

    Returns:
        {
            "written": bool,
            "path": str,
            "compiled": bool,
            "errors": List[str],  # Parsed error messages
            "raw_output": str     # Full compiler output (truncated)
        }

    Example:
        result = write_and_compile("MyTest.t.sol", '''
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;
        import "forge-std/Test.sol";
        import "contracts/MyContract.sol";

        contract MyTest is Test {
            function test_example() public {
                assertTrue(true);
            }
        }
        ''')

        if result["compiled"]:
            # Ready to run
            pass
        else:
            # Fix errors in result["errors"]
            pass
    """
    agent = _get_current_agent()
    if agent is None:
        return {"written": False, "error": "No agent context available"}

    # Use the provisioned workspace
    workspace_path = getattr(agent, "workspace_path", None)
    if not workspace_path:
        return {
            "written": False,
            "error": "No workspace provisioned. Set agent.workspace_path first.",
        }

    workspace = Path(workspace_path)

    # Normalize file_path.
    #
    # Users/agents often provide paths like:
    # - "INV_X.t.sol"
    # - "poc/INV_X.t.sol"
    # - "test/poc/INV_X.t.sol"
    #
    # We always write under the provisioned workspace's `test/` directory, while
    # preserving any subdirectories under `test/` (e.g. `test/poc/...`).
    p = Path(file_path)
    if p.is_absolute():
        p = Path(p.name)
    # If caller already included leading "test/", strip it (we add it below).
    if p.parts and p.parts[0] == "test":
        p = Path(*p.parts[1:]) if len(p.parts) > 1 else Path(p.name)
    # Ensure suffix
    if not p.name.endswith(".sol"):
        # If they didn't specify extension, default to Foundry-style test suffix.
        p = p.with_name(p.name + ".t.sol")
    abs_path = workspace / "test" / p

    # Create parent directories
    try:
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(content)
    except Exception as e:
        return {"written": False, "error": f"Failed to write file: {e}"}

    # Run forge build in the workspace to check compilation
    rel_test_path = f".kai_workspace/test/{p.as_posix()}"
    try:
        forge_bin = _find_forge()
        result = subprocess.run(
            [forge_bin, "build"],
            cwd=str(workspace),  # Run in workspace, not main repo
            capture_output=True,
            text=True,
            timeout=120,
        )

        compiled = result.returncode == 0
        raw_output = result.stdout + result.stderr

        # Parse errors
        errors = []
        if not compiled:
            for line in raw_output.split("\n"):
                line_lower = line.lower()
                if "error" in line_lower or "Error" in line:
                    errors.append(line.strip())
            # Limit to most relevant errors
            errors = errors[:10]

        # Track compilation attempts
        if not hasattr(agent, "_compile_attempts"):
            agent._compile_attempts = 0
        agent._compile_attempts += 1

        return {
            "written": True,
            "path": rel_test_path,
            "workspace": str(workspace),
            "compiled": compiled,
            "errors": errors,
            "raw_output": raw_output[:3000] if len(raw_output) > 3000 else raw_output,
            "attempt": agent._compile_attempts,
        }

    except subprocess.TimeoutExpired:
        return {
            "written": True,
            "path": rel_test_path,
            "workspace": str(workspace),
            "compiled": False,
            "errors": ["Compilation timed out after 120 seconds"],
            "raw_output": "",
        }
    except FileNotFoundError:
        return {
            "written": True,
            "path": file_path,
            "compiled": False,
            "errors": ["forge not found - is Foundry installed?"],
            "raw_output": "",
        }
    except Exception as e:
        return {
            "written": True,
            "path": file_path,
            "compiled": False,
            "errors": [str(e)],
            "raw_output": "",
        }


def forge_test(
    match_contract: Optional[str] = None,
    match_test: Optional[str] = None,
    verbosity: int = 3,
    gas_report: bool = False,
) -> Dict[str, Any]:
    """
    Run Foundry tests with parsed results.

    Args:
        match_contract: Filter by contract name pattern
        match_test: Filter by test function name pattern
        verbosity: -v level (0-5), default 3 for traces on failure
        gas_report: Include gas report

    Returns:
        {
            "success": bool,          # forge command succeeded
            "tests_passed": int,
            "tests_failed": int,
            "assertion_failures": List[str],  # Test names that had assertion failures
            "reverts": List[str],             # Test names that reverted
            "raw_output": str,
            "parsed_results": Dict[str, str]  # test_name -> "pass"|"fail"|"revert"
        }

    Example:
        result = forge_test(match_contract="ExploitTest", match_test="test_drain")

        if result["tests_passed"] > 0 and result["assertion_failures"]:
            # Assertion failed = we proved the invariant can be broken
            print("Exploit confirmed!")
    """
    agent = _get_current_agent()
    if agent is None:
        return {"success": False, "error": "No agent context available"}

    # Use the provisioned workspace
    workspace_path = getattr(agent, "workspace_path", None)
    if not workspace_path:
        return {
            "success": False,
            "error": "No workspace provisioned. Set agent.workspace_path first.",
        }

    # Build command
    try:
        forge_bin = _find_forge()
    except FileNotFoundError:
        return {"success": False, "error": "forge not found - is Foundry installed?"}

    cmd = [forge_bin, "test"]

    if match_contract:
        cmd.extend(["--match-contract", match_contract])
    if match_test:
        cmd.extend(["--match-test", match_test])

    # Add verbosity
    if verbosity > 0:
        cmd.append("-" + "v" * verbosity)

    if gas_report:
        cmd.append("--gas-report")

    # Run tests in workspace
    try:
        result = subprocess.run(
            cmd,
            cwd=workspace_path,  # Run in provisioned workspace
            capture_output=True,
            text=True,
            timeout=300,  # 5 min timeout for tests
        )

        output = result.stdout + result.stderr
        success = result.returncode == 0

        # Parse results
        tests_passed = 0
        tests_failed = 0
        assertion_failures = []
        reverts = []
        parsed_results = {}

        # Count passes and failures
        for line in output.split("\n"):
            # [PASS] test_name()
            if "[PASS]" in line:
                tests_passed += 1
                # Extract test name
                if "test_" in line:
                    test_name = (
                        line.split("test_")[1].split("(")[0] if "test_" in line else ""
                    )
                    if test_name:
                        parsed_results[f"test_{test_name}"] = "pass"

            # [FAIL] test_name()
            elif "[FAIL]" in line:
                tests_failed += 1
                if "test_" in line:
                    test_name = (
                        line.split("test_")[1].split("(")[0] if "test_" in line else ""
                    )
                    full_name = f"test_{test_name}" if test_name else "unknown"

                    # Check if it's an assertion failure or revert
                    if "assertion" in line.lower() or "assert" in output.lower():
                        assertion_failures.append(full_name)
                        parsed_results[full_name] = "assertion_fail"
                    else:
                        reverts.append(full_name)
                        parsed_results[full_name] = "revert"

        # Track test attempts
        if not hasattr(agent, "_test_attempts"):
            agent._test_attempts = 0
        agent._test_attempts += 1

        return {
            "success": success,
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "assertion_failures": assertion_failures,
            "reverts": reverts,
            "parsed_results": parsed_results,
            "raw_output": output[:5000] if len(output) > 5000 else output,
            "attempt": agent._test_attempts,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "tests_passed": 0,
            "tests_failed": 0,
            "assertion_failures": [],
            "reverts": [],
            "parsed_results": {},
            "raw_output": "Test execution timed out after 300 seconds",
            "error": "timeout",
        }
    except FileNotFoundError:
        return {"success": False, "error": "forge not found - is Foundry installed?"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def patch_file(file_path: str, old_content: str, new_content: str) -> Dict[str, Any]:
    """
    Patch a file by replacing old_content with new_content, then recompile.

    Useful for fixing compilation errors without rewriting the entire file.

    Args:
        file_path: Path to file (must be in test/poc/)
        old_content: Exact string to find and replace
        new_content: Replacement string

    Returns:
        Same as write_and_compile: {written, path, compiled, errors, ...}

    Example:
        # Fix an import error
        result = patch_file(
            "test/poc/Exploit.t.sol",
            'import "../src/Token.sol";',
            'import "src/Token.sol";'
        )
    """
    agent = _get_current_agent()
    if agent is None:
        return {"written": False, "error": "No agent context available"}

    abs_path = _normalize_agent_path(file_path)
    if abs_path is None:
        return {"written": False, "error": f"Invalid path: {file_path}"}

    # Safety check
    rel_path = (
        os.path.relpath(abs_path, agent.repo_path) if agent.repo_path else file_path
    )
    if not rel_path.startswith("test/poc") and not rel_path.startswith("test\\poc"):
        return {"written": False, "error": "Can only patch files in test/poc/"}

    # Read current content
    try:
        current = Path(abs_path).read_text()
    except Exception as e:
        return {"written": False, "error": f"Failed to read file: {e}"}

    # Check if old_content exists
    if old_content not in current:
        return {
            "written": False,
            "error": f"Could not find content to replace. Looking for: {old_content[:100]}...",
        }

    # Replace
    new_file_content = current.replace(old_content, new_content, 1)

    # Write and compile
    return write_and_compile(file_path, new_file_content)


def register_exploit(
    exploit_found: bool,
    reasoning: str,
    poc_path: Optional[str] = None,
    poc_code: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Register an exploit finding (or verification that invariant holds).

    Call this tool when you have determined whether the invariant can be violated.
    You can call this multiple times if you find multiple distinct exploits.

    Args:
        exploit_found: True if you found a way to violate the invariant
        reasoning: Explanation of your analysis and conclusion
        poc_path: Path to the PoC test file (e.g., "test/poc/Exploit.t.sol")
        poc_code: Full Solidity code of the PoC (required if exploit_found or verification test)

    Returns:
        Confirmation of registration with exploit count

    Example (exploit found):
        register_exploit(
            exploit_found=True,
            reasoning="The mint() function lacks role check when...",
            poc_path="test/poc/INV_ACCESS_001.t.sol",
            poc_code="// SPDX-License-Identifier: MIT\\npragma solidity..."
        )

    Example (no exploit, with verification test):
        register_exploit(
            exploit_found=False,
            reasoning="All paths to mint() are guarded by onlyRole(MINTER_ROLE)...",
            poc_path="test/poc/INV_ACCESS_001_verify.t.sol",
            poc_code="// Test that unauthorized users cannot mint..."
        )
    """
    agent = _get_current_agent()
    if agent is None:
        return {"registered": False, "error": "No agent context available"}

    # Initialize exploit registry if not present
    if not hasattr(agent, "_registered_exploits"):
        agent._registered_exploits = []

    # Build exploit record
    exploit_record = {
        "exploit_found": exploit_found,
        "reasoning": reasoning,
        "poc_path": poc_path,
        "poc_code": poc_code,
    }

    agent._registered_exploits.append(exploit_record)

    return {
        "registered": True,
        "exploit_count": len(agent._registered_exploits),
        "type": "exploit" if exploit_found else "verification",
        "message": f"Registered {'exploit' if exploit_found else 'verification'}. Total findings: {len(agent._registered_exploits)}. Continue exploring or register more findings.",
    }


__all__ = [
    "dependency_graph_loc",
    "dependency_graph_slice",
    "dependency_graph_paths",
    "dependency_graph_neighbors",
    "dependency_graph_resolve",
    "dependency_graph_snippet",
    "dependency_graph_callers",
    "dependency_graph_callees",
    "dependency_graph_explain",
    "dependency_graph_protocol_entrypoints",
    "write_and_compile",
    "forge_test",
    "patch_file",
    "register_exploit",
]
