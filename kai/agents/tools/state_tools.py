"""
Tools for StateAgent - finding state/ordering vulnerabilities.

Provides:
- Graph tools for understanding code (reused from shared tools)
- write_and_compile: Write file + immediate compilation feedback
- run_test: Run tests with parsed output (framework-agnostic)
"""

import os
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
from kai.utils.tool_adapters import get_tool_adapter, ToolAdapter


def _get_agent_framework() -> str:
    """
    Get the tool framework from the current agent context.

    Checks master_context.frameworks for supported tool frameworks (foundry, hardhat, etc.),
    then falls back to agent.framework attribute if set.

    Returns:
        Framework name (defaults to "foundry" if not available)
    """
    from kai.utils.tool_adapters import get_supported_frameworks

    agent = _get_current_agent()
    if agent is None:
        return "foundry"

    # Check master_context.frameworks for supported tool framework
    master_context = getattr(agent, "master_context", None)
    if master_context:
        frameworks = getattr(master_context, "frameworks", None) or []
        supported = set(get_supported_frameworks())
        for fw in frameworks:
            fw_lower = fw.lower()
            if fw_lower in supported:
                return fw_lower

    # Try framework attribute directly on agent
    framework = getattr(agent, "framework", None)
    if framework:
        return framework.lower()

    return "foundry"


def _get_adapter() -> ToolAdapter:
    """Get the tool adapter for the current agent's framework."""
    return get_tool_adapter(_get_agent_framework())


def write_and_compile(file_path: str, content: str) -> Dict[str, Any]:
    """
    Write a test file to the agent workspace and compile it.

    Tests are written to the provisioned workspace's test/ directory.
    The workspace has remappings to access the main repo's contracts.

    Args:
        file_path: Test file name (e.g., "MyExploit.t.sol")
        content: The test file content

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

    # Get the adapter for framework-specific operations
    adapter = _get_adapter()

    # Normalize the test path using the adapter
    abs_path = adapter.normalize_test_path(file_path, workspace)
    rel_path = abs_path.relative_to(workspace)

    # Create parent directories and write file
    try:
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(content)
    except Exception as e:
        return {"written": False, "error": f"Failed to write file: {e}"}

    # Compile using the adapter
    rel_test_path = f".kai_workspace/{rel_path.as_posix()}"
    compile_result = adapter.compile(workspace)

    # Track compilation attempts
    if not hasattr(agent, "_compile_attempts"):
        agent._compile_attempts = 0
    agent._compile_attempts += 1

    return {
        "written": True,
        "path": rel_test_path,
        "workspace": str(workspace),
        "compiled": compile_result.success,
        "errors": compile_result.errors,
        "raw_output": compile_result.raw_output,
        "attempt": agent._compile_attempts,
    }


def run_test(
    match_contract: Optional[str] = None,
    match_test: Optional[str] = None,
    verbosity: int = 3,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run tests with parsed results (framework-agnostic).

    Uses the appropriate test runner based on the project framework
    (Foundry, Hardhat, Anchor, etc.).

    Args:
        match_contract: Filter by contract/module name pattern
        match_test: Filter by test function name pattern
        verbosity: Verbosity level (0-5), default 3 for traces on failure
        additional_args: Additional CLI arguments for the test runner

    Returns:
        {
            "success": bool,          # Test command succeeded
            "tests_passed": int,
            "tests_failed": int,
            "assertion_failures": List[str],  # Test names that had assertion failures
            "reverts": List[str],             # Test names that reverted
            "raw_output": str,
            "parsed_results": Dict[str, str]  # test_name -> "pass"|"fail"|"revert"
        }

    Example:
        result = run_test(match_contract="ExploitTest", match_test="test_drain")

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

    workspace = Path(workspace_path)

    # Get the adapter for framework-specific operations
    adapter = _get_adapter()

    # Run tests using the adapter
    test_result = adapter.run_test(
        workspace_path=workspace,
        match_contract=match_contract,
        match_test=match_test,
        verbosity=verbosity,
        additional_args=additional_args,
    )

    # Track test attempts
    if not hasattr(agent, "_test_attempts"):
        agent._test_attempts = 0
    agent._test_attempts += 1

    # Convert TestResult to dict and add attempt number
    result_dict = test_result.to_dict()
    result_dict["attempt"] = agent._test_attempts

    return result_dict


def patch_file(file_path: str, old_content: str, new_content: str) -> Dict[str, Any]:
    """
    Patch a file by replacing old_content with new_content, then recompile.

    Useful for fixing compilation errors without rewriting the entire file.
    Can only patch files in allowed test directories (framework-specific).

    Args:
        file_path: Path to file (must be in allowed test directory)
        old_content: Exact string to find and replace
        new_content: Replacement string

    Returns:
        Same as write_and_compile: {written, path, compiled, errors, ...}
    """
    agent = _get_current_agent()
    if agent is None:
        return {"written": False, "error": "No agent context available"}

    abs_path = _normalize_agent_path(file_path)
    if abs_path is None:
        return {"written": False, "error": f"Invalid path: {file_path}"}

    # Safety check - use adapter's allowed directories
    rel_path = (
        os.path.relpath(abs_path, agent.repo_path) if agent.repo_path else file_path
    )
    adapter = _get_adapter()
    allowed_dirs = adapter.get_allowed_patch_directories()
    if not any(rel_path.startswith(d) for d in allowed_dirs):
        return {
            "written": False,
            "error": f"Can only patch files in: {', '.join(allowed_dirs)}",
        }

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
    "run_test",
    "patch_file",
    "register_exploit",
]
