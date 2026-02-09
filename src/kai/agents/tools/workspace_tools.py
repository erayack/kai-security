"""
Workspace and PoC tools for agents.

This module contains tools for writing and compiling test files,
registering exploits, and getting framework-specific tool descriptions.
"""

from typing import Any, Dict, Optional

from .shared import get_adapter, get_current_agent


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
            "workspace": str,
            "compiled": bool,
            "errors": List[str],  # Parsed error messages
            "raw_output": str,    # Full compiler output
            "attempt": int        # Compilation attempt number
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
    from pathlib import Path

    agent = get_current_agent()
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
    adapter = get_adapter()

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
    compile_result = adapter.compile(workspace)

    # Track compilation attempts
    if not hasattr(agent, "_compile_attempts"):
        agent._compile_attempts = 0
    agent._compile_attempts += 1

    # Store match_path on agent so run_test can use it automatically
    # This avoids the need for the agent to pass framework_kwargs manually
    agent._last_poc_match_path = rel_path.as_posix()

    return {
        "written": True,
        "path": rel_path.as_posix(),
        "match_path": rel_path.as_posix(),  # Expose for run_test
        "workspace": str(workspace),
        "compiled": compile_result.success,
        "errors": compile_result.errors,
        "warnings": getattr(compile_result, "warnings", []),
        "raw_output": compile_result.raw_output,
        "attempt": agent._compile_attempts,
    }


def register_exploit(
    exploit_found: bool,
    reasoning: str,
    poc_path: Optional[str] = None,
    poc_code: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Register an exploit finding with automatic PoC compilation.

    This is the unified registration tool used by State, Quant, and Gamified agents.
    If poc_code and poc_path are provided, the PoC is compiled first. Registration
    fails if compilation fails, giving the agent a chance to fix errors.

    Args:
        exploit_found: True if you found a way to violate the invariant/exploit a gap
        reasoning: Explanation of your analysis and conclusion
        poc_path: Path to the PoC test file (e.g., "test/poc/Exploit.t.sol")
        poc_code: Full code of the PoC (required if exploit_found=True)

    Returns:
        On success: {"registered": True, "compiled": bool, "exploit_count": int, ...}
        On compile failure: {"registered": False, "compile_errors": [...], ...}

    Example (exploit found):
        register_exploit(
            exploit_found=True,
            reasoning="The mint() function lacks role check when...",
            poc_path="test/poc/MintExploit.t.sol",
            poc_code="// SPDX-License-Identifier: MIT\\npragma solidity..."
        )

    Example (no exploit - verified safe):
        register_exploit(
            exploit_found=False,
            reasoning="All paths to mint() are guarded by onlyRole(MINTER_ROLE)..."
        )
    """
    agent = get_current_agent()
    if agent is None:
        return {"registered": False, "error": "No agent context available"}

    # Initialize exploit registry if not present
    if not hasattr(agent, "_registered_exploits"):
        agent._registered_exploits = []
    if not hasattr(agent, "_exploit_candidates"):
        agent._exploit_candidates = []

    compiled = False
    compile_result = None

    # If exploit found, require PoC and compile it
    if exploit_found:
        if not poc_code or not poc_path:
            return {
                "registered": False,
                "error": "exploit_found=True requires both poc_path and poc_code",
                "message": "Provide the PoC code and path to register the exploit.",
            }

        # Use write_and_compile from this module
        compile_result = write_and_compile(poc_path, poc_code)

        if not compile_result.get("compiled"):
            # Return full compile result so agent has all info to debug
            return {
                "registered": False,
                "message": "PoC failed to compile. Fix the errors and try again.",
                **compile_result,  # Include written, path, workspace, errors, raw_output, etc.
            }

        compiled = True

        try:
            mc = getattr(agent, "master_context", None)
            recipe = getattr(mc, "import_recipe", None) if mc else None
            if recipe and getattr(recipe, "validated", False):
                imports_ok = False
                code_lc = poc_code.lower()
                paths = []
                if getattr(recipe, "main_import", None):
                    paths.append(str(recipe.main_import))
                for v in (getattr(recipe, "submodule_paths", {}) or {}).values():
                    paths.append(str(v))
                for p in paths:
                    if p and p.lower() in code_lc:
                        imports_ok = True
                        break
                if not imports_ok:
                    return {
                        "registered": False,
                        "message": "PoC must import real code using the validated ImportRecipe.",
                        "hint": getattr(recipe, "example_import", None) or "",
                    }
                if any(
                    k in poc_code
                    for k in ["Mock", "Fake", "Hostile", "Malicious", "Evil"]
                ):
                    return {
                        "registered": False,
                        "message": "PoC appears to use mock components. Import and exercise real code using the ImportRecipe.",
                        "hint": getattr(recipe, "example_import", None) or "",
                    }
        except Exception:
            pass

    # Build exploit record
    exploit_record = {
        "exploit_found": exploit_found,
        "reasoning": reasoning,
        "poc_path": poc_path,
        "poc_code": poc_code,
        "compiled": compiled,
    }
    agent._registered_exploits.append(exploit_record)

    # If exploit found, also add to exploit_candidates for dispatcher
    if exploit_found:
        from kai.schemas import ExploitCandidate

        mission = getattr(agent, "mission", None)
        mission_id = mission.mission_id if mission else "unknown"
        worker_id = getattr(agent, "execution_id", f"agent_{id(agent)}")

        # Determine invariant_id and invariant_ids from mission context
        invariant = getattr(mission, "invariant", None) if mission else None
        invariant_cluster = (
            getattr(mission, "invariant_cluster", None) if mission else None
        )

        if invariant:
            # State/Quant agents have a single target invariant
            invariant_id = invariant.id
            invariant_ids = [invariant.id]
        elif invariant_cluster and len(invariant_cluster) > 0:
            # Gamified agents have an invariant cluster
            invariant_ids = [inv.id for inv in invariant_cluster]
            invariant_id = invariant_ids[0]  # Primary is first in cluster
        else:
            invariant_id = "unknown"
            invariant_ids = []

        exploit_candidate = ExploitCandidate(
            mission_id=mission_id,
            worker_id=worker_id,
            invariant_id=invariant_id,
            invariant_ids=invariant_ids,
            mechanism=reasoning[:200] if len(reasoning) > 200 else reasoning,
            poc_code=poc_code or "",
            target_file=poc_path or "",
            target_function="",
            description=reasoning,
            compiled=compiled,
            logs=[f"registered_by_{type(agent).__name__}"],
        )
        agent._exploit_candidates.append(exploit_candidate)

    return {
        "registered": True,
        "compiled": compiled,
        "type": "exploit" if exploit_found else "verification",
        "exploit_count": len(agent._exploit_candidates),
        "finding_count": len(agent._registered_exploits),
        "message": f"Registered {'exploit' if exploit_found else 'verification'}. "
        f"Total exploits: {len(agent._exploit_candidates)}. "
        "Continue exploring or register more findings.",
    }


# =============================================================================
# Tool Schema Helpers
# =============================================================================

# Tools that need framework-specific descriptions from adapters
ADAPTER_DESCRIBED_TOOLS = {
    "write_and_compile",
    "run_test",
    "patch_file",
    "register_exploit",
}


def get_tool_description(tool_fn, adapter=None) -> str:
    """
    Get the description for a tool, using adapter if needed.

    For tools in ADAPTER_DESCRIBED_TOOLS, uses adapter.get_tool_description()
    to get framework-specific descriptions. Otherwise uses the tool's docstring.
    """
    tool_name = tool_fn.__name__

    # Get description from adapter if available and tool needs it
    if adapter is not None and tool_name in ADAPTER_DESCRIBED_TOOLS:
        desc = adapter.get_tool_description(tool_name)
        if desc is not None:
            return desc.strip()

    # Fall back to docstring
    return (tool_fn.__doc__ or f"Tool: {tool_name}").strip()
