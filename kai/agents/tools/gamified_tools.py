"""
Tools for GamifiedAgent - gap discovery with self-verification.

Tools:
- register_finding: Register exploit or verification finding (main output)
- write_and_compile: Write test file and compile it
- run_test: Run tests to verify hypothesis
- dependency_graph_snippet: Get function source code
- dependency_graph_neighbors: See what a function reads/writes/calls
- dependency_graph_callers: Find callers of a function
- dependency_graph_callees: Find functions called by a function
- dependency_graph_resolve: Find node ID from name
"""

from typing import Dict, Any

from kai.agents.tools.tools import (
    dependency_graph_snippet,
    dependency_graph_neighbors,
    dependency_graph_callers,
    dependency_graph_callees,
    dependency_graph_resolve,
    _get_current_agent,
)
from kai.agents.tools.state_tools import (
    write_and_compile,
    run_test,
)


def register_finding(
    exploit_found: bool,
    reasoning: str,
    poc_path: str = "",
    poc_code: str = "",
) -> Dict[str, Any]:
    """
    Register a finding (exploit or verification that invariant holds).

    Call this when you have determined whether a gap can be exploited.
    You can call this multiple times for multiple findings.

    Args:
        exploit_found: True if you found a way to exploit the gap
        reasoning: Explanation of your analysis and conclusion
        poc_path: Path to the PoC test file (optional)
        poc_code: Full code of the PoC (optional)

    Returns:
        Confirmation of registration with finding count

    Example (exploit found):
        register_finding(
            exploit_found=True,
            reasoning="functionX() bypasses the rate limit because...",
            poc_path="test/poc/RateLimitBypass.t.sol",
            poc_code="..."
        )

    Example (no exploit - verified safe):
        register_finding(
            exploit_found=False,
            reasoning="All paths enforce the limit via _checkLimit()..."
        )
    """
    agent = _get_current_agent()
    if agent is None:
        return {"registered": False, "error": "No agent context"}

    # Initialize registries if not present
    if not hasattr(agent, "_registered_findings"):
        agent._registered_findings = []
    if not hasattr(agent, "_exploit_candidates"):
        agent._exploit_candidates = []

    finding_record = {
        "exploit_found": exploit_found,
        "reasoning": reasoning,
        "poc_path": poc_path,
        "poc_code": poc_code,
    }
    agent._registered_findings.append(finding_record)

    # If exploit found, also add to exploit_candidates for DB compatibility
    if exploit_found:
        from kai.schemas import ExploitCandidate

        mission = getattr(agent, "mission", None)
        mission_id = mission.mission_id if mission else "unknown"
        worker_id = getattr(agent, "execution_id", f"gamified_{id(agent)}")

        exploit_candidate = ExploitCandidate(
            mission_id=mission_id,
            worker_id=worker_id,
            invariant_id="gap_exploit",
            mechanism=reasoning[:200] if len(reasoning) > 200 else reasoning,
            poc_code=poc_code or "",
            target_file=poc_path,
            target_function="",
            description=reasoning,
            compiled=False,
            logs=["from_gamified_agent"],
        )
        agent._exploit_candidates.append(exploit_candidate)

    finding_type = "EXPLOIT" if exploit_found else "VERIFICATION"
    return {
        "registered": True,
        "type": finding_type,
        "finding_count": len(agent._registered_findings),
        "exploit_count": len(agent._exploit_candidates),
    }


__all__ = [
    "register_finding",
    "write_and_compile",
    "run_test",
    "dependency_graph_snippet",
    "dependency_graph_callees",
    "dependency_graph_neighbors",
    "dependency_graph_callers",
    "dependency_graph_resolve",
]
