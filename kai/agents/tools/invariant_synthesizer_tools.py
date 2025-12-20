"""
Tools for the InvariantSynthesizerAgent to finalize invariant drafts.
"""

from typing import Any, Dict

from kai.agents.tools.tools import _get_current_agent


def finalize_invariant(
    type: str, rule: str, explanation: str = "", confidence: float = 0.5
) -> Dict[str, Any]:
    """
    Finalize a tentative invariant draft derived from an observation.

    IMPORTANT:
    - Provide ONLY the draft semantic fields: type/rule/explanation/confidence.
    - Do NOT include grounded target IDs (functions/vars/files). The system will ground those deterministically.
    - Do NOT provide an invariant ID; the system will generate it deterministically.

    Example:
        finalize_invariant(
            type="solvency",
            rule="The total USDe supply must always be less than or equal to the total collateral value.",
            explanation="Observation showed USDe could be minted without sufficient collateral in edge case X.",
            confidence=0.9,
        )
    """
    agent = _get_current_agent()
    if agent is None:
        return {"finalized": False, "error": "No active agent context found."}

    inv_type = (type or "").strip()
    inv_rule = (rule or "").strip()
    inv_expl = (explanation or "").strip()

    if not inv_type:
        return {"finalized": False, "error": "Missing required field: type"}
    if not inv_rule:
        return {"finalized": False, "error": "Missing required field: rule"}

    try:
        inv_conf = float(confidence)
    except Exception:
        return {
            "finalized": False,
            "error": "confidence must be a number between 0.0 and 1.0",
        }

    if inv_conf < 0.0 or inv_conf > 1.0:
        return {"finalized": False, "error": "confidence must be between 0.0 and 1.0"}

    try:
        draft: Dict[str, Any] = {
            "type": inv_type,
            "rule": inv_rule,
            "explanation": inv_expl,
            "confidence": inv_conf,
        }
        # Store on agent instance
        agent._finalized_invariant_draft = draft
        return {
            "finalized": True,
            "message": "Invariant finalized successfully. You may now stop.",
        }
    except Exception as e:
        return {"finalized": False, "error": f"Failed to finalize: {str(e)}"}


def finalize_no_invariant(reason: str) -> Dict[str, Any]:
    """
    Call this if the observation cannot be converted into a meaningful or actionable invariant.

    Args:
        reason: Why no invariant is being produced.
    """
    agent = _get_current_agent()
    if agent is None:
        return {"finalized": False, "error": "No active agent context found."}

    agent._finalized_no_invariant_reason = reason
    return {
        "finalized": True,
        "message": "No-invariant decision recorded. You may now stop.",
    }


__all__ = ["finalize_invariant", "finalize_no_invariant"]


