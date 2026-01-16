"""
Tools for the BucketingAgent to assign functions to lens buckets.
"""

import logging
from typing import Any, Dict, List

from kai.agents.tools.tools import _get_current_agent

logger = logging.getLogger(__name__)


def assign_to_lens(function_ids: List[str], lens_names: List[str]) -> Dict[str, Any]:
    """
    Assign one or more functions to one or more lens buckets.

    Use this to batch assign multiple functions that belong to the same lenses.

    Args:
        function_ids: List of function IDs to assign (can be a single ID or multiple).
        lens_names: List of lens names these functions belong to (e.g., ["safety", "economic"]).

    Returns:
        Result indicating success or error.

    Example:
        # Assign multiple payable functions to economic lens
        assign_to_lens(
            function_ids=["Contract.deposit()", "Contract.withdraw()", "Contract.claim()"],
            lens_names=["economic", "safety"]
        )
    """
    agent = _get_current_agent()
    if agent is None:
        return {"success": False, "error": "No active agent context found."}

    if not function_ids:
        return {"success": False, "error": "function_ids is required"}

    if not lens_names:
        return {"success": False, "error": "lens_names must contain at least one lens"}

    # Handle single string input
    if isinstance(function_ids, str):
        function_ids = [function_ids]

    # Validate lens names against available lenses
    available_lenses = set(agent.available_lens_names)
    invalid_lenses = [ln for ln in lens_names if ln not in available_lenses]
    if invalid_lenses:
        return {
            "success": False,
            "error": f"Invalid lens names: {invalid_lenses}. Available: {list(available_lenses)}",
        }

    # Validate function IDs
    invalid_funcs = [fid for fid in function_ids if fid not in agent.all_function_ids]
    if invalid_funcs:
        return {
            "success": False,
            "error": f"Invalid function IDs (not in vocab): {invalid_funcs[:5]}{'...' if len(invalid_funcs) > 5 else ''}",
        }

    # Add functions to each lens bucket
    assigned_count = 0
    for function_id in function_ids:
        for lens_name in lens_names:
            if function_id not in agent.buckets[lens_name]:
                agent.buckets[lens_name].append(function_id)
        agent.assigned_functions.add(function_id)
        assigned_count += 1

    remaining = len(agent.all_function_ids) - len(agent.assigned_functions)
    logger.info(
        f"[Bucketing] Assigned {assigned_count} functions to {lens_names} | Remaining: {remaining}"
    )

    return {
        "success": True,
        "assigned_count": assigned_count,
        "assigned_to": lens_names,
        "remaining": remaining,
    }


def skip_functions(function_ids: List[str], reason: str = "") -> Dict[str, Any]:
    """
    Skip one or more functions that don't belong to any lens bucket.

    Args:
        function_ids: List of function IDs to skip.
        reason: Optional reason for skipping.

    Returns:
        Result indicating success.
    """
    agent = _get_current_agent()
    if agent is None:
        return {"success": False, "error": "No active agent context found."}

    if not function_ids:
        return {"success": False, "error": "function_ids is required"}

    # Handle single string input
    if isinstance(function_ids, str):
        function_ids = [function_ids]

    # Track as assigned (but to no lens)
    for function_id in function_ids:
        agent.assigned_functions.add(function_id)
        agent.skipped_functions[function_id] = reason

    remaining = len(agent.all_function_ids) - len(agent.assigned_functions)
    logger.info(
        f"[Bucketing] Skipped {len(function_ids)} functions | Remaining: {remaining}"
    )

    return {
        "success": True,
        "skipped_count": len(function_ids),
        "remaining": remaining,
    }


def finalize_bucketing() -> Dict[str, Any]:
    """
    Finalize the bucketing process. Call this when all functions have been assigned.

    Returns:
        Summary of the bucketing results.
    """
    agent = _get_current_agent()
    if agent is None:
        return {"success": False, "error": "No active agent context found."}

    # Check for unassigned functions
    unassigned = agent.all_function_ids - agent.assigned_functions
    if unassigned:
        return {
            "success": False,
            "error": f"Not all functions assigned. Remaining: {list(unassigned)[:5]}{'...' if len(unassigned) > 5 else ''}",
            "unassigned_count": len(unassigned),
        }

    # Mark as finalized
    agent.bucketing_finalized = True

    # Build summary
    summary = {
        "success": True,
        "finalized": True,
        "buckets": {lens: len(funcs) for lens, funcs in agent.buckets.items()},
        "total_functions": len(agent.all_function_ids),
        "skipped": len(agent.skipped_functions),
    }

    logger.info(f"[Bucketing] FINALIZED - {summary}")

    return summary


def get_bucketing_status() -> Dict[str, Any]:
    """
    Get the current status of the bucketing process.

    Returns:
        Current bucketing statistics.
    """
    agent = _get_current_agent()
    if agent is None:
        return {"success": False, "error": "No active agent context found."}

    return {
        "total_functions": len(agent.all_function_ids),
        "assigned": len(agent.assigned_functions),
        "remaining": len(agent.all_function_ids) - len(agent.assigned_functions),
        "buckets": {lens: len(funcs) for lens, funcs in agent.buckets.items()},
        "skipped": len(agent.skipped_functions),
    }


__all__ = [
    "assign_to_lens",
    "skip_functions",
    "finalize_bucketing",
    "get_bucketing_status",
]
