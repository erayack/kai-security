"""Centralized MongoDB logging functions using a model-based approach."""

from typing import Optional
from logger import logging


def log_execution_pending(execution_id: str, repo_url: str, model: str) -> None:
    """Log when execution is created with pending status."""
    logging.info(
        f"Execution pending: {execution_id}",
        extra={
            "mongo": True,
            "event_type": "execution_state",
            "status": "pending",
            "execution_id": execution_id,
            "repo_url": repo_url,
            "model": model,
        },
    )


def log_execution_in_progress(execution_id: str) -> None:
    """Log when execution starts (in_progress)."""
    logging.info(
        f"Execution started: {execution_id}",
        extra={
            "mongo": True,
            "event_type": "execution_state",
            "status": "in_progress",
            "execution_id": execution_id,
        },
    )


def log_execution_complete(execution_id: str, status: str = "completed") -> None:
    """Log when execution completes or fails."""
    logging.info(
        f"Execution {status}: {execution_id}",
        extra={
            "mongo": True,
            "event_type": "execution_state",
            "status": status,
            "execution_id": execution_id,
        },
    )


def log_execution_failed(execution_id: str, error: str) -> None:
    """Log when execution fails."""
    logging.error(
        f"Execution failed: {execution_id}",
        extra={
            "mongo": True,
            "event_type": "execution_state",
            "status": "failed",
            "execution_id": execution_id,
            "error": error,
        },
    )


def log_agent_started(
    agent_id: str,
    execution_id: str,
    parent_agent_id: Optional[str] = None,
    depth: int = 0,
    scope_paths: str = "",
) -> None:
    """Log when agent starts."""
    logging.info(
        f"Agent started: {agent_id}",
        extra={
            "mongo": True,
            "event_type": "agent_start",
            "agent_id": agent_id,
            "execution_id": execution_id,
            "parent_agent_id": parent_agent_id or "",
            "depth": str(depth),
            "scope_paths": scope_paths,
        },
    )


def log_agent_metrics(
    agent_id: str,
    current_cost: float,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
) -> None:
    """Log real-time agent metrics."""
    logging.info(
        f"Agent metrics update: {agent_id}",
        extra={
            "mongo": True,
            "event_type": "agent_update",
            "agent_id": agent_id,
            "current_cost": str(current_cost),
            "prompt_tokens": str(prompt_tokens),
            "completion_tokens": str(completion_tokens),
            "total_tokens": str(total_tokens),
        },
    )


def log_agent_complete(agent_id: str, total_cost: float, total_tokens: int) -> None:
    """Log when agent completes."""
    logging.info(
        f"Agent completed: {agent_id}",
        extra={
            "mongo": True,
            "event_type": "agent_complete",
            "agent_id": agent_id,
            "total_cost": str(total_cost),
            "total_tokens": str(total_tokens),
        },
    )


def log_exploit_discovered(
    agent_id: str,
    exploit_id: str,
    category: str,
    severity: str,
    file_path: str,
    line_start: int,
    description: str,
    line_end: Optional[int] = None,
    class_name: Optional[str] = None,
    function_name: Optional[str] = None,
    suggested_fix: Optional[str] = None,
    old_code: Optional[str] = None,
    new_code: Optional[str] = None,
    fixed_at: Optional[str] = None,
) -> None:
    """Log when an exploit is discovered."""
    extra_data = {
        "mongo": True,
        "event_type": "exploit_discovered",
        "agent_id": agent_id,
        "exploit_id": exploit_id,
        "category": category,
        "severity": severity,
        "file_path": file_path,
        "line_start": str(line_start),
        "description": description[:200],  # Truncate
    }

    if line_end is not None:
        extra_data["line_end"] = str(line_end)
    if class_name:
        extra_data["class_name"] = class_name
    if function_name:
        extra_data["function_name"] = function_name
    if suggested_fix:
        extra_data["suggested_fix"] = suggested_fix[:200]  # Truncate
    if old_code and new_code:
        extra_data["old_code"] = old_code
        extra_data["new_code"] = new_code
    if fixed_at:
        extra_data["fixed_at"] = fixed_at

    logging.info(
        f"Exploit discovered: {severity} - {category} in {file_path}",
        extra=extra_data,
    )


__all__ = [
    "log_execution_pending",
    "log_execution_in_progress",
    "log_execution_complete",
    "log_execution_failed",
    "log_agent_started",
    "log_agent_metrics",
    "log_agent_complete",
    "log_exploit_discovered",
]
