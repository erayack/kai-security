"""
Shared utilities for agent tools.

This module contains:
- Context variable management for async-safe agent access
- Path normalization for agent-relative paths
- Helper functions to access dependency graph and query engine
"""

import contextvars
import os
from typing import Optional

from kai.utils.dependency import GraphQueryEngine
from kai.utils.dependency.adapters import SolidityAdapter
from kai.utils.dependency.analysis import FileSourceLoader

# Context variable for current agent (async-safe)
_current_agent_var: contextvars.ContextVar = contextvars.ContextVar(
    "current_agent", default=None
)


def set_current_agent(agent):
    """Set the current agent for tools to access (async-safe)."""
    _current_agent_var.set(agent)


def get_current_agent():
    """
    Get the current agent instance from contextvars.

    All agents using tools must call set_current_agent() before tool execution.
    This is handled automatically by BaseAgent._create_tool_executor().
    """
    return _current_agent_var.get()


def normalize_agent_path(path: Optional[str]) -> Optional[str]:
    """
    Normalize user-provided paths so agents can reference files using either
    repo-relative paths (e.g. repos/<slug>/...) or working-dir relative paths.
    """
    if path is None:
        return None

    try:
        agent = get_current_agent()
    except (NameError, TypeError):
        agent = None

    # Absolute paths stay as-is
    if path and os.path.isabs(path):
        return path

    normalized = os.path.normpath(path) if path else ""
    if normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized == ".":
        normalized = ""

    if agent:
        repo_slug = (
            os.path.basename(agent.repo_path)
            if getattr(agent, "repo_path", None)
            else ""
        )
        if normalized:
            parts = normalized.split(os.sep)
            if len(parts) >= 2 and parts[0] == "repos" and parts[1] == repo_slug:
                remaining = os.path.join(*parts[2:]) if len(parts) > 2 else ""
                return os.path.join(agent.repo_path, remaining)

        base_dir = getattr(agent, "working_dir", agent.repo_path)
        if base_dir and normalized:
            return os.path.join(base_dir, normalized)
        return base_dir

    # Fallback: resolve relative to current directory
    if normalized:
        return os.path.abspath(normalized)
    return os.getcwd()


def get_dependency_graph():
    """Retrieve the dependency graph attached to the current agent, if any."""
    agent = get_current_agent()
    if agent and getattr(agent, "dependency_graph", None) is not None:
        return agent.dependency_graph
    return None


def get_query_engine() -> Optional[GraphQueryEngine]:
    """
    Build a GraphQueryEngine for the current agent if a dependency graph is present.
    """
    graph = get_dependency_graph()
    agent = get_current_agent()
    if graph is None or agent is None:
        return None

    base_path = (
        getattr(agent, "repo_path", None)
        or getattr(agent, "working_dir", None)
        or os.getcwd()
    )
    adapter = SolidityAdapter()
    source_loader = FileSourceLoader(base_path)
    return GraphQueryEngine(graph=graph, adapter=adapter, source_loader=source_loader)


def get_agent_framework() -> str:
    """
    Get the tool framework from the current agent context.

    Priority order:
    1. agent.framework (explicit setting by process, e.g., WorkspaceValidationProcess)
    2. master_context.frameworks (detected during setup)
    3. Default to "foundry"

    Note: master_context.adapter is the domain/language adapter (e.g., "solidity", "rust")
    for dependency graph analysis, NOT the build/test framework. Don't use it here.

    Returns:
        Framework name (defaults to "foundry" if not available)
    """
    from kai.utils.tool_adapters import get_supported_frameworks

    agent = get_current_agent()
    if agent is None:
        return "foundry"

    # Check agent.framework first (explicit setting takes priority)
    # This allows processes like WorkspaceValidationProcess to override the framework
    framework = getattr(agent, "framework", None)
    if framework:
        return framework.lower()

    # Fall back to master_context.frameworks for supported tool framework
    master_context = getattr(agent, "master_context", None)
    if master_context:
        frameworks = getattr(master_context, "frameworks", None) or []
        supported = set(get_supported_frameworks())
        for fw in frameworks:
            fw_lower = fw.lower()
            if fw_lower in supported:
                return fw_lower

    return "foundry"


def get_adapter():
    """Get the tool adapter for the current agent's framework."""
    from kai.utils.tool_adapters import get_tool_adapter

    return get_tool_adapter(get_agent_framework())
