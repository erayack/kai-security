"""
Workspace adapters for framework-specific workspace provisioning.

Each adapter handles the specifics of setting up a workspace for a particular
framework (Foundry, Hardhat, etc.).
"""

from kai.utils.workspace.base import WorkspaceAdapter
from kai.utils.workspace.foundry import FoundryWorkspaceAdapter

__all__ = [
    "WorkspaceAdapter",
    "FoundryWorkspaceAdapter",
    "get_workspace_adapter",
]


def get_workspace_adapter(framework: str) -> WorkspaceAdapter:
    """
    Get the appropriate workspace adapter for a framework.

    Args:
        framework: Framework name (e.g., "foundry", "hardhat")

    Returns:
        WorkspaceAdapter instance for the framework

    Raises:
        ValueError: If framework is not supported
    """
    adapters = {
        "foundry": FoundryWorkspaceAdapter,
    }

    framework_lower = framework.lower()
    if framework_lower not in adapters:
        supported = ", ".join(adapters.keys())
        raise ValueError(f"Unsupported framework: {framework}. Supported: {supported}")

    return adapters[framework_lower]()
