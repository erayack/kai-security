"""Workspace provisioning for kai agents."""

from kai.workspace.integration import inject_workspace
from kai.workspace.provisioner import provision_workspace
from kai.workspace.recipe import WorkspaceRecipe

__all__ = ["WorkspaceRecipe", "inject_workspace", "provision_workspace"]
