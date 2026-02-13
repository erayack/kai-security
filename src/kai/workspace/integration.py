"""Inject workspace provisioning into an agent config tree."""

from __future__ import annotations

from dataclasses import replace
from functools import partial

from ra.agents.config import RecursiveAgentConfig

from kai.workspace.provisioner import provision_workspace
from kai.workspace.recipe import WorkspaceRecipe


def _make_factory(recipe: WorkspaceRecipe) -> partial[str]:
    """Return a picklable callable that provisions a workspace."""
    return partial(provision_workspace, recipe)


def inject_workspace(
    config: RecursiveAgentConfig,
    recipe: WorkspaceRecipe,
) -> RecursiveAgentConfig:
    """Return a copy of *config* with workspace_factory on every node.

    Each node gets ``environment_kwargs["workspace_factory"]`` set to a
    closure that calls ``provision_workspace(recipe)``.  The original
    config is not mutated.
    """
    factory = _make_factory(recipe)
    new_env_kwargs = {**config.environment_kwargs, "workspace_factory": factory}
    return replace(
        config,
        environment_kwargs=new_env_kwargs,
        agents=[inject_workspace(a, recipe) for a in config.agents],
    )
