"""Inject workspace provisioning into an agent config tree."""

from __future__ import annotations

from dataclasses import replace
from functools import partial

from ra.agents.config import RecursiveAgentConfig

from kai.workspace.provisioner import provision_workspace
from kai.workspace.recipe import WorkspaceRecipe

# Tools that signal an agent needs a provisioned workspace.
_WORKSPACE_TOOLS = frozenset(
    {"read_file", "write_file", "list_dir", "run_shell", "search_files"}
)


def _needs_workspace(config: RecursiveAgentConfig) -> bool:
    """True if the agent's tools include any workspace tool."""
    return bool(set(config.tools) & _WORKSPACE_TOOLS)


def _make_factory(recipe: WorkspaceRecipe) -> partial[str]:
    """Return a picklable callable that provisions a workspace."""
    return partial(provision_workspace, recipe)


def inject_workspace(
    config: RecursiveAgentConfig,
    recipe: WorkspaceRecipe,
    *,
    verbose: bool | None = None,
) -> RecursiveAgentConfig:
    """Return a copy of *config* with workspace_factory where needed.

    Only agents whose tools overlap with ``_WORKSPACE_TOOLS`` get a
    workspace factory.  If *verbose* is given it is propagated to all
    nodes.  The original config is not mutated.
    """
    overrides: dict[str, object] = {}

    if _needs_workspace(config):
        factory = _make_factory(recipe)
        overrides["environment_kwargs"] = {
            **config.environment_kwargs,
            "workspace_factory": factory,
        }

    if verbose is not None:
        overrides["verbose"] = verbose

    return replace(
        config,
        **overrides,  # type: ignore[arg-type]
        agents=[inject_workspace(a, recipe, verbose=verbose) for a in config.agents],
    )
