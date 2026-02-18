"""Inject state manager hooks into an agent config tree."""

from __future__ import annotations

from dataclasses import replace

from ra.agents.config import RecursiveAgentConfig

from kai.state.base import StateManager
from kai.state.hooks import make_on_iteration_hook, make_on_spawn_result_hook


def inject_state_manager(
    config: RecursiveAgentConfig,
    state_manager: StateManager,
    run_id: str,
) -> RecursiveAgentConfig:
    """Return a copy of *config* with state-tracking hooks attached.

    Follows the same recursive pattern as ``inject_workspace``:

    - ``on_iteration`` is set on the **root** config (depth-0 progress).
    - ``on_spawn_result`` is set on configs that have sub-agents.
    - Child configs are processed recursively.
    """
    overrides: dict[str, object] = {}

    overrides["on_iteration"] = make_on_iteration_hook(
        state_manager, run_id, config.name
    )

    if config.agents:
        overrides["on_spawn_result"] = make_on_spawn_result_hook(state_manager, run_id)

    return replace(
        config,
        **overrides,
        agents=[
            inject_state_manager(child, state_manager, run_id)
            for child in config.agents
        ],
    )
