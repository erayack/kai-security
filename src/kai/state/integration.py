"""Inject state manager hooks into an agent config tree."""

from __future__ import annotations

from dataclasses import replace

from ra.agents.config import RecursiveAgentConfig

from kai.state.base import StateManager
from kai.state.hooks import SpawnParser, make_on_iteration_hook


def inject_state_manager(
    config: RecursiveAgentConfig,
    state_manager: StateManager,
    run_id: str,
    spawn_parsers: dict[str, SpawnParser] | None = None,
) -> RecursiveAgentConfig:
    """Return a copy of *config* with state-tracking hooks attached.

    Args:
        config: Agent config tree to instrument.
        state_manager: Where to persist state records.
        run_id: Unique identifier for the current run.
        spawn_parsers: Optional mapping of agent name to parser
            function.  Passed through to the iteration hook so
            spawn results are dispatched to domain-specific parsers.
    """
    on_iteration = make_on_iteration_hook(
        state_manager, run_id, config.name,
        spawn_parsers=spawn_parsers,
    )

    return replace(
        config,
        on_iteration=on_iteration,
        agents=[
            inject_state_manager(
                child, state_manager, run_id,
                spawn_parsers=spawn_parsers,
            )
            for child in config.agents
        ],
    )
