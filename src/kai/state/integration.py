"""Inject state manager hooks into an agent config tree."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from ra.agents.config import RecursiveAgentConfig

from kai.state.base import StateManager
from kai.state.hooks import make_on_iteration_hook

# Processor signature before binding: (state_manager, run_id, kwargs, raw) -> str
ResultProcessor = Callable[[StateManager, str, dict[str, Any], str], str]


def inject_state_manager(
    config: RecursiveAgentConfig,
    state_manager: StateManager,
    run_id: str,
    result_processors: dict[str, ResultProcessor] | None = None,
) -> RecursiveAgentConfig:
    """Return a copy of *config* with state-tracking hooks attached.

    Args:
        config: Agent config tree to instrument.
        state_manager: Where to persist state records.
        run_id: Unique identifier for the current run.
        result_processors: Optional mapping of agent name to processor
            function.  Each matching sub-agent config gets a bound
            ``result_processor`` closure so enrichment runs inside the
            spawn function.
    """
    on_iteration = make_on_iteration_hook(
        state_manager,
        run_id,
        config.name,
    )

    processors = result_processors or {}

    children: list[RecursiveAgentConfig] = []
    for child in config.agents:
        injected_child = inject_state_manager(
            child,
            state_manager,
            run_id,
            result_processors=result_processors,
        )
        processor_fn = processors.get(child.name)
        if processor_fn is not None:

            def _bound(
                kwargs: dict[str, Any],
                raw: str,
                _fn: ResultProcessor = processor_fn,
            ) -> str:
                return _fn(state_manager, run_id, kwargs, raw)

            injected_child = replace(
                injected_child,
                result_processor=_bound,
            )
        children.append(injected_child)

    return replace(
        config,
        on_iteration=on_iteration,
        agents=children,
    )
