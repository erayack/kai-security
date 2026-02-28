"""Inject state manager hooks into an agent config tree."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any, Callable

from ra.agents.config import RecursiveAgentConfig
from ra.core.types import RLMIteration

from kai.state.base import StateManager
from kai.state.hooks import (
    make_on_extend_hook,
    make_on_iteration_hook,
    make_rollout_on_iteration_hook,
)

_DEFAULT_MAX_EXTEND_ITERS = 15
_DEFAULT_EXTEND_ITERS_PER_CANDIDATE = 5

# Processor signature before binding: (state_manager, run_id, kwargs, raw) -> str
ResultProcessor = Callable[[StateManager, str, dict[str, Any], str], str]


def _chain_hooks(
    *hooks: Callable[[RLMIteration, int], None],
) -> Callable[[RLMIteration, int], None]:
    """Return a single callback that invokes all *hooks* in order."""

    def _chained(iteration: RLMIteration, iteration_num: int) -> None:
        for hook in hooks:
            hook(iteration, iteration_num)

    return _chained


def inject_state_manager(
    config: RecursiveAgentConfig,
    state_manager: StateManager,
    run_id: str,
    result_processors: dict[str, ResultProcessor] | None = None,
    *,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
    _depth: int = 0,
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
        save_rollouts: When ``True``, also attach rollout-writing hooks
            that persist per-agent iteration histories as JSONL.
        rollout_agents: If given, only record rollouts for agents whose
            names appear in this set.  ``None`` means record all.
    """
    status_hook = make_on_iteration_hook(
        state_manager,
        run_id,
        config.name,
    )

    hooks: list[Callable[[RLMIteration, int], None]] = [status_hook]

    if save_rollouts:
        record = rollout_agents is None or config.name in rollout_agents
        if record:
            model = config.backend_kwargs.get("model_name", "")
            rollout_hook = make_rollout_on_iteration_hook(
                state_manager,
                run_id,
                config.name,
                depth=_depth,
                backend=str(config.backend),
                model=str(model),
            )
            hooks.append(rollout_hook)

    on_iteration = hooks[0] if len(hooks) == 1 else _chain_hooks(*hooks)

    processors = result_processors or {}

    children: list[RecursiveAgentConfig] = []
    for child in config.agents:
        injected_child = inject_state_manager(
            child,
            state_manager,
            run_id,
            result_processors=result_processors,
            save_rollouts=save_rollouts,
            rollout_agents=rollout_agents,
            _depth=_depth + 1,
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

    extras: dict[str, Any] = {}
    if _depth == 0:
        iters_per_candidate = int(
            os.environ.get(
                "KAI_EXTEND_ITERS_PER_CANDIDATE",
                _DEFAULT_EXTEND_ITERS_PER_CANDIDATE,
            )
        )
        extras["on_extend"] = make_on_extend_hook(
            state_manager,
            run_id,
            iters_per_candidate=iters_per_candidate,
        )
        extras["max_iterations_limit"] = config.max_iterations + int(
            os.environ.get("KAI_MAX_EXTEND_ITERS", _DEFAULT_MAX_EXTEND_ITERS)
        )

    return replace(
        config,
        on_iteration=on_iteration,
        agents=children,
        **extras,
    )
