"""Inject state manager hooks into an agent config tree."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any, Callable

from ra.agents.config import RecursiveAgentConfig
from ra.core.types import RLMIteration

from kai.state import cybergym_gate
from kai.state.base import StateManager
from kai.state.hooks import (
    make_on_early_stop_hook,
    make_on_extend_hook,
    make_on_iteration_hook,
    make_rollout_on_iteration_hook,
)

_DEFAULT_MAX_EXTEND_ITERS = 15
_DEFAULT_EXTEND_ITERS_PER_CANDIDATE = 5


def _apply_cybergym_spawn_gate(spawn_wrappers: dict[str, Any]) -> None:
    """Wrap analyzer/researcher/verifier factories with a per-task gate.

    Cybergym tasks frequently spin in analyzer + researcher loops (or,
    after R18, in REPL ``read_file`` loops) without ever calling
    ``spawn_verifier``. This gate caps each of ``spawn_analyzer`` and
    ``spawn_researcher`` at a fixed number of calls until
    ``spawn_verifier`` has been invoked at least once. The shared state
    lives in :mod:`kai.state.cybergym_gate` so the file-tool wrappers in
    :mod:`kai.workspace.tools` can apply the SAME cap to direct REPL
    file reads — closing the bypass route the R18 model used.
    """

    cybergym_gate.init()

    def _call_without_parent_cancel(
        inner_fn: Any, bare_spawn: Any, *args: Any, **kwargs: Any
    ) -> Any:
        """Invoke ``inner_fn`` with the BARE ``_spawn``'s ``_cancel_event``
        temporarily nulled. Restored on exit.

        Cybergym-only. The cancel_event mechanism in the shared ra/
        core (set when the parent REPL's worker.join(effective_timeout)
        returns with the worker still alive) is poisoning every
        sub-agent invocation: when the model emits a code block that
        does heavy work before calling spawn_X, the parent's per-block
        timeout fires DURING or BEFORE the sub-agent's setup. The
        sub-agent then breaks on iter-1 entry, falls through to
        _default_answer, and writes a misleading "Unable to verify"
        rollout (or, after 50094f9, an ABORTED marker).

        Bumping KAI_EXEC_TIMEOUT to 3600s + KAI_ITER_WALL_CAP to 1800s
        did NOT fix this empirically (R34 still showed ABORTED markers
        on researcher sub-agents). The cancel_event is firing for
        reasons orthogonal to the per-block budget — likely an orphan
        daemon worker race that can't be eliminated from the cybergym
        side without changing shared ra/ core.

        Cybergym-specific workaround: temporarily clear
        ``bare_spawn._cancel_event`` (the actual closure built by
        ``ra.agents.agent._make_spawn_fn`` — the one whose attribute
        is read at agent.py:148 before propagating into the
        sub-agent's environment_kwargs). Setting it on intermediate
        wrappers (spawn_hooks' ``make_<X>_spawn_wrapper`` returns plain
        closures that do NOT forward the attribute, so an earlier
        version of this fix was a no-op for verifier/critic/fixer).

        After the call: the sub-agent ran to completion on its own
        time budget. Its result_processor (process_verifier_result
        etc.) already ran, persisting PoC bytes / critic enrichment
        to state_manager.

        Trade-off: in-progress sub-agents that the parent intends to
        cancel continue running until their own bounds (max_iters ~30
        * per-LLM-call 900s = ~7.5h upper bound, in practice 5-30
        min). Acceptable for cybergym where sub-agent engagement is
        more valuable than fast parent cancellation. Other benchmarks
        retain normal cancel behavior — this gate is cybergym-only.
        """
        saved = getattr(bare_spawn, "_cancel_event", None)
        try:
            try:
                bare_spawn._cancel_event = None
            except AttributeError:
                pass
            return inner_fn(*args, **kwargs)
        finally:
            try:
                bare_spawn._cancel_event = saved
            except AttributeError:
                pass

    def _gate(name: str, inner_fn: Any, bare_spawn: Any) -> Any:
        def gated(*args: Any, **kwargs: Any) -> Any:
            blocked = cybergym_gate.check_and_count_spawn(name)
            if blocked is not None:
                return blocked
            return _call_without_parent_cancel(inner_fn, bare_spawn, *args, **kwargs)

        return gated

    def _mark_verifier(inner_fn: Any, bare_spawn: Any) -> Any:
        def marked(*args: Any, **kwargs: Any) -> Any:
            cybergym_gate.mark_verifier_called()
            return _call_without_parent_cancel(inner_fn, bare_spawn, *args, **kwargs)

        return marked

    original_analyzer = spawn_wrappers.get("spawn_analyzer")
    if original_analyzer is not None:

        def analyzer_factory(original_fn: Any) -> Any:
            inner = original_analyzer(original_fn)
            return _gate("analyzer", inner, original_fn)

        spawn_wrappers["spawn_analyzer"] = analyzer_factory

    original_researcher = spawn_wrappers.get("spawn_researcher")
    if original_researcher is not None:

        def researcher_factory(original_fn: Any) -> Any:
            inner = original_researcher(original_fn)
            return _gate("researcher", inner, original_fn)

        spawn_wrappers["spawn_researcher"] = researcher_factory

    original_verifier = spawn_wrappers.get("spawn_verifier")
    if original_verifier is not None:

        def verifier_factory(original_fn: Any) -> Any:
            inner = original_verifier(original_fn)
            return _mark_verifier(inner, original_fn)

        spawn_wrappers["spawn_verifier"] = verifier_factory

    def _mark_critic(inner_fn: Any, bare_spawn: Any) -> Any:
        def marked(*args: Any, **kwargs: Any) -> Any:
            cybergym_gate.mark_critic_called()
            return _call_without_parent_cancel(inner_fn, bare_spawn, *args, **kwargs)

        return marked

    original_critic = spawn_wrappers.get("spawn_critic")
    if original_critic is not None:

        def critic_factory(original_fn: Any) -> Any:
            inner = original_critic(original_fn)
            return _mark_critic(inner, original_fn)

        spawn_wrappers["spawn_critic"] = critic_factory

    # Cybergym: wrap spawn_fixer too. It has no cybergym-specific
    # marker, but it's still a sub-agent that suffers the cancel_event
    # leak. Without this wrap, fixer spawns mid-pipeline would also
    # abort on iter-1 entry.
    def _wrap_fixer(inner_fn: Any, bare_spawn: Any) -> Any:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            return _call_without_parent_cancel(inner_fn, bare_spawn, *args, **kwargs)

        return wrapped

    original_fixer = spawn_wrappers.get("spawn_fixer")
    if original_fixer is not None:

        def fixer_factory(original_fn: Any) -> Any:
            inner = original_fixer(original_fn)
            return _wrap_fixer(inner, original_fn)

        spawn_wrappers["spawn_fixer"] = fixer_factory


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
    recipe: Any | None = None,
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
        recipe: Optional workspace recipe for PoC pre-checks.
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
            recipe=recipe,
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
        from kai.definitions.exploit.config import poc_auditor_config
        from kai.definitions.exploit.proxy import ExploitsProxy
        from kai.definitions.exploit.spawn_hooks import (
            make_analyzer_spawn_wrapper,
            make_critic_spawn_wrapper,
            make_fixer_spawn_wrapper,
            make_researcher_batch,
            make_verifier_spawn_wrapper,
        )

        exploits_proxy = ExploitsProxy(state_manager, run_id)
        spawn_wrappers = dict(config.spawn_wrappers)

        child_names = {a.name for a in config.agents}
        batch_tools: dict[str, Any] = {}

        # Analyzer batch — only when analyzer is a sub-agent
        if "analyzer" in child_names:
            _analyzer_wrapped: list[Any] = []

            def _analyzer_factory(original_fn: Any) -> Any:
                w = make_analyzer_spawn_wrapper(original_fn)
                _analyzer_wrapped.append(w)
                return w

            def spawn_analyzers(specs: list[dict[str, Any]]) -> list[str]:
                """Run multiple analyzer passes concurrently.

                Each element of *specs* is a kwargs dict for
                ``spawn_analyzer`` (files, focus, exclude, …).
                Returns results in the same order as *specs*.
                """
                if not _analyzer_wrapped:
                    return ["spawn_analyzers: not initialized"] * len(specs)
                return _analyzer_wrapped[0]._batch(specs)

            batch_tools["spawn_analyzers"] = spawn_analyzers
            spawn_wrappers["spawn_analyzer"] = _analyzer_factory

        # Researcher batch — only when researcher is a sub-agent
        if "researcher" in child_names:
            _researcher_original: list[Any] = []
            _spawn_researchers_fn: list[Any] = []

            def _researcher_factory(original_fn: Any) -> Any:
                _researcher_original.append(original_fn)
                _spawn_researchers_fn.append(make_researcher_batch(original_fn))
                return original_fn  # no wrapping needed

            def spawn_researchers(queries: list[str]) -> list[str]:
                """Run multiple researcher queries concurrently.

                Each element of *queries* is a query string for
                ``spawn_researcher``.
                Returns results in the same order as *queries*.
                """
                if not _spawn_researchers_fn:
                    return ["spawn_researchers: not initialized"] * len(queries)
                return _spawn_researchers_fn[0](queries)

            batch_tools["spawn_researchers"] = spawn_researchers
            spawn_wrappers["spawn_researcher"] = _researcher_factory

        extras["tools"] = {
            **config.tools,
            "exploits": exploits_proxy,
            **batch_tools,
        }

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
        extras["on_early_stop"] = make_on_early_stop_hook(state_manager, run_id)
        _recipe = recipe
        spawn_wrappers["spawn_verifier"] = lambda original_fn: (
            make_verifier_spawn_wrapper(
                original_fn,
                state_manager,
                run_id,
                auditor_config=poc_auditor_config,
            )
        )
        spawn_wrappers["spawn_critic"] = lambda original_fn: make_critic_spawn_wrapper(
            original_fn, state_manager, run_id
        )
        spawn_wrappers["spawn_fixer"] = lambda original_fn: make_fixer_spawn_wrapper(
            original_fn, state_manager, run_id, recipe=_recipe
        )
        if os.environ.get("KAI_BENCHMARK") == "cybergym":
            _apply_cybergym_spawn_gate(spawn_wrappers)
        extras["spawn_wrappers"] = spawn_wrappers

    return replace(
        config,
        on_iteration=on_iteration,
        agents=children,
        **extras,
    )
