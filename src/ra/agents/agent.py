"""RecursiveAgent: build and run an RLM from a config tree."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any, Callable

from ra.agents.config import RecursiveAgentConfig
from ra.core.types import SpawnRecord
from ra.exceptions import SpawnError

log = logging.getLogger(__name__)


def _make_spawn_fn(
    config: RecursiveAgentConfig,
    parent_depth: int,
    max_depth: int,
    log_file: str = "",
) -> Callable[..., str]:
    """Build a spawn closure for a sub-agent config.

    The closure creates a ``RecursiveAgent`` at ``parent_depth + 1``,
    runs its full agentic loop, and returns the response string.
    Errors are caught so a failing sub-agent never crashes the
    parent's REPL.

    The returned function exposes:
    - ``_pending_completions``: list of ``RLMChatCompletion`` for
      token usage rollup.
    - ``_spawn_records``: list of ``SpawnRecord`` for deterministic
      spawn data collection.
    """
    pending: list[Any] = []
    records: list[SpawnRecord] = []
    call_count = [0]  # mutable counter shared across calls

    def _log_error(msg: str) -> None:
        log.error(msg)
        if log_file:
            try:
                with open(log_file, "a") as fh:
                    fh.write(f"\n[spawn error] {msg}\n")
            except OSError:
                pass

    def _spawn(**kwargs: Any) -> str:
        call_count[0] += 1
        indexed_config = config
        if call_count[0] > 1:
            indexed_config = replace(config, name=f"{config.name}#{call_count[0]}")

        # Forward cooperative cancellation event from parent REPL
        cancel_event = getattr(_spawn, "_cancel_event", None)
        if cancel_event is not None:
            indexed_config = replace(
                indexed_config,
                environment_kwargs={
                    **indexed_config.environment_kwargs,
                    "cancel_event": cancel_event,
                },
            )

        try:
            agent = RecursiveAgent(
                indexed_config,
                depth=parent_depth + 1,
                max_depth=max_depth,
            )
            result = agent.completion(kwargs)
            if isinstance(result, str):
                result_str = result
            else:
                pending.append(result)
                result_str = result.response

            if config.result_processor is not None:
                try:
                    result_str = config.result_processor(
                        kwargs,
                        result_str,
                    )
                except Exception:
                    _log_error(f"result_processor failed for {config.name}")

            records.append(
                SpawnRecord(
                    agent_name=config.name,
                    kwargs=kwargs,
                    result=result_str,
                )
            )
            return result_str
        except SpawnError as exc:
            error_msg = f"[spawn_{config.name} error] {type(exc).__name__}: {exc}"
            records.append(
                SpawnRecord(
                    agent_name=config.name,
                    kwargs=kwargs,
                    result=error_msg,
                )
            )
            return error_msg

    _spawn.__name__ = f"spawn_{config.name}"
    _spawn.__qualname__ = f"spawn_{config.name}"
    _spawn.__doc__ = (
        f"Spawn the '{config.name}' agent. "
        f"Runs an agentic loop (up to {config.max_iterations} "
        f"iterations) and returns the final answer string."
    )
    _spawn._pending_completions = pending  # type: ignore[attr-defined]
    _spawn._spawn_records = records  # type: ignore[attr-defined]
    return _spawn


class RecursiveAgent:
    """An agent node that wraps an RLM, built from a config tree.

    Any ``RecursiveAgentConfig`` can be used as an entry point —
    there is no distinction between root and sub-agent.  Sub-agents
    declared in ``config.agents`` become ``spawn_<name>()`` functions
    in this agent's REPL namespace.

    Example::

        agent = RecursiveAgent(my_config)
        result = agent.completion("analyze this code")
    """

    def __init__(
        self,
        config: RecursiveAgentConfig,
        depth: int = 0,
        max_depth: int | None = None,
    ) -> None:
        config.validate()
        self.config = config
        self.depth = depth
        self.max_depth = max_depth if max_depth is not None else config.tree_depth() + 1
        self._rlm = self._build_rlm()

    def _build_tools(self) -> dict[str, Any]:
        """Merge direct tools with spawn functions for sub-agents."""
        tools: dict[str, Any] = dict(self.config.tools)
        for sub in self.config.agents:
            tools[f"spawn_{sub.name}"] = _make_spawn_fn(
                sub,
                self.depth,
                self.max_depth,
                log_file=self.config.log_file,
            )
        return tools

    def _build_rlm(self) -> Any:
        """Construct the underlying RLM instance.

        Import is deferred to avoid circular imports
        (agents -> rlm -> environments -> agents).
        """
        from ra.core.rlm import RLM

        env_kwargs = dict(self.config.environment_kwargs)
        env_kwargs["tools"] = self._build_tools()

        return RLM(
            depth=self.depth,
            max_depth=self.max_depth,
            backend=self.config.backend,
            backend_kwargs=self.config.backend_kwargs,
            other_backends=self.config.other_backends,
            other_backend_kwargs=self.config.other_backend_kwargs,
            query_model=self.config.query_model,
            custom_system_prompt=self.config.system_prompt,
            environment="local",
            environment_kwargs=env_kwargs,
            max_iterations=self.config.max_iterations,
            verbose=self.config.verbose,
            log_file=self.config.log_file,
            name=self.config.name,
            on_iteration=self.config.on_iteration,
        )

    def completion(self, data: str | dict[str, Any]) -> Any:
        """Run the agentic loop and return the result.

        Args:
            data: Input data passed as ``context`` in the REPL.

        Returns:
            ``RLMChatCompletion`` with ``.response`` as the final answer.
        """
        return self._rlm.completion(data)
