"""RecursiveAgent: build and run an RLM from a config tree."""

from __future__ import annotations

from typing import Any, Callable

from ra.agents.config import RecursiveAgentConfig
from ra.exceptions import SpawnError


def _make_spawn_fn(
    config: RecursiveAgentConfig,
    parent_depth: int,
    max_depth: int,
) -> Callable[[Any], str]:
    """Build a spawn closure for a sub-agent config.

    The closure creates a ``RecursiveAgent`` at ``parent_depth + 1``,
    runs its full agentic loop, and returns the response string.
    Errors are caught so a failing sub-agent never crashes the
    parent's REPL.

    The returned function exposes a ``_pending_completions`` list
    attribute. Each successful sub-agent run appends its full
    ``RLMChatCompletion`` so the parent REPL can drain token usage.
    """
    pending: list[Any] = []

    def _spawn(data: Any) -> str:
        try:
            agent = RecursiveAgent(
                config,
                depth=parent_depth + 1,
                max_depth=max_depth,
            )
            result = agent.completion(data)
            if isinstance(result, str):
                return result
            pending.append(result)
            return result.response
        except SpawnError as exc:
            return f"[spawn_{config.name} error] {type(exc).__name__}: {exc}"

    _spawn.__name__ = f"spawn_{config.name}"
    _spawn.__qualname__ = f"spawn_{config.name}"
    _spawn.__doc__ = (
        f"Spawn the '{config.name}' agent. "
        f"Runs an agentic loop (up to {config.max_iterations} "
        f"iterations) and returns the final answer string."
    )
    _spawn._pending_completions = pending  # type: ignore[attr-defined]
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
            tools[f"spawn_{sub.name}"] = _make_spawn_fn(sub, self.depth, self.max_depth)
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
            custom_system_prompt=self.config.system_prompt,
            environment="local",
            environment_kwargs=env_kwargs,
            max_iterations=self.config.max_iterations,
            verbose=self.config.verbose,
        )

    def completion(self, data: str | dict[str, Any]) -> Any:
        """Run the agentic loop and return the result.

        Args:
            data: Input data passed as ``context`` in the REPL.

        Returns:
            ``RLMChatCompletion`` with ``.response`` as the final answer.
        """
        return self._rlm.completion(data)
