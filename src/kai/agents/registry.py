"""Agent registry: stores configs, builds spawn functions."""

from typing import Any, Callable

from kai.agents.config import AgentConfig
from kai.exceptions import SpawnError

def _make_spawn_fn(
    config: AgentConfig,
    parent_depth: int,
    parent_max_depth: int,
) -> Callable[[Any], str]:
    """Build a spawn closure for a single agent config.

    The closure creates an RLM at ``parent_depth + 1``, runs a full
    agentic loop, and returns the response string.  Errors are caught
    so a failing sub-agent never crashes the root REPL.

    The ``from kai.core.rlm import RLM`` import is deferred to the
    call-site to avoid circular imports (agents → rlm → environments
    → agents).
    """

    def _spawn(data: Any) -> str:
        from kai.core.rlm import RLM

        try:
            sub_rlm = RLM(
                depth=parent_depth + 1,
                max_depth=parent_max_depth,
                backend=config.backend,
                backend_kwargs=config.backend_kwargs,
                custom_system_prompt=config.system_prompt,
                environment="local",
                environment_kwargs={"tools": config.tools},
                max_iterations=config.max_iterations,
            )
            result = sub_rlm.completion(data)
            if isinstance(result, str):
                return result
            return result.response
        except SpawnError as exc:
            return f"[spawn_{config.name} error] {type(exc).__name__}: {exc}"

    _spawn.__name__ = f"spawn_{config.name}"
    _spawn.__qualname__ = f"spawn_{config.name}"
    _spawn.__doc__ = (
        f"Spawn the '{config.name}' sub-agent. "
        f"Runs an agentic RLM loop (up to {config.max_iterations} "
        f"iterations) and returns the final answer string."
    )
    return _spawn


class AgentRegistry:
    """Stores ``AgentConfig`` objects by name and builds spawn functions."""

    def __init__(self) -> None:
        self._configs: dict[str, AgentConfig] = {}

    def register(self, config: AgentConfig) -> None:
        """Register an agent config.

        Raises:
            ValueError: If a config with the same name already exists.
        """
        config.validate()
        if config.name in self._configs:
            raise ValueError(
                f"Agent '{config.name}' is already registered. "
                f"Registered agents: {self.list_agents()}"
            )
        self._configs[config.name] = config

    def get(self, name: str) -> AgentConfig:
        """Look up a config by name.

        Raises:
            KeyError: If no agent with that name is registered.
        """
        if name not in self._configs:
            raise KeyError(f"No agent named '{name}'. Available: {self.list_agents()}")
        return self._configs[name]

    def list_agents(self) -> list[str]:
        """Return sorted list of registered agent names."""
        return sorted(self._configs)

    def build_spawn_functions(
        self,
        parent_depth: int = 0,
        parent_max_depth: int = 2,
    ) -> dict[str, Callable[..., str]]:
        """Build ``spawn_<name>`` closures for all registered agents.

        Args:
            parent_depth: Depth of the parent RLM (sub-agents run
                at ``parent_depth + 1``).
            parent_max_depth: Max depth passed through to sub-RLMs.

        Returns:
            Dict mapping ``"spawn_<name>"`` to callable closures.
        """
        return {
            f"spawn_{name}": _make_spawn_fn(config, parent_depth, parent_max_depth)
            for name, config in self._configs.items()
        }
