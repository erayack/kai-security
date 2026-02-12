"""Optional agent registry for dynamic registration workflows."""

from ra.agents.config import RecursiveAgentConfig


class AgentRegistry:
    """Stores ``RecursiveAgentConfig`` objects by name.

    This is an optional utility for workflows that register agents
    dynamically.  For static config trees, declare sub-agents directly
    via ``RecursiveAgentConfig.agents`` and use ``RecursiveAgent``.
    """

    def __init__(self) -> None:
        self._configs: dict[str, RecursiveAgentConfig] = {}

    def register(self, config: RecursiveAgentConfig) -> None:
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

    def get(self, name: str) -> RecursiveAgentConfig:
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
