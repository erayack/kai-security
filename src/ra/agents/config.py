"""Configuration dataclass for recursive agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ra.core.types import ClientBackend


@dataclass
class RecursiveAgentConfig:
    """Describes an agent node in the config tree.

    Every node is identical in structure — there is no distinction
    between "root" and "sub-agent".  Sub-agents listed in ``agents``
    become ``spawn_<name>()`` functions in this agent's REPL.

    The system prompt must document the available tools and spawn
    functions so the LLM knows how to call them in ```repl blocks.
    """

    name: str
    system_prompt: str
    tools: dict[str, Callable[..., Any]] = field(default_factory=dict)
    agents: list[RecursiveAgentConfig] = field(default_factory=list)
    backend: ClientBackend = "openai"
    backend_kwargs: dict[str, Any] = field(default_factory=dict)
    other_backends: list[ClientBackend] | None = None
    other_backend_kwargs: list[dict[str, Any]] | None = None
    query_model: str | None = None
    environment_kwargs: dict[str, Any] = field(default_factory=dict)
    max_iterations: int = 10
    verbose: bool = False
    log_file: str = ""
    log_structured: bool = False
    on_iteration: Callable[..., None] | None = None
    result_processor: Callable[[dict[str, Any], str], str] | None = None

    def validate(self) -> None:
        """Validate this config and all sub-agent configs recursively.

        Raises:
            ValueError: If any field is invalid or names collide.
        """
        if not self.name:
            raise ValueError("RecursiveAgentConfig.name must be non-empty")
        if not self.system_prompt:
            raise ValueError("RecursiveAgentConfig.system_prompt must be non-empty")
        if self.max_iterations < 1:
            raise ValueError(
                "RecursiveAgentConfig.max_iterations must be >= 1, "
                f"got {self.max_iterations}"
            )
        # Check for duplicate sub-agent names
        names = [a.name for a in self.agents]
        if len(names) != len(set(names)):
            raise ValueError(f"Duplicate sub-agent names in '{self.name}': {names}")
        # Check tool/spawn name collisions
        for agent in self.agents:
            spawn_name = f"spawn_{agent.name}"
            if spawn_name in self.tools:
                raise ValueError(
                    f"Tool '{spawn_name}' in '{self.name}' collides "
                    f"with spawn function for sub-agent '{agent.name}'"
                )
        # Enforce that tools and spawn functions are documented
        # in the system prompt so the LLM knows they exist
        missing_tools = [name for name in self.tools if name not in self.system_prompt]
        missing_spawns = [
            f"spawn_{a.name}"
            for a in self.agents
            if f"spawn_{a.name}" not in self.system_prompt
        ]
        missing = missing_tools + missing_spawns
        if missing:
            raise ValueError(
                f"Agent '{self.name}' system_prompt must document all "
                f"tools and spawn functions. Missing: {missing}"
            )
        for agent in self.agents:
            agent.validate()

    def tree_depth(self) -> int:
        """Return the depth of the config tree rooted at this node.

        A leaf (no sub-agents) has depth 0.  A node with sub-agents
        has depth 1 + max child depth.
        """
        if not self.agents:
            return 0
        return 1 + max(a.tree_depth() for a in self.agents)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict. Tools stored as names, agents nested."""
        return {
            "name": self.name,
            "system_prompt": self.system_prompt,
            "tools": list(self.tools.keys()),
            "agents": [a.to_dict() for a in self.agents],
            "backend": self.backend,
            "backend_kwargs": self.backend_kwargs,
            "other_backends": self.other_backends,
            "other_backend_kwargs": self.other_backend_kwargs,
            "query_model": self.query_model,
            "environment_kwargs": {
                k: v for k, v in self.environment_kwargs.items() if not callable(v)
            },
            "max_iterations": self.max_iterations,
            "verbose": self.verbose,
            "log_structured": self.log_structured,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        tools: dict[str, Callable[..., Any]] | None = None,
        agent_tools: dict[str, dict[str, Callable[..., Any]]] | None = None,
    ) -> RecursiveAgentConfig:
        """Deserialize from dict.

        Args:
            data: Serialized config dict (from ``to_dict``).
            tools: Callable mapping for this node's tools.
            agent_tools: Mapping of ``agent_name -> tools dict``
                for sub-agents, since callables aren't serializable.
        """
        agent_tools = agent_tools or {}
        return cls(
            name=data["name"],
            system_prompt=data["system_prompt"],
            tools=tools or {},
            agents=[
                cls.from_dict(a, tools=agent_tools.get(a["name"]))
                for a in data.get("agents", [])
            ],
            backend=data.get("backend", "openai"),
            backend_kwargs=data.get("backend_kwargs", {}),
            other_backends=data.get("other_backends"),
            other_backend_kwargs=data.get("other_backend_kwargs"),
            query_model=data.get("query_model"),
            environment_kwargs=data.get("environment_kwargs", {}),
            max_iterations=data.get("max_iterations", 10),
            verbose=data.get("verbose", False),
            log_structured=data.get("log_structured", False),
        )
