"""Agent configuration dataclass for typed sub-agents."""

from dataclasses import dataclass, field
from typing import Any, Callable

from kai.core.types import ClientBackend


@dataclass
class AgentConfig:
    """Fully describes a sub-agent's configuration.

    The system prompt must document the available tools (names, arguments,
    return types, usage examples) since the LLM needs to know how to call
    them in ```repl blocks.
    """

    name: str
    system_prompt: str
    tools: dict[str, Callable[..., Any]]
    backend: ClientBackend = "openai"
    backend_kwargs: dict[str, Any] = field(default_factory=dict)
    max_iterations: int = 10

    def validate(self) -> None:
        """Validate config fields.

        Raises:
            ValueError: If any field is invalid.
        """
        if not self.name:
            raise ValueError("AgentConfig.name must be non-empty")
        if not self.system_prompt:
            raise ValueError("AgentConfig.system_prompt must be non-empty")
        if self.max_iterations < 1:
            raise ValueError(
                f"AgentConfig.max_iterations must be >= 1, got {self.max_iterations}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict. Tools are stored as names."""
        return {
            "name": self.name,
            "system_prompt": self.system_prompt,
            "tools": list(self.tools.keys()),
            "backend": self.backend,
            "backend_kwargs": self.backend_kwargs,
            "max_iterations": self.max_iterations,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        tools: dict[str, Callable[..., Any]] | None = None,
    ) -> "AgentConfig":
        """Deserialize from dict.

        Args:
            data: Serialized config dict (from ``to_dict``).
            tools: Callable mapping to restore, since callables
                are not JSON-serializable.
        """
        return cls(
            name=data["name"],
            system_prompt=data["system_prompt"],
            tools=tools or {},
            backend=data.get("backend", "openai"),
            backend_kwargs=data.get("backend_kwargs", {}),
            max_iterations=data.get("max_iterations", 10),
        )
