"""Agentic layer for the RLM framework.

Provides typed sub-agents that the root RLM can spawn, each with its
own system prompt, REPL tools, and iteration budget.

Usage::

    from kai.agents import AgentConfig, AgentRegistry

    config = AgentConfig(
        name="reviewer",
        system_prompt="You are a code reviewer...",
        tools={"count_lines": count_lines},
        backend="openai",
        backend_kwargs={"model_name": "gpt-4o-mini"},
        max_iterations=10,
    )

    registry = AgentRegistry()
    registry.register(config)

    spawn_fns = registry.build_spawn_functions(
        parent_depth=0, parent_max_depth=2,
    )
    # spawn_fns == {"spawn_reviewer": <callable>}
"""

from kai.agents.config import AgentConfig
from kai.agents.registry import AgentRegistry

__all__ = ["AgentConfig", "AgentRegistry"]
