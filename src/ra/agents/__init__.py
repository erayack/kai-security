"""Agentic layer for the RLM framework.

Any ``RecursiveAgentConfig`` can be used as an entry point — there
is no root/sub-agent distinction.  Sub-agents listed in ``agents``
become ``spawn_<name>()`` functions in the parent's REPL.

Usage::

    from ra.agents import RecursiveAgent, RecursiveAgentConfig

    search = RecursiveAgentConfig(
        name="search",
        system_prompt="You are a search agent...",
        tools={"calculate": calculate},
    )

    root = RecursiveAgentConfig(
        name="root",
        system_prompt="You are an orchestrator...",
        agents=[search],
        max_iterations=30,
    )

    # Start from any node in the tree
    agent = RecursiveAgent(root)
    result = agent.completion(data)

    # Or run the sub-agent directly
    agent = RecursiveAgent(search)
    result = agent.completion(data)
"""

from ra.agents.agent import RecursiveAgent
from ra.agents.config import RecursiveAgentConfig
from ra.agents.registry import AgentRegistry

__all__ = ["RecursiveAgent", "RecursiveAgentConfig", "AgentRegistry"]
