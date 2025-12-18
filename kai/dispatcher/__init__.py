"""
Dispatcher: Mission control for Kai v2.
"""

from kai.dispatcher.core import (
    Dispatcher,
    DispatcherConfig,
    AgentFactory,
    VerifierProtocol,
)
from kai.dispatcher.planner import MissionPlanner
from kai.dispatcher.workspace import WorkspaceManager
from kai.dispatcher.agent_factories import (
    create_state_agent,
    create_blackbox_agent,
    filter_actor_context,
    get_agent_factory,
    AGENT_FACTORIES,
)

__all__ = [
    "Dispatcher",
    "DispatcherConfig",
    "AgentFactory",
    "VerifierProtocol",
    "MissionPlanner",
    "WorkspaceManager",
    # Agent factories
    "create_state_agent",
    "create_blackbox_agent",
    "filter_actor_context",
    "get_agent_factory",
    "AGENT_FACTORIES",
]
