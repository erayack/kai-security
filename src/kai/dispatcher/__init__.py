"""
Dispatcher: Mission control for Kai v2.
"""

from kai.dispatcher.core import (
    Dispatcher,
    DispatcherConfig,
    AgentFactory,
)
from kai.dispatcher.planner import MissionPlanner
from kai.dispatcher.workspace import WorkspaceManager
from kai.dispatcher.usage_tracker import UsageTracker
from kai.dispatcher.boot_pipeline import BootPipeline, BootResult, SetupResult
from kai.dispatcher.coverage import hash_graph, diff_invariants
from kai.dispatcher.verification import VerificationPipeline
from kai.dispatcher.fix_pipeline import FixPipeline
from kai.dispatcher.agent_factories import (
    create_state_agent,
    create_blackbox_agent,
    filter_actor_context,
    get_agent_factory,
    AGENT_FACTORIES,
)
from kai.exceptions import (
    DispatcherBootError,
    EnvironmentSetupError,
    StaticAnalysisError,
    WorkspaceValidationError,
    ActorAnalysisError,
)

__all__ = [
    "Dispatcher",
    "DispatcherConfig",
    "AgentFactory",
    "MissionPlanner",
    "WorkspaceManager",
    "UsageTracker",
    "BootPipeline",
    "BootResult",
    "SetupResult",
    "hash_graph",
    "diff_invariants",
    "VerificationPipeline",
    "FixPipeline",
    # Boot error classes
    "DispatcherBootError",
    "EnvironmentSetupError",
    "StaticAnalysisError",
    "WorkspaceValidationError",
    "ActorAnalysisError",
    # Agent factories
    "create_state_agent",
    "create_blackbox_agent",
    "filter_actor_context",
    "get_agent_factory",
    "AGENT_FACTORIES",
]
