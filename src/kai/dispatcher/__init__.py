"""
Dispatcher: Mission control for Kai.
"""

from kai.dispatcher.core import (
    Dispatcher,
    DispatcherConfig,
    AgentFactory,
)
from kai.dispatcher.workspace import WorkspaceManager
from kai.dispatcher.usage_tracker import UsageTracker
from kai.dispatcher.boot_pipeline import BootPipeline, BootResult, SetupResult
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
    "WorkspaceManager",
    "UsageTracker",
    "BootPipeline",
    "BootResult",
    "SetupResult",
    # Boot error classes
    "DispatcherBootError",
    "EnvironmentSetupError",
    "StaticAnalysisError",
    "WorkspaceValidationError",
    "ActorAnalysisError",
]
