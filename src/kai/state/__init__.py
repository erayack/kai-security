"""State management for kai pipeline runs."""

from kai.state.base import StateManager
from kai.state.hooks import SpawnParser
from kai.state.integration import inject_state_manager
from kai.state.local import LocalStateManager
from kai.state.models import ExploitRecord, FixRecord, RunRecord, StatusUpdate

__all__ = [
    "ExploitRecord",
    "FixRecord",
    "LocalStateManager",
    "RunRecord",
    "SpawnParser",
    "StateManager",
    "StatusUpdate",
    "inject_state_manager",
]
