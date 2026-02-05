"""
Kai exception classes.

This module defines custom exceptions used throughout the Kai framework.
"""


class KaiError(Exception):
    """Base exception for all Kai errors."""

    pass


class DispatcherBootError(KaiError):
    """Raised when dispatcher boot fails."""

    pass


class EnvironmentSetupError(DispatcherBootError):
    """Raised when environment setup fails during boot."""

    pass


class StaticAnalysisError(DispatcherBootError):
    """Raised when static analysis (dependency graph building) fails during boot."""

    pass


class WorkspaceValidationError(DispatcherBootError):
    """Raised when workspace validation fails during boot."""

    pass


class ActorAnalysisError(DispatcherBootError):
    """Raised when actor analysis fails during boot."""

    pass
