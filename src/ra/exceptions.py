"""
Recursive Agent exception classes.

This module defines custom exceptions used throughout the RecursiveAgentError framework.
"""


class RecursiveAgentError(Exception):
    """Base exception for all Kai errors."""

    pass


class SetupRLMError(RecursiveAgentError):
    """Raised when setup RLM fails."""

    pass


class RootRLMError(RecursiveAgentError):
    """Raised when root RLM fails."""

    pass


class SubRLMError(RecursiveAgentError):
    """Raised when sub RLM fails."""

    pass


class LMError(RecursiveAgentError):
    """Raised when a sub LM request fails."""

    pass


class SpawnError(RecursiveAgentError):
    """Raised when spawning a sub-agent fails."""

    pass


class SerializationError(RecursiveAgentError):
    """Raised when serialization of an object fails."""

    pass
