"""
Kai exception classes.

This module defines custom exceptions used throughout the Kai framework.
"""


class KaiError(Exception):
    """Base exception for all Kai errors."""

    pass


class SetupRLMError(KaiError):
    """Raised when setup RLM fails."""

    pass


class RootRLMError(KaiError):
    """Raised when root RLM fails."""

    pass


class SubRLMError(KaiError):
    """Raised when sub RLM fails."""

    pass


class LMError(KaiError):
    """Raised when a sub LM request fails."""

    pass
