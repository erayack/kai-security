"""
Recursive Agent exception classes.

This module defines custom exceptions used throughout the RecursiveAgentError framework.
"""

from __future__ import annotations


class RecursiveAgentError(Exception):
    """Base exception for all RA errors.

    Carries optional runtime context so errors from deeply nested
    agent trees can be diagnosed without reproducing the full run.
    """

    depth: int | None
    agent_name: str | None
    iteration_num: int | None
    model: str | None

    def __init__(
        self,
        *args: object,
        depth: int | None = None,
        agent_name: str | None = None,
        iteration_num: int | None = None,
        model: str | None = None,
    ) -> None:
        super().__init__(*args)
        self.depth = depth
        self.agent_name = agent_name
        self.iteration_num = iteration_num
        self.model = model

    def __str__(self) -> str:
        base = super().__str__()
        ctx_parts: list[str] = []
        if self.agent_name is not None:
            ctx_parts.append(f"agent={self.agent_name}")
        if self.depth is not None:
            ctx_parts.append(f"depth={self.depth}")
        if self.iteration_num is not None:
            ctx_parts.append(f"iter={self.iteration_num}")
        if self.model is not None:
            ctx_parts.append(f"model={self.model}")
        if not ctx_parts:
            return base
        return f"{base} [{', '.join(ctx_parts)}]"

    def enrich(
        self,
        *,
        depth: int | None = None,
        agent_name: str | None = None,
        iteration_num: int | None = None,
        model: str | None = None,
    ) -> RecursiveAgentError:
        """Set context fields that are still ``None`` and return self."""
        if depth is not None and self.depth is None:
            self.depth = depth
        if agent_name is not None and self.agent_name is None:
            self.agent_name = agent_name
        if iteration_num is not None and self.iteration_num is None:
            self.iteration_num = iteration_num
        if model is not None and self.model is None:
            self.model = model
        return self


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
