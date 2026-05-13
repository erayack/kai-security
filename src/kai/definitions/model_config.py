"""Helpers for resolving agent model backends from environment variables."""

from __future__ import annotations

import os
from typing import cast

from ra.core.types import ClientBackend

_SUPPORTED_BACKENDS: set[str] = {
    "openai",
    "openrouter",
}


def _agent_key(agent: str, suffix: str) -> str:
    return f"KAI_{agent.upper()}_{suffix}"


def resolve_backend(agent: str) -> ClientBackend:
    """Return the backend for *agent* from env, defaulting to OpenRouter.

    ``KAI_BACKEND`` sets the default backend for all Kai agents.
    ``KAI_<AGENT>_BACKEND`` overrides a single agent.
    """
    raw = os.environ.get(_agent_key(agent, "BACKEND"), os.environ.get("KAI_BACKEND"))
    backend = (raw or "openrouter").strip().lower()
    if backend not in _SUPPORTED_BACKENDS:
        supported = ", ".join(sorted(_SUPPORTED_BACKENDS))
        raise ValueError(
            f"Unsupported backend {backend!r} for {agent}. "
            f"Supported values: {supported}"
        )
    return cast(ClientBackend, backend)


def resolve_model(agent: str, defaults: dict[str, str]) -> str:
    """Return the model for *agent* from env or backend-specific defaults."""
    override = os.environ.get(_agent_key(agent, "MODEL"))
    if override:
        return override

    backend = resolve_backend(agent)
    if backend in defaults:
        return defaults[backend]
    if "openrouter" in defaults:
        return defaults["openrouter"]
    raise ValueError(f"No default model configured for {agent} on backend {backend}")
