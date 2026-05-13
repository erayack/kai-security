"""Helpers for resolving agent model backends from environment variables."""

from __future__ import annotations

import os
from functools import lru_cache
from importlib import resources
from typing import Any, cast

import yaml
from ra.core.types import ClientBackend

_DEFAULTS_RESOURCE = "model_defaults.yaml"


def _agent_key(agent: str, suffix: str) -> str:
    return f"KAI_{agent.upper()}_{suffix}"


@lru_cache(maxsize=1)
def _load_defaults() -> dict[str, Any]:
    """Load packaged model defaults from YAML."""
    raw = resources.files(__package__).joinpath(_DEFAULTS_RESOURCE).read_text()
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{_DEFAULTS_RESOURCE} must contain a mapping")
    return data


def supported_backends() -> set[str]:
    """Return supported Kai-wide model backends."""
    raw = _load_defaults().get("supported_backends", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError(f"{_DEFAULTS_RESOURCE} supported_backends must be a list")
    return set(raw)


def model_defaults(agent: str) -> dict[str, str]:
    """Return backend-specific model defaults for *agent*."""
    models = _load_defaults().get("models", {})
    if not isinstance(models, dict):
        raise ValueError(f"{_DEFAULTS_RESOURCE} models must be a mapping")
    raw = models.get(agent)
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw.items()
    ):
        raise ValueError(f"No model defaults configured for {agent!r}")
    return dict(raw)


def resolve_backend(agent: str) -> ClientBackend:
    """Return the backend for *agent* from env, defaulting to OpenRouter.

    ``KAI_BACKEND`` sets the default backend for all Kai agents.
    ``KAI_<AGENT>_BACKEND`` overrides a single agent.
    """
    raw = os.environ.get(_agent_key(agent, "BACKEND"), os.environ.get("KAI_BACKEND"))
    backend = (raw or "openrouter").strip().lower()
    backends = supported_backends()
    if backend not in backends:
        supported = ", ".join(sorted(backends))
        raise ValueError(
            f"Unsupported backend {backend!r} for {agent}. "
            f"Supported values: {supported}"
        )
    return cast(ClientBackend, backend)


def resolve_model(agent: str, defaults: dict[str, str] | None = None) -> str:
    """Return the model for *agent* from env or backend-specific defaults."""
    override = os.environ.get(_agent_key(agent, "MODEL"))
    if override:
        return override

    defaults = defaults or model_defaults(agent)
    backend = resolve_backend(agent)
    if backend in defaults:
        return defaults[backend]
    if "openrouter" in defaults:
        return defaults["openrouter"]
    raise ValueError(f"No default model configured for {agent} on backend {backend}")
