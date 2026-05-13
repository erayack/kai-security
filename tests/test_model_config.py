"""Tests for Kai model backend resolution."""

from __future__ import annotations

import pytest

from kai.definitions.model_config import resolve_backend, resolve_model


def test_default_backend_is_openrouter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KAI_BACKEND", raising=False)
    monkeypatch.delenv("KAI_ANALYZER_BACKEND", raising=False)

    assert resolve_backend("analyzer") == "openrouter"


def test_global_backend_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_BACKEND", "openai")
    monkeypatch.delenv("KAI_ANALYZER_BACKEND", raising=False)

    assert resolve_backend("analyzer") == "openai"


def test_agent_backend_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_BACKEND", "openrouter")
    monkeypatch.setenv("KAI_VERIFIER_BACKEND", "openai")

    assert resolve_backend("verifier") == "openai"


def test_invalid_backend_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_BACKEND", "not-a-backend")

    with pytest.raises(ValueError, match="Unsupported backend"):
        resolve_backend("root")


def test_model_uses_backend_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_BACKEND", "openai")
    monkeypatch.delenv("KAI_ROOT_MODEL", raising=False)

    model = resolve_model(
        "root",
        {
            "openrouter": "anthropic/claude-opus-4.5",
            "openai": "gpt-5.2",
        },
    )

    assert model == "gpt-5.2"


def test_model_env_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_BACKEND", "openai")
    monkeypatch.setenv("KAI_ROOT_MODEL", "gpt-custom")

    model = resolve_model(
        "root",
        {
            "openrouter": "anthropic/claude-opus-4.5",
            "openai": "gpt-5.2",
        },
    )

    assert model == "gpt-custom"
