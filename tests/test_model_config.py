"""Tests for Kai model backend resolution."""

from __future__ import annotations

import pytest

from kai.definitions.model_config import (
    model_defaults,
    resolve_backend,
    resolve_model,
    supported_backends,
)


def test_supported_backends_loaded_from_yaml() -> None:
    assert supported_backends() == {"openai", "openrouter"}


def test_model_defaults_loaded_from_yaml() -> None:
    assert model_defaults("root") == {
        "openrouter": "anthropic/claude-opus-4.5",
        "openai": "gpt-5.5",
    }


@pytest.mark.parametrize("agent", ["root", "analyzer", "verifier"])
def test_primary_openai_defaults_use_gpt_55(agent: str) -> None:
    assert model_defaults(agent)["openai"] == "gpt-5.5"


@pytest.mark.parametrize(
    "agent",
    [
        "query",
        "fixer",
        "critic",
        "researcher",
        "setup",
        "chain",
        "patch_assembler",
        "poc_auditor",
    ],
)
def test_secondary_openai_defaults_use_gpt_54(agent: str) -> None:
    assert model_defaults(agent)["openai"] == "gpt-5.4"


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

    assert resolve_model("root") == "gpt-5.5"


def test_model_env_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_BACKEND", "openai")
    monkeypatch.setenv("KAI_ROOT_MODEL", "gpt-custom")

    assert resolve_model("root") == "gpt-custom"


def test_model_can_still_use_explicit_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KAI_BACKEND", "openrouter")
    monkeypatch.delenv("KAI_TEST_AGENT_MODEL", raising=False)

    assert (
        resolve_model(
            "test_agent",
            {
                "openrouter": "router-model",
                "openai": "openai-model",
            },
        )
        == "router-model"
    )
