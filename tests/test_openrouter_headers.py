"""Tests for OpenRouter attribution headers."""

from __future__ import annotations

from ra.clients.openai import OpenAIClient


def test_openrouter_client_uses_kai_security_headers() -> None:
    client = OpenAIClient(
        api_key="test-key",
        model_name="openai/gpt-5.2",
        base_url="https://openrouter.ai/api/v1",
    )

    assert client._async_client_kwargs["default_headers"] == {
        "HTTP-Referer": "https://github.com/firstbatchxyz/kai-security",
        "X-OpenRouter-Title": "kai-security",
        "X-OpenRouter-Categories": "cli-agent,programming-app",
    }


def test_openai_client_does_not_use_openrouter_headers() -> None:
    client = OpenAIClient(
        api_key="test-key",
        model_name="gpt-5.4",
        base_url="https://api.openai.com/v1",
    )

    assert client._async_client_kwargs["default_headers"] is None
