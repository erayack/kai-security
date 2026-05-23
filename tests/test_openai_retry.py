"""Tests for the OpenAI client's transient-failure retry path."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import openai
import pytest

from ra.clients import openai as openai_module


def test_is_retryable_jsondecodeerror() -> None:
    err = json.JSONDecodeError("Expecting value", "doc", 0)
    assert openai_module._is_retryable(err)


def test_is_retryable_openai_transient() -> None:
    from openai import APIConnectionError, RateLimitError

    # Use MagicMock for the request arg openai expects
    assert openai_module._is_retryable(APIConnectionError(request=MagicMock()))
    # RateLimitError needs a fake response
    resp = MagicMock()
    resp.status_code = 429
    err = RateLimitError("rate limited", response=resp, body=None)
    assert openai_module._is_retryable(err)


def test_is_retryable_status_error_429() -> None:
    resp = MagicMock()
    resp.status_code = 429
    err = openai.APIStatusError("rate limited", response=resp, body=None)
    assert openai_module._is_retryable(err)


def test_is_retryable_status_error_500() -> None:
    resp = MagicMock()
    resp.status_code = 502
    err = openai.APIStatusError("bad gateway", response=resp, body=None)
    assert openai_module._is_retryable(err)


def test_not_retryable_status_error_400() -> None:
    resp = MagicMock()
    resp.status_code = 400
    err = openai.APIStatusError("bad request", response=resp, body=None)
    assert not openai_module._is_retryable(err)


def test_not_retryable_value_error() -> None:
    err = ValueError("bad input")
    assert not openai_module._is_retryable(err)


def test_call_with_retry_succeeds_after_blip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transient JSONDecodeError on attempt 1 should retry and succeed on 2."""
    monkeypatch.setattr(openai_module, "_DEFAULT_MAX_RETRIES", 3)
    monkeypatch.setattr(openai_module, "_DEFAULT_BASE_BACKOFF_S", 0.01)

    state = {"calls": 0}

    def _flaky() -> str:
        state["calls"] += 1
        if state["calls"] == 1:
            raise json.JSONDecodeError("Expecting value", "doc", 0)
        return "ok"

    result = openai_module._call_with_retry(_flaky, model="m", log_prefix="t:")
    assert result == "ok"
    assert state["calls"] == 2


def test_call_with_retry_gives_up_after_max(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(openai_module, "_DEFAULT_MAX_RETRIES", 2)
    monkeypatch.setattr(openai_module, "_DEFAULT_BASE_BACKOFF_S", 0.01)

    state = {"calls": 0}

    def _always_fails() -> str:
        state["calls"] += 1
        raise json.JSONDecodeError("Expecting value", "doc", 0)

    with pytest.raises(json.JSONDecodeError):
        openai_module._call_with_retry(_always_fails, model="m", log_prefix="t:")
    assert state["calls"] == 2


def test_call_with_retry_no_retry_on_hard_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(openai_module, "_DEFAULT_MAX_RETRIES", 5)
    monkeypatch.setattr(openai_module, "_DEFAULT_BASE_BACKOFF_S", 0.01)

    state = {"calls": 0}

    def _bad_input() -> str:
        state["calls"] += 1
        raise ValueError("hard error")

    with pytest.raises(ValueError):
        openai_module._call_with_retry(_bad_input, model="m", log_prefix="t:")
    assert state["calls"] == 1


def test_extract_text_empty_content_raises() -> None:
    """An empty response.content must raise so the retry layer can act."""
    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message.content = ""
    with pytest.raises(openai.APIError):
        openai_module._extract_text(response)


def test_extract_text_no_choices_raises() -> None:
    response = MagicMock()
    response.choices = []
    with pytest.raises(openai.APIError):
        openai_module._extract_text(response)


def test_extract_text_happy_path() -> None:
    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message.content = "hello"
    assert openai_module._extract_text(response) == "hello"
