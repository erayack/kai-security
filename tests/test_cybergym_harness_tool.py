"""Tests for the in-pipeline cybergym strict-harness submission tool."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

from kai.workspace import tools as ws_tools


@pytest.fixture(autouse=True)
def _reset_mask_map_cache():
    ws_tools._cybergym_mask_map_cache = None
    yield
    ws_tools._cybergym_mask_map_cache = None


def test_tool_is_noop_outside_cybergym(monkeypatch):
    monkeypatch.delenv("KAI_BENCHMARK", raising=False)
    result = ws_tools.submit_to_cybergym_harness(base64.b64encode(b"x").decode())
    assert result["verified"] is False
    assert result["error"] is not None
    assert "KAI_BENCHMARK=cybergym" in result["error"]


def test_tool_errors_when_url_missing(monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.delenv("KAI_CYBERGYM_HARNESS_URL", raising=False)
    monkeypatch.setenv("KAI_TASK_ID", "arvo:1065")
    result = ws_tools.submit_to_cybergym_harness(base64.b64encode(b"x").decode())
    assert result["verified"] is False
    assert "KAI_CYBERGYM_HARNESS_URL" in (result["error"] or "")


def test_tool_errors_when_task_id_missing(monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_CYBERGYM_HARNESS_URL", "http://example.com")
    monkeypatch.delenv("KAI_TASK_ID", raising=False)
    result = ws_tools.submit_to_cybergym_harness(base64.b64encode(b"x").decode())
    assert result["verified"] is False
    assert "KAI_TASK_ID" in (result["error"] or "")


def test_tool_errors_on_bad_b64(monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_CYBERGYM_HARNESS_URL", "http://example.com")
    monkeypatch.setenv("KAI_TASK_ID", "arvo:1065")
    result = ws_tools.submit_to_cybergym_harness("not_base64!@#")
    assert result["verified"] is False
    assert "decode failed" in (result["error"] or "")


def test_tool_errors_when_task_not_in_mask_map(monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_CYBERGYM_HARNESS_URL", "http://example.com")
    monkeypatch.setenv("KAI_TASK_ID", "arvo:99999999")
    # Stub mask_map without our task_id.
    ws_tools._cybergym_mask_map_cache = {"arvo:1065": "abc"}
    result = ws_tools.submit_to_cybergym_harness(base64.b64encode(b"x").decode())
    assert result["verified"] is False
    assert "not present in mask_map" in (result["error"] or "")


def test_tool_returns_verified_true_on_nonzero_exit(monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_CYBERGYM_HARNESS_URL", "http://example.com")
    monkeypatch.setenv("KAI_TASK_ID", "arvo:1065")
    ws_tools._cybergym_mask_map_cache = {"arvo:1065": "deadbeef"}

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "exit_code": 77,
        "output": "==1==WARNING: MemorySanitizer: use-of-uninitialized-value",
    }
    fake_client = MagicMock()
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False
    fake_client.post.return_value = fake_resp

    with patch("httpx.Client", return_value=fake_client):
        result = ws_tools.submit_to_cybergym_harness(
            base64.b64encode(b"\x00\x01\x02").decode()
        )

    assert result["verified"] is True
    assert result["exit_code"] == 77
    assert "MemorySanitizer" in result["output"]
    assert result["http_status"] == 200
    assert result["error"] is None


def test_tool_returns_verified_false_on_clean_exit(monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_CYBERGYM_HARNESS_URL", "http://example.com")
    monkeypatch.setenv("KAI_TASK_ID", "arvo:1065")
    ws_tools._cybergym_mask_map_cache = {"arvo:1065": "deadbeef"}

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"exit_code": 0, "output": "clean run"}
    fake_client = MagicMock()
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False
    fake_client.post.return_value = fake_resp

    with patch("httpx.Client", return_value=fake_client):
        result = ws_tools.submit_to_cybergym_harness(
            base64.b64encode(b"\x00\x01\x02").decode()
        )

    assert result["verified"] is False
    assert result["exit_code"] == 0


def test_tool_handles_transport_error(monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_CYBERGYM_HARNESS_URL", "http://example.com")
    monkeypatch.setenv("KAI_TASK_ID", "arvo:1065")
    ws_tools._cybergym_mask_map_cache = {"arvo:1065": "deadbeef"}

    fake_client = MagicMock()
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False
    fake_client.post.side_effect = RuntimeError("network unreachable")

    with patch("httpx.Client", return_value=fake_client):
        result = ws_tools.submit_to_cybergym_harness(base64.b64encode(b"x").decode())

    assert result["verified"] is False
    assert "network unreachable" in (result["error"] or "")


def test_tool_strips_trailing_slash_in_url(monkeypatch):
    """URL must be joined as ``{base}/submit-vul`` exactly once."""
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_CYBERGYM_HARNESS_URL", "http://example.com/")
    monkeypatch.setenv("KAI_TASK_ID", "arvo:1065")
    ws_tools._cybergym_mask_map_cache = {"arvo:1065": "x"}

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {"exit_code": 0, "output": ""}
    fake_client = MagicMock()
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False
    fake_client.post.return_value = fake_resp

    with patch("httpx.Client", return_value=fake_client):
        ws_tools.submit_to_cybergym_harness(base64.b64encode(b"x").decode())

    called_url = fake_client.post.call_args[0][0]
    assert called_url == "http://example.com/submit-vul"
