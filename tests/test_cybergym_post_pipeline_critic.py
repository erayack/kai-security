"""Tests for the post-pipeline critic stage."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from kai.state import cybergym_gate
from kai.state.local import LocalStateManager
from kai.state.models import ExploitRecord


@pytest.fixture(autouse=True)
def _reset_gate():
    cybergym_gate.reset()
    yield
    cybergym_gate.reset()


@pytest.fixture
def manager(tmp_path):
    return LocalStateManager(state_dir=str(tmp_path))


def _seed(manager, run_id, **fields):
    record = ExploitRecord(
        run_id=run_id,
        exploit_id=fields.get("exploit_id", "e1"),
        timestamp="2026-05-24T00:00:00+00:00",
        source_agent="verifier",
        status=fields.get("status", "soft_verified"),
        hypothesis=fields.get("hypothesis", "test hypothesis"),
        file=fields.get("file", "src-vul/x.c"),
        function=fields.get("function", "func"),
        poc_code=fields.get("poc_code", "__POC_BYTES__b64=AAA="),
    )
    manager.add_exploit(record)
    return record.exploit_id


def test_post_pipeline_critic_skips_outside_cybergym(manager, monkeypatch):
    monkeypatch.delenv("KAI_BENCHMARK", raising=False)
    _seed(manager, "r")
    cybergym_gate.init()
    from kai.main import _maybe_run_post_pipeline_critic

    # Should be a no-op — never calls the inner pipeline.
    with patch("kai.main.RecursiveAgent") as agent_cls:
        _maybe_run_post_pipeline_critic(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )
        agent_cls.assert_not_called()


def test_post_pipeline_critic_skips_when_already_called(manager, monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    cybergym_gate.init()
    cybergym_gate.mark_critic_called()
    _seed(manager, "r")
    from kai.main import _maybe_run_post_pipeline_critic

    with patch("kai.main.RecursiveAgent") as agent_cls:
        _maybe_run_post_pipeline_critic(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )
        agent_cls.assert_not_called()


def test_post_pipeline_critic_skips_without_record(manager, monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    cybergym_gate.init()
    # No exploits seeded — nothing to critique.
    from kai.main import _maybe_run_post_pipeline_critic

    with patch("kai.main.RecursiveAgent") as agent_cls:
        _maybe_run_post_pipeline_critic(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )
        agent_cls.assert_not_called()


def test_post_pipeline_critic_runs_and_marks_called(manager, monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    cybergym_gate.init()
    _seed(manager, "r", status="soft_verified")
    assert not cybergym_gate.critic_was_called()

    from kai.main import _maybe_run_post_pipeline_critic

    class _FakeResult:
        response = (
            '{"adversarial_viability": "exploitable", '
            '"critic_summary": "looks like a real bug"}'
        )

    class _FakeAgent:
        def __init__(self, cfg):
            self.cfg = cfg

        def completion(self, context):
            return _FakeResult()

    with (
        patch("kai.main.RecursiveAgent", _FakeAgent),
        patch("kai.main.inject_workspace", side_effect=lambda c, *a, **k: c),
        patch("kai.main.inject_state_manager", side_effect=lambda c, *a, **k: c),
    ):
        _maybe_run_post_pipeline_critic(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )

    # Gate flipped + status restored to prior soft_verified.
    assert cybergym_gate.critic_was_called()
    rec = list(manager.get_exploits("r"))[0]
    assert rec.status == "soft_verified"
    assert rec.adversarial_viability == "exploitable"
    assert rec.critic_summary == "looks like a real bug"


def test_post_pipeline_critic_restores_status_on_failure(manager, monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    cybergym_gate.init()
    _seed(manager, "r", status="verified")

    from kai.main import _maybe_run_post_pipeline_critic

    class _FailingAgent:
        def __init__(self, cfg):
            pass

        def completion(self, context):
            raise RuntimeError("simulated critic failure")

    with (
        patch("kai.main.RecursiveAgent", _FailingAgent),
        patch("kai.main.inject_workspace", side_effect=lambda c, *a, **k: c),
        patch("kai.main.inject_state_manager", side_effect=lambda c, *a, **k: c),
    ):
        _maybe_run_post_pipeline_critic(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )

    # Status restored to "verified" despite the failure — does NOT mark
    # critic_called since the agent did not actually run successfully.
    rec = list(manager.get_exploits("r"))[0]
    assert rec.status == "verified"
    assert not cybergym_gate.critic_was_called()
