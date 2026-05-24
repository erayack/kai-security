"""Tests for the post-pipeline fixer stage."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from kai.state.local import LocalStateManager
from kai.state.models import ExploitRecord


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


def test_post_pipeline_fixer_skips_outside_cybergym(manager, monkeypatch):
    monkeypatch.delenv("KAI_BENCHMARK", raising=False)
    _seed(manager, "r")
    from kai.main import _maybe_run_post_pipeline_fixer

    with patch("kai.main.RecursiveAgent") as agent_cls:
        _maybe_run_post_pipeline_fixer(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )
        agent_cls.assert_not_called()


def test_post_pipeline_fixer_skips_without_record(manager, monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    # No exploits seeded.
    from kai.main import _maybe_run_post_pipeline_fixer

    with patch("kai.main.RecursiveAgent") as agent_cls:
        _maybe_run_post_pipeline_fixer(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )
        agent_cls.assert_not_called()


def test_post_pipeline_fixer_skips_when_attempt_exists(manager, monkeypatch):
    """If a fixer attempt is already recorded, don't run again."""
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    exploit_id = _seed(manager, "r")
    from kai.state.models import FixAttemptRecord

    manager.add_fix_attempt(
        FixAttemptRecord(
            run_id="r",
            exploit_id=exploit_id,
            attempt_num=1,
            timestamp="2026-05-24T00:00:01+00:00",
            strategy="prior attempt",
            patch="",
            failure_reason="prior",
            succeeded=False,
        )
    )

    from kai.main import _maybe_run_post_pipeline_fixer

    with patch("kai.main.RecursiveAgent") as agent_cls:
        _maybe_run_post_pipeline_fixer(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )
        agent_cls.assert_not_called()


def test_post_pipeline_fixer_runs_and_writes_attempt(manager, monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    _seed(manager, "r", status="soft_verified")

    class _FakeResult:
        response = (
            '{"hypothesis": "test hypothesis", '
            '"file": "src-vul/x.c", "function": "func", '
            '"strategy": "patch the regex check", '
            '"patch": "--- a/file\\n+++ b/file\\n@@ -1 +1 @@\\n-bad\\n+good", '
            '"fix_succeeded": false, "failure_reason": "build broke"}'
        )

    class _FakeAgent:
        def __init__(self, cfg):
            self.cfg = cfg

        def completion(self, context):
            return _FakeResult()

    from kai.main import _maybe_run_post_pipeline_fixer

    with (
        patch("kai.main.RecursiveAgent", _FakeAgent),
        patch("kai.main.inject_workspace", side_effect=lambda c, *a, **k: c),
        patch("kai.main.inject_state_manager", side_effect=lambda c, *a, **k: c),
    ):
        _maybe_run_post_pipeline_fixer(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )

    attempts = manager.get_fix_attempts("r", "e1")
    assert len(attempts) == 1
    assert attempts[0].strategy == "patch the regex check"
    assert attempts[0].succeeded is False
    # Status stays soft_verified since fix did not succeed.
    rec = list(manager.get_exploits("r"))[0]
    assert rec.status == "soft_verified"


def test_post_pipeline_fixer_success_writes_fix_record(manager, monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    _seed(manager, "r", status="soft_verified")

    class _FakeResult:
        response = (
            '{"hypothesis": "test hypothesis", '
            '"file": "src-vul/x.c", "function": "func", '
            '"strategy": "patch the regex check", '
            '"patch": "diff", '
            '"test_results": "all green", '
            '"fix_succeeded": true, '
            '"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'
        )

    class _FakeAgent:
        def __init__(self, cfg):
            self.cfg = cfg

        def completion(self, context):
            return _FakeResult()

    from kai.main import _maybe_run_post_pipeline_fixer

    with (
        patch("kai.main.RecursiveAgent", _FakeAgent),
        patch("kai.main.inject_workspace", side_effect=lambda c, *a, **k: c),
        patch("kai.main.inject_state_manager", side_effect=lambda c, *a, **k: c),
    ):
        _maybe_run_post_pipeline_fixer(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )

    attempts = manager.get_fix_attempts("r", "e1")
    assert len(attempts) == 1 and attempts[0].succeeded is True
    fixes = manager.get_fixes("r")
    assert len(fixes) == 1
    # Status flipped to verified_and_fixed by the parser.
    rec = list(manager.get_exploits("r"))[0]
    assert rec.status == "verified_and_fixed"


def test_post_pipeline_fixer_restores_status_on_failure(manager, monkeypatch):
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    _seed(manager, "r", status="soft_verified")

    class _FailingAgent:
        def __init__(self, cfg):
            pass

        def completion(self, context):
            raise RuntimeError("simulated fixer crash")

    from kai.main import _maybe_run_post_pipeline_fixer

    with (
        patch("kai.main.RecursiveAgent", _FailingAgent),
        patch("kai.main.inject_workspace", side_effect=lambda c, *a, **k: c),
        patch("kai.main.inject_state_manager", side_effect=lambda c, *a, **k: c),
    ):
        _maybe_run_post_pipeline_fixer(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )

    # No attempt recorded since the agent crashed before producing output.
    assert manager.get_fix_attempts("r", "e1") == []
    rec = list(manager.get_exploits("r"))[0]
    assert rec.status == "soft_verified"
