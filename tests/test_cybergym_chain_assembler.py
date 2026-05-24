"""Tests for chain_assembler soft_verified acceptance (cybergym path)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from kai.state.local import LocalStateManager
from kai.state.models import ExploitRecord


@pytest.fixture
def manager(tmp_path):
    return LocalStateManager(state_dir=str(tmp_path))


def _seed(manager, run_id, status):
    record = ExploitRecord(
        run_id=run_id,
        exploit_id="e1",
        timestamp="2026-05-24T00:00:00+00:00",
        source_agent="verifier",
        status=status,
        hypothesis="h",
        file="src-vul/x.c",
        function="func",
        poc_code="__POC_BYTES__b64=AAA=",
    )
    manager.add_exploit(record)


def test_chain_assembler_skips_without_records(manager, monkeypatch):
    """No verified/soft records → early return, no agent built."""
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    from kai.main import _run_chain_assembler

    with (
        patch("kai.main.RecursiveAgent") as agent_cls,
        patch("kai.main.TreeSitterBuilder") as tsb_cls,
    ):
        result = _run_chain_assembler(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )
        assert result is None
        agent_cls.assert_not_called()
        tsb_cls.assert_not_called()


def test_chain_assembler_accepts_soft_verified_under_cybergym(manager, monkeypatch):
    """Regression: cybergym soft_verified records must trigger the chain
    assembler. Prior to this fix the outer guard kicked off the thread
    but the inner filter dropped soft_verified records, silently
    skipping the stage on every cybergym run.
    """
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    _seed(manager, "r", status="soft_verified")

    from kai.main import _run_chain_assembler

    class _Result:
        response = "[]"

    class _FakeAgent:
        def __init__(self, cfg):
            self.cfg = cfg

        def completion(self, context):
            # Verify the soft_verified record made it into context.
            assert len(context["verified_exploits"]) == 1
            assert context["verified_exploits"][0]["status"] == "soft_verified"
            return _Result()

    class _FakeGraph:
        pass

    class _FakeTSB:
        def build(self, path):
            return _FakeGraph()

    class _FakeRecipe:
        master_path = "/tmp/dummy"

    with (
        patch("kai.main.RecursiveAgent", _FakeAgent),
        patch("kai.main.TreeSitterBuilder", _FakeTSB),
        patch("kai.main.make_graph_tools", return_value={}),
        patch("kai.main.inject_workspace", side_effect=lambda c, *a, **k: c),
        patch("kai.main.inject_state_manager", side_effect=lambda c, *a, **k: c),
    ):
        result = _run_chain_assembler(
            recipe=_FakeRecipe(),  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )
    assert result == "[]"


def test_chain_assembler_skips_soft_verified_outside_cybergym(manager, monkeypatch):
    """soft_verified records OUTSIDE cybergym are NOT a chain input."""
    monkeypatch.delenv("KAI_BENCHMARK", raising=False)
    _seed(manager, "r", status="soft_verified")

    from kai.main import _run_chain_assembler

    with patch("kai.main.RecursiveAgent") as agent_cls:
        result = _run_chain_assembler(
            recipe=None,  # type: ignore[arg-type]
            state_manager=manager,
            run_id="r",
        )
    assert result is None
    agent_cls.assert_not_called()
