"""Tests for cybergym soft-verified status transitions.

The in-pipeline verifier sub-agent cannot reach cybergym's strict
harness server (it lives on the user's laptop, not in the Railway
pipeline). When the verifier emits ``confirmed=false`` because it
couldn't actually run the harness, we still want critic / fixer /
chain_assembler to fire on the candidate so the model can polish
the PoC. The fix flips status to ``soft_verified`` instead of
``rejected`` for cybergym; downstream guards accept the new marker.
"""

from __future__ import annotations

import json

import pytest

from kai.definitions.exploit.parsers import process_verifier_result
from kai.definitions.exploit.spawn_hooks import _check_exploit_status
from kai.state.local import LocalStateManager
from kai.state.models import ExploitRecord


@pytest.fixture
def manager(tmp_path):
    return LocalStateManager(state_dir=str(tmp_path))


def _seed(manager: LocalStateManager, run_id: str, **fields) -> str:
    record = ExploitRecord(
        run_id=run_id,
        exploit_id=fields.get("exploit_id", "e1"),
        timestamp="2026-05-24T00:00:00+00:00",
        source_agent="analyzer",
        status=fields.get("status", "candidate"),
        hypothesis=fields.get("hypothesis", "test hypothesis"),
        file=fields.get("file", "src-vul/x.c"),
        function=fields.get("function", "func"),
    )
    manager.add_exploit(record)
    return record.exploit_id


def test_cybergym_no_poc_still_rejects(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    exploit_id = _seed(manager, "r")
    verdict = {
        "confirmed": False,
        "hypothesis": "test hypothesis",
        "file": "src-vul/x.c",
        "function": "func",
        "poc_code": "",
    }
    process_verifier_result(
        manager,
        "r",
        {"exploit_id": exploit_id},
        json.dumps(verdict),
    )
    records = list(manager.get_exploits("r"))
    assert records[0].status == "rejected"


def test_cybergym_with_poc_flips_to_soft_verified(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    exploit_id = _seed(manager, "r")
    verdict = {
        "confirmed": False,
        "hypothesis": "test hypothesis",
        "file": "src-vul/x.c",
        "function": "func",
        "poc_code": "__POC_BYTES__b64=AAA=",
    }
    process_verifier_result(
        manager,
        "r",
        {"exploit_id": exploit_id},
        json.dumps(verdict),
    )
    records = list(manager.get_exploits("r"))
    assert records[0].status == "soft_verified"


def test_non_cybergym_still_rejects_with_poc(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("KAI_BENCHMARK", raising=False)
    exploit_id = _seed(manager, "r")
    verdict = {
        "confirmed": False,
        "hypothesis": "test hypothesis",
        "file": "src-vul/x.c",
        "function": "func",
        "poc_code": "__POC_BYTES__b64=AAA=",
    }
    process_verifier_result(
        manager,
        "r",
        {"exploit_id": exploit_id},
        json.dumps(verdict),
    )
    records = list(manager.get_exploits("r"))
    assert records[0].status == "rejected"


def test_cybergym_confirmed_true_uses_verified(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    exploit_id = _seed(manager, "r")
    verdict = {
        "confirmed": True,
        "hypothesis": "test hypothesis",
        "file": "src-vul/x.c",
        "function": "func",
        "poc_code": "__POC_BYTES__b64=AAA=",
    }
    process_verifier_result(
        manager,
        "r",
        {"exploit_id": exploit_id},
        json.dumps(verdict),
    )
    records = list(manager.get_exploits("r"))
    assert records[0].status == "verified"


def test_check_exploit_status_accepts_soft_verified_under_cybergym(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    exploit_id = _seed(manager, "r", status="soft_verified")
    result = _check_exploit_status(
        {"exploit_id": exploit_id},
        manager,
        "r",
        ("verified",),
        "critic",
    )
    assert result is None


def test_check_exploit_status_rejects_soft_verified_outside_cybergym(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("KAI_BENCHMARK", raising=False)
    exploit_id = _seed(manager, "r", status="soft_verified")
    result = _check_exploit_status(
        {"exploit_id": exploit_id},
        manager,
        "r",
        ("verified",),
        "critic",
    )
    assert result is not None
    assert "soft_verified" in result


def test_check_exploit_status_blocks_rejected_under_cybergym(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cybergym carve-out only opens for soft_verified, not rejected."""
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    exploit_id = _seed(manager, "r", status="rejected")
    result = _check_exploit_status(
        {"exploit_id": exploit_id},
        manager,
        "r",
        ("verified",),
        "critic",
    )
    assert result is not None
    assert "rejected" in result
