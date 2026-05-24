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


def test_critic_gate_blocks_final_answer_when_no_critic(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The on_iteration hook MUST reject FINAL_VAR when a
    verified/soft_verified record exists and spawn_critic was never
    called.

    Regression for R23's failure mode: model emitted FINAL_VAR(verified_exploits)
    after 7 ignored critic-reminders. Without this structural gate the
    pipeline would happily exit with no critic ever invoked.
    """
    from kai.state import cybergym_gate
    from kai.state.hooks import make_on_iteration_hook
    from ra.core.types import RLMIteration

    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    cybergym_gate.reset()
    cybergym_gate.init()
    # Seed a soft_verified record so the gate has work to do.
    _seed(manager, "r", status="soft_verified")

    hook = make_on_iteration_hook(manager, run_id="r", agent_name="exploit")
    iteration = RLMIteration(
        prompt="root",
        response="FINAL_VAR(verified_exploits)",
        code_blocks=[],
        final_answer="[{'hypothesis': '...'}]",
    )
    hook(iteration, 14)

    # Structural gate fires: final_answer is cleared so the iteration
    # loop continues.
    assert iteration.final_answer is None
    # And the model receives a forcing notice in its next prompt.
    assert iteration.truncation_notice is not None
    assert "FINAL_VAR rejected" in iteration.truncation_notice
    assert "spawn_critic(exploit_index=0)" in iteration.truncation_notice


def test_critic_gate_allows_final_answer_after_critic_called(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once spawn_critic has been called, the gate becomes a no-op."""
    from kai.state import cybergym_gate
    from kai.state.hooks import make_on_iteration_hook
    from ra.core.types import RLMIteration

    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    cybergym_gate.reset()
    cybergym_gate.init()
    cybergym_gate.mark_critic_called()
    _seed(manager, "r", status="soft_verified")

    hook = make_on_iteration_hook(manager, run_id="r", agent_name="exploit")
    iteration = RLMIteration(
        prompt="root",
        response="FINAL_VAR(verified_exploits)",
        code_blocks=[],
        final_answer="[{'hypothesis': '...'}]",
    )
    hook(iteration, 20)
    assert iteration.final_answer == "[{'hypothesis': '...'}]"


def test_critic_gate_no_op_outside_cybergym(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The structural gate fires only under KAI_BENCHMARK=cybergym."""
    from kai.state import cybergym_gate
    from kai.state.hooks import make_on_iteration_hook
    from ra.core.types import RLMIteration

    monkeypatch.delenv("KAI_BENCHMARK", raising=False)
    cybergym_gate.reset()
    _seed(manager, "r", status="verified")

    hook = make_on_iteration_hook(manager, run_id="r", agent_name="exploit")
    iteration = RLMIteration(
        prompt="root",
        response="FINAL_VAR(verified_exploits)",
        code_blocks=[],
        final_answer="[{'hypothesis': '...'}]",
    )
    hook(iteration, 14)
    assert iteration.final_answer == "[{'hypothesis': '...'}]"


def test_critic_gate_no_op_without_verified_record(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gate only fires when there's something to critique."""
    from kai.state import cybergym_gate
    from kai.state.hooks import make_on_iteration_hook
    from ra.core.types import RLMIteration

    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    cybergym_gate.reset()
    cybergym_gate.init()
    # Only candidate / rejected records — nothing verified yet.
    _seed(manager, "r", status="candidate")

    hook = make_on_iteration_hook(manager, run_id="r", agent_name="exploit")
    iteration = RLMIteration(
        prompt="root",
        response="FINAL_VAR(verified_exploits)",
        code_blocks=[],
        final_answer="[]",
    )
    hook(iteration, 14)
    assert iteration.final_answer == "[]"


def test_cybergym_kwargs_poc_fallback(
    manager: LocalStateManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When verifier returns empty poc_code but root submitted bytes, soft_verify.

    Regression for R22: the verifier sub-agent often emits poc_code=""
    in its final verdict even when the root agent passed real bytes
    via spawn_verifier kwargs. The earlier soft_verified check only
    looked at the verdict, so every R22 record stayed in 'rejected'
    despite valid root-submitted PoCs.
    """
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
        {"exploit_id": exploit_id, "poc_code": "__POC_BYTES__b64=ABC="},
        json.dumps(verdict),
    )
    records = list(manager.get_exploits("r"))
    assert records[0].status == "soft_verified"
    # Bytes were preserved from kwargs.
    assert records[0].poc_code == "__POC_BYTES__b64=ABC="
