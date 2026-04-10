"""Tests for kai.state.hooks and kai.definitions.exploit.parsers."""

from __future__ import annotations

import json
import tempfile

from ra.core.types import CodeBlock, REPLResult, RLMIteration, SpawnRecord

from kai.definitions.exploit.parsers import (
    process_analyzer_result,
    process_fixer_result,
    process_verifier_result,
)
from kai.state.hooks import make_on_iteration_hook
from kai.state.local import LocalStateManager
from kai.state.models import ExploitRecord


def _make_manager() -> LocalStateManager:
    return LocalStateManager(state_dir=tempfile.mkdtemp())


def _repl_result(
    spawn_records: list[SpawnRecord] | None = None,
    **kwargs: object,
) -> REPLResult:
    """Build a REPLResult with optional spawn records."""
    defaults: dict[str, object] = {"stdout": "", "stderr": "", "locals": {}}
    defaults.update(kwargs)
    return REPLResult(
        **defaults,  # type: ignore[arg-type]
        spawn_records=spawn_records,
    )


class TestOnIterationHook:
    """Generic hook behaviour — processors handle persistence now."""

    def test_saves_iteration_with_code(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(mgr, "r1", "exploit")
        iteration = RLMIteration(
            prompt="test",
            response="I will analyze this",
            code_blocks=[
                CodeBlock(
                    code="print('hello')",
                    result=_repl_result(stdout="hello"),
                )
            ],
            iteration_time=1.5,
        )
        hook(iteration, 1)
        updates = mgr.get_status_updates("r1")
        assert len(updates) == 1
        assert updates[0].iteration_num == 1
        assert updates[0].agent_name == "exploit"
        assert updates[0].has_spawn_calls is False
        assert updates[0].spawn_agent is None

    def test_skips_no_code_blocks(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(mgr, "r1", "exploit")
        iteration = RLMIteration(
            prompt="test",
            response="Just thinking...",
            code_blocks=[],
        )
        hook(iteration, 1)
        assert mgr.get_status_updates("r1") == []

    def test_detects_spawn_from_records(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(mgr, "r1", "exploit")
        records = [
            SpawnRecord(
                agent_name="analyzer",
                kwargs={"targets": ["Vault.sol"]},
                result="[]",
            )
        ]
        iteration = RLMIteration(
            prompt="test",
            response="launching sub-agent",
            code_blocks=[
                CodeBlock(
                    code="result = spawn_analyzer(targets=data)",
                    result=_repl_result(spawn_records=records),
                )
            ],
        )
        hook(iteration, 2)
        updates = mgr.get_status_updates("r1")
        assert len(updates) == 1
        assert updates[0].has_spawn_calls is True
        assert updates[0].spawn_agent == "analyzer"
        assert updates[0].spawn_kwargs == {"targets": ["Vault.sol"]}
        assert updates[0].spawn_result == "[]"

    def test_no_exploit_records_without_processors(self) -> None:
        """Without processors wired, hook only saves status updates."""
        mgr = _make_manager()
        hook = make_on_iteration_hook(mgr, "r1", "exploit")
        candidates = json.dumps([{"hypothesis": "h", "file": "f", "function": "fn"}])
        records = [
            SpawnRecord(
                agent_name="analyzer",
                kwargs={},
                result=candidates,
            )
        ]
        iteration = RLMIteration(
            prompt="test",
            response="analyzing",
            code_blocks=[
                CodeBlock(
                    code="spawn_analyzer()",
                    result=_repl_result(spawn_records=records),
                )
            ],
        )
        hook(iteration, 1)
        assert mgr.get_status_updates("r1")[0].spawn_agent == "analyzer"
        assert mgr.get_exploits("r1") == []


class TestAnalyzerProcessor:
    """Test process_analyzer_result enrichment."""

    def test_enriches_result_with_exploit_ids(self) -> None:
        mgr = _make_manager()
        raw = json.dumps(
            [
                {
                    "hypothesis": "reentrancy in withdraw",
                    "file": "Vault.sol",
                    "function": "withdraw",
                    "exploit_sketch": "call before update",
                },
                {
                    "hypothesis": "overflow in deposit",
                    "file": "Vault.sol",
                    "function": "deposit",
                    "exploit_sketch": "large value",
                },
            ]
        )
        enriched = process_analyzer_result(mgr, "r1", {}, raw)
        candidates = json.loads(enriched)
        assert len(candidates) == 2
        assert "exploit_id" in candidates[0]
        assert "exploit_id" in candidates[1]
        assert candidates[0]["exploit_id"] != candidates[1]["exploit_id"]
        # Records persisted
        exploits = mgr.get_exploits("r1")
        assert len(exploits) == 2
        assert exploits[0].status == "candidate"
        assert exploits[0].exploit_id == candidates[0]["exploit_id"]
        assert exploits[1].exploit_id == candidates[1]["exploit_id"]

    def test_single_dict_wrapped_in_list(self) -> None:
        mgr = _make_manager()
        raw = json.dumps({"hypothesis": "h", "file": "f", "function": "fn"})
        enriched = process_analyzer_result(mgr, "r1", {}, raw)
        candidates = json.loads(enriched)
        assert len(candidates) == 1
        assert "exploit_id" in candidates[0]

    def test_skips_non_dict_items(self) -> None:
        mgr = _make_manager()
        raw = json.dumps(["not a dict", {"hypothesis": "h"}])
        enriched = process_analyzer_result(mgr, "r1", {}, raw)
        candidates = json.loads(enriched)
        assert len(candidates) == 2
        # String item has no exploit_id
        assert "exploit_id" not in candidates[0]
        assert "exploit_id" in candidates[1]
        assert len(mgr.get_exploits("r1")) == 1

    def test_persists_precondition_fields(self) -> None:
        mgr = _make_manager()
        raw = json.dumps(
            [
                {
                    "hypothesis": "reentrancy",
                    "file": "Vault.sol",
                    "function": "withdraw",
                    "exploit_sketch": "call before update",
                    "attacker_role": "anyone",
                    "required_privileges": "none",
                    "category": "active_exploit",
                    "trusted_component_abused": "none (permissionless)",
                },
            ]
        )
        process_analyzer_result(mgr, "r1", {}, raw)
        exploits = mgr.get_exploits("r1")
        assert len(exploits) == 1
        e = exploits[0]
        assert e.attacker_role == "anyone"
        assert e.required_privileges == "none"
        assert e.category == "active_exploit"
        assert e.trusted_component_abused == "none (permissionless)"

    def test_precondition_fields_default_empty(self) -> None:
        """Candidates without precondition fields get empty defaults."""
        mgr = _make_manager()
        raw = json.dumps([{"hypothesis": "h", "file": "f", "function": "fn"}])
        process_analyzer_result(mgr, "r1", {}, raw)
        e = mgr.get_exploits("r1")[0]
        assert e.attacker_role == ""
        assert e.category == ""


class TestVerifierProcessor:
    """Test process_verifier_result with ID-based and fallback matching."""

    def test_updates_by_exploit_id(self) -> None:
        mgr = _make_manager()
        mgr.add_exploit(
            ExploitRecord(
                run_id="r1",
                exploit_id="e1",
                timestamp="t",
                source_agent="analyzer",
                status="candidate",
                hypothesis="reentrancy",
                file="Vault.sol",
                function="withdraw",
            )
        )
        raw = json.dumps(
            {
                "confirmed": True,
                "poc_code": "attack()",
                "test_output": "EXPLOITED",
            }
        )
        result = process_verifier_result(
            mgr,
            "r1",
            {"exploit_id": "e1"},
            raw,
        )
        assert result == raw
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "verified"
        assert exploits[0].confirmed is True
        assert exploits[0].poc_code == "attack()"

    def test_fallback_string_match(self) -> None:
        mgr = _make_manager()
        mgr.add_exploit(
            ExploitRecord(
                run_id="r1",
                exploit_id="e1",
                timestamp="t",
                source_agent="analyzer",
                status="candidate",
                hypothesis="reentrancy",
                file="Vault.sol",
                function="withdraw",
            )
        )
        raw = json.dumps(
            {
                "hypothesis": "reentrancy",
                "file": "Vault.sol",
                "function": "withdraw",
                "confirmed": True,
                "poc_code": "attack()",
                "test_output": "EXPLOITED",
            }
        )
        # No exploit_id in kwargs — falls back to string match
        result = process_verifier_result(mgr, "r1", {}, raw)
        assert result == raw
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "verified"

    def test_rejected_when_not_confirmed(self) -> None:
        """confirmed=False should set status to 'rejected'."""
        mgr = _make_manager()
        mgr.add_exploit(
            ExploitRecord(
                run_id="r1",
                exploit_id="e1",
                timestamp="t",
                source_agent="analyzer",
                status="candidate",
                hypothesis="maybe vuln",
                file="Token.sol",
                function="transfer",
            )
        )
        raw = json.dumps(
            {
                "confirmed": False,
                "poc_code": "test()",
                "test_output": "NOT EXPLOITABLE",
            }
        )
        process_verifier_result(mgr, "r1", {"exploit_id": "e1"}, raw)
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "rejected"
        assert exploits[0].confirmed is False

    def test_rejected_default_when_confirmed_missing(self) -> None:
        """Missing 'confirmed' key defaults to False → rejected."""
        mgr = _make_manager()
        mgr.add_exploit(
            ExploitRecord(
                run_id="r1",
                exploit_id="e1",
                timestamp="t",
                source_agent="analyzer",
                status="candidate",
                hypothesis="h",
                file="f",
                function="fn",
            )
        )
        raw = json.dumps({"poc_code": "x", "test_output": "y"})
        process_verifier_result(mgr, "r1", {"exploit_id": "e1"}, raw)
        assert mgr.get_exploits("r1")[0].status == "rejected"

    def test_no_matching_exploit_returns_raw(self) -> None:
        mgr = _make_manager()
        raw = json.dumps(
            {
                "hypothesis": "nonexistent",
                "file": "Ghost.sol",
                "function": "vanish",
                "confirmed": True,
            }
        )
        result = process_verifier_result(mgr, "r1", {}, raw)
        assert result == raw
        assert mgr.get_exploits("r1") == []


class TestFixerProcessor:
    """Test process_fixer_result with ID-based and fallback matching."""

    def test_updates_by_exploit_id_and_creates_fix(self) -> None:
        mgr = _make_manager()
        mgr.add_exploit(
            ExploitRecord(
                run_id="r1",
                exploit_id="e1",
                timestamp="t",
                source_agent="verifier",
                status="verified",
                hypothesis="reentrancy",
                file="Vault.sol",
                function="withdraw",
                confirmed=True,
            )
        )
        raw = json.dumps(
            {
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "patch": "--- a/Vault.sol\n+++ b/Vault.sol",
                "test_results": "ALL PASS",
                "fix_succeeded": True,
            }
        )
        result = process_fixer_result(
            mgr,
            "r1",
            {"exploit_id": "e1"},
            raw,
        )
        assert result == raw
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "verified_and_fixed"
        assert exploits[0].severity == "Critical"
        fixes = mgr.get_fixes("r1")
        assert len(fixes) == 1
        assert fixes[0].exploit_id == "e1"
        assert fixes[0].severity == "Critical"

    def test_fallback_string_match(self) -> None:
        mgr = _make_manager()
        mgr.add_exploit(
            ExploitRecord(
                run_id="r1",
                exploit_id="e1",
                timestamp="t",
                source_agent="verifier",
                status="verified",
                hypothesis="reentrancy",
                file="Vault.sol",
                function="withdraw",
                confirmed=True,
            )
        )
        raw = json.dumps(
            {
                "hypothesis": "reentrancy",
                "file": "Vault.sol",
                "function": "withdraw",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "patch": "...",
                "test_results": "ALL PASS",
                "fix_succeeded": True,
            }
        )
        result = process_fixer_result(mgr, "r1", {}, raw)
        assert result == raw
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "verified_and_fixed"
        fixes = mgr.get_fixes("r1")
        assert len(fixes) == 1
        assert fixes[0].exploit_id == "e1"

    def test_no_matching_exploit_returns_raw(self) -> None:
        mgr = _make_manager()
        raw = json.dumps(
            {
                "hypothesis": "nonexistent",
                "file": "Ghost.sol",
                "function": "vanish",
            }
        )
        result = process_fixer_result(mgr, "r1", {}, raw)
        assert result == raw
        assert mgr.get_fixes("r1") == []
