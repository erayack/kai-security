"""Tests for kai.state.hooks callback dispatch logic."""

from __future__ import annotations

import json
import tempfile

from ra.core.types import CodeBlock, REPLResult, RLMIteration

from kai.state.hooks import make_on_iteration_hook, make_on_spawn_result_hook
from kai.state.local import LocalStateManager


def _make_manager() -> LocalStateManager:
    return LocalStateManager(state_dir=tempfile.mkdtemp())


class TestOnIterationHook:
    def test_saves_iteration_with_code(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(mgr, "r1", "exploit")
        iteration = RLMIteration(
            prompt="test",
            response="I will analyze this",
            code_blocks=[
                CodeBlock(
                    code="print('hello')",
                    result=REPLResult(
                        stdout="hello",
                        stderr="",
                        locals={},
                    ),
                )
            ],
            iteration_time=1.5,
        )
        hook(iteration, 1)
        updates = mgr.get_status_updates("r1")
        assert len(updates) == 1
        assert updates[0].iteration_num == 1
        assert updates[0].agent_name == "exploit"
        assert updates[0].response_text == "I will analyze this"
        assert updates[0].has_spawn_calls is False

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

    def test_detects_spawn_calls(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(mgr, "r1", "exploit")
        iteration = RLMIteration(
            prompt="test",
            response="launching sub-agent",
            code_blocks=[
                CodeBlock(
                    code="result = spawn_analyzer(targets=data)",
                    result=REPLResult(
                        stdout="",
                        stderr="",
                        locals={},
                    ),
                )
            ],
        )
        hook(iteration, 2)
        updates = mgr.get_status_updates("r1")
        assert len(updates) == 1
        assert updates[0].has_spawn_calls is True


class TestOnSpawnResultHook:
    def test_analyzer_creates_candidates(self) -> None:
        mgr = _make_manager()
        hook = make_on_spawn_result_hook(mgr, "r1")
        candidates = json.dumps(
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
        hook("analyzer", "{}", candidates)
        exploits = mgr.get_exploits("r1")
        assert len(exploits) == 2
        assert exploits[0].status == "candidate"
        assert exploits[0].hypothesis == "reentrancy in withdraw"
        assert exploits[1].hypothesis == "overflow in deposit"

    def test_verifier_updates_exploit(self) -> None:
        mgr = _make_manager()
        hook = make_on_spawn_result_hook(mgr, "r1")
        # First add a candidate
        from kai.state.models import ExploitRecord

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
        # Now verify it
        verdict = json.dumps(
            {
                "hypothesis": "reentrancy",
                "file": "Vault.sol",
                "function": "withdraw",
                "confirmed": True,
                "poc_code": "attack()",
                "test_output": "EXPLOITED",
            }
        )
        hook("verifier", "{}", verdict)
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "verified"
        assert exploits[0].confirmed is True
        assert exploits[0].poc_code == "attack()"

    def test_fixer_updates_exploit_and_adds_fix(self) -> None:
        mgr = _make_manager()
        hook = make_on_spawn_result_hook(mgr, "r1")
        from kai.state.models import ExploitRecord

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
        fix_result = json.dumps(
            {
                "hypothesis": "reentrancy",
                "file": "Vault.sol",
                "function": "withdraw",
                "severity": "critical",
                "patch": "--- a/Vault.sol\n+++ b/Vault.sol",
                "test_results": "ALL PASS",
            }
        )
        hook("fixer", "{}", fix_result)
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "verified_and_fixed"
        assert exploits[0].severity == "critical"
        fixes = mgr.get_fixes("r1")
        assert len(fixes) == 1
        assert fixes[0].exploit_id == "e1"
        assert fixes[0].severity == "critical"

    def test_unknown_agent_ignored(self) -> None:
        mgr = _make_manager()
        hook = make_on_spawn_result_hook(mgr, "r1")
        # Should not raise
        hook("unknown_agent", "{}", "some result")
        assert mgr.get_exploits("r1") == []

    def test_malformed_json_ignored(self) -> None:
        mgr = _make_manager()
        hook = make_on_spawn_result_hook(mgr, "r1")
        # Should not raise
        hook("analyzer", "{}", "not valid json {{{")
        assert mgr.get_exploits("r1") == []

    def test_verifier_no_matching_exploit(self) -> None:
        mgr = _make_manager()
        hook = make_on_spawn_result_hook(mgr, "r1")
        verdict = json.dumps(
            {
                "hypothesis": "nonexistent",
                "file": "Ghost.sol",
                "function": "vanish",
                "confirmed": True,
            }
        )
        # Should not raise
        hook("verifier", "{}", verdict)
        assert mgr.get_exploits("r1") == []
