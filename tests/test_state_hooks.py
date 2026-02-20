"""Tests for kai.state.hooks callback dispatch logic."""

from __future__ import annotations

import json
import tempfile

from ra.core.types import CodeBlock, REPLResult, RLMIteration, SpawnRecord

from kai.definitions.exploit.parsers import SPAWN_PARSERS
from kai.state.hooks import make_on_iteration_hook
from kai.state.local import LocalStateManager


def _make_manager() -> LocalStateManager:
    return LocalStateManager(state_dir=tempfile.mkdtemp())


def _repl_result(
    spawn_records: list[SpawnRecord] | None = None,
    **kwargs: object,
) -> REPLResult:
    """Build a REPLResult with optional spawn records."""
    defaults = {"stdout": "", "stderr": "", "locals": {}}
    defaults.update(kwargs)
    return REPLResult(
        **defaults,  # type: ignore[arg-type]
        spawn_records=spawn_records,
    )


class TestOnIterationHook:
    """Generic hook behaviour — no parsers needed."""

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

    def test_no_dispatch_without_parsers(self) -> None:
        """Without spawn_parsers, records are saved but not parsed."""
        mgr = _make_manager()
        hook = make_on_iteration_hook(mgr, "r1", "exploit")
        candidates = json.dumps([{"hypothesis": "h", "file": "f", "function": "fn"}])
        records = [
            SpawnRecord(agent_name="analyzer", kwargs={}, result=candidates)
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
        # Status update recorded with spawn data
        assert mgr.get_status_updates("r1")[0].spawn_agent == "analyzer"
        # But no exploit records created (no parsers)
        assert mgr.get_exploits("r1") == []


class TestSpawnRecordDispatch:
    """Test that on_iteration dispatches exploit-pipeline parsers."""

    def test_analyzer_creates_candidates(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(
            mgr, "r1", "exploit", spawn_parsers=SPAWN_PARSERS,
        )
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
        records = [
            SpawnRecord(
                agent_name="analyzer",
                kwargs={"targets": ["Vault.sol"]},
                result=candidates,
            )
        ]
        iteration = RLMIteration(
            prompt="test",
            response="analyzing",
            code_blocks=[
                CodeBlock(
                    code="spawn_analyzer(targets=['Vault.sol'])",
                    result=_repl_result(spawn_records=records),
                )
            ],
        )
        hook(iteration, 1)
        exploits = mgr.get_exploits("r1")
        assert len(exploits) == 2
        assert exploits[0].status == "candidate"
        assert exploits[0].hypothesis == "reentrancy in withdraw"
        assert exploits[1].hypothesis == "overflow in deposit"
        updates = mgr.get_status_updates("r1")
        assert len(updates) == 1
        assert updates[0].spawn_agent == "analyzer"
        assert updates[0].spawn_kwargs == {"targets": ["Vault.sol"]}
        assert updates[0].spawn_result == candidates

    def test_verifier_updates_exploit(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(
            mgr, "r1", "exploit", spawn_parsers=SPAWN_PARSERS,
        )
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
        records = [
            SpawnRecord(
                agent_name="verifier",
                kwargs={},
                result=verdict,
            )
        ]
        iteration = RLMIteration(
            prompt="test",
            response="verifying",
            code_blocks=[
                CodeBlock(
                    code="spawn_verifier()",
                    result=_repl_result(spawn_records=records),
                )
            ],
        )
        hook(iteration, 1)
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "verified"
        assert exploits[0].confirmed is True
        assert exploits[0].poc_code == "attack()"

    def test_fixer_updates_exploit_and_adds_fix(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(
            mgr, "r1", "exploit", spawn_parsers=SPAWN_PARSERS,
        )
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
        records = [
            SpawnRecord(
                agent_name="fixer",
                kwargs={},
                result=fix_result,
            )
        ]
        iteration = RLMIteration(
            prompt="test",
            response="fixing",
            code_blocks=[
                CodeBlock(
                    code="spawn_fixer()",
                    result=_repl_result(spawn_records=records),
                )
            ],
        )
        hook(iteration, 1)
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "verified_and_fixed"
        assert exploits[0].severity == "critical"
        fixes = mgr.get_fixes("r1")
        assert len(fixes) == 1
        assert fixes[0].exploit_id == "e1"
        assert fixes[0].severity == "critical"

    def test_unknown_agent_ignored(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(
            mgr, "r1", "exploit", spawn_parsers=SPAWN_PARSERS,
        )
        records = [
            SpawnRecord(
                agent_name="unknown_agent",
                kwargs={},
                result="some result",
            )
        ]
        iteration = RLMIteration(
            prompt="test",
            response="spawning",
            code_blocks=[
                CodeBlock(
                    code="spawn_unknown_agent()",
                    result=_repl_result(spawn_records=records),
                )
            ],
        )
        hook(iteration, 1)
        assert mgr.get_exploits("r1") == []

    def test_malformed_json_ignored(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(
            mgr, "r1", "exploit", spawn_parsers=SPAWN_PARSERS,
        )
        records = [
            SpawnRecord(
                agent_name="analyzer",
                kwargs={},
                result="not valid json {{{",
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
        assert mgr.get_exploits("r1") == []

    def test_verifier_no_matching_exploit(self) -> None:
        mgr = _make_manager()
        hook = make_on_iteration_hook(
            mgr, "r1", "exploit", spawn_parsers=SPAWN_PARSERS,
        )
        verdict = json.dumps(
            {
                "hypothesis": "nonexistent",
                "file": "Ghost.sol",
                "function": "vanish",
                "confirmed": True,
            }
        )
        records = [
            SpawnRecord(
                agent_name="verifier",
                kwargs={},
                result=verdict,
            )
        ]
        iteration = RLMIteration(
            prompt="test",
            response="verifying",
            code_blocks=[
                CodeBlock(
                    code="spawn_verifier()",
                    result=_repl_result(spawn_records=records),
                )
            ],
        )
        hook(iteration, 1)
        assert mgr.get_exploits("r1") == []
