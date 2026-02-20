"""Tests for kai.state.models data model serialization."""

from __future__ import annotations

import json

from kai.state.models import ExploitRecord, FixRecord, RunRecord, StatusUpdate


class TestRunRecord:
    def test_round_trip(self) -> None:
        record = RunRecord(
            run_id="abc-123",
            repo_path="/tmp/repo",
            started_at="2025-01-01T00:00:00Z",
            status="running",
            root_model="gpt-4o",
            config_snapshot={"key": "value"},
        )
        d = record.to_dict()
        restored = RunRecord.from_dict(d)
        assert restored == record

    def test_defaults(self) -> None:
        record = RunRecord(
            run_id="x",
            repo_path="/r",
            started_at="t",
            status="running",
            root_model="m",
        )
        assert record.finished_at is None
        assert record.config_snapshot == {}
        assert record.usage_summary is None
        assert record.execution_time is None
        assert record.total_exploits == 0
        assert record.total_fixes == 0

    def test_from_dict_partial(self) -> None:
        d = {
            "run_id": "x",
            "repo_path": "/r",
            "started_at": "t",
        }
        record = RunRecord.from_dict(d)
        assert record.status == "running"
        assert record.root_model == "unknown"

    def test_json_safe(self) -> None:
        record = RunRecord(
            run_id="x",
            repo_path="/r",
            started_at="t",
            status="completed",
            root_model="m",
            usage_summary={"tokens": 100},
        )
        serialized = json.dumps(record.to_dict())
        restored = RunRecord.from_dict(json.loads(serialized))
        assert restored == record


class TestStatusUpdate:
    def test_round_trip(self) -> None:
        update = StatusUpdate(
            run_id="r1",
            iteration_num=3,
            timestamp="2025-01-01T00:00:00Z",
            agent_name="exploit",
            has_spawn_calls=True,
            iteration_time=1.5,
            spawn_agent="analyzer",
            spawn_kwargs={"targets": ["file.sol"]},
        )
        d = update.to_dict()
        restored = StatusUpdate.from_dict(d)
        assert restored == update

    def test_defaults(self) -> None:
        update = StatusUpdate(
            run_id="r1",
            iteration_num=1,
            timestamp="t",
            agent_name="a",
        )
        assert update.has_spawn_calls is False
        assert update.iteration_time is None
        assert update.spawn_agent is None
        assert update.spawn_kwargs is None


class TestExploitRecord:
    def test_round_trip(self) -> None:
        exploit = ExploitRecord(
            run_id="r1",
            exploit_id="e1",
            timestamp="t",
            source_agent="analyzer",
            status="candidate",
            hypothesis="reentrancy in withdraw",
            file="src/Vault.sol",
            function="withdraw",
            exploit_sketch="call before state update",
        )
        d = exploit.to_dict()
        restored = ExploitRecord.from_dict(d)
        assert restored == exploit

    def test_progressive_enrichment_fields(self) -> None:
        exploit = ExploitRecord(
            run_id="r1",
            exploit_id="e1",
            timestamp="t",
            source_agent="verifier",
            status="verified",
            hypothesis="h",
            file="f",
            function="fn",
            confirmed=True,
            poc_code="exploit()",
            test_output="PASS",
        )
        d = exploit.to_dict()
        assert d["confirmed"] is True
        assert d["poc_code"] == "exploit()"

    def test_defaults(self) -> None:
        exploit = ExploitRecord(
            run_id="r",
            exploit_id="e",
            timestamp="t",
            source_agent="analyzer",
            status="candidate",
            hypothesis="h",
            file="f",
            function="fn",
        )
        assert exploit.exploit_sketch == ""
        assert exploit.confirmed is None
        assert exploit.poc_code is None
        assert exploit.severity is None
        assert exploit.patch is None


class TestFixRecord:
    def test_round_trip(self) -> None:
        fix = FixRecord(
            run_id="r1",
            fix_id="f1",
            exploit_id="e1",
            timestamp="t",
            hypothesis="h",
            file="f",
            function="fn",
            severity="high",
            patch="--- a/f\n+++ b/f\n@@ ...",
            test_results="PASS",
            applied=True,
        )
        d = fix.to_dict()
        restored = FixRecord.from_dict(d)
        assert restored == fix

    def test_default_applied(self) -> None:
        fix = FixRecord(
            run_id="r",
            fix_id="f",
            exploit_id="e",
            timestamp="t",
            hypothesis="h",
            file="f",
            function="fn",
            severity="low",
            patch="p",
            test_results="ok",
        )
        assert fix.applied is False

    def test_json_safe(self) -> None:
        fix = FixRecord(
            run_id="r",
            fix_id="f",
            exploit_id="e",
            timestamp="t",
            hypothesis="h",
            file="f",
            function="fn",
            severity="critical",
            patch="diff",
            test_results="ok",
            applied=True,
        )
        serialized = json.dumps(fix.to_dict())
        restored = FixRecord.from_dict(json.loads(serialized))
        assert restored == fix
