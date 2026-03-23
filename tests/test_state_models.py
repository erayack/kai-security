"""Tests for kai.state.models data model serialization."""

from __future__ import annotations

import json

from kai.state.models import (
    ChainRecord,
    ExploitRecord,
    FixRecord,
    RunRecord,
    StatusUpdate,
    ThreatContext,
)


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
        assert exploit.attacker_role == ""
        assert exploit.required_privileges == ""
        assert exploit.category == ""
        assert exploit.trusted_component_abused == ""
        assert exploit.confirmed is None
        assert exploit.poc_code is None
        assert exploit.severity is None
        assert exploit.patch is None
        assert exploit.cvss_vector is None
        assert exploit.cvss_score is None
        assert exploit.cvss_justification is None
        assert exploit.chain_id is None

    def test_cvss_fields_round_trip(self) -> None:
        exploit = ExploitRecord(
            run_id="r",
            exploit_id="e",
            timestamp="t",
            source_agent="fixer",
            status="verified_and_fixed",
            hypothesis="h",
            file="f",
            function="fn",
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            cvss_justification={"AV": "network accessible"},
            chain_id="chain-1",
        )
        d = exploit.to_dict()
        restored = ExploitRecord.from_dict(d)
        assert restored.cvss_vector == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert restored.cvss_score == 9.8
        assert restored.cvss_justification == {"AV": "network accessible"}
        assert restored.chain_id == "chain-1"

    def test_precondition_fields_round_trip(self) -> None:
        exploit = ExploitRecord(
            run_id="r",
            exploit_id="e",
            timestamp="t",
            source_agent="analyzer",
            status="candidate",
            hypothesis="h",
            file="f",
            function="fn",
            attacker_role="anyone",
            required_privileges="none",
            category="active_exploit",
            trusted_component_abused="none (permissionless)",
        )
        d = exploit.to_dict()
        assert d["attacker_role"] == "anyone"
        assert d["required_privileges"] == "none"
        assert d["category"] == "active_exploit"
        assert d["trusted_component_abused"] == "none (permissionless)"
        restored = ExploitRecord.from_dict(d)
        assert restored == exploit

    def test_from_dict_legacy_no_preconditions(self) -> None:
        """Old JSON without precondition fields deserializes cleanly."""
        d = {
            "run_id": "r",
            "exploit_id": "e",
            "timestamp": "t",
            "source_agent": "analyzer",
            "hypothesis": "h",
            "file": "f",
            "function": "fn",
        }
        record = ExploitRecord.from_dict(d)
        assert record.attacker_role == ""
        assert record.required_privileges == ""
        assert record.category == ""
        assert record.trusted_component_abused == ""

    def test_from_dict_legacy_no_cvss(self) -> None:
        """Old JSON without CVSS fields should deserialize cleanly."""
        d = {
            "run_id": "r",
            "exploit_id": "e",
            "timestamp": "t",
            "source_agent": "analyzer",
            "hypothesis": "h",
            "file": "f",
            "function": "fn",
        }
        record = ExploitRecord.from_dict(d)
        assert record.cvss_vector is None
        assert record.cvss_score is None


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

    def test_cvss_fields(self) -> None:
        fix = FixRecord(
            run_id="r",
            fix_id="f",
            exploit_id="e",
            timestamp="t",
            hypothesis="h",
            file="f",
            function="fn",
            severity="High",
            patch="p",
            test_results="ok",
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
        )
        d = fix.to_dict()
        restored = FixRecord.from_dict(d)
        assert restored.cvss_vector == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert restored.cvss_score == 9.8

    def test_from_dict_legacy_no_cvss(self) -> None:
        """Old JSON without CVSS fields should deserialize cleanly."""
        d = {
            "run_id": "r",
            "fix_id": "f",
            "exploit_id": "e",
            "timestamp": "t",
            "hypothesis": "h",
            "file": "f",
            "function": "fn",
            "severity": "Low",
            "patch": "p",
            "test_results": "ok",
        }
        record = FixRecord.from_dict(d)
        assert record.cvss_vector == ""
        assert record.cvss_score is None


class TestThreatContext:
    def test_round_trip(self) -> None:
        tc = ThreatContext(
            deployment_type="web-app",
            environment="server",
            access_roles=[{"name": "user", "trust": "low"}],
            boundaries=["API gateway"],
            known_constraints=["rate limited"],
        )
        d = tc.to_dict()
        restored = ThreatContext.from_dict(d)
        assert restored == tc

    def test_defaults(self) -> None:
        tc = ThreatContext(deployment_type="cli-tool")
        assert tc.environment == ""
        assert tc.access_roles == []
        assert tc.boundaries == []
        assert tc.known_constraints == []

    def test_from_dict_minimal(self) -> None:
        d = {"deployment_type": "library"}
        tc = ThreatContext.from_dict(d)
        assert tc.deployment_type == "library"
        assert tc.environment == ""

    def test_json_safe(self) -> None:
        tc = ThreatContext(
            deployment_type="smart-contract",
            environment="on-chain",
        )
        serialized = json.dumps(tc.to_dict())
        restored = ThreatContext.from_dict(json.loads(serialized))
        assert restored == tc


class TestChainRecord:
    def test_round_trip(self) -> None:
        chain = ChainRecord(
            run_id="r1",
            chain_id="c1",
            timestamp="2025-01-01T00:00:00Z",
            status="proposed",
            description="Double-mint via reentrancy",
            steps=[{"exploit_id": "e1", "role": "anchor", "description": "re-enter"}],
            anchor_exploit_ids=["e1"],
            composite_cvss_vector="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            composite_cvss_score=10.0,
        )
        d = chain.to_dict()
        restored = ChainRecord.from_dict(d)
        assert restored == chain

    def test_defaults(self) -> None:
        chain = ChainRecord(
            run_id="r",
            chain_id="c",
            timestamp="t",
            status="proposed",
            description="desc",
        )
        assert chain.steps == []
        assert chain.anchor_exploit_ids == []
        assert chain.composite_cvss_vector is None
        assert chain.composite_cvss_score is None

    def test_from_dict_minimal(self) -> None:
        d = {
            "run_id": "r",
            "chain_id": "c",
            "timestamp": "t",
            "description": "d",
        }
        chain = ChainRecord.from_dict(d)
        assert chain.status == "proposed"
        assert chain.steps == []

    def test_json_safe(self) -> None:
        chain = ChainRecord(
            run_id="r",
            chain_id="c",
            timestamp="t",
            status="verified",
            description="desc",
            composite_cvss_score=7.5,
        )
        serialized = json.dumps(chain.to_dict())
        restored = ChainRecord.from_dict(json.loads(serialized))
        assert restored == chain
