"""Tests for kai.state.local.LocalStateManager CRUD operations."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from kai.state.local import LocalStateManager
from kai.state.models import (
    ExploitRecord,
    FixRecord,
    RunRecord,
    StatusUpdate,
)


def _make_manager(tmp_path: str | None = None) -> LocalStateManager:
    if tmp_path is None:
        tmp_path = tempfile.mkdtemp()
    return LocalStateManager(state_dir=tmp_path)


class TestRunLifecycle:
    def test_create_and_get(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        record = RunRecord(
            run_id="run-1",
            repo_path="/repo",
            started_at="2025-01-01T00:00:00Z",
            status="running",
            root_model="gpt-4o",
        )
        mgr.create_run(record)
        got = mgr.get_run("run-1")
        assert got is not None
        assert got.run_id == "run-1"
        assert got.status == "running"

    def test_get_nonexistent(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        assert mgr.get_run("nope") is None

    def test_update_run(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        mgr.create_run(
            RunRecord(
                run_id="r1",
                repo_path="/r",
                started_at="t",
                status="running",
                root_model="m",
            )
        )
        mgr.update_run("r1", status="completed", total_exploits=5)
        got = mgr.get_run("r1")
        assert got is not None
        assert got.status == "completed"
        assert got.total_exploits == 5

    def test_update_nonexistent_run(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        # Should not raise
        mgr.update_run("nope", status="failed")

    def test_persisted_to_disk(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        mgr.create_run(
            RunRecord(
                run_id="r1",
                repo_path="/r",
                started_at="t",
                status="running",
                root_model="m",
            )
        )
        run_file = tmp_path / "r1" / "run.json"
        assert run_file.exists()
        data = json.loads(run_file.read_text())
        assert data["run_id"] == "r1"


class TestStatusUpdates:
    def test_add_and_get(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        u1 = StatusUpdate(
            run_id="r1",
            iteration_num=1,
            timestamp="t1",
            agent_name="exploit",
            response_text="found something",
        )
        u2 = StatusUpdate(
            run_id="r1",
            iteration_num=2,
            timestamp="t2",
            agent_name="exploit",
            response_text="more stuff",
        )
        mgr.add_status_update(u1)
        mgr.add_status_update(u2)
        updates = mgr.get_status_updates("r1", last_n=2)
        assert len(updates) == 2
        assert updates[0].iteration_num == 1
        assert updates[1].iteration_num == 2

    def test_empty(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        assert mgr.get_status_updates("r1") == []

    def test_jsonl_format(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        mgr.add_status_update(
            StatusUpdate(
                run_id="r1",
                iteration_num=1,
                timestamp="t",
                agent_name="a",
                response_text="text",
            )
        )
        path = tmp_path / "r1" / "status_updates.jsonl"
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["iteration_num"] == 1


class TestExploits:
    def test_add_and_get(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        exploit = ExploitRecord(
            run_id="r1",
            exploit_id="e1",
            timestamp="t",
            source_agent="analyzer",
            status="candidate",
            hypothesis="reentrancy",
            file="Vault.sol",
            function="withdraw",
        )
        mgr.add_exploit(exploit)
        exploits = mgr.get_exploits("r1")
        assert len(exploits) == 1
        assert exploits[0].exploit_id == "e1"

    def test_filter_by_status(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        mgr.add_exploit(
            ExploitRecord(
                run_id="r1",
                exploit_id="e1",
                timestamp="t",
                source_agent="analyzer",
                status="candidate",
                hypothesis="h1",
                file="f",
                function="fn",
            )
        )
        mgr.add_exploit(
            ExploitRecord(
                run_id="r1",
                exploit_id="e2",
                timestamp="t",
                source_agent="verifier",
                status="verified",
                hypothesis="h2",
                file="f",
                function="fn2",
            )
        )
        assert len(mgr.get_exploits("r1", status="candidate")) == 1
        assert len(mgr.get_exploits("r1", status="verified")) == 1
        assert len(mgr.get_exploits("r1")) == 2

    def test_find_exploit(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
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
        found = mgr.find_exploit("r1", "reentrancy", "Vault.sol", "withdraw")
        assert found is not None
        assert found.exploit_id == "e1"

    def test_find_exploit_not_found(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        assert mgr.find_exploit("r1", "h", "f", "fn") is None

    def test_update_exploit(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
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
        mgr.update_exploit(
            "r1",
            "e1",
            status="verified",
            confirmed=True,
            poc_code="exploit()",
        )
        exploits = mgr.get_exploits("r1")
        assert exploits[0].status == "verified"
        assert exploits[0].confirmed is True
        assert exploits[0].poc_code == "exploit()"

    def test_update_nonexistent_exploit(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        # Should not raise
        mgr.update_exploit("r1", "nope", status="verified")

    def test_persisted_to_disk(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
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
        path = tmp_path / "r1" / "exploits.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert len(data) == 1
        assert data[0]["exploit_id"] == "e1"


class TestFixes:
    def test_add_and_get(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        fix = FixRecord(
            run_id="r1",
            fix_id="f1",
            exploit_id="e1",
            timestamp="t",
            hypothesis="h",
            file="f",
            function="fn",
            severity="high",
            patch="diff",
            test_results="PASS",
            applied=True,
        )
        mgr.add_fix(fix)
        fixes = mgr.get_fixes("r1")
        assert len(fixes) == 1
        assert fixes[0].fix_id == "f1"
        assert fixes[0].applied is True

    def test_empty(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        assert mgr.get_fixes("r1") == []


class TestSummarizeProgress:
    def test_no_data(self, tmp_path: Path) -> None:
        mgr = _make_manager(str(tmp_path))
        summary = mgr.summarize_progress("r1")
        assert summary == "No progress recorded yet."

    def test_fallback_on_error(self, tmp_path: Path) -> None:
        """When LLM is unavailable, falls back to raw context."""
        mgr = LocalStateManager(
            state_dir=str(tmp_path),
            summary_backend="openrouter",
            summary_model="nonexistent/model-that-will-fail",
        )
        mgr.add_status_update(
            StatusUpdate(
                run_id="r1",
                iteration_num=1,
                timestamp="t",
                agent_name="exploit",
                response_text="found a bug",
            )
        )
        summary = mgr.summarize_progress("r1")
        assert "r1" in summary
        assert "latest iteration" in summary
