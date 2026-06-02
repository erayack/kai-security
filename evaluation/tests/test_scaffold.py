"""Plumbing tests for the evaluation harness.

These never invoke the real ``kai.main`` subprocess — they exercise the
adapter registry, schema serialisation, ETA estimator, and the CLI status
/ report paths against a synthetic BenchmarkRun.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from evaluation.adapters.base import (
    BenchAdapter,
    register_adapter,
    resolve_adapter,
)
from evaluation.adapters.noop.adapter import NoopAdapter
from evaluation.eta import estimate_eta_seconds, format_eta
from evaluation.schemas import BenchmarkRun, PreparedTask, TaskRef, TaskScore


def test_noop_adapter_lists_tasks(tmp_path: Path) -> None:
    adapter = NoopAdapter({"count": 4})
    tasks = list(adapter.list_tasks())
    assert [t.task_id for t in tasks] == [
        "noop-000",
        "noop-001",
        "noop-002",
        "noop-003",
    ]
    assert all(t.benchmark == "noop" for t in tasks)


def test_noop_adapter_prepare_creates_repo(tmp_path: Path) -> None:
    adapter = NoopAdapter()
    task = next(iter(adapter.list_tasks()))
    prepared = adapter.prepare(task, tmp_path / "noop")
    assert prepared.repo_path.exists()
    assert (prepared.repo_path / "README.md").exists()


def test_noop_adapter_always_scores_success() -> None:
    adapter = NoopAdapter()
    task = TaskRef(benchmark="noop", task_id="x")
    prepared = PreparedTask(task_ref=task, repo_path=Path("/tmp"), workdir=Path("/tmp"))
    score = adapter.score(prepared, pipeline_result=None, exit_code=0)
    assert score.success is True


def test_resolve_adapter_picks_up_noop() -> None:
    adapter = resolve_adapter("noop", {"count": 1})
    assert isinstance(adapter, NoopAdapter)
    assert list(adapter.list_tasks())[0].task_id == "noop-000"


def test_resolve_adapter_unknown_raises() -> None:
    with pytest.raises(KeyError):
        resolve_adapter("does-not-exist")


def test_filter_tasks_by_ids_and_limit() -> None:
    adapter = NoopAdapter({"count": 10})
    by_id = list(adapter.filter_tasks(ids=["noop-002", "noop-005"]))
    assert {t.task_id for t in by_id} == {"noop-002", "noop-005"}
    by_limit = list(adapter.filter_tasks(limit=3))
    assert [t.task_id for t in by_limit] == ["noop-000", "noop-001", "noop-002"]


def test_benchmark_run_pass_fail_counts() -> None:
    now = datetime.now(timezone.utc)
    task = TaskRef(benchmark="noop", task_id="x")
    run = BenchmarkRun(
        run_id="r",
        benchmark="noop",
        started_at=now,
        task_scores=[
            TaskScore(task_ref=task, success=True),
            TaskScore(task_ref=task, success=False),
            TaskScore(task_ref=task, success=True),
        ],
    )
    assert run.pass_count == 2
    assert run.fail_count == 1


def test_eta_returns_none_without_state(tmp_path: Path) -> None:
    assert estimate_eta_seconds(tmp_path) is None


def test_eta_estimates_from_status_updates(tmp_path: Path) -> None:
    updates = [
        {"agent_name": "exploit", "iteration_num": 1, "iteration_time": 5.0},
        {"agent_name": "exploit", "iteration_num": 2, "iteration_time": 5.0},
    ]
    (tmp_path / "status_updates.jsonl").write_text(
        "\n".join(json.dumps(u) for u in updates)
    )
    eta = estimate_eta_seconds(tmp_path, max_iters={"exploit": 5})
    assert eta is not None and eta > 0


def test_format_eta_branches() -> None:
    assert format_eta(None) == "—"
    assert format_eta(45) == "45s"
    assert format_eta(125).startswith("2m")
    assert format_eta(4000).startswith("1h")


def test_register_adapter_duplicate_rejected() -> None:
    name = "dup-test-adapter"

    @register_adapter(name)
    def _f(config):  # pragma: no cover - exercised below
        return NoopAdapter(config)

    with pytest.raises(ValueError):

        @register_adapter(name)
        def _g(config):  # pragma: no cover
            return NoopAdapter(config)


class _MinimalAdapter(BenchAdapter):
    name = "mini"

    def list_tasks(self):
        yield TaskRef(benchmark="mini", task_id="t1")

    def prepare(self, task, workdir):
        return PreparedTask(task_ref=task, repo_path=workdir, workdir=workdir)

    def score(self, prepared, pipeline_result, exit_code):
        return TaskScore(task_ref=prepared.task_ref, success=exit_code == 0)


def test_minimal_adapter_obeys_abc() -> None:
    adapter = _MinimalAdapter()
    task = next(iter(adapter.list_tasks()))
    prepared = adapter.prepare(task, Path("/tmp"))
    success_score = adapter.score(prepared, None, 0)
    fail_score = adapter.score(prepared, None, 1)
    assert success_score.success is True
    assert fail_score.success is False
