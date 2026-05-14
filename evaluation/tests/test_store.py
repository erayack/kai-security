"""Tests for :mod:`evaluation.store`.

The store has two production backends -- Postgres on Railway, SQLite for
single-machine ad-hoc use. The tests target SQLite (stdlib only) so they
run on CI without external dependencies. The SQL the tests exercise is
intentionally chosen to overlap as much as possible with the Postgres
path: schema migration, bulk enqueue, atomic ``claim_next`` (no two
workers claim the same row), idempotent re-enqueue, completion, and
status tailing.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from evaluation.schemas import TaskRef, TaskScore
from evaluation.store import (
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    ClaimedTask,
    TaskStore,
    _detect_dialect,
)


@pytest.fixture()
def store(tmp_path: Path) -> Iterator[TaskStore]:
    db_path = tmp_path / "bench.db"
    instance = TaskStore(f"sqlite:///{db_path}")
    instance.setup_schema()
    yield instance
    instance.close()


def _make_tasks(benchmark: str, count: int) -> list[TaskRef]:
    return [
        TaskRef(benchmark=benchmark, task_id=f"t-{i:03d}", metadata={"idx": i})
        for i in range(count)
    ]


def test_detect_dialect_recognises_known_schemes() -> None:
    assert _detect_dialect("sqlite:///tmp/foo.db") == "sqlite"
    assert _detect_dialect("postgres://u:p@h/db") == "postgres"
    assert _detect_dialect("postgresql://u:p@h/db") == "postgres"


def test_detect_dialect_rejects_unknown_scheme() -> None:
    with pytest.raises(ValueError):
        _detect_dialect("mysql://u:p@h/db")


def test_setup_schema_is_idempotent(store: TaskStore) -> None:
    # Calling setup twice must not raise; the second call should be a no-op.
    store.setup_schema()
    store.setup_schema()
    runs = store.list_runs()
    assert runs == []


def test_enqueue_inserts_unique_rows(store: TaskStore) -> None:
    tasks = _make_tasks("noop", 3)
    inserted = store.enqueue("run-1", "noop", tasks, config={"k": "v"})
    assert inserted == 3

    # Re-enqueueing the same (run_id, task_id) is a no-op.
    again = store.enqueue("run-1", "noop", tasks)
    assert again == 3  # returns total submitted, but DB-side OR IGNORE prevents dup
    rows = store.tail_status("run-1")
    assert {r["task_id"] for r in rows} == {"t-000", "t-001", "t-002"}


def test_claim_next_returns_each_row_once(store: TaskStore) -> None:
    tasks = _make_tasks("noop", 3)
    store.enqueue("run-1", "noop", tasks)

    claims: list[ClaimedTask] = []
    while True:
        claimed = store.claim_next("worker-A", benchmark="noop")
        if claimed is None:
            break
        claims.append(claimed)
    assert {c.task_ref.task_id for c in claims} == {"t-000", "t-001", "t-002"}
    # Second pass returns nothing -- rows are all in `running`.
    assert store.claim_next("worker-A") is None


def test_claim_next_atomic_across_threads(store: TaskStore) -> None:
    tasks = _make_tasks("noop", 20)
    store.enqueue("run-1", "noop", tasks)

    seen: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(4)

    def worker(name: str) -> None:
        barrier.wait()
        while True:
            claimed = store.claim_next(name, benchmark="noop")
            if claimed is None:
                return
            with lock:
                seen.append(claimed.task_ref.task_id)

    threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(seen) == sorted([t.task_id for t in tasks])
    # No duplicate claims.
    assert len(set(seen)) == len(seen)


def test_complete_writes_score_and_marks_done(store: TaskStore) -> None:
    tasks = _make_tasks("noop", 1)
    store.enqueue("run-1", "noop", tasks)
    claimed = store.claim_next("worker", benchmark="noop")
    assert claimed is not None
    score = TaskScore(
        task_ref=claimed.task_ref,
        success=True,
        pipeline_exit_code=0,
        pipeline_duration_s=12.5,
        details={"note": "ok"},
    )
    store.complete(claimed.task_db_id, score)

    rows = store.tail_status("run-1")
    assert rows[0]["status"] == STATUS_DONE
    persisted = store.get_score("run-1", claimed.task_ref.task_id)
    assert persisted is not None
    assert persisted["success"] is True
    assert persisted["pipeline_duration_s"] == 12.5


def test_complete_marks_failed_when_success_false(store: TaskStore) -> None:
    tasks = _make_tasks("noop", 1)
    store.enqueue("run-1", "noop", tasks)
    claimed = store.claim_next("worker", benchmark="noop")
    assert claimed is not None
    score = TaskScore(
        task_ref=claimed.task_ref,
        success=False,
        failure_reason="boom",
    )
    store.complete(claimed.task_db_id, score)
    rows = store.tail_status("run-1")
    assert rows[0]["status"] == STATUS_FAILED


def test_release_returns_row_to_pending(store: TaskStore) -> None:
    tasks = _make_tasks("noop", 1)
    store.enqueue("run-1", "noop", tasks)
    claimed = store.claim_next("worker-A", benchmark="noop")
    assert claimed is not None
    store.release(claimed.task_db_id)

    rows = store.tail_status("run-1")
    assert rows[0]["status"] == STATUS_PENDING

    reclaimed = store.claim_next("worker-B", benchmark="noop")
    assert reclaimed is not None
    assert reclaimed.task_db_id == claimed.task_db_id
    assert reclaimed.attempts == 2


def test_list_runs_filters_by_benchmark(store: TaskStore) -> None:
    store.enqueue("run-1", "noop", _make_tasks("noop", 2))
    store.enqueue("run-2", "cybergym", _make_tasks("cybergym", 1))

    noop_runs = store.list_runs(benchmark="noop")
    assert [r.run_id for r in noop_runs] == ["run-1"]

    all_runs = store.list_runs()
    assert {r.run_id for r in all_runs} == {"run-1", "run-2"}


def test_get_run_returns_counts(store: TaskStore) -> None:
    store.enqueue("run-1", "noop", _make_tasks("noop", 3))
    claimed = store.claim_next("w", benchmark="noop")
    assert claimed is not None
    summary = store.get_run("run-1")
    assert summary is not None
    assert summary.pending == 2
    assert summary.running == 1
    assert summary.done == 0


def test_finalise_run_stamps_finished_at(store: TaskStore) -> None:
    store.enqueue("run-1", "noop", _make_tasks("noop", 1))
    assert store.finalise_run_if_drained("run-1") is False
    claimed = store.claim_next("w", benchmark="noop")
    assert claimed is not None
    score = TaskScore(task_ref=claimed.task_ref, success=True)
    store.complete(claimed.task_db_id, score)
    assert store.finalise_run_if_drained("run-1") is True
    summary = store.get_run("run-1")
    assert summary is not None
    assert summary.finished_at is not None


def test_tail_status_filters_by_since(store: TaskStore) -> None:
    store.enqueue("run-1", "noop", _make_tasks("noop", 2))
    claimed = store.claim_next("w", benchmark="noop")
    assert claimed is not None
    score = TaskScore(task_ref=claimed.task_ref, success=True)
    store.complete(claimed.task_db_id, score)

    future = datetime.now(timezone.utc).replace(year=3000)
    assert store.tail_status("run-1", since=future) == []

    past = datetime(2000, 1, 1, tzinfo=timezone.utc)
    rows = store.tail_status("run-1", since=past)
    assert any(r["status"] == STATUS_DONE for r in rows)


def test_claim_next_filters_by_run_id(store: TaskStore) -> None:
    store.enqueue("run-1", "noop", _make_tasks("noop", 2))
    store.enqueue("run-2", "noop", _make_tasks("noop", 2))

    claimed = store.claim_next("w", run_id="run-2")
    assert claimed is not None
    assert claimed.run_id == "run-2"


def test_missing_database_url_raises() -> None:
    import os

    saved = os.environ.pop("DATABASE_URL", None)
    try:
        with pytest.raises(ValueError):
            TaskStore()
    finally:
        if saved is not None:
            os.environ["DATABASE_URL"] = saved


def test_has_pending(store: TaskStore) -> None:
    assert store.has_pending() is False
    store.enqueue("run-1", "noop", _make_tasks("noop", 1))
    assert store.has_pending() is True
    claimed = store.claim_next("w")
    assert claimed is not None
    score = TaskScore(task_ref=claimed.task_ref, success=True)
    store.complete(claimed.task_db_id, score)
    assert store.has_pending() is False


def test_complete_unknown_id_raises(store: TaskStore) -> None:
    score = TaskScore(task_ref=TaskRef(benchmark="noop", task_id="ghost"), success=True)
    with pytest.raises(LookupError):
        store.complete(999999, score)


def test_claim_next_increments_attempts(store: TaskStore) -> None:
    store.enqueue("run-1", "noop", _make_tasks("noop", 1))
    first = store.claim_next("w", benchmark="noop")
    assert first is not None
    assert first.attempts == 1
    store.release(first.task_db_id)
    second = store.claim_next("w", benchmark="noop")
    assert second is not None
    assert second.attempts == 2


def test_enqueue_zero_tasks_is_noop(store: TaskStore) -> None:
    inserted = store.enqueue("run-1", "noop", [])
    assert inserted == 0
    # The parent bench_runs row was still created (so subsequent enqueues work).
    assert store.get_run("run-1") is not None


def test_status_filter_on_running_rows(store: TaskStore) -> None:
    store.enqueue("run-1", "noop", _make_tasks("noop", 3))
    store.claim_next("w", benchmark="noop")
    store.claim_next("w", benchmark="noop")
    summary = store.get_run("run-1")
    assert summary is not None
    assert summary.running == 2
    assert summary.pending == 1


def test_metadata_round_trips(store: TaskStore) -> None:
    refs = [
        TaskRef(
            benchmark="noop",
            task_id="t-meta",
            metadata={"difficulty": "hard", "tags": ["x", "y"]},
        )
    ]
    store.enqueue("run-1", "noop", refs)
    claimed = store.claim_next("w")
    assert claimed is not None
    assert claimed.task_ref.metadata == {"difficulty": "hard", "tags": ["x", "y"]}


def _other_dialect_smoke(store: TaskStore) -> dict[str, Any]:
    """Helper that runs the same shape across either backend.

    Kept here to make it obvious that the SQLite path covers the surface
    used by the Postgres path. We don't actually open a Postgres
    connection in tests (no live cluster).
    """

    store.enqueue("run-x", "noop", _make_tasks("noop", 1))
    claimed = store.claim_next("w", benchmark="noop")
    assert claimed is not None
    score = TaskScore(task_ref=claimed.task_ref, success=True)
    store.complete(claimed.task_db_id, score)
    return {"finalised": store.finalise_run_if_drained("run-x")}


def test_sqlite_path_exercises_all_writes(store: TaskStore) -> None:
    result = _other_dialect_smoke(store)
    assert result["finalised"] is True


def test_unused_status_running_constant_value() -> None:
    # Cheap guard so the value never drifts -- the worker code checks it.
    assert STATUS_RUNNING == "running"
    assert STATUS_PENDING == "pending"
    assert STATUS_DONE == "done"
    assert STATUS_FAILED == "failed"
