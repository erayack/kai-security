"""Shared-state store for the parallel benchmark runner.

The store is a thin DAO over Postgres (used in production when running
on Railway) with a SQLite fallback used by unit tests and ad-hoc local
multi-process runs. Per-task artefact directories on disk
(``output/bench/<benchmark>/<task_id>/``) continue to be written by the
runner -- the store is an *additional* sink that gives multiple workers
a single source of truth for which tasks are in flight, complete, or
pending.

Schema (intentionally tiny):

* ``bench_runs`` -- one row per ``evaluation.cli enqueue`` invocation.
* ``bench_tasks`` -- one row per ``(run_id, task_id)``; status moves
  ``pending -> running -> done``. ``claim_next`` flips the status
  atomically so multiple workers never race on the same row.
* ``bench_scores`` -- denormalised per-task score payload. The runner
  also writes ``score.json`` to disk; this table is a queryable mirror.

Both backends speak the same SQL where possible. SQLite uses ``?``
placeholders and a polling-based ``claim_next``; Postgres uses ``%s``
placeholders and the canonical ``FOR UPDATE SKIP LOCKED`` pattern.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import urllib.parse
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from evaluation.schemas import TaskRef, TaskScore

LOG = logging.getLogger("evaluation.store")

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"


# DB-API 2.0 cursor / connection. The concrete drivers ship slightly
# different signatures (`sqlite3` exposes more methods than `psycopg`)
# so we type-erase to `Any` here and rely on runtime conformance.
_Cursor = Any
_Connection = Any


@dataclass(frozen=True)
class ClaimedTask:
    """A row returned by :meth:`TaskStore.claim_next`."""

    task_db_id: int
    run_id: str
    benchmark: str
    task_ref: TaskRef
    attempts: int


@dataclass(frozen=True)
class RunSummary:
    """A row returned by :meth:`TaskStore.list_runs` / :meth:`get_run`."""

    run_id: str
    benchmark: str
    started_at: datetime
    finished_at: datetime | None
    pending: int
    running: int
    done: int
    failed: int
    config: dict[str, Any]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _from_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


def _coerce_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        return _from_iso(value)
    raise TypeError(f"cannot coerce {value!r} to datetime")


def _coerce_json(value: Any) -> Any:
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8")
    if isinstance(value, str):
        return json.loads(value)
    return value


class TaskStore:
    """Thin DAO for the shared bench queue."""

    def __init__(self, database_url: str | None = None) -> None:
        self.database_url = database_url or os.environ.get("DATABASE_URL", "")
        if not self.database_url:
            raise ValueError(
                "TaskStore requires DATABASE_URL (Postgres URI or sqlite:/// path)."
            )
        self._dialect = _detect_dialect(self.database_url)
        self._param_style = "?" if self._dialect == "sqlite" else "%s"
        self._driver = _load_driver(self._dialect)
        self._sqlite_lock = threading.Lock()
        self._sqlite_conn: sqlite3.Connection | None = None

    @contextmanager
    def _connect(self) -> Iterator[Any]:
        if self._dialect == "sqlite":
            with self._sqlite_lock:
                if self._sqlite_conn is None:
                    self._sqlite_conn = _open_sqlite(self.database_url)
                yield self._sqlite_conn
        else:
            conn = self._driver.connect(self.database_url)
            try:
                yield conn
            finally:
                conn.close()

    def _sql(self, statement: str) -> str:
        if self._param_style == "%s":
            return statement
        return statement.replace("%s", "?")

    def setup_schema(self) -> None:
        """Idempotently create the three tables the runner needs."""

        statements = self._schema_statements()
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                for sql in statements:
                    cur.execute(sql)
                conn.commit()
            finally:
                cur.close()

    def _schema_statements(self) -> list[str]:
        json_col = "JSONB" if self._dialect == "postgres" else "TEXT"
        ts_col = "TIMESTAMPTZ" if self._dialect == "postgres" else "TIMESTAMP"
        autoinc = (
            "BIGSERIAL PRIMARY KEY"
            if self._dialect == "postgres"
            else "INTEGER PRIMARY KEY AUTOINCREMENT"
        )
        statements: list[str] = [
            (
                "CREATE TABLE IF NOT EXISTS bench_runs ("
                "  run_id        TEXT PRIMARY KEY,"
                "  benchmark     TEXT NOT NULL,"
                f"  started_at    {ts_col} NOT NULL,"
                f"  finished_at   {ts_col},"
                f"  config        {json_col}"
                ")"
            ),
            (
                "CREATE TABLE IF NOT EXISTS bench_tasks ("
                f"  id                  {autoinc},"
                "  run_id              TEXT NOT NULL REFERENCES bench_runs(run_id),"
                "  benchmark           TEXT NOT NULL,"
                "  task_id             TEXT NOT NULL,"
                f"  task_metadata       {json_col},"
                "  status              TEXT NOT NULL DEFAULT 'pending',"
                "  attempts            INTEGER NOT NULL DEFAULT 0,"
                "  worker_id           TEXT,"
                f"  claimed_at          {ts_col},"
                f"  last_heartbeat_at   {ts_col},"
                f"  finished_at         {ts_col},"
                "  UNIQUE (run_id, task_id)"
                ")"
            ),
            (
                "CREATE INDEX IF NOT EXISTS bench_tasks_status_idx "
                "ON bench_tasks (status, run_id)"
            ),
            (
                "CREATE TABLE IF NOT EXISTS bench_scores ("
                "  task_db_id   INTEGER PRIMARY KEY REFERENCES bench_tasks(id),"
                "  run_id       TEXT NOT NULL,"
                "  benchmark    TEXT NOT NULL,"
                "  task_id      TEXT NOT NULL,"
                "  success      INTEGER NOT NULL,"
                "  exit_code    INTEGER,"
                "  duration_s   REAL,"
                "  failure      TEXT,"
                f"  score_json   {json_col},"
                f"  recorded_at  {ts_col} NOT NULL"
                ")"
            ),
        ]
        if self._dialect == "postgres":
            # Live-deploy migration: Postgres clusters created before the
            # ``last_heartbeat_at`` column existed don't get it from the
            # idempotent CREATE TABLE above. ``ADD COLUMN IF NOT EXISTS``
            # surfaces it without locking out healthy in-flight workers.
            # SQLite doesn't support IF NOT EXISTS on ADD COLUMN, but it
            # only ever opens fresh databases in tests / single-machine
            # use, so the CREATE TABLE path is enough there.
            statements.append(
                f"ALTER TABLE bench_tasks ADD COLUMN IF NOT EXISTS "
                f"last_heartbeat_at {ts_col}"
            )
        return statements

    def ensure_run(
        self,
        run_id: str,
        benchmark: str,
        config: dict[str, Any] | None = None,
        started_at: datetime | None = None,
    ) -> None:
        """Insert (or no-op if existing) the parent ``bench_runs`` row."""

        ts = started_at or _now()
        params = (run_id, benchmark, ts, json.dumps(config or {}))
        if self._dialect == "postgres":
            sql = (
                "INSERT INTO bench_runs (run_id, benchmark, started_at, config) "
                "VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (run_id) DO NOTHING"
            )
        else:
            sql = (
                "INSERT OR IGNORE INTO bench_runs "
                "(run_id, benchmark, started_at, config) VALUES (?, ?, ?, ?)"
            )
        self._exec(sql, self._sqlite_params(params), commit=True)

    def enqueue(
        self,
        run_id: str,
        benchmark: str,
        task_refs: Iterable[TaskRef],
        *,
        config: dict[str, Any] | None = None,
    ) -> int:
        """Bulk-insert ``task_refs`` into ``bench_tasks`` for ``run_id``."""

        self.ensure_run(run_id, benchmark, config)
        rows: list[tuple[Any, ...]] = []
        for ref in task_refs:
            rows.append(
                (
                    run_id,
                    benchmark,
                    ref.task_id,
                    json.dumps(ref.metadata or {}),
                )
            )
        if not rows:
            return 0
        if self._dialect == "postgres":
            sql = (
                "INSERT INTO bench_tasks "
                "(run_id, benchmark, task_id, task_metadata) "
                "VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (run_id, task_id) DO NOTHING"
            )
        else:
            sql = (
                "INSERT OR IGNORE INTO bench_tasks "
                "(run_id, benchmark, task_id, task_metadata) "
                "VALUES (?, ?, ?, ?)"
            )
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.executemany(sql, [self._sqlite_params(r) for r in rows])
                conn.commit()
            finally:
                cur.close()
        return len(rows)

    def claim_next(
        self,
        worker_id: str,
        *,
        benchmark: str | None = None,
        run_id: str | None = None,
    ) -> ClaimedTask | None:
        """Atomically claim the next ``pending`` row."""

        now = _now()
        if self._dialect == "postgres":
            return self._claim_postgres(worker_id, benchmark, run_id, now)
        return self._claim_sqlite(worker_id, benchmark, run_id, now)

    def _claim_postgres(
        self,
        worker_id: str,
        benchmark: str | None,
        run_id: str | None,
        now: datetime,
    ) -> ClaimedTask | None:
        filters = ["status = %s"]
        params: list[Any] = [STATUS_PENDING]
        if benchmark is not None:
            filters.append("benchmark = %s")
            params.append(benchmark)
        if run_id is not None:
            filters.append("run_id = %s")
            params.append(run_id)
        where = " AND ".join(filters)
        sql = (
            "UPDATE bench_tasks "
            "SET status = %s, worker_id = %s, claimed_at = %s, "
            "    last_heartbeat_at = %s, attempts = attempts + 1 "
            "WHERE id = ("
            "  SELECT id FROM bench_tasks "
            f"  WHERE {where} "
            "  ORDER BY id ASC "
            "  FOR UPDATE SKIP LOCKED "
            "  LIMIT 1"
            ") "
            "RETURNING id, run_id, benchmark, task_id, task_metadata, attempts"
        )
        update_params: list[Any] = [STATUS_RUNNING, worker_id, now, now]
        update_params.extend(params)
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(sql, update_params)
                row = cur.fetchone()
                conn.commit()
            finally:
                cur.close()
        if row is None:
            return None
        return _row_to_claimed(row)

    def _claim_sqlite(
        self,
        worker_id: str,
        benchmark: str | None,
        run_id: str | None,
        now: datetime,
    ) -> ClaimedTask | None:
        filters = ["status = ?"]
        params: list[Any] = [STATUS_PENDING]
        if benchmark is not None:
            filters.append("benchmark = ?")
            params.append(benchmark)
        if run_id is not None:
            filters.append("run_id = ?")
            params.append(run_id)
        where = " AND ".join(filters)
        select_sql = (
            "SELECT id, run_id, benchmark, task_id, task_metadata, attempts "
            f"FROM bench_tasks WHERE {where} ORDER BY id ASC LIMIT 1"
        )
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")
                cur.execute(select_sql, params)
                row = cur.fetchone()
                if row is None:
                    conn.commit()
                    return None
                task_db_id = row[0]
                cur.execute(
                    "UPDATE bench_tasks SET status = ?, worker_id = ?, "
                    "claimed_at = ?, last_heartbeat_at = ?, "
                    "attempts = attempts + 1 WHERE id = ?",
                    (
                        STATUS_RUNNING,
                        worker_id,
                        self._sqlite_dt(now),
                        self._sqlite_dt(now),
                        task_db_id,
                    ),
                )
                conn.commit()
            finally:
                cur.close()
        return _row_to_claimed((row[0], row[1], row[2], row[3], row[4], row[5] + 1))

    def complete(
        self,
        task_db_id: int,
        score: TaskScore,
        *,
        status: str | None = None,
    ) -> None:
        """Persist ``score`` and mark the task ``done`` / ``failed``."""

        target_status = status or (STATUS_DONE if score.success else STATUS_FAILED)
        now = _now()
        score_payload = score.model_dump(mode="json")
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    self._sql(
                        "SELECT run_id, benchmark, task_id FROM bench_tasks "
                        "WHERE id = %s"
                    ),
                    self._sqlite_params((task_db_id,)),
                )
                row = cur.fetchone()
                if row is None:
                    raise LookupError(f"bench_tasks id={task_db_id} not found")
                run_id, benchmark, task_id = row
                cur.execute(
                    self._sql(
                        "UPDATE bench_tasks SET status = %s, finished_at = %s "
                        "WHERE id = %s"
                    ),
                    self._sqlite_params(
                        (target_status, self._sqlite_dt(now), task_db_id)
                    ),
                )
                cur.execute(
                    self._sql("DELETE FROM bench_scores WHERE task_db_id = %s"),
                    self._sqlite_params((task_db_id,)),
                )
                cur.execute(
                    self._sql(
                        "INSERT INTO bench_scores "
                        "(task_db_id, run_id, benchmark, task_id, success, "
                        "exit_code, duration_s, failure, score_json, recorded_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    ),
                    self._sqlite_params(
                        (
                            task_db_id,
                            run_id,
                            benchmark,
                            task_id,
                            1 if score.success else 0,
                            score.pipeline_exit_code,
                            score.pipeline_duration_s,
                            score.failure_reason,
                            json.dumps(score_payload),
                            self._sqlite_dt(now),
                        )
                    ),
                )
                conn.commit()
            finally:
                cur.close()

    def release(self, task_db_id: int, *, reason: str | None = None) -> None:
        """Push a ``running`` row back into the ``pending`` pool (for retries)."""

        del reason
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    self._sql(
                        "UPDATE bench_tasks SET status = %s, worker_id = NULL, "
                        "claimed_at = NULL WHERE id = %s AND status = %s"
                    ),
                    self._sqlite_params((STATUS_PENDING, task_db_id, STATUS_RUNNING)),
                )
                conn.commit()
            finally:
                cur.close()

    def heartbeat(self, task_db_id: int) -> bool:
        """Refresh ``last_heartbeat_at`` for an in-flight claim.

        Workers call this once per heartbeat tick (usually 60 s) so the
        reclaim sweep can distinguish a healthy long-running task from a
        zombie claim left behind by a killed worker.

        Returns True if the row was still ``running`` and the heartbeat
        landed; False if the row had already moved on (raced with a
        ``complete()`` / ``release()`` / ``reclaim_stale_claims()``).
        """

        now = _now()
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    self._sql(
                        "UPDATE bench_tasks SET last_heartbeat_at = %s "
                        "WHERE id = %s AND status = %s"
                    ),
                    self._sqlite_params(
                        (self._sqlite_dt(now), task_db_id, STATUS_RUNNING)
                    ),
                )
                touched = (cur.rowcount or 0) > 0
                conn.commit()
            finally:
                cur.close()
        return touched

    def reclaim_stale_claims(self, max_age_seconds: int) -> int:
        """Return any ``running`` tasks whose heartbeat has gone stale.

        A claim is considered stale when ``last_heartbeat_at`` (or
        ``claimed_at`` if the heartbeat column is still NULL — old
        pre-migration rows) is older than ``max_age_seconds``. Healthy
        workers refresh ``last_heartbeat_at`` every heartbeat tick, so
        long-running but live tasks stay safe regardless of how old the
        claim is; only orphans from dead workers get swept.

        Workers call this periodically (default cadence in
        :class:`evaluation.worker.Worker` is once per minute with a 300 s
        threshold) so a killed replica's claims become re-claimable
        within ~5 minutes instead of hours.
        """

        if max_age_seconds <= 0:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    self._sql(
                        "UPDATE bench_tasks SET status = %s, worker_id = NULL, "
                        "claimed_at = NULL, last_heartbeat_at = NULL "
                        "WHERE status = %s "
                        "AND COALESCE(last_heartbeat_at, claimed_at) IS NOT NULL "
                        "AND COALESCE(last_heartbeat_at, claimed_at) < %s"
                    ),
                    self._sqlite_params(
                        (
                            STATUS_PENDING,
                            STATUS_RUNNING,
                            self._sqlite_dt(cutoff),
                        )
                    ),
                )
                count = cur.rowcount or 0
                conn.commit()
            finally:
                cur.close()
        return count

    def list_runs(
        self,
        *,
        benchmark: str | None = None,
        limit: int | None = None,
    ) -> list[RunSummary]:
        filters: list[str] = []
        params: list[Any] = []
        if benchmark is not None:
            filters.append("benchmark = %s")
            params.append(benchmark)
        where = f" WHERE {' AND '.join(filters)}" if filters else ""
        limit_sql = f" LIMIT {int(limit)}" if limit else ""
        sql = self._sql(
            "SELECT run_id, benchmark, started_at, finished_at, config"
            f" FROM bench_runs{where} ORDER BY started_at DESC{limit_sql}"
        )
        rows = self._fetchall(sql, self._sqlite_params(tuple(params)))
        runs: list[RunSummary] = []
        for row in rows:
            run_id = str(row[0])
            counts = self._task_counts(run_id)
            runs.append(
                RunSummary(
                    run_id=run_id,
                    benchmark=str(row[1]),
                    started_at=_coerce_datetime(row[2]) or _now(),
                    finished_at=_coerce_datetime(row[3]),
                    pending=counts.get(STATUS_PENDING, 0),
                    running=counts.get(STATUS_RUNNING, 0),
                    done=counts.get(STATUS_DONE, 0),
                    failed=counts.get(STATUS_FAILED, 0),
                    config=_coerce_json(row[4]) or {},
                )
            )
        return runs

    def get_run(self, run_id: str) -> RunSummary | None:
        for run in self.list_runs():
            if run.run_id == run_id:
                return run
        return None

    def tail_status(
        self,
        run_id: str,
        *,
        since: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return per-task status snapshots, optionally newer than ``since``."""

        params: list[Any] = [run_id]
        where = "run_id = %s"
        if since is not None:
            where += " AND COALESCE(finished_at, claimed_at) >= %s"
            params.append(self._sqlite_dt(since))
        sql = self._sql(
            "SELECT id, task_id, status, attempts, worker_id, claimed_at, "
            "finished_at, task_metadata "
            f"FROM bench_tasks WHERE {where} ORDER BY id ASC"
        )
        rows = self._fetchall(sql, self._sqlite_params(tuple(params)))
        out: list[dict[str, Any]] = []
        for row in rows:
            out.append(
                {
                    "task_db_id": int(row[0]),
                    "task_id": str(row[1]),
                    "status": str(row[2]),
                    "attempts": int(row[3] or 0),
                    "worker_id": row[4],
                    "claimed_at": _to_iso(_coerce_datetime(row[5])),
                    "finished_at": _to_iso(_coerce_datetime(row[6])),
                    "metadata": _coerce_json(row[7]) or {},
                }
            )
        return out

    def get_score(self, run_id: str, task_id: str) -> dict[str, Any] | None:
        sql = self._sql(
            "SELECT score_json FROM bench_scores WHERE run_id = %s AND task_id = %s"
        )
        row = self._fetchone(sql, self._sqlite_params((run_id, task_id)))
        if row is None:
            return None
        return _coerce_json(row[0])

    def finalise_run_if_drained(self, run_id: str) -> bool:
        """Stamp ``finished_at`` when no pending/running rows remain."""

        counts = self._task_counts(run_id)
        if counts.get(STATUS_PENDING, 0) > 0 or counts.get(STATUS_RUNNING, 0) > 0:
            return False
        now = _now()
        sql = self._sql(
            "UPDATE bench_runs SET finished_at = %s "
            "WHERE run_id = %s AND finished_at IS NULL"
        )
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    sql,
                    self._sqlite_params((self._sqlite_dt(now), run_id)),
                )
                conn.commit()
            finally:
                cur.close()
        return True

    def has_pending(self, *, run_id: str | None = None) -> bool:
        params: list[Any] = [STATUS_PENDING]
        where = "status = %s"
        if run_id is not None:
            where += " AND run_id = %s"
            params.append(run_id)
        sql = self._sql(f"SELECT 1 FROM bench_tasks WHERE {where} LIMIT 1")
        return self._fetchone(sql, self._sqlite_params(tuple(params))) is not None

    def _task_counts(self, run_id: str) -> dict[str, int]:
        sql = self._sql(
            "SELECT status, COUNT(*) FROM bench_tasks WHERE run_id = %s GROUP BY status"
        )
        rows = self._fetchall(sql, self._sqlite_params((run_id,)))
        return {str(r[0]): int(r[1]) for r in rows}

    def _exec(
        self,
        sql: str,
        params: Sequence[Any] = (),
        *,
        commit: bool = False,
    ) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(self._sql(sql), params)
                if commit:
                    conn.commit()
            finally:
                cur.close()

    def _fetchone(self, sql: str, params: Sequence[Any] = ()) -> tuple[Any, ...] | None:
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(sql, params)
                return cur.fetchone()
            finally:
                cur.close()

    def _fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        with self._connect() as conn:
            cur = conn.cursor()
            try:
                cur.execute(sql, params)
                return cur.fetchall()
            finally:
                cur.close()

    def _sqlite_params(self, params: Sequence[Any]) -> tuple[Any, ...]:
        if self._dialect != "sqlite":
            return tuple(params)
        return tuple(self._sqlite_value(p) for p in params)

    def _sqlite_value(self, value: Any) -> Any:
        if isinstance(value, datetime):
            return self._sqlite_dt(value)
        return value

    @staticmethod
    def _sqlite_dt(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    def close(self) -> None:
        """Close any pooled connection."""

        if self._sqlite_conn is not None:
            try:
                self._sqlite_conn.close()
            except sqlite3.Error:
                LOG.exception("sqlite close failed")
            self._sqlite_conn = None


def _detect_dialect(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme.startswith("postgres") or scheme.startswith("postgresql"):
        return "postgres"
    if scheme in {"sqlite", "sqlite3"} or url.startswith("sqlite:"):
        return "sqlite"
    if url.startswith("file:") or url.endswith(".db"):
        return "sqlite"
    raise ValueError(f"Unsupported DATABASE_URL scheme: {scheme!r}")


def _load_driver(dialect: str) -> Any:
    if dialect == "sqlite":
        return sqlite3
    try:
        import importlib

        return importlib.import_module("psycopg")
    except ImportError as exc:
        raise RuntimeError(
            "psycopg is required for the Postgres backend. "
            "Install with `uv sync --extra railway`."
        ) from exc


def _open_sqlite(database_url: str) -> sqlite3.Connection:
    parsed = urllib.parse.urlparse(database_url)
    if parsed.scheme in {"sqlite", "sqlite3"}:
        path = parsed.path
        if path.startswith("/:memory:"):
            path = ":memory:"
        elif path.startswith("/") and parsed.netloc in ("", "localhost"):
            if database_url.startswith("sqlite:////"):
                pass
            else:
                path = path.lstrip("/")
    else:
        path = database_url
    if path != ":memory:":
        Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        path,
        check_same_thread=False,
        isolation_level=None,
        timeout=30.0,
    )
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _row_to_claimed(row: tuple[Any, ...]) -> ClaimedTask:
    task_db_id = int(row[0])
    run_id = str(row[1])
    benchmark = str(row[2])
    task_id = str(row[3])
    metadata = _coerce_json(row[4]) or {}
    attempts = int(row[5])
    return ClaimedTask(
        task_db_id=task_db_id,
        run_id=run_id,
        benchmark=benchmark,
        task_ref=TaskRef(benchmark=benchmark, task_id=task_id, metadata=metadata),
        attempts=attempts,
    )


def wait_for_pending(
    store: TaskStore,
    *,
    poll_seconds: float = 2.0,
) -> None:
    """Block until at least one row is pending."""

    while True:
        if store.has_pending():
            return
        time.sleep(poll_seconds)
