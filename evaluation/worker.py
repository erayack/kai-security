"""Railway worker loop: claim a task, run it, mark complete, repeat.

The worker is intentionally tiny -- it holds **no** benchmark-specific
logic. All it does is:

1. Resolve the adapter named by ``BENCHMARK_ADAPTER`` env var, parsing
   any ``BENCHMARK_CONFIG`` JSON the user pre-attached on Railway.
2. Open a :class:`evaluation.store.TaskStore` against ``DATABASE_URL``.
3. Spin a loop that calls ``store.claim_next(...)`` and invokes
   :meth:`evaluation.runner.BenchmarkRunner._run_task` for each row.
4. Write the resulting ``TaskScore`` back via ``store.complete(...)``.

SIGTERM / SIGINT handling: when Railway recycles the container, the
worker finishes the *current* task (or honours its existing wall-clock
cap), then exits 0 so the platform can replace the replica cleanly. We
never abandon a task mid-flight without releasing it.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

from evaluation.adapters.base import resolve_adapter
from evaluation.runner import DEFAULT_OUTPUT_ROOT, BenchmarkRunner
from evaluation.schemas import TaskScore
from evaluation.store import (
    STATUS_FAILED,
    ClaimedTask,
    TaskStore,
)

LOG = logging.getLogger("evaluation.worker")


class Worker:
    """A long-running benchmark worker.

    The worker is parameterised entirely by environment variables to
    match Railway's deployment model:

    ===========================  ==========================================
    var                          purpose
    ===========================  ==========================================
    ``DATABASE_URL``             Postgres URI; Railway injects this when a
                                 Postgres plugin is attached.
    ``BENCHMARK_ADAPTER``        Adapter name, e.g. ``cybergym``.
    ``BENCHMARK_CONFIG``         JSON-encoded adapter config dict.
    ``BENCHMARK_RUN_ID``         Optional scope; consume only this run.
    ``BENCHMARK_OUTPUT_ROOT``    Override on-disk artefact root.
    ``BENCHMARK_PIPELINE_ARGS``  Optional JSON list of extra pipeline flags.
    ``BENCHMARK_TASK_TIMEOUT_S`` Per-task wall-clock cap (default 3600).
    ``BENCHMARK_POLL_SECONDS``   Sleep between claim attempts (default 5).
    ``BENCHMARK_IDLE_EXIT_AFTER``  Seconds of pending-empty before the
                                   worker exits (default: never).
    ===========================  ==========================================
    """

    def __init__(
        self,
        store: TaskStore,
        runner: BenchmarkRunner,
        *,
        run_id: str | None,
        worker_id: str,
        poll_seconds: float,
        idle_exit_after: float | None,
    ) -> None:
        self.store = store
        self.runner = runner
        self.run_id = run_id
        self.worker_id = worker_id
        self.poll_seconds = max(0.5, poll_seconds)
        self.idle_exit_after = idle_exit_after
        self._stop = threading.Event()
        self._in_flight: ClaimedTask | None = None
        self._in_flight_lock = threading.Lock()

    def request_stop(self) -> None:
        """Trigger a graceful shutdown after the current task completes."""

        if not self._stop.is_set():
            LOG.info("stop requested; will exit after current task")
        self._stop.set()

    def install_signal_handlers(self) -> None:
        """Wire SIGTERM/SIGINT to :meth:`request_stop`."""

        def handle_signal(signum: int, _frame: Any) -> None:
            LOG.info("received signal=%s", signum)
            self.request_stop()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, handle_signal)
            except (OSError, ValueError):
                LOG.warning("could not install handler for signal %s", sig)

    def run(self) -> int:
        """Run the claim/process loop until shutdown."""

        LOG.info(
            "worker=%s adapter=%s queue=%s in_flight=%s",
            self.worker_id,
            self.runner.adapter.name,
            self._pending_count(),
            0,
        )
        self._start_heartbeat()
        idle_since: float | None = None
        while not self._stop.is_set():
            try:
                claimed = self.store.claim_next(
                    self.worker_id,
                    benchmark=self.runner.adapter.name,
                    run_id=self.run_id,
                )
            except Exception:
                LOG.exception("claim_next failed; backing off")
                self._sleep(self.poll_seconds)
                continue

            if claimed is None:
                if self.idle_exit_after is not None:
                    idle_since = idle_since or time.monotonic()
                    if time.monotonic() - idle_since >= self.idle_exit_after:
                        LOG.info(
                            "no work for %.0fs; exiting",
                            self.idle_exit_after,
                        )
                        break
                self._sleep(self.poll_seconds)
                continue

            idle_since = None
            try:
                self._handle_claim(claimed)
            except Exception:
                LOG.exception(
                    "task=%s failed unexpectedly; marking failed",
                    claimed.task_ref.task_id,
                )
                self._fail_claim(claimed, "worker_exception")

            self.store.finalise_run_if_drained(claimed.run_id)

        LOG.info("worker=%s shutting down", self.worker_id)
        self.store.close()
        return 0

    def _handle_claim(self, claimed: ClaimedTask) -> None:
        with self._in_flight_lock:
            self._in_flight = claimed
        LOG.info(
            "claimed task=%s run=%s attempt=%s",
            claimed.task_ref.task_id,
            claimed.run_id,
            claimed.attempts,
        )
        run_dir = self._run_dir(claimed)
        try:
            score = self.runner._run_task(  # noqa: SLF001 -- internal call by design
                claimed.task_ref, run_dir
            )
        finally:
            with self._in_flight_lock:
                self._in_flight = None
        self.store.complete(claimed.task_db_id, score)
        LOG.info(
            "completed task=%s success=%s exit=%s duration=%.1fs",
            claimed.task_ref.task_id,
            score.success,
            score.pipeline_exit_code,
            score.pipeline_duration_s or 0.0,
        )

    def _run_dir(self, claimed: ClaimedTask) -> Path:
        run_dir = self.runner.output_root / f"run_{claimed.run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    def _fail_claim(self, claimed: ClaimedTask, reason: str) -> None:
        score = TaskScore(
            task_ref=claimed.task_ref,
            success=False,
            failure_reason=reason,
        )
        try:
            self.store.complete(claimed.task_db_id, score, status=STATUS_FAILED)
        except Exception:
            LOG.exception(
                "failed to record failure for task=%s", claimed.task_ref.task_id
            )

    def _start_heartbeat(
        self,
        interval: float = 60.0,
        reclaim_every: int = 1,
        reclaim_max_age_seconds: int = 300,
    ) -> None:
        """Spawn a daemon thread that refreshes ``last_heartbeat_at`` for
        the in-flight claim and periodically reclaims stale ``running``
        rows back to ``pending``.

        Each ``interval``-second tick:

        * Writes ``last_heartbeat_at = now()`` for the worker's current
          claim (if any) so the reclaim sweep treats it as live.
        * Logs an ``in_flight=...`` heartbeat line.
        * Every ``reclaim_every`` ticks (default: every tick, i.e. once
          per minute), calls
          :meth:`evaluation.store.TaskStore.reclaim_stale_claims` with
          ``reclaim_max_age_seconds`` (default 300 s = 5 × heartbeat
          interval, well past any in-flight worker that's still alive).

        Because the reclaim now keys on ``last_heartbeat_at`` rather
        than ``claimed_at``, a long-running healthy task is *never*
        swept regardless of how old the claim is — its heartbeat keeps
        the row fresh. Only orphan claims from killed replicas (no
        heartbeat for >5 min) get returned to the pending pool.
        """

        def loop() -> None:
            started_for: dict[int, float] = {}
            tick = 0
            while not self._stop.is_set():
                self._stop.wait(interval)
                if self._stop.is_set():
                    return
                tick += 1
                with self._in_flight_lock:
                    claimed = self._in_flight
                if claimed is not None:
                    try:
                        self.store.heartbeat(claimed.task_db_id)
                    except Exception:  # noqa: BLE001
                        LOG.exception(
                            "heartbeat write failed for task=%s",
                            claimed.task_ref.task_id,
                        )
                if tick % max(reclaim_every, 1) == 0:
                    try:
                        n = self.store.reclaim_stale_claims(reclaim_max_age_seconds)
                        if n:
                            LOG.info(
                                "reclaimed %d stale claim(s) (no heartbeat for >%ds)",
                                n,
                                reclaim_max_age_seconds,
                            )
                    except Exception:  # noqa: BLE001
                        LOG.exception("reclaim_stale_claims failed; will retry")
                if claimed is None:
                    LOG.info("heartbeat worker=%s in_flight=idle", self.worker_id)
                    continue
                start = started_for.setdefault(claimed.task_db_id, time.monotonic())
                elapsed = time.monotonic() - start
                LOG.info(
                    "heartbeat worker=%s in_flight=%s elapsed=%.0fs attempt=%s",
                    self.worker_id,
                    claimed.task_ref.task_id,
                    elapsed,
                    claimed.attempts,
                )

        thread = threading.Thread(target=loop, name="worker-heartbeat", daemon=True)
        thread.start()

    def _release(self, claimed: ClaimedTask) -> None:
        try:
            self.store.release(
                claimed.task_db_id, reason="worker shutdown before completion"
            )
        except Exception:
            LOG.exception("failed to release task=%s", claimed.task_ref.task_id)

    def _sleep(self, seconds: float) -> None:
        if self._stop.wait(seconds):
            return

    def _pending_count(self) -> int:
        # The store has a richer API but for the startup banner all we
        # need is "is there anything to do?". Counting exact pending rows
        # would mean an extra query per heartbeat; we settle for a bool.
        try:
            return 1 if self.store.has_pending(run_id=self.run_id) else 0
        except Exception:
            LOG.exception("pending count probe failed")
            return -1


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        LOG.warning("invalid float for %s=%r; using default %s", name, raw, default)
        return default


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        LOG.warning("invalid int for %s=%r; using default %s", name, raw, default)
        return default


def _optional_float_env(name: str) -> float | None:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return None
    try:
        return float(raw)
    except ValueError:
        LOG.warning("invalid float for %s=%r; ignoring", name, raw)
        return None


def _parse_json_env(name: str) -> Any:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        LOG.exception("could not parse %s as JSON", name)
        raise


def _configure_logging() -> None:
    level_name = os.environ.get("BENCHMARK_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
    )


def build_worker_from_env() -> Worker:
    """Construct a worker entirely from environment variables."""

    adapter_name = os.environ.get("BENCHMARK_ADAPTER")
    if not adapter_name:
        raise SystemExit("BENCHMARK_ADAPTER env var is required")

    adapter_config = _parse_json_env("BENCHMARK_CONFIG") or {}
    if not isinstance(adapter_config, dict):
        raise SystemExit("BENCHMARK_CONFIG must be a JSON object")

    pipeline_args_raw = _parse_json_env("BENCHMARK_PIPELINE_ARGS") or []
    if not isinstance(pipeline_args_raw, list):
        raise SystemExit("BENCHMARK_PIPELINE_ARGS must be a JSON list")
    pipeline_args = [str(arg) for arg in pipeline_args_raw]

    output_root_env = os.environ.get("BENCHMARK_OUTPUT_ROOT")
    output_root = Path(output_root_env).expanduser() if output_root_env else None

    adapter = resolve_adapter(adapter_name, adapter_config)

    env_overrides_raw = _parse_json_env("BENCHMARK_ENV_OVERRIDES") or {}
    if not isinstance(env_overrides_raw, dict):
        raise SystemExit("BENCHMARK_ENV_OVERRIDES must be a JSON object")
    env_overrides = {str(k): str(v) for k, v in env_overrides_raw.items()}

    runner = BenchmarkRunner(
        adapter,
        output_root=output_root or DEFAULT_OUTPUT_ROOT,
        concurrency=1,
        per_task_timeout_s=_int_env("BENCHMARK_TASK_TIMEOUT_S", 60 * 60),
        pipeline_args=pipeline_args,
        env_overrides=env_overrides,
    )

    store = TaskStore()
    store.setup_schema()

    worker_id = (
        os.environ.get("BENCHMARK_WORKER_ID")
        or os.environ.get("RAILWAY_REPLICA_ID")
        or socket.gethostname()
    )

    return Worker(
        store=store,
        runner=runner,
        run_id=os.environ.get("BENCHMARK_RUN_ID") or None,
        worker_id=worker_id,
        poll_seconds=_float_env("BENCHMARK_POLL_SECONDS", 5.0),
        idle_exit_after=_optional_float_env("BENCHMARK_IDLE_EXIT_AFTER"),
    )


def main(argv: list[str] | None = None) -> int:
    """Module entry point: ``python -m evaluation.worker``."""

    del argv
    _configure_logging()
    worker = build_worker_from_env()
    worker.install_signal_handlers()
    return worker.run()


if __name__ == "__main__":
    raise SystemExit(main())
