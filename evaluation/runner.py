"""Benchmark runner: drives an adapter over a task list via ``kai.main``.

The runner shells out to ``python -m kai.main pipeline`` for every task so
that pipeline crashes never take the runner down with them. Each task is
given its own state directory, log file, and result JSON path under
``<output_root>/<benchmark>/<task_id>/``.

Concurrency is provided by ``ThreadPoolExecutor`` — every worker thread is
mostly idle waiting on a subprocess, and per-task state directories prevent
any contention on the SQLite/JSONL state files.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kai import generate_id

from evaluation.adapters.base import BenchAdapter
from evaluation.schemas import BenchmarkRun, PreparedTask, TaskRef, TaskScore

LOG = logging.getLogger("evaluation.runner")

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "output" / "bench"
PIPELINE_MODULE = "kai.main"


class BenchmarkRunner:
    """Drive an adapter over a list of tasks and aggregate the results."""

    def __init__(
        self,
        adapter: BenchAdapter,
        *,
        output_root: Path | None = None,
        concurrency: int = 1,
        per_task_timeout_s: int = 60 * 60,
        pipeline_args: list[str] | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> None:
        self.adapter = adapter
        self.output_root = (output_root or DEFAULT_OUTPUT_ROOT) / adapter.name
        self.concurrency = max(1, concurrency)
        self.per_task_timeout_s = per_task_timeout_s
        self.pipeline_args = pipeline_args or []
        self.env_overrides = env_overrides or {}
        self._summary_lock = threading.Lock()

    def run(self, tasks: list[TaskRef]) -> BenchmarkRun:
        run = BenchmarkRun(
            run_id=generate_id(),
            benchmark=self.adapter.name,
            started_at=datetime.now(timezone.utc),
            config={
                "concurrency": self.concurrency,
                "per_task_timeout_s": self.per_task_timeout_s,
                "pipeline_args": self.pipeline_args,
                "env_overrides": list(self.env_overrides.keys()),
            },
        )

        self.output_root.mkdir(parents=True, exist_ok=True)
        run_dir = self.output_root / f"run_{run.run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)
        self._write_summary(run, run_dir)

        LOG.info(
            "benchmark=%s tasks=%d concurrency=%d output=%s",
            self.adapter.name,
            len(tasks),
            self.concurrency,
            run_dir,
        )

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures: dict[Future[TaskScore], TaskRef] = {
                pool.submit(self._run_task, task, run_dir): task for task in tasks
            }
            for fut in as_completed(futures):
                task = futures[fut]
                try:
                    score = fut.result()
                except Exception as exc:  # noqa: BLE001
                    LOG.exception("task %s failed with unhandled error", task.task_id)
                    score = TaskScore(
                        task_ref=task,
                        success=False,
                        failure_reason=f"unhandled: {type(exc).__name__}: {exc}",
                    )
                with self._summary_lock:
                    run.task_scores.append(score)
                    self._write_summary(run, run_dir)

        run.finished_at = datetime.now(timezone.utc)
        self._write_summary(run, run_dir)
        self._write_markdown(run, run_dir)
        return run

    def _run_task(self, task: TaskRef, run_dir: Path) -> TaskScore:
        task_dir = run_dir / task.task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        prepared: PreparedTask | None = None
        result_path = task_dir / "run.json"
        log_path = task_dir / "log.jsonl"
        state_dir = task_dir / "state"
        score_path = task_dir / "score.json"
        cmd_path = task_dir / "command.txt"

        try:
            prepared = self.adapter.prepare(task, task_dir / "prepared")
            (task_dir / "prepared.json").write_text(prepared.model_dump_json(indent=2))

            cmd = self._build_command(prepared, result_path, log_path, state_dir)
            cmd_path.write_text(" ".join(cmd) + "\n")

            env = os.environ.copy()
            env.update(self.env_overrides)
            env.setdefault("KAI_LOG_STRUCTURED", "1")

            start = time.monotonic()
            try:
                completed = subprocess.run(
                    cmd,
                    cwd=REPO_ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=self.per_task_timeout_s,
                    check=False,
                )
                duration = time.monotonic() - start
                exit_code = completed.returncode
                (task_dir / "stdout.log").write_text(completed.stdout)
                (task_dir / "stderr.log").write_text(completed.stderr)
            except subprocess.TimeoutExpired as exc:
                duration = time.monotonic() - start
                exit_code = -1
                partial_stdout = _as_text(exc.stdout)
                partial_stderr = _as_text(exc.stderr)
                (task_dir / "stdout.log").write_text(partial_stdout)
                (task_dir / "stderr.log").write_text(
                    f"TIMEOUT after {self.per_task_timeout_s}s\n{partial_stderr}"
                )
                pipeline_result = self._read_result(result_path)
                score = TaskScore(
                    task_ref=task,
                    success=False,
                    failure_reason=f"timeout after {self.per_task_timeout_s}s",
                    pipeline_exit_code=exit_code,
                    pipeline_duration_s=duration,
                    pipeline_result_path=result_path if result_path.exists() else None,
                    state_dir=state_dir if state_dir.exists() else None,
                )
                score_path.write_text(score.model_dump_json(indent=2))
                return score

            pipeline_result = self._read_result(result_path)
            score = self.adapter.score(prepared, pipeline_result, exit_code)
            score = score.model_copy(
                update={
                    "pipeline_exit_code": exit_code,
                    "pipeline_duration_s": duration,
                    "pipeline_result_path": result_path
                    if result_path.exists()
                    else None,
                    "state_dir": state_dir if state_dir.exists() else None,
                }
            )
            score_path.write_text(score.model_dump_json(indent=2))
            return score
        finally:
            if prepared is not None:
                try:
                    self.adapter.cleanup(prepared)
                except Exception:  # noqa: BLE001
                    LOG.exception("cleanup failed for task %s", task.task_id)

    def _build_command(
        self,
        prepared: PreparedTask,
        result_path: Path,
        log_path: Path,
        state_dir: Path,
    ) -> list[str]:
        cmd = [
            sys.executable,
            "-m",
            PIPELINE_MODULE,
            "pipeline",
        ]
        if prepared.recipe_path is not None:
            cmd.extend(["--recipe", str(prepared.recipe_path)])
        else:
            cmd.extend(["--repo-path", str(prepared.repo_path)])
        cmd.extend(
            [
                "--output",
                str(result_path),
                "--state-dir",
                str(state_dir),
                "--log-file",
                str(log_path),
                "--log-structured",
                "--save-rollouts",
            ]
        )
        if prepared.prompt_extras:
            cmd.extend(["--instructions", prepared.prompt_extras])
        cmd.extend(self.pipeline_args)
        return cmd

    @staticmethod
    def _read_result(path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            LOG.exception("result JSON at %s is not parseable", path)
            return None

    @staticmethod
    def _write_summary(run: BenchmarkRun, run_dir: Path) -> None:
        (run_dir / "summary.json").write_text(run.model_dump_json(indent=2))

    @staticmethod
    def _write_markdown(run: BenchmarkRun, run_dir: Path) -> None:
        lines = [
            f"# {run.benchmark} — run {run.run_id}",
            "",
            f"- started: `{run.started_at.isoformat()}`",
            f"- finished: `{run.finished_at.isoformat() if run.finished_at else '—'}`",
            f"- pass / fail: **{run.pass_count} / {run.fail_count}**",
            "",
            "| task_id | success | exit | duration_s | failure_reason |",
            "|---|---|---|---|---|",
        ]
        for score in run.task_scores:
            lines.append(
                "| {tid} | {ok} | {ec} | {dur} | {reason} |".format(
                    tid=score.task_ref.task_id,
                    ok="✅" if score.success else "❌",
                    ec=score.pipeline_exit_code
                    if score.pipeline_exit_code is not None
                    else "—",
                    dur=(
                        f"{score.pipeline_duration_s:.1f}"
                        if score.pipeline_duration_s is not None
                        else "—"
                    ),
                    reason=(score.failure_reason or "").replace("\n", " ")[:80],
                )
            )
        (run_dir / "summary.md").write_text("\n".join(lines) + "\n")


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
