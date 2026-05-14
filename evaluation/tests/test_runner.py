"""Integration tests for :class:`BenchmarkRunner` without invoking kai.main.

The runner shells out via ``subprocess.run`` — we monkeypatch that out so
the tests verify end-to-end plumbing (artefact paths, score persistence,
adapter cleanup, summary aggregation) without paying for real LLM calls.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from evaluation import runner as runner_module
from evaluation.adapters.base import BenchAdapter
from evaluation.runner import BenchmarkRunner
from evaluation.schemas import PreparedTask, TaskRef, TaskScore


class _Adapter(BenchAdapter):
    name = "fake"

    def __init__(self) -> None:
        self.cleanup_calls: list[str] = []

    def list_tasks(self) -> Iterable[TaskRef]:
        yield TaskRef(benchmark=self.name, task_id="t1")
        yield TaskRef(benchmark=self.name, task_id="t2")

    def prepare(self, task: TaskRef, workdir: Path) -> PreparedTask:
        workdir.mkdir(parents=True, exist_ok=True)
        repo = workdir / "repo"
        repo.mkdir()
        (repo / "marker").write_text(task.task_id)
        return PreparedTask(task_ref=task, repo_path=repo, workdir=workdir)

    def score(
        self,
        prepared: PreparedTask,
        pipeline_result: dict[str, Any] | None,
        exit_code: int,
    ) -> TaskScore:
        return TaskScore(
            task_ref=prepared.task_ref,
            success=exit_code == 0,
            details={"pipeline_result_was_none": pipeline_result is None},
        )

    def cleanup(self, prepared: PreparedTask) -> None:
        self.cleanup_calls.append(prepared.task_ref.task_id)


def _patch_subprocess_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    exit_code: int = 0,
    raise_timeout: bool = False,
    write_result: dict[str, Any] | None = None,
) -> list[list[str]]:
    """Replace ``subprocess.run`` with a stub that records calls + writes a result JSON."""

    calls: list[list[str]] = []

    def fake_run(
        cmd: list[str], *, cwd: Path, env: dict[str, str], **_kwargs: Any
    ) -> SimpleNamespace:
        calls.append(cmd)
        if raise_timeout:
            raise subprocess.TimeoutExpired(cmd, timeout=5, output=b"", stderr=b"")
        if write_result is not None:
            out_index = cmd.index("--output") + 1
            Path(cmd[out_index]).write_text(json.dumps(write_result))
        return SimpleNamespace(returncode=exit_code, stdout="ok\n", stderr="")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    return calls


def test_runner_writes_summary_and_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _Adapter()
    calls = _patch_subprocess_run(monkeypatch, exit_code=0, write_result={"result": []})

    runner = BenchmarkRunner(adapter, output_root=tmp_path)
    tasks = list(adapter.list_tasks())
    run = runner.run(tasks)

    assert run.pass_count == 2
    assert run.fail_count == 0
    assert len(calls) == 2

    bench_dir = tmp_path / "fake"
    run_dir = next(bench_dir.iterdir())
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "summary.md").exists()
    for task in tasks:
        td = run_dir / task.task_id
        assert (td / "score.json").exists()
        assert (td / "prepared.json").exists()
        assert (td / "command.txt").exists()
        score = TaskScore.model_validate_json((td / "score.json").read_text())
        assert score.pipeline_exit_code == 0


def test_runner_records_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _Adapter()
    _patch_subprocess_run(monkeypatch, raise_timeout=True)

    runner = BenchmarkRunner(adapter, output_root=tmp_path, per_task_timeout_s=5)
    run = runner.run([next(iter(adapter.list_tasks()))])
    assert run.fail_count == 1
    assert "timeout" in (run.task_scores[0].failure_reason or "")


def test_runner_propagates_env_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen_env: dict[str, str] = {}

    def fake_run(cmd, *, cwd, env, **_kwargs):
        seen_env.update(env)
        out_index = cmd.index("--output") + 1
        Path(cmd[out_index]).write_text("{}")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)

    adapter = _Adapter()
    runner = BenchmarkRunner(
        adapter,
        output_root=tmp_path,
        env_overrides={"KAI_ROOT_ITERS": "5", "EXTRA_KEY": "yes"},
    )
    runner.run([next(iter(adapter.list_tasks()))])
    assert seen_env.get("KAI_ROOT_ITERS") == "5"
    assert seen_env.get("EXTRA_KEY") == "yes"
    assert seen_env.get("KAI_LOG_STRUCTURED") == "1"


def test_runner_calls_cleanup_for_each_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _Adapter()
    _patch_subprocess_run(monkeypatch, write_result={"result": []})
    runner = BenchmarkRunner(adapter, output_root=tmp_path)
    runner.run(list(adapter.list_tasks()))
    assert sorted(adapter.cleanup_calls) == ["t1", "t2"]


def test_runner_pipeline_arg_forwarding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _Adapter()
    calls = _patch_subprocess_run(monkeypatch, write_result={"result": []})
    runner = BenchmarkRunner(
        adapter,
        output_root=tmp_path,
        pipeline_args=["--skip-fixer", "--no-iterative"],
    )
    runner.run([next(iter(adapter.list_tasks()))])
    assert "--skip-fixer" in calls[0]
    assert "--no-iterative" in calls[0]


def test_runner_nonzero_exit_marks_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _Adapter()
    _patch_subprocess_run(monkeypatch, exit_code=2, write_result=None)
    runner = BenchmarkRunner(adapter, output_root=tmp_path)
    run = runner.run([next(iter(adapter.list_tasks()))])
    assert run.fail_count == 1
    score = run.task_scores[0]
    assert score.success is False
    assert score.pipeline_exit_code == 2
