"""Trivial adapter that does no real work — used to validate harness plumbing."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from evaluation.adapters.base import BenchAdapter, register_adapter
from evaluation.schemas import PreparedTask, TaskRef, TaskScore


class NoopAdapter(BenchAdapter):
    """Always succeeds. Used by ``evaluation.cli run --adapter noop`` plumbing tests.

    The ``count`` config option controls how many synthetic tasks are produced.
    """

    name = "noop"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        self.count = int(config.get("count", 3))

    def list_tasks(self) -> Iterable[TaskRef]:
        for i in range(self.count):
            yield TaskRef(benchmark=self.name, task_id=f"noop-{i:03d}")

    def prepare(self, task: TaskRef, workdir: Path) -> PreparedTask:
        repo = workdir / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "README.md").write_text(
            f"# Synthetic noop task {task.task_id}\n\n"
            "This task has no real content. The harness should be able to "
            "shell out to `kai.main`, time-out or finish quickly, and still "
            "produce a structured TaskScore.\n"
        )
        return PreparedTask(task_ref=task, repo_path=repo, workdir=workdir)

    def score(
        self,
        prepared: PreparedTask,
        pipeline_result: dict[str, Any] | None,
        exit_code: int,
    ) -> TaskScore:
        return TaskScore(
            task_ref=prepared.task_ref,
            success=True,
            details={
                "note": "noop adapter always reports success",
                "pipeline_returned_result": pipeline_result is not None,
            },
            pipeline_exit_code=exit_code,
        )


@register_adapter("noop")
def _factory(config: dict[str, Any]) -> NoopAdapter:
    return NoopAdapter(config)
