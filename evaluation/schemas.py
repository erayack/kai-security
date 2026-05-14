"""Pydantic models shared across the evaluation harness.

These types are deliberately benchmark-agnostic. Adapter-specific payloads
live inside the free-form ``metadata`` / ``details`` / ``oracle`` dicts so
that adding a new adapter does not require schema changes here.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class TaskRef(BaseModel):
    """Stable identifier for a single benchmark task."""

    benchmark: str
    task_id: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class PreparedTask(BaseModel):
    """A task that has been materialised on disk and is ready to run."""

    task_ref: TaskRef
    repo_path: Path
    workdir: Path
    prompt_extras: str | None = None
    oracle: dict[str, Any] = Field(default_factory=dict)
    recipe_path: Path | None = None
    """Optional pre-baked WorkspaceRecipe JSON.

    When set, the runner invokes ``kai.main pipeline --recipe <path>``
    instead of ``--repo-path``, which skips the setup agent entirely.
    Useful for static-analysis benchmarks (e.g. BountyBench DETECT) where
    we don't want or can't run a real build on the worker container.
    """


class TaskScore(BaseModel):
    """Outcome of a single task after the pipeline + adapter scoring step."""

    task_ref: TaskRef
    success: bool
    details: dict[str, Any] = Field(default_factory=dict)
    failure_reason: str | None = None
    pipeline_exit_code: int | None = None
    pipeline_duration_s: float | None = None
    pipeline_result_path: Path | None = None
    state_dir: Path | None = None
    cost: dict[str, Any] | None = None


class BenchmarkRun(BaseModel):
    """Aggregate of one harness invocation across many tasks."""

    run_id: str
    benchmark: str
    started_at: datetime
    finished_at: datetime | None = None
    task_scores: list[TaskScore] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)

    @property
    def pass_count(self) -> int:
        return sum(1 for s in self.task_scores if s.success)

    @property
    def fail_count(self) -> int:
        return sum(1 for s in self.task_scores if not s.success)
