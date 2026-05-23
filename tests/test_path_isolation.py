"""Tests for the cybergym cross-task path isolation guard."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from kai.utils.path_isolation import (
    SiblingTaskAccessBlocked,
    assert_task_isolation,
)


@pytest.fixture
def cybergym_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_TASK_ID", "arvo:48736")


def test_no_op_outside_cybergym(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KAI_BENCHMARK", raising=False)
    monkeypatch.delenv("KAI_TASK_ID", raising=False)
    assert_task_isolation("output/bench/cybergym/run_x/arvo:1065/state")


def test_no_op_without_task_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.delenv("KAI_TASK_ID", raising=False)
    assert_task_isolation("output/bench/cybergym/run_x/arvo:1065/state")


def test_blocks_sibling_task(cybergym_env: None) -> None:
    with pytest.raises(SiblingTaskAccessBlocked):
        assert_task_isolation(
            "output/bench/cybergym/run_x/arvo:1065/state/exploits.jsonl"
        )


def test_blocks_absolute_sibling_path(cybergym_env: None) -> None:
    with pytest.raises(SiblingTaskAccessBlocked):
        assert_task_isolation("/app/output/bench/cybergym/run_abc/arvo:1065/state")


def test_allows_current_task(cybergym_env: None) -> None:
    assert_task_isolation("output/bench/cybergym/run_x/arvo:48736/state/exploits.jsonl")


def test_allows_unrelated_paths(cybergym_env: None) -> None:
    assert_task_isolation("/tmp/cybergym_seeds/file/")
    assert_task_isolation("description.txt")
    assert_task_isolation("/etc/hosts")


def test_blocks_other_benchmark_unaffected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KAI_BENCHMARK", "evmbench")
    monkeypatch.setenv("KAI_TASK_ID", "task-a")
    assert_task_isolation("output/bench/cybergym/run_x/arvo:1065/state")


def test_pathlib_input(cybergym_env: None) -> None:
    with pytest.raises(SiblingTaskAccessBlocked):
        assert_task_isolation(Path("output/bench/cybergym/run_x/arvo:1065/state"))


def test_repl_open_guard_blocks_sibling(
    cybergym_env: None,
    tmp_path: Path,
) -> None:
    """The LocalREPL ``open`` wrapper rejects sibling-task paths."""
    from ra.environments.local_repl import _guarded_open

    sibling = (
        tmp_path
        / "output"
        / "bench"
        / "cybergym"
        / "run_x"
        / "arvo:1065"
        / "state"
        / "exploits.jsonl"
    )
    sibling.parent.mkdir(parents=True)
    sibling.write_text("hypothesis: reentrancy")
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        with pytest.raises(PermissionError):
            _guarded_open("output/bench/cybergym/run_x/arvo:1065/state/exploits.jsonl")
    finally:
        os.chdir(cwd)


def test_repl_open_guard_allows_current(
    cybergym_env: None,
    tmp_path: Path,
) -> None:
    from ra.environments.local_repl import _guarded_open

    current = (
        tmp_path
        / "output"
        / "bench"
        / "cybergym"
        / "run_x"
        / "arvo:48736"
        / "state"
        / "exploits.jsonl"
    )
    current.parent.mkdir(parents=True)
    current.write_text("hypothesis: own task")
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        with _guarded_open(
            "output/bench/cybergym/run_x/arvo:48736/state/exploits.jsonl"
        ) as f:
            assert "own task" in f.read()
    finally:
        os.chdir(cwd)
