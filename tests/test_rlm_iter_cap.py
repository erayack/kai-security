"""Tests for the per-iteration wall-clock and block-count caps.

Covers:
* default env (no overrides) → block cap = 6, wall cap = 600s.
* env override changes both caps.
* truncation notice is non-None when blocks are dropped.
* ``format_iteration`` surfaces the notice in the next iter prompt.
"""

from __future__ import annotations

import time

import pytest

from ra.core.rlm import (
    _DEFAULT_ITER_WALL_CAP_S,
    _DEFAULT_MAX_BLOCKS_PER_ITER,
    _format_truncation_notice,
    _read_iter_wall_cap,
    _read_max_blocks_per_iter,
)
from ra.core.types import CodeBlock, REPLResult, RLMIteration
from ra.utils.parsing import format_iteration


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KAI_ITER_WALL_CAP", raising=False)
    monkeypatch.delenv("KAI_MAX_BLOCKS_PER_ITER", raising=False)
    assert _read_iter_wall_cap() == _DEFAULT_ITER_WALL_CAP_S
    assert _read_max_blocks_per_iter() == _DEFAULT_MAX_BLOCKS_PER_ITER


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_ITER_WALL_CAP", "120")
    monkeypatch.setenv("KAI_MAX_BLOCKS_PER_ITER", "3")
    assert _read_iter_wall_cap() == 120.0
    assert _read_max_blocks_per_iter() == 3


def test_env_zero_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_ITER_WALL_CAP", "0")
    monkeypatch.setenv("KAI_MAX_BLOCKS_PER_ITER", "0")
    assert _read_iter_wall_cap() == 0.0
    assert _read_max_blocks_per_iter() == 0


def test_env_invalid_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KAI_ITER_WALL_CAP", "abc")
    monkeypatch.setenv("KAI_MAX_BLOCKS_PER_ITER", "xyz")
    assert _read_iter_wall_cap() == _DEFAULT_ITER_WALL_CAP_S
    assert _read_max_blocks_per_iter() == _DEFAULT_MAX_BLOCKS_PER_ITER


def test_notice_none_when_nothing_dropped() -> None:
    assert (
        _format_truncation_notice(
            iteration_num=1,
            iteration_time=1.0,
            wall_cap=600.0,
            max_blocks=6,
            total_emitted=3,
            executed=3,
            wall_capped_at=None,
            block_capped_at=None,
        )
        is None
    )


def test_notice_block_cap() -> None:
    notice = _format_truncation_notice(
        iteration_num=1,
        iteration_time=12.0,
        wall_cap=600.0,
        max_blocks=6,
        total_emitted=42,
        executed=6,
        wall_capped_at=None,
        block_capped_at=6,
    )
    assert notice is not None
    assert "executed 6 of the 42" in notice
    assert "block cap" in notice
    assert "KAI_MAX_BLOCKS_PER_ITER=6" in notice
    assert "ONE concrete" in notice


def test_notice_wall_cap() -> None:
    notice = _format_truncation_notice(
        iteration_num=2,
        iteration_time=620.0,
        wall_cap=600.0,
        max_blocks=6,
        total_emitted=5,
        executed=3,
        wall_capped_at=3,
        block_capped_at=None,
    )
    assert notice is not None
    assert "wall-clock cap of 600s" in notice
    assert "after 620s" in notice


def test_notice_both_caps() -> None:
    notice = _format_truncation_notice(
        iteration_num=3,
        iteration_time=605.0,
        wall_cap=600.0,
        max_blocks=4,
        total_emitted=10,
        executed=3,
        wall_capped_at=3,
        block_capped_at=4,
    )
    assert notice is not None
    assert "block cap" in notice
    assert "wall-clock cap" in notice


def test_format_iteration_surfaces_notice() -> None:
    """``format_iteration`` must inject the notice as a user message."""
    iteration = RLMIteration(
        prompt="root prompt",
        response="assistant response",
        code_blocks=[
            CodeBlock(
                code="print(1)",
                result=REPLResult(
                    stdout="1\n", stderr="", locals={}, exception_name=None
                ),
            ),
        ],
        truncation_notice="[harness notice] dropped 3 blocks",
        dropped_blocks=3,
    )
    messages = format_iteration(iteration)
    assert messages[-1]["role"] == "user"
    assert "dropped 3 blocks" in messages[-1]["content"]


def test_format_iteration_no_notice_when_unset() -> None:
    iteration = RLMIteration(
        prompt="root prompt",
        response="assistant response",
        code_blocks=[
            CodeBlock(
                code="print(1)",
                result=REPLResult(
                    stdout="1\n", stderr="", locals={}, exception_name=None
                ),
            ),
        ],
    )
    messages = format_iteration(iteration)
    # Should be exactly assistant + 1 user (code exec); no extra notice.
    assert len(messages) == 2
    assert messages[0]["role"] == "assistant"
    assert messages[1]["role"] == "user"


def test_completion_turn_block_cap_drops_excess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: when LLM emits > cap blocks, harness runs cap and drops rest."""
    from ra.core import rlm as rlm_module

    monkeypatch.setenv("KAI_MAX_BLOCKS_PER_ITER", "3")
    monkeypatch.setenv("KAI_ITER_WALL_CAP", "600")

    # Stub find_code_blocks to return 8 block strings.
    monkeypatch.setattr(
        rlm_module,
        "find_code_blocks",
        lambda response: [f"# block {i}" for i in range(8)],
    )

    class _FakeLM:
        def completion(self, prompt):  # type: ignore[no-untyped-def]
            return "fake response with 8 blocks"

    class _FakeEnv:
        def execute_code(self, code):  # type: ignore[no-untyped-def]
            return REPLResult(stdout="ok", stderr="", locals={}, exception_name=None)

    class _FakeVerbose:
        def print_iteration_start(self, n):  # type: ignore[no-untyped-def]
            pass

        def print_completion(self, *a, **kw):  # type: ignore[no-untyped-def]
            pass

        def print_pre_execution(self, *a, **kw):  # type: ignore[no-untyped-def]
            pass

        def print_code_execution(self, *a, **kw):  # type: ignore[no-untyped-def]
            pass

        def print_subcall(self, *a, **kw):  # type: ignore[no-untyped-def]
            pass

    rlm_instance = rlm_module.RLM.__new__(rlm_module.RLM)
    rlm_instance.verbose = _FakeVerbose()

    iteration = rlm_module.RLM._completion_turn(
        rlm_instance,
        prompt="anything",
        lm_handler=_FakeLM(),
        environment=_FakeEnv(),
        iteration_num=1,
    )

    assert len(iteration.code_blocks) == 3
    assert iteration.dropped_blocks == 5
    assert iteration.truncation_notice is not None
    assert "KAI_MAX_BLOCKS_PER_ITER=3" in iteration.truncation_notice


def test_completion_turn_wall_cap_aborts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wall-clock cap aborts the for-loop before the remaining blocks run."""
    from ra.core import rlm as rlm_module

    monkeypatch.setenv("KAI_ITER_WALL_CAP", "1")  # 1s wall budget
    monkeypatch.setenv("KAI_MAX_BLOCKS_PER_ITER", "10")

    monkeypatch.setattr(
        rlm_module,
        "find_code_blocks",
        lambda response: [f"# block {i}" for i in range(5)],
    )

    class _FakeLM:
        def completion(self, prompt):  # type: ignore[no-untyped-def]
            return "slow response"

    class _SlowEnv:
        def execute_code(self, code):  # type: ignore[no-untyped-def]
            time.sleep(0.6)
            return REPLResult(stdout="ok", stderr="", locals={}, exception_name=None)

    class _FakeVerbose:
        def print_iteration_start(self, n):  # type: ignore[no-untyped-def]
            pass

        def print_completion(self, *a, **kw):  # type: ignore[no-untyped-def]
            pass

        def print_pre_execution(self, *a, **kw):  # type: ignore[no-untyped-def]
            pass

        def print_code_execution(self, *a, **kw):  # type: ignore[no-untyped-def]
            pass

        def print_subcall(self, *a, **kw):  # type: ignore[no-untyped-def]
            pass

    rlm_instance = rlm_module.RLM.__new__(rlm_module.RLM)
    rlm_instance.verbose = _FakeVerbose()

    iteration = rlm_module.RLM._completion_turn(
        rlm_instance,
        prompt="anything",
        lm_handler=_FakeLM(),
        environment=_SlowEnv(),
        iteration_num=1,
    )

    # 5 blocks × 0.6s = 3s; 1s cap should stop us after 2 blocks
    # (the third block's pre-loop elapsed check trips).
    assert len(iteration.code_blocks) < 5
    assert iteration.truncation_notice is not None
    assert "wall-clock cap" in iteration.truncation_notice
