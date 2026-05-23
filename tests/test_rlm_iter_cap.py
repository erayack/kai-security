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
        def execute_code(self, code, max_time=None):  # type: ignore[no-untyped-def]
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


def test_execute_code_max_time_clamps_local_repl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """``LocalREPL.execute_code(max_time=N)`` honours the per-call cap.

    Regression for the codex finding that the wall-clock check before
    each block was useless when a single block could still run for
    KAI_EXEC_TIMEOUT seconds.
    """
    from ra.environments.local_repl import LocalREPL

    env = LocalREPL.__new__(LocalREPL)
    env._exec_timeout = 60  # default per-block cap
    env._pending_llm_calls = []
    env._tools = {}
    env.globals = {"__builtins__": __builtins__}
    env.locals = {}

    # Stub the parts of LocalREPL.execute_code that we don't need.
    monkeypatch.setattr(
        env, "_split_last_expr", lambda code: (code, None), raising=False
    )
    monkeypatch.setattr(env, "_find_assignment_targets", lambda code: [], raising=False)
    monkeypatch.setattr(env, "_writeback_locals", lambda *a, **kw: None, raising=False)

    import contextlib
    import io

    @contextlib.contextmanager
    def _fake_capture():
        yield io.StringIO(), io.StringIO()

    @contextlib.contextmanager
    def _fake_temp_cwd():
        yield

    monkeypatch.setattr(env, "_capture_output", _fake_capture, raising=False)
    monkeypatch.setattr(env, "_temp_cwd", _fake_temp_cwd, raising=False)

    start = time.perf_counter()
    result = env.execute_code("import time; time.sleep(5)", max_time=1)
    elapsed = time.perf_counter() - start

    # max_time=1 clamps the inner worker.join to 1s; the call
    # returns the TimeoutError quickly instead of waiting 5s or 60s.
    assert elapsed < 3.5
    assert result.exception_name == "TimeoutError"
    assert "1s limit" in result.stderr


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
        def execute_code(self, code, max_time=None):  # type: ignore[no-untyped-def]
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


def test_rollout_hook_persists_dropped_blocks(tmp_path) -> None:
    """``make_rollout_on_iteration_hook`` must serialize the new fields."""
    import json

    from kai.state.hooks import make_rollout_on_iteration_hook
    from kai.state.local import LocalStateManager

    mgr = LocalStateManager(state_dir=str(tmp_path))
    hook = make_rollout_on_iteration_hook(
        mgr, run_id="r", agent_name="exploit", depth=0
    )
    iteration = RLMIteration(
        prompt="root",
        response="capped iter",
        code_blocks=[],
        dropped_blocks=5,
        truncation_notice="[harness notice] dropped 5 blocks",
        iteration_time=601.2,
    )
    hook(iteration, 3)
    rollout_files = list(tmp_path.rglob("exploit.jsonl"))
    assert rollout_files, "rollout jsonl was not created"
    contents = rollout_files[0].read_text().strip().splitlines()
    iter_records = [
        json.loads(line) for line in contents if json.loads(line).get("iteration") == 3
    ]
    assert iter_records, "iteration record missing from rollout jsonl"
    rec = iter_records[0]
    assert rec["dropped_blocks"] == 5
    assert "dropped 5 blocks" in rec["truncation_notice"]
    assert rec["iteration_time"] == pytest.approx(601.2)


def test_status_hook_fires_on_capped_iter(tmp_path) -> None:
    """Status hook must NOT skip when iteration was harness-capped."""
    from kai.state.hooks import make_on_iteration_hook
    from kai.state.local import LocalStateManager

    mgr = LocalStateManager(state_dir=str(tmp_path))
    hook = make_on_iteration_hook(mgr, run_id="r", agent_name="exploit")
    iteration = RLMIteration(
        prompt="root",
        response="wall capped before any block executed",
        code_blocks=[],
        dropped_blocks=8,
        truncation_notice="[harness notice] wall-clock cap",
        iteration_time=605.0,
    )
    hook(iteration, 5)
    updates = list(mgr.get_status_updates("r"))
    assert any(u.iteration_num == 5 for u in updates), (
        "capped iteration with zero blocks was silently dropped from status_updates"
    )
    capped = next(u for u in updates if u.iteration_num == 5)
    assert capped.dropped_blocks == 8
    assert capped.truncation_notice is not None


def test_status_hook_skips_truly_empty_iter(tmp_path) -> None:
    """Status hook still skips iterations with no work and no cap."""
    from kai.state.hooks import make_on_iteration_hook
    from kai.state.local import LocalStateManager

    mgr = LocalStateManager(state_dir=str(tmp_path))
    hook = make_on_iteration_hook(mgr, run_id="r", agent_name="exploit")
    iteration = RLMIteration(prompt="root", response="", code_blocks=[])
    hook(iteration, 7)
    updates = list(mgr.get_status_updates("r"))
    assert not any(u.iteration_num == 7 for u in updates)
