"""Tests for cancel_event handling in the RecursiveAgent spawn wrapper.

R27-R32 cybergym verifier sub-agents consistently hit a silent
synthetic-iter fallback path: orphan worker threads (Python daemon
threads from timed-out execute_code calls cannot be killed) eventually
reached spawn_verifier lines while their parent's cancel_event was
already set. The sub-agent broke on iter-1 entry, fell through to
_default_answer, and emitted a "Unable to verify... iteration limit
was reached" JSON that looked like an organic model response.

These tests pin the two fixes in place:

1. ``ra.agents.agent._spawn`` short-circuits with a BYPASS marker
   (and bypass rollout) when ``_cancel_event.is_set()`` at call time.
2. ``ra.core.rlm.RLM.completion`` tracks the loop exit reason and
   does NOT call ``_default_answer`` on cancel — substitutes an
   explicit ``ABORTED:`` marker.

Regression-only — if either condition fires in production, a clear
WARNING log + distinctive marker text becomes visible to operators
instead of a misleading silent JSON.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch


from ra.agents.agent import _make_spawn_fn
from ra.agents.config import RecursiveAgentConfig


def _make_config(name: str = "verifier") -> RecursiveAgentConfig:
    """Build a minimal config — enough to satisfy validate() and replace()."""
    return RecursiveAgentConfig(
        name=name,
        system_prompt="test prompt",
        tools={},
        environment_kwargs={"setup_code": ""},
        backend="ra.clients.openai.OpenAIClient",
        backend_kwargs={"model_name": "openai/gpt-5.5"},
        query_model="openai/gpt-5.5",
        max_iterations=5,
    )


def test_spawn_fails_fast_when_cancel_event_already_set():
    """Pre-set cancel_event → bypass marker, no RecursiveAgent invocation."""
    config = _make_config()
    spawn = _make_spawn_fn(config, parent_depth=0, max_depth=2)
    cancel = threading.Event()
    cancel.set()  # pre-set before spawn is called
    spawn._cancel_event = cancel  # type: ignore[attr-defined]

    with patch("ra.agents.agent.RecursiveAgent") as agent_cls:
        result = spawn(hypothesis="anything", file="x.c", function="f")

    # No sub-agent was constructed
    agent_cls.assert_not_called()
    # The bypass marker text is greppable in rollouts
    assert "BYPASS: spawn_verifier" in result
    assert "cancel_event already set on entry" in result
    # SpawnRecord still recorded so the parent's accounting is intact
    assert len(spawn._spawn_records) == 1  # type: ignore[attr-defined]
    assert spawn._spawn_records[0].result == result  # type: ignore[attr-defined]


def test_spawn_normal_path_when_cancel_event_unset():
    """Unset cancel_event → normal sub-agent invocation."""
    config = _make_config()
    spawn = _make_spawn_fn(config, parent_depth=0, max_depth=2)
    cancel = threading.Event()  # NOT set
    spawn._cancel_event = cancel  # type: ignore[attr-defined]

    fake_agent = MagicMock()
    fake_agent.completion.return_value = "OK"
    with patch("ra.agents.agent.RecursiveAgent", return_value=fake_agent):
        result = spawn(hypothesis="real", file="x.c", function="f")

    fake_agent.completion.assert_called_once()
    assert result == "OK"
    # No BYPASS in result
    assert "BYPASS" not in result


def test_spawn_no_cancel_event_at_all_works():
    """No cancel_event attr → normal sub-agent invocation."""
    config = _make_config()
    spawn = _make_spawn_fn(config, parent_depth=0, max_depth=2)
    # Don't set _cancel_event at all

    fake_agent = MagicMock()
    fake_agent.completion.return_value = "OK"
    with patch("ra.agents.agent.RecursiveAgent", return_value=fake_agent):
        result = spawn(hypothesis="real", file="x.c", function="f")

    fake_agent.completion.assert_called_once()
    assert result == "OK"


def test_spawn_bypass_emits_rollout_when_on_iteration_set():
    """Bypass path goes through _emit_failed_spawn_iteration so the
    sub-agent rollout JSONL still appears on disk (mirrors the existing
    failed-spawn pattern)."""
    config = _make_config()
    captured = []

    def fake_on_iteration(iteration, num):
        captured.append((iteration, num))

    config_with_hook = RecursiveAgentConfig(
        name=config.name,
        system_prompt=config.system_prompt,
        tools=config.tools,
        environment_kwargs=config.environment_kwargs,
        backend=config.backend,
        backend_kwargs=config.backend_kwargs,
        query_model=config.query_model,
        max_iterations=config.max_iterations,
        on_iteration=fake_on_iteration,
    )

    spawn = _make_spawn_fn(config_with_hook, parent_depth=0, max_depth=2)
    cancel = threading.Event()
    cancel.set()
    spawn._cancel_event = cancel  # type: ignore[attr-defined]

    with patch("ra.agents.agent.RecursiveAgent") as agent_cls:
        spawn(hypothesis="x")

    agent_cls.assert_not_called()
    assert len(captured) == 1
    iteration, num = captured[0]
    assert num == 1
    assert "BYPASS: spawn_verifier" in iteration.response
    assert iteration.code_blocks == []
    # final_answer set so rollout writer also emits the result entry
    assert "BYPASS: spawn_verifier" in iteration.final_answer
