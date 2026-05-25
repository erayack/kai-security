"""Verify cybergym spawn gate decouples sub-agents from parent cancel_event.

R34 evidence: even with KAI_EXEC_TIMEOUT=3600 + KAI_ITER_WALL_CAP=1800
+ KAI_LLM_REQUEST_TIMEOUT_S=900, sub-agent (researcher/verifier)
invocations consistently emit the ABORTED marker — cancel_event is
set when the sub-agent's RLM loop entry checks it.

`_apply_cybergym_spawn_gate` now nulls ``inner_fn._cancel_event``
before invoking the sub-agent, then restores it. This means the
sub-agent's RLM constructor pops `cancel_event=None` and skips the
loop-entry cancel check. Sub-agents run to their own time bounds.

Other benchmarks (bountybench, evmbench) are unaffected — the gate
is only applied when ``inject_state_manager`` is called for a
cybergym pipeline.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import MagicMock

import pytest

from kai.state import cybergym_gate
from kai.state.integration import _apply_cybergym_spawn_gate


@pytest.fixture(autouse=True)
def _reset_gate(monkeypatch):
    cybergym_gate.reset()
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    yield
    cybergym_gate.reset()


def _make_fake_spawn(name: str) -> Any:
    """Build a fake bare-_spawn-style closure with the expected attrs."""

    captured: dict[str, Any] = {}

    def fake_spawn(**kwargs: Any) -> str:
        # Capture what the sub-agent sees for _cancel_event AT CALL TIME
        captured["cancel_event"] = getattr(fake_spawn, "_cancel_event", "MISSING")
        return f"{name}_OK"

    fake_spawn._cancel_event = None  # type: ignore[attr-defined]
    fake_spawn._captured = captured  # type: ignore[attr-defined]
    return fake_spawn


def _make_factory(inner: Any) -> Any:
    """Pretend the upstream stack wraps spawn fns through a factory."""

    def factory(original_fn: Any) -> Any:
        return inner

    return factory


def test_gate_nulls_cancel_event_before_sub_agent(monkeypatch):
    """Pre-set cancel_event → temporarily nulled while sub-agent runs."""
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()  # bypass the spawn cap

    # Pre-set the parent cancel_event to simulate an orphan-worker race
    parent_event = threading.Event()
    parent_event.set()

    fake_analyzer = _make_fake_spawn("analyzer")
    fake_analyzer._cancel_event = parent_event  # type: ignore[attr-defined]

    wrappers: dict[str, Any] = {"spawn_analyzer": _make_factory(fake_analyzer)}
    _apply_cybergym_spawn_gate(wrappers)

    # Build the wrapped function as inject_state_manager would
    wrapped = wrappers["spawn_analyzer"](MagicMock())
    result = wrapped(hypothesis="x", file="x.c", function="f")

    assert result == "analyzer_OK"
    # The sub-agent saw _cancel_event = None at call time
    assert fake_analyzer._captured["cancel_event"] is None
    # After the call, the original cancel_event is restored
    assert fake_analyzer._cancel_event is parent_event


def test_gate_restores_cancel_event_on_exception(monkeypatch):
    """Sub-agent raises → original cancel_event still restored."""
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()

    parent_event = threading.Event()

    def failing_spawn(**kwargs: Any) -> str:
        raise RuntimeError("sub-agent boom")

    failing_spawn._cancel_event = parent_event  # type: ignore[attr-defined]

    wrappers: dict[str, Any] = {"spawn_analyzer": _make_factory(failing_spawn)}
    _apply_cybergym_spawn_gate(wrappers)

    wrapped = wrappers["spawn_analyzer"](MagicMock())
    with pytest.raises(RuntimeError, match="sub-agent boom"):
        wrapped(hypothesis="x")

    # Original event reference preserved through the exception
    assert failing_spawn._cancel_event is parent_event


def test_gate_wraps_all_sub_agents(monkeypatch):
    """All four cybergym sub-agents (analyzer/researcher/verifier/critic +
    fixer) get the decouple treatment."""
    cybergym_gate.init()

    wrappers: dict[str, Any] = {}
    fake_spawns = {}
    for name in ["analyzer", "researcher", "verifier", "critic", "fixer"]:
        fake = _make_fake_spawn(name)
        fake_spawns[name] = fake
        wrappers[f"spawn_{name}"] = _make_factory(fake)

    _apply_cybergym_spawn_gate(wrappers)

    parent_event = threading.Event()
    parent_event.set()

    # spawn_verifier marks verifier_called → also unblocks subsequent
    # spawn caps. Call it first to allow other spawns under the cap.
    fake_spawns["verifier"]._cancel_event = parent_event
    wrappers["spawn_verifier"](MagicMock())(hypothesis="x")
    assert fake_spawns["verifier"]._captured["cancel_event"] is None

    for name in ["analyzer", "researcher", "critic", "fixer"]:
        fake_spawns[name]._cancel_event = parent_event
        wrappers[f"spawn_{name}"](MagicMock())(hypothesis="x")
        assert fake_spawns[name]._captured["cancel_event"] is None, (
            f"spawn_{name} did NOT have its cancel_event nulled"
        )


def test_gate_handles_unsettable_cancel_event(monkeypatch):
    """If inner_fn._cancel_event setter raises AttributeError, the gate
    still calls inner_fn (skip the null trick, accept whatever happens
    next)."""
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()

    class _NoAttrSpawn:
        # A callable that disallows setting _cancel_event
        __slots__ = ()

        def __call__(self, **kwargs: Any) -> str:
            return "no_attr_OK"

    no_attr = _NoAttrSpawn()
    wrappers: dict[str, Any] = {"spawn_analyzer": _make_factory(no_attr)}
    _apply_cybergym_spawn_gate(wrappers)

    wrapped = wrappers["spawn_analyzer"](MagicMock())
    result = wrapped(hypothesis="x")
    # Doesn't crash; inner_fn still ran
    assert result == "no_attr_OK"
