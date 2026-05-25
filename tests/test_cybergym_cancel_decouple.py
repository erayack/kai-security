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

import pytest

from kai.state import cybergym_gate
from kai.state.integration import (
    _apply_cybergym_spawn_gate,
    _cybergym_cancel_null,
)


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
    """Pre-set cancel_event → temporarily nulled while sub-agent runs.

    The null happens on the BARE _spawn (which is the factory's
    original_fn argument and what agent.py:148 actually reads),
    NOT on the wrapped intermediate (which a previous version of
    the fix incorrectly targeted, making it a no-op for
    verifier/critic/fixer paths that include spawn_hooks wrappers).
    """
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()  # bypass the spawn cap

    # Pre-set the parent cancel_event to simulate an orphan-worker race
    parent_event = threading.Event()
    parent_event.set()

    bare_spawn = _make_fake_spawn("analyzer")
    bare_spawn._cancel_event = parent_event  # type: ignore[attr-defined]

    # The factory in inject_state_manager is called with the bare _spawn
    # as its argument; the factory builds the wrap chain that ultimately
    # calls bare_spawn. We pass `bare_spawn` as `original_fn` and a
    # MagicMock for the wrapped-chain return value to verify the call
    # path uses bare_spawn for the cancel null.

    # Use a factory that returns bare_spawn directly (simulating no
    # spawn_hooks wrapper for simplicity in this test).
    def factory(original_fn: Any) -> Any:
        # original_fn IS bare_spawn here
        return original_fn

    wrappers: dict[str, Any] = {"spawn_analyzer": factory}
    _apply_cybergym_spawn_gate(wrappers)

    # Now invoke the wrapped factory with bare_spawn as original
    wrapped = wrappers["spawn_analyzer"](bare_spawn)
    result = wrapped(hypothesis="x", file="x.c", function="f")

    assert result == "analyzer_OK"
    # The sub-agent saw _cancel_event = None at call time (on the bare spawn)
    assert bare_spawn._captured["cancel_event"] is None
    # After the call, the original cancel_event is restored on bare_spawn
    assert bare_spawn._cancel_event is parent_event


def test_gate_restores_cancel_event_on_exception(monkeypatch):
    """Sub-agent raises → original cancel_event still restored on bare _spawn."""
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()

    parent_event = threading.Event()

    def failing_spawn(**kwargs: Any) -> str:
        raise RuntimeError("sub-agent boom")

    failing_spawn._cancel_event = parent_event  # type: ignore[attr-defined]

    def factory(original_fn: Any) -> Any:
        return original_fn

    wrappers: dict[str, Any] = {"spawn_analyzer": factory}
    _apply_cybergym_spawn_gate(wrappers)

    wrapped = wrappers["spawn_analyzer"](failing_spawn)
    with pytest.raises(RuntimeError, match="sub-agent boom"):
        wrapped(hypothesis="x")

    # Original event reference preserved through the exception
    assert failing_spawn._cancel_event is parent_event


def test_gate_wraps_all_sub_agents(monkeypatch):
    """All five cybergym sub-agents (analyzer/researcher/verifier/critic/
    fixer) get the decouple treatment when their bare _spawn is passed
    through the factory."""
    cybergym_gate.init()

    wrappers: dict[str, Any] = {}
    fake_spawns = {}
    for name in ["analyzer", "researcher", "verifier", "critic", "fixer"]:
        fake = _make_fake_spawn(name)
        fake_spawns[name] = fake

        def factory(original_fn: Any) -> Any:
            return original_fn

        wrappers[f"spawn_{name}"] = factory

    _apply_cybergym_spawn_gate(wrappers)

    parent_event = threading.Event()
    parent_event.set()

    # spawn_verifier marks verifier_called → also unblocks subsequent
    # spawn caps. Call it first to allow other spawns under the cap.
    fake_spawns["verifier"]._cancel_event = parent_event
    wrappers["spawn_verifier"](fake_spawns["verifier"])(hypothesis="x")
    assert fake_spawns["verifier"]._captured["cancel_event"] is None

    for name in ["analyzer", "researcher", "critic", "fixer"]:
        fake_spawns[name]._cancel_event = parent_event
        wrappers[f"spawn_{name}"](fake_spawns[name])(hypothesis="x")
        assert fake_spawns[name]._captured["cancel_event"] is None, (
            f"spawn_{name} did NOT have its cancel_event nulled"
        )


def test_cancel_null_shim_for_batch_invocation(monkeypatch):
    """Batch spawn tools (spawn_researchers / spawn_analyzers) capture
    the bare _spawn at factory time and call it directly, bypassing
    the singular-path gate. ``_cybergym_cancel_null`` is the shim used
    in those factories to ensure each batched call still nulls the
    parent cancel_event around the sub-agent invocation."""
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")

    bare = _make_fake_spawn("researcher")
    parent_event = threading.Event()
    parent_event.set()
    bare._cancel_event = parent_event

    shim = _cybergym_cancel_null(bare)
    # Shim must be a wrapper, not the bare spawn itself.
    assert shim is not bare

    result = shim(query="what is the bug")
    assert result == "researcher_OK"
    # Sub-agent saw cancel_event=None at call time.
    assert bare._captured["cancel_event"] is None
    # Restored after the call.
    assert bare._cancel_event is parent_event


def test_cancel_null_shim_noop_outside_cybergym(monkeypatch):
    """Outside cybergym, the shim is a pass-through (returns bare_spawn
    unchanged) so other benchmarks keep normal cancel propagation."""
    monkeypatch.delenv("KAI_BENCHMARK", raising=False)

    bare = _make_fake_spawn("researcher")
    result = _cybergym_cancel_null(bare)
    assert result is bare


def test_gate_handles_unsettable_cancel_event(monkeypatch):
    """If bare_spawn._cancel_event setter raises AttributeError, the gate
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

    def factory(original_fn: Any) -> Any:
        return original_fn

    wrappers: dict[str, Any] = {"spawn_analyzer": factory}
    _apply_cybergym_spawn_gate(wrappers)

    wrapped = wrappers["spawn_analyzer"](no_attr)
    result = wrapped(hypothesis="x")
    # Doesn't crash; inner_fn still ran
    assert result == "no_attr_OK"
