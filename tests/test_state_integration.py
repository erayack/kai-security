"""Tests for kai.state.integration.inject_state_manager."""

from __future__ import annotations

import tempfile
from typing import Any

from ra.agents.config import RecursiveAgentConfig

from kai.state.integration import inject_state_manager
from kai.state.local import LocalStateManager


def _make_config(
    name: str = "root",
    agents: list[RecursiveAgentConfig] | None = None,
) -> RecursiveAgentConfig:
    """Build a minimal config with spawn functions documented."""
    agent_list = agents or []
    spawn_docs = "".join(f" spawn_{a.name}" for a in agent_list)
    return RecursiveAgentConfig(
        name=name,
        system_prompt=f"Agent {name}.{spawn_docs}",
        agents=agent_list,
    )


def _dummy_processor(
    sm: object, run_id: str, kwargs: dict[str, Any], raw: str,
) -> str:
    return raw


class TestInjectStateManager:
    def test_sets_on_iteration(self) -> None:
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        config = _make_config()
        injected = inject_state_manager(config, mgr, "run-1")
        assert injected.on_iteration is not None
        assert callable(injected.on_iteration)

    def test_recursive_children(self) -> None:
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        grandchild = _make_config(name="sub_analyzer")
        child = _make_config(name="analyzer", agents=[grandchild])
        config = _make_config(name="root", agents=[child])
        injected = inject_state_manager(config, mgr, "run-1")
        assert injected.on_iteration is not None
        assert len(injected.agents) == 1
        child_injected = injected.agents[0]
        assert child_injected.on_iteration is not None
        grandchild_injected = child_injected.agents[0]
        assert grandchild_injected.on_iteration is not None

    def test_does_not_mutate_original(self) -> None:
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        config = _make_config()
        inject_state_manager(config, mgr, "run-1")
        assert config.on_iteration is None

    def test_sets_result_processor_on_matching_child(self) -> None:
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        child = _make_config(name="analyzer")
        config = _make_config(name="root", agents=[child])
        injected = inject_state_manager(
            config, mgr, "run-1",
            result_processors={"analyzer": _dummy_processor},
        )
        assert injected.agents[0].result_processor is not None
        assert callable(injected.agents[0].result_processor)

    def test_no_result_processor_on_unmatched_child(self) -> None:
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        child = _make_config(name="verifier")
        config = _make_config(name="root", agents=[child])
        injected = inject_state_manager(
            config, mgr, "run-1",
            result_processors={"analyzer": _dummy_processor},
        )
        assert injected.agents[0].result_processor is None

    def test_bound_processor_calls_through(self) -> None:
        """The bound closure should invoke the processor correctly."""
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        calls: list[tuple[str, str]] = []

        def tracking_processor(
            sm: object, run_id: str,
            kwargs: dict[str, Any], raw: str,
        ) -> str:
            calls.append((run_id, raw))
            return f"enriched:{raw}"

        child = _make_config(name="analyzer")
        config = _make_config(name="root", agents=[child])
        injected = inject_state_manager(
            config, mgr, "run-1",
            result_processors={"analyzer": tracking_processor},
        )
        bound = injected.agents[0].result_processor
        assert bound is not None
        result = bound({}, "test_data")
        assert result == "enriched:test_data"
        assert calls == [("run-1", "test_data")]
