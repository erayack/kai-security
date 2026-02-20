"""Tests for kai.state.integration.inject_state_manager."""

from __future__ import annotations

import tempfile

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
        # Root has on_iteration
        assert injected.on_iteration is not None
        # Child also has on_iteration
        assert len(injected.agents) == 1
        child_injected = injected.agents[0]
        assert child_injected.on_iteration is not None
        # Grandchild has on_iteration
        grandchild_injected = child_injected.agents[0]
        assert grandchild_injected.on_iteration is not None

    def test_does_not_mutate_original(self) -> None:
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        config = _make_config()
        inject_state_manager(config, mgr, "run-1")
        assert config.on_iteration is None
