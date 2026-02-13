"""Tests for kai.workspace.integration.inject_workspace."""

from __future__ import annotations

from ra.agents.config import RecursiveAgentConfig

from kai.workspace.integration import inject_workspace
from kai.workspace.recipe import WorkspaceRecipe


def _leaf_config(name: str) -> RecursiveAgentConfig:
    return RecursiveAgentConfig(
        name=name,
        system_prompt=f"I am {name}",
        max_iterations=1,
    )


def _tree_config() -> RecursiveAgentConfig:
    """A root with two sub-agents (no tools to avoid prompt validation)."""
    child_a = _leaf_config("child_a")
    child_b = _leaf_config("child_b")
    return RecursiveAgentConfig(
        name="root",
        system_prompt=("I am root. spawn_child_a spawn_child_b"),
        agents=[child_a, child_b],
        max_iterations=5,
    )


def _recipe() -> WorkspaceRecipe:
    return WorkspaceRecipe(
        master_path="/tmp/master",
        symlink_dirs=["node_modules"],
        copy_dirs=["src"],
    )


class TestInjectWorkspace:
    def test_original_not_mutated(self) -> None:
        config = _tree_config()
        recipe = _recipe()
        inject_workspace(config, recipe)
        assert "workspace_factory" not in config.environment_kwargs
        for sub in config.agents:
            assert "workspace_factory" not in sub.environment_kwargs

    def test_root_gets_factory(self) -> None:
        config = _tree_config()
        injected = inject_workspace(config, _recipe())
        assert "workspace_factory" in injected.environment_kwargs
        assert callable(injected.environment_kwargs["workspace_factory"])

    def test_all_children_get_factory(self) -> None:
        config = _tree_config()
        injected = inject_workspace(config, _recipe())
        for sub in injected.agents:
            assert "workspace_factory" in sub.environment_kwargs
            assert callable(sub.environment_kwargs["workspace_factory"])

    def test_preserves_existing_env_kwargs(self) -> None:
        config = _leaf_config("x")
        config.environment_kwargs["custom_key"] = "value"
        injected = inject_workspace(config, _recipe())
        assert injected.environment_kwargs["custom_key"] == "value"
        assert "workspace_factory" in injected.environment_kwargs

    def test_preserves_other_config_fields(self) -> None:
        config = _tree_config()
        injected = inject_workspace(config, _recipe())
        assert injected.name == config.name
        assert injected.system_prompt == config.system_prompt
        assert injected.max_iterations == config.max_iterations
        assert injected.backend == config.backend
        assert len(injected.agents) == len(config.agents)

    def test_factory_is_callable(self) -> None:
        """The factory should be a callable that accepts no args."""
        config = _leaf_config("x")
        injected = inject_workspace(config, _recipe())
        factory = injected.environment_kwargs["workspace_factory"]
        # It's a functools.partial — verify it has the right structure
        assert hasattr(factory, "func")
        assert hasattr(factory, "args") or hasattr(factory, "keywords")

    def test_leaf_config(self) -> None:
        """Injection works on a config with no sub-agents."""
        config = _leaf_config("solo")
        injected = inject_workspace(config, _recipe())
        assert "workspace_factory" in injected.environment_kwargs
        assert injected.agents == []
