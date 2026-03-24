"""Tests for kai.workspace.integration.inject_workspace."""

from __future__ import annotations

from ra.agents.config import RecursiveAgentConfig

from kai.workspace.integration import _needs_workspace, inject_workspace
from kai.workspace.recipe import WorkspaceRecipe


def _noop() -> None:
    pass


def _ws_config(name: str) -> RecursiveAgentConfig:
    """Config with a workspace tool (read_file)."""
    return RecursiveAgentConfig(
        name=name,
        system_prompt=f"I am {name}. read_file",
        tools={"read_file": _noop},
        max_iterations=1,
    )


def _web_config(name: str) -> RecursiveAgentConfig:
    """Config with a non-workspace tool (search_web)."""
    return RecursiveAgentConfig(
        name=name,
        system_prompt=f"I am {name}. search_web",
        tools={"search_web": _noop},
        max_iterations=1,
    )


def _tree_config() -> RecursiveAgentConfig:
    """Root (no tools) with a workspace child and a web-only child."""
    child_ws = _ws_config("worker")
    child_web = _web_config("researcher")
    return RecursiveAgentConfig(
        name="root",
        system_prompt="I am root. spawn_worker spawn_researcher",
        agents=[child_ws, child_web],
        max_iterations=5,
    )


def _recipe() -> WorkspaceRecipe:
    return WorkspaceRecipe(
        master_path="/tmp/master",
        symlink_dirs=["node_modules"],
        copy_dirs=["src"],
    )


class TestNeedsWorkspace:
    def test_workspace_tool(self) -> None:
        assert _needs_workspace(_ws_config("x")) is True

    def test_web_tool(self) -> None:
        assert _needs_workspace(_web_config("x")) is False

    def test_no_tools(self) -> None:
        cfg = RecursiveAgentConfig(name="empty", system_prompt="hi", max_iterations=1)
        assert _needs_workspace(cfg) is False


class TestInjectWorkspace:
    def test_original_not_mutated(self) -> None:
        config = _tree_config()
        inject_workspace(config, _recipe())
        assert "workspace_factory" not in config.environment_kwargs
        for sub in config.agents:
            assert "workspace_factory" not in sub.environment_kwargs

    def test_root_no_factory(self) -> None:
        """Root has no workspace tools so it gets no factory."""
        config = _tree_config()
        injected = inject_workspace(config, _recipe())
        assert "workspace_factory" not in injected.environment_kwargs

    def test_workspace_child_gets_factory(self) -> None:
        config = _tree_config()
        injected = inject_workspace(config, _recipe())
        worker = injected.agents[0]
        assert "workspace_factory" in worker.environment_kwargs
        assert callable(worker.environment_kwargs["workspace_factory"])

    def test_web_child_no_factory(self) -> None:
        """Researcher (web-only tools) should not get a workspace."""
        config = _tree_config()
        injected = inject_workspace(config, _recipe())
        researcher = injected.agents[1]
        assert "workspace_factory" not in researcher.environment_kwargs

    def test_preserves_existing_env_kwargs(self) -> None:
        config = _ws_config("x")
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
        config = _ws_config("x")
        injected = inject_workspace(config, _recipe())
        factory = injected.environment_kwargs["workspace_factory"]
        assert hasattr(factory, "func")
        assert hasattr(factory, "args") or hasattr(factory, "keywords")

    def test_verbose_propagates(self) -> None:
        config = _tree_config()
        injected = inject_workspace(config, _recipe(), verbose=True)
        assert injected.verbose is True
        for sub in injected.agents:
            assert sub.verbose is True

    def test_verbose_default_unchanged(self) -> None:
        config = _tree_config()
        injected = inject_workspace(config, _recipe())
        assert injected.verbose is False
