"""Tests for kai.definitions package structure."""

from __future__ import annotations


class TestDefinitionsImports:
    def test_top_level_imports(self) -> None:
        from kai.definitions import exploit_config, setup_config

        assert setup_config is not None
        assert exploit_config is not None

    def test_setup_subpackage(self) -> None:
        from kai.definitions.setup import config

        assert config.name == "setup"

    def test_exploit_subpackage(self) -> None:
        from kai.definitions.exploit import config

        assert config.name == "exploit"


class TestSetupConfig:
    def test_name(self) -> None:
        from kai.definitions import setup_config

        assert setup_config.name == "setup"

    def test_tools(self) -> None:
        from kai.definitions import setup_config

        expected = {"read_file", "list_dir", "search_files", "run_shell"}
        assert set(setup_config.tools.keys()) == expected

    def test_tools_are_callable(self) -> None:
        from kai.definitions import setup_config

        for name, fn in setup_config.tools.items():
            assert callable(fn), f"{name} is not callable"

    def test_backend(self) -> None:
        from kai.definitions import setup_config

        assert setup_config.backend == "openrouter"

    def test_max_iterations(self) -> None:
        from kai.definitions import setup_config

        assert setup_config.max_iterations == 30

    def test_no_sub_agents(self) -> None:
        from kai.definitions import setup_config

        assert setup_config.agents == []

    def test_validation_passes(self) -> None:
        from kai.definitions import setup_config

        setup_config.validate()


class TestExploitConfig:
    def test_name(self) -> None:
        from kai.definitions import exploit_config

        assert exploit_config.name == "exploit"

    def test_sub_agents(self) -> None:
        from kai.definitions import exploit_config

        names = [a.name for a in exploit_config.agents]
        assert names == [
            "analyzer",
            "verifier",
            "critic",
            "researcher",
            "fixer",
        ]

    def test_no_direct_tools(self) -> None:
        from kai.definitions import exploit_config

        assert exploit_config.tools == {}

    def test_validation_passes(self) -> None:
        from kai.definitions import exploit_config

        exploit_config.validate()

    def test_analyzer_tools(self) -> None:
        from kai.definitions import exploit_config

        analyzer = exploit_config.agents[0]
        assert set(analyzer.tools.keys()) == {
            "read_file",
            "list_dir",
            "search_files",
            "run_shell",
        }

    def test_verifier_tools(self) -> None:
        from kai.definitions import exploit_config

        verifier = exploit_config.agents[1]
        assert set(verifier.tools.keys()) == {
            "read_file",
            "write_file",
            "list_dir",
            "run_shell",
        }

    def test_researcher_tools(self) -> None:
        from kai.definitions import exploit_config

        researcher = exploit_config.agents[3]
        assert set(researcher.tools.keys()) == {
            "search_web",
            "read_url",
        }

    def test_fixer_tools(self) -> None:
        from kai.definitions import exploit_config

        fixer = exploit_config.agents[4]
        assert set(fixer.tools.keys()) == {
            "read_file",
            "update_file",
            "insert_lines",
            "delete_lines",
            "list_dir",
            "run_shell",
        }

    def test_tree_depth(self) -> None:
        from kai.definitions import exploit_config

        assert exploit_config.tree_depth() == 1


class TestPrompts:
    def test_setup_prompt_nonempty(self) -> None:
        from kai.definitions.setup.prompt import SYSTEM_PROMPT

        assert len(SYSTEM_PROMPT) > 100

    def test_setup_prompt_documents_tools(self) -> None:
        from kai.definitions.setup.prompt import SYSTEM_PROMPT

        for tool in ["read_file", "list_dir", "search_files", "run_shell"]:
            assert tool in SYSTEM_PROMPT

    def test_exploit_prompts_nonempty(self) -> None:
        from kai.definitions.exploit.prompt import (
            ANALYZER_PROMPT,
            FIXER_PROMPT,
            RESEARCHER_PROMPT,
            ROOT_PROMPT,
            VERIFIER_PROMPT,
        )

        for prompt in [
            ROOT_PROMPT,
            ANALYZER_PROMPT,
            RESEARCHER_PROMPT,
            VERIFIER_PROMPT,
            FIXER_PROMPT,
        ]:
            assert len(prompt) > 50

    def test_orchestrator_documents_spawns(self) -> None:
        from kai.definitions.exploit.prompt import ROOT_PROMPT

        for name in [
            "spawn_analyzer",
            "spawn_verifier",
            "spawn_researcher",
            "spawn_fixer",
        ]:
            assert name in ROOT_PROMPT
