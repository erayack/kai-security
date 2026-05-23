"""Tests for kai.state.integration.inject_state_manager."""

from __future__ import annotations

import json
import tempfile
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

from ra.agents.agent import RecursiveAgent
from ra.agents.config import RecursiveAgentConfig
from ra.core.rlm import RLM
from ra.core.types import CodeBlock, REPLResult, RLMIteration
from ra.core.types import UsageSummary

from kai.state.integration import inject_state_manager
from kai.state.hooks import make_rollout_on_iteration_hook
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
    sm: object,
    run_id: str,
    kwargs: dict[str, Any],
    raw: str,
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
            config,
            mgr,
            "run-1",
            result_processors={"analyzer": _dummy_processor},
        )
        assert injected.agents[0].result_processor is not None
        assert callable(injected.agents[0].result_processor)

    def test_no_result_processor_on_unmatched_child(self) -> None:
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        child = _make_config(name="verifier")
        config = _make_config(name="root", agents=[child])
        injected = inject_state_manager(
            config,
            mgr,
            "run-1",
            result_processors={"analyzer": _dummy_processor},
        )
        assert injected.agents[0].result_processor is None

    def test_bound_processor_calls_through(self) -> None:
        """The bound closure should invoke the processor correctly."""
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        calls: list[tuple[str, str]] = []

        def tracking_processor(
            sm: object,
            run_id: str,
            kwargs: dict[str, Any],
            raw: str,
        ) -> str:
            calls.append((run_id, raw))
            return f"enriched:{raw}"

        child = _make_config(name="analyzer")
        config = _make_config(name="root", agents=[child])
        injected = inject_state_manager(
            config,
            mgr,
            "run-1",
            result_processors={"analyzer": tracking_processor},
        )
        bound = injected.agents[0].result_processor
        assert bound is not None
        result = bound({}, "test_data")
        assert result == "enriched:test_data"
        assert calls == [("run-1", "test_data")]

    def test_fixer_spawn_wrapper_installed(self) -> None:
        """inject_state_manager installs spawn_fixer wrapper at depth 0."""
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        fixer = _make_config(name="fixer")
        config = _make_config(name="root", agents=[fixer])
        injected = inject_state_manager(config, mgr, "run-1")
        assert "spawn_fixer" in injected.spawn_wrappers

    def test_recipe_passed_through_wrapper(self) -> None:
        """When recipe is provided, the spawn_fixer wrapper is installed."""
        from kai.workspace.recipe import WorkspaceRecipe

        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        fixer = _make_config(name="fixer")
        config = _make_config(name="root", agents=[fixer])
        recipe = WorkspaceRecipe(master_path="/tmp/test")

        injected = inject_state_manager(config, mgr, "run-1", recipe=recipe)
        # spawn_fixer wrapper should be installed
        assert "spawn_fixer" in injected.spawn_wrappers
        # The wrapper factory should be callable
        factory = injected.spawn_wrappers["spawn_fixer"]
        assert callable(factory)

    def test_recipe_none_still_installs_wrapper(self) -> None:
        """Without recipe, spawn_fixer wrapper still installed."""
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        fixer = _make_config(name="fixer")
        config = _make_config(name="root", agents=[fixer])

        injected = inject_state_manager(config, mgr, "run-1")
        assert "spawn_fixer" in injected.spawn_wrappers

    def test_bootstrap_verifier_spawn_writes_rollout(self) -> None:
        """Bootstrap verifier spawns should persist verifier.jsonl."""
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        verifier = _make_config(name="verifier")
        config = RecursiveAgentConfig(
            name="root",
            system_prompt="Agent root. spawn_verifier exploits",
            agents=[verifier],
        )
        injected = inject_state_manager(
            config,
            mgr,
            "run-1",
            save_rollouts=True,
        )

        def _fake_completion(
            self: RecursiveAgent,
            data: str | dict[str, Any],
        ) -> str:
            del data
            assert self.config.on_iteration is not None
            self.config.on_iteration(
                RLMIteration(
                    prompt="verify",
                    response="checking",
                    code_blocks=[
                        CodeBlock(
                            code="print('verify')",
                            result=REPLResult(
                                stdout="verify",
                                stderr="",
                                locals={},
                                spawn_records=[],
                            ),
                        )
                    ],
                    final_answer='{"confirmed": true}',
                ),
                1,
            )
            return '{"confirmed": true}'

        with patch.object(RecursiveAgent, "completion", new=_fake_completion):
            root_agent = RecursiveAgent(injected)
            spawn_verifier = root_agent._build_tools()["spawn_verifier"]
            result = spawn_verifier(
                hypothesis="h",
                file="target.c",
                function="do_work",
                poc_code="__POC_BYTES__b64=AA==",
            )

        assert json.loads(result)["confirmed"] is True
        rollout_path = mgr._run_dir("run-1") / "rollouts" / "verifier.jsonl"
        assert rollout_path.exists()
        entries = [json.loads(line) for line in rollout_path.read_text().splitlines()]
        assert [entry["type"] for entry in entries] == [
            "metadata",
            "iteration",
            "result",
        ]
        assert entries[0]["agent"] == "verifier"

    def test_failed_spawn_still_writes_rollout(self) -> None:
        """Spawn errors before iteration should still create rollout JSONL."""
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        verifier = _make_config(name="verifier")
        config = RecursiveAgentConfig(
            name="root",
            system_prompt="Agent root. spawn_verifier exploits",
            agents=[verifier],
        )
        injected = inject_state_manager(
            config,
            mgr,
            "run-1",
            save_rollouts=True,
        )

        def _boom(
            self: RecursiveAgent,
            data: str | dict[str, Any],
        ) -> str:
            del self, data
            raise RuntimeError("boom")

        with patch.object(RecursiveAgent, "completion", new=_boom):
            root_agent = RecursiveAgent(injected)
            spawn_verifier = root_agent._build_tools()["spawn_verifier"]
            result = spawn_verifier(
                hypothesis="h",
                file="target.c",
                function="do_work",
                poc_code="__POC_BYTES__b64=AA==",
            )

        assert result == "[spawn_verifier error] RuntimeError: boom"
        rollout_path = mgr._run_dir("run-1") / "rollouts" / "verifier.jsonl"
        assert rollout_path.exists()
        entries = [json.loads(line) for line in rollout_path.read_text().splitlines()]
        assert [entry["type"] for entry in entries] == [
            "metadata",
            "iteration",
            "result",
        ]
        assert entries[1]["response"] == "[spawn_verifier error] RuntimeError: boom"

    def test_default_answer_after_internal_error_still_writes_rollout(self) -> None:
        """Internal RLM fallback should still open the rollout file."""
        mgr = LocalStateManager(state_dir=tempfile.mkdtemp())
        rollout_hook = make_rollout_on_iteration_hook(
            mgr,
            "run-1",
            "verifier",
        )
        rlm = RLM(
            name="verifier",
            on_iteration=rollout_hook,
            max_iterations=1,
            backend_kwargs={"model_name": "test-model"},
        )

        class _FakeLMHandler:
            def get_usage_summary(self) -> UsageSummary:
                return UsageSummary(model_usage_summaries={})

        class _FakeEnv:
            pass

        @contextmanager
        def _fake_spawn_context(
            self: RLM,
            prompt: str | dict[str, Any],
        ) -> Any:
            del self, prompt
            yield _FakeLMHandler(), _FakeEnv()

        def _boom(
            self: RLM,
            prompt: str | dict[str, Any] | list[dict[str, Any]],
            lm_handler: object,
            environment: object,
            iteration_num: int = 0,
        ) -> RLMIteration:
            del self, prompt, lm_handler, environment, iteration_num
            raise RuntimeError("boom")

        def _default_answer(
            self: RLM,
            message_history: list[dict[str, Any]],
            lm_handler: object,
            *,
            environment: object,
        ) -> str:
            del self, message_history, lm_handler, environment
            return '{"confirmed": false}'

        with (
            patch.object(RLM, "_spawn_completion_context", _fake_spawn_context),
            patch.object(RLM, "_setup_prompt", return_value=[]),
            patch.object(RLM, "_completion_turn", new=_boom),
            patch.object(RLM, "_default_answer", new=_default_answer),
        ):
            result = rlm.completion({"hypothesis": "h"})

        assert result.response == '{"confirmed": false}'
        rollout_path = mgr._run_dir("run-1") / "rollouts" / "verifier.jsonl"
        assert rollout_path.exists()
        entries = [json.loads(line) for line in rollout_path.read_text().splitlines()]
        assert [entry["type"] for entry in entries] == [
            "metadata",
            "iteration",
            "result",
        ]
        assert entries[1]["response"] == '{"confirmed": false}'
