"""Tests for RecursiveAgentConfig.environment_kwargs field."""

from __future__ import annotations

from ra.agents.config import RecursiveAgentConfig


def _simple_config(**overrides) -> RecursiveAgentConfig:
    defaults = {
        "name": "test",
        "system_prompt": "test prompt",
        "max_iterations": 1,
    }
    defaults.update(overrides)
    return RecursiveAgentConfig(**defaults)  # type: ignore[arg-type]


class TestEnvironmentKwargsField:
    def test_default_empty(self) -> None:
        config = _simple_config()
        assert config.environment_kwargs == {}

    def test_custom_value(self) -> None:
        config = _simple_config(environment_kwargs={"key": "val"})
        assert config.environment_kwargs == {"key": "val"}

    def test_independent_defaults(self) -> None:
        a = _simple_config()
        b = _simple_config()
        a.environment_kwargs["x"] = 1
        assert b.environment_kwargs == {}


class TestToDictWithEnvKwargs:
    def test_serializable_values_included(self) -> None:
        config = _simple_config(environment_kwargs={"timeout": 30, "debug": True})
        d = config.to_dict()
        assert d["environment_kwargs"] == {"timeout": 30, "debug": True}

    def test_callable_values_excluded(self) -> None:
        config = _simple_config(
            environment_kwargs={
                "timeout": 30,
                "workspace_factory": lambda: "/tmp/x",
            }
        )
        d = config.to_dict()
        assert d["environment_kwargs"] == {"timeout": 30}

    def test_empty_env_kwargs_in_dict(self) -> None:
        config = _simple_config()
        d = config.to_dict()
        assert d["environment_kwargs"] == {}


class TestFromDictWithEnvKwargs:
    def test_round_trip(self) -> None:
        config = _simple_config(environment_kwargs={"timeout": 30, "mode": "fast"})
        d = config.to_dict()
        restored = RecursiveAgentConfig.from_dict(d)
        assert restored.environment_kwargs == {"timeout": 30, "mode": "fast"}

    def test_missing_env_kwargs_defaults_empty(self) -> None:
        d = {
            "name": "test",
            "system_prompt": "prompt",
            "tools": [],
            "agents": [],
        }
        config = RecursiveAgentConfig.from_dict(d)
        assert config.environment_kwargs == {}

    def test_validation_still_passes(self) -> None:
        config = _simple_config(environment_kwargs={"custom": "data"})
        config.validate()
