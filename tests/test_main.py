"""Tests for kai.main module."""

from __future__ import annotations

import json

from kai.main import _build_parser, _load_threat_context, _parse_input
from kai.state.models import ThreatContext


class TestParseInput:
    def test_json_object(self) -> None:
        result = _parse_input('{"key": "value"}')
        assert result == {"key": "value"}

    def test_json_array(self) -> None:
        result = _parse_input("[1, 2, 3]")
        assert result == [1, 2, 3]

    def test_raw_string(self) -> None:
        result = _parse_input("not json")
        assert result == "not json"

    def test_none_input(self) -> None:
        result = _parse_input(None)  # type: ignore[arg-type]
        assert result is None


class TestBuildParser:
    def test_agent_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["agent", "setup", "--input", "{}"])
        assert args.command == "agent"
        assert args.name == "setup"
        assert args.input == "{}"

    def test_pipeline_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["pipeline", "--repo-path", "/tmp/repo"])
        assert args.command == "pipeline"
        assert args.repo_path == "/tmp/repo"

    def test_agent_with_overrides(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(
            [
                "agent",
                "exploit",
                "--input",
                "{}",
                "--backend",
                "anthropic",
                "--model",
                "claude-sonnet-4-5-20250929",
                "--max-iterations",
                "50",
            ]
        )
        assert args.backend == "anthropic"
        assert args.model == "claude-sonnet-4-5-20250929"
        assert args.max_iterations == 50

    def test_agent_defaults(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["agent", "setup", "--input", "test"])
        assert args.backend is None
        assert args.model is None
        assert args.max_iterations is None

    def test_no_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args([])
        assert args.command is None


class TestRunPipelineImport:
    def test_importable(self) -> None:
        from kai.main import run_pipeline

        assert callable(run_pipeline)


class TestThreatContextFlag:
    def test_pipeline_flag_parsed(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(
            ["pipeline", "--repo-path", "/tmp/r", "--threat-context", "tc.json"]
        )
        assert args.threat_context == "tc.json"

    def test_agent_flag_parsed(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(
            ["agent", "setup", "--input", "{}", "--threat-context", "tc.yaml"]
        )
        assert args.threat_context == "tc.yaml"

    def test_flag_default_none(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["pipeline", "--repo-path", "/tmp/r"])
        assert args.threat_context is None

    def test_load_json(self, tmp_path) -> None:
        data = {"deployment_type": "web-app", "environment": "server"}
        f = tmp_path / "tc.json"
        f.write_text(json.dumps(data))
        tc = _load_threat_context(str(f))
        assert isinstance(tc, ThreatContext)
        assert tc.deployment_type == "web-app"
        assert tc.environment == "server"

    def test_load_yaml(self, tmp_path) -> None:
        f = tmp_path / "tc.yaml"
        f.write_text("deployment_type: cli-tool\nenvironment: local\n")
        tc = _load_threat_context(str(f))
        assert tc.deployment_type == "cli-tool"
        assert tc.environment == "local"

    def test_load_minimal(self, tmp_path) -> None:
        f = tmp_path / "tc.json"
        f.write_text('{"deployment_type": "library"}')
        tc = _load_threat_context(str(f))
        assert tc.deployment_type == "library"
        assert tc.access_roles == []


class TestMainAgentCommand:
    def test_main_reads_json_file(self, tmp_path) -> None:
        """Verify input file loading logic (without running an agent)."""
        data = {"repo_path": "/test"}
        f = tmp_path / "input.json"
        f.write_text(json.dumps(data))

        # We can only test parsing — running the agent requires
        # an LM backend. Verify the file is valid JSON.
        loaded = json.loads(f.read_text())
        assert loaded == data
