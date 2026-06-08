"""Tests for the unified ``kai`` CLI dispatcher."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kai import cli


def _write_run(dir_path: Path) -> None:
    exploits = [
        {
            "exploit_id": "e1", "status": "verified", "confirmed": True,
            "hypothesis": "Reentrancy in withdraw drains the vault.",
            "file": "Vault.sol", "function": "withdraw", "category": "active_exploit",
            "severity": "critical", "cvss_score": 9.1,
        }
    ]
    (dir_path / "exploits.json").write_text(json.dumps(exploits), encoding="utf-8")


def test_help_and_no_args_print_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 0
    assert "usage: kai <command>" in capsys.readouterr().out
    assert cli.main(["--help"]) == 0
    assert "audit" in capsys.readouterr().out


def test_unknown_command_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["bogus"]) == 2
    err = capsys.readouterr().err
    assert "unknown command 'bogus'" in err


@pytest.mark.parametrize(
    "command,expected",
    [
        (["audit", "/repo", "--verbose"], ["pipeline", "/repo", "--verbose"]),
        (["pipeline", "--recipe", "r.json"], ["pipeline", "--recipe", "r.json"]),
        (["agent", "setup", "--input", "{}"], ["agent", "setup", "--input", "{}"]),
    ],
)
def test_audit_pipeline_agent_delegate_to_kai_main(
    command: list[str], expected: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr("kai.main.main", lambda argv: captured.append(argv))
    assert cli.main(command) == 0
    assert captured == [expected]


def test_view_delegates_and_writes_html(tmp_path: Path) -> None:
    _write_run(tmp_path)
    out = tmp_path / "v.html"
    assert cli.main(["view", str(tmp_path), "-o", str(out)]) == 0
    assert out.exists() and out.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_report_delegates(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write_run(tmp_path)
    assert cli.main(["report", str(tmp_path)]) == 0
    assert "Security findings" in capsys.readouterr().out

    out = tmp_path / "r.html"
    assert cli.main(["report", str(tmp_path), "--format", "html", "-o", str(out)]) == 0
    assert out.exists()
