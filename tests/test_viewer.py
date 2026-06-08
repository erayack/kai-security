"""Tests for the kai run viewer (findings loader + HTML render)."""

from __future__ import annotations

import json
from pathlib import Path

from kai.viewer import load_findings, render_html, write_html
from kai.viewer.trace import RunTrace, load_rollout_dir

_EXPLOITS = [
    {
        "exploit_id": "e2",
        "status": "rejected",
        "confirmed": False,
        "hypothesis": "Fee truncation rounds small trades to zero.",
        "file": "contracts/Fees.sol",
        "function": "calcFee",
        "category": "theoretical_bounds",
        "cvss_score": 4.3,
    },
    {
        "exploit_id": "e1",
        "status": "verified",
        "confirmed": True,
        "hypothesis": (
            "Reentrancy in withdraw drains the vault. The external call "
            "precedes the balance update and there is no guard."
        ),
        "file": "contracts/Vault.sol",
        "function": "withdraw",
        "category": "active_exploit",
        "severity": "critical",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_justification": {"AV": "remote attacker", "AC": "no special conditions"},
        "poc_code": "contract Attacker { function pwn() external {} }",
        "patch": "-        msg.sender.call{value: amount}(\"\");\n+        balances[msg.sender] -= amount;",
        "attacker_role": "anyone",
        "prerequisite": "a non-zero deposit",
    },
]


def _write_run(dir_path: Path) -> None:
    (dir_path / "exploits.json").write_text(json.dumps(_EXPLOITS), encoding="utf-8")
    rollouts = dir_path / "rollouts"
    rollouts.mkdir()
    exploit = [
        {"type": "metadata", "agent": "exploit", "depth": 0, "spawn_id": "r1",
         "timestamp": "2026-06-03T00:00:00+00:00", "model": "anthropic/claude-opus-4.8"},
        {"type": "iteration", "agent": "exploit", "iteration": 1, "spawn_id": "r1",
         "timestamp": "2026-06-03T00:01:00+00:00",
         "response": "Analyzing the vault.", "code_blocks": []},
        {"type": "result", "agent": "exploit", "iteration": 1, "spawn_id": "r1",
         "timestamp": "2026-06-03T00:02:00+00:00", "final_answer": "done"},
    ]
    (rollouts / "exploit.jsonl").write_text(
        "\n".join(json.dumps(r) for r in exploit), encoding="utf-8"
    )


def test_load_findings_drops_deduplicated(tmp_path: Path) -> None:
    records = [
        {"exploit_id": "keep", "status": "verified_and_fixed", "confirmed": True,
         "hypothesis": "real bug", "file": "A.sol", "function": "f",
         "category": "active_exploit", "severity": "high", "cvss_score": 8.0},
        {"exploit_id": "dup", "status": "deduplicated", "confirmed": None,
         "hypothesis": "merged duplicate", "file": "A.sol", "function": "f",
         "category": "active_exploit"},
    ]
    (tmp_path / "exploits.json").write_text(json.dumps(records), encoding="utf-8")
    findings = load_findings(tmp_path)
    # The deduplicated bookkeeping shell is hidden; the real finding remains.
    assert [f.exploit_id for f in findings] == ["keep"]


def test_load_findings_sorts_and_derives(tmp_path: Path) -> None:
    _write_run(tmp_path)
    findings = load_findings(tmp_path)

    # Confirmed critical sorts ahead of the unconfirmed lower-severity finding.
    assert [f.exploit_id for f in findings] == ["e1", "e2"]
    e1, e2 = findings
    assert e1.severity == "critical"
    assert e1.title.startswith("Reentrancy in withdraw")
    # Severity is derived from the CVSS score when the field is absent.
    assert e2.severity == "medium"
    # The CVSS vector is expanded into ordered, human-readable rows.
    assert [r["metric"] for r in e1.cvss_rows] == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    assert e1.cvss_rows[0] == {"metric": "AV", "value": "Network", "why": "remote attacker"}


def test_load_findings_missing_file_is_empty(tmp_path: Path) -> None:
    assert load_findings(tmp_path) == []


def test_render_is_self_contained_and_has_findings(tmp_path: Path) -> None:
    _write_run(tmp_path)
    html = render_html(load_rollout_dir(tmp_path), load_findings(tmp_path))

    assert html.startswith("<!DOCTYPE html>")
    # Fully offline: no external resources.
    assert "http://" not in html and "https://" not in html
    for needle in (
        "Reentrancy in withdraw",
        "contracts/Vault.sol",
        "active_exploit",
        "critical",
        "Attacker",  # poc_code
        "balances[msg.sender]",  # patch diff body
    ):
        assert needle in html


def test_render_without_findings_still_renders(tmp_path: Path) -> None:
    # A benchmark-style dir: a trace but no exploits.json.
    (tmp_path / "rollouts").mkdir()
    run = RunTrace(
        title="t", benchmark="rollout", task_id="t", success=None,
        failure_reason=None, poc_source=None, models=[], agents=[],
        root_name="", root_result=None, root_steps=[], unlinked=[],
    )
    html = render_html(run)
    assert html.startswith("<!DOCTYPE html>")
    assert "No findings recorded" in html or "view-findings" in html


def test_write_html_creates_file(tmp_path: Path) -> None:
    _write_run(tmp_path)
    out = write_html(tmp_path)
    assert out == tmp_path / "trace.html"
    assert "Reentrancy in withdraw" in out.read_text(encoding="utf-8")
