"""Tests for the ``evaluation.cli index`` overall-gallery builder."""

from __future__ import annotations

import json
from pathlib import Path

from evaluation.cli import _gallery_row, _render_gallery_html, main


def _write_score(task_dir: Path, payload: dict) -> None:
    task_dir.mkdir(parents=True, exist_ok=True)
    (task_dir / "score.json").write_text(json.dumps(payload))


def test_gallery_row_reads_evmbench_detail(tmp_path: Path) -> None:
    d = tmp_path / "2024-01-curves"
    _write_score(
        d,
        {
            "task_ref": {"benchmark": "evmbench", "task_id": "2024-01-curves"},
            "success": True,
            "details": {"n_matched": 4, "n_oracle_vulns": 4},
        },
    )
    row = _gallery_row(d)
    assert row["benchmark"] == "evmbench"
    assert row["success"] is True
    assert row["detail"] == "4/4 vulns matched"


def test_gallery_row_reads_cybergym_failure(tmp_path: Path) -> None:
    d = tmp_path / "arvo-47101"
    _write_score(
        d,
        {
            "task_ref": {"benchmark": "cybergym", "task_id": "arvo:47101"},
            "success": False,
            "failure_reason": "timeout after 10800s",
            "details": {},
        },
    )
    row = _gallery_row(d)
    assert row["benchmark"] == "cybergym"
    assert row["success"] is False
    assert row["detail"] == "timeout after 10800s"


def test_render_gallery_html_has_summary_and_links() -> None:
    rows = [
        {
            "dir": "a",
            "benchmark": "evmbench",
            "task_id": "evm-1",
            "success": True,
            "failure": "",
            "detail": "2/2 vulns matched",
            "has_trace": True,
        },
        {
            "dir": "b",
            "benchmark": "cybergym",
            "task_id": "cy-1",
            "success": False,
            "failure": "no_poc_binary",
            "detail": "no_poc_binary",
            "has_trace": False,
            "found_bug": "MATCH",
            "found_bug_reason": "same root cause in the same function",
            "ground_truth": "the documented null-deref bug",
            "hypothesis": "what the agent reported",
        },
    ]
    html = _render_gallery_html(rows, "trial")
    assert "2 rollouts" in html
    assert "evmbench: <b>1/1</b> pass" in html
    assert "cybergym: <b>0/1</b> pass" in html
    assert "<b>1/1</b> found-bug (LLM)" in html  # the LLM judge tally
    assert "found-bug (LLM)" in html  # the column header
    assert ">MATCH<" in html  # the judge badge in the cyber row
    assert 'href="./a/trace.html"' in html  # relative link when the trace exists
    assert 'href="./b/trace.html"' not in html  # no link when absent
    assert "evm-1" in html and "cy-1" in html
    # the judge-reasoning detail section
    assert "same root cause in the same function" in html  # the judge's reason
    assert "the documented null-deref bug" in html  # ground truth shown
    assert "what the agent reported" in html  # agent hypothesis shown
    # the cyber row is clickable and its reasoning expands inline beneath it
    assert 'class="exp"' in html
    assert 'class="det"' in html and 'colspan="7"' in html


def test_index_command_writes_index_and_traces(tmp_path: Path) -> None:
    base = tmp_path / "rollouts"
    d = base / "noop:1"  # colon in the dir name, like real cybergym task ids
    d.mkdir(parents=True)
    (d / "score.json").write_text(
        json.dumps(
            {
                "task_ref": {"benchmark": "cybergym", "task_id": "noop:1"},
                "success": False,
            }
        )
    )
    (d / "exploit.jsonl").write_text(
        json.dumps(
            {
                "type": "metadata",
                "agent": "exploit",
                "depth": 0,
                "model": "m",
                "timestamp": "t",
            }
        )
        + "\n"
        + json.dumps(
            {
                "type": "iteration",
                "iteration": 1,
                "timestamp": "t",
                "response": "hi",
                "code_blocks": [],
            }
        )
        + "\n"
    )

    assert main(["index", "--no-judge", str(base)]) == 0
    assert (base / "index.html").is_file()
    assert (d / "trace.html").is_file()
    idx = (base / "index.html").read_text()
    # the colon must be URL-encoded so the browser doesn't read "noop:" as a
    # URI scheme (the dead-trace-link bug this guards against).
    assert "noop:1" in idx and 'href="./noop%3A1/trace.html"' in idx
