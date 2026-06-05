"""Tests for the rollout HTML trace viewer."""

from __future__ import annotations

import json
from pathlib import Path

from evaluation.trace_viewer import load_rollout_dir, render_html


def _write_rollout(dir_path: Path) -> None:
    """A root that spawns analyzer, the analyzer run, a stub, and a score."""

    exploit = [
        {
            "type": "metadata",
            "agent": "exploit",
            "depth": 0,
            "spawn_id": "root1",
            "timestamp": "2026-06-03T00:00:00+00:00",
            "backend": "openrouter",
            "model": "anthropic/claude-opus-4.6",
        },
        {
            "type": "iteration",
            "agent": "exploit",
            "iteration": 1,
            "spawn_id": "root1",
            "timestamp": "2026-06-03T00:10:00+00:00",
            "response": "Let me delegate analysis.\n\n```repl\nresult = spawn_analyzer(focus='find the bug')\nprint(result)\n```",
            "code_blocks": [
                {
                    "code": "result = spawn_analyzer(focus='find the bug')\nprint(result)",
                    "output": "ANALYZER_RETURN_IN_ROOT_OUTPUT",
                }
            ],
        },
        {
            "type": "result",
            "agent": "exploit",
            "iteration": 1,
            "spawn_id": "root1",
            "timestamp": "2026-06-03T00:10:01+00:00",
            "final_answer": "FINAL_ANSWER_MARKER",
        },
    ]
    # The analyzer runs *inside* the root's iter-1 code call, so its timestamps
    # precede the root iteration's completion stamp -- the case the viewer must
    # not be fooled by.
    analyzer = [
        {
            "type": "metadata",
            "agent": "analyzer",
            "depth": 1,
            "spawn_id": "sub1",
            "timestamp": "2026-06-03T00:00:05+00:00",
            "backend": "openrouter",
            "model": "openai/gpt-5.5",
        },
        {
            "type": "iteration",
            "agent": "analyzer",
            "iteration": 1,
            "spawn_id": "sub1",
            "timestamp": "2026-06-03T00:00:06+00:00",
            "response": "Inspecting the target.",
            "code_blocks": [
                {"code": "list_dir('.')", "output": "ANALYZER_STEP_OUTPUT"}
            ],
        },
        {
            "type": "result",
            "agent": "analyzer",
            "iteration": 1,
            "spawn_id": "sub1",
            "timestamp": "2026-06-03T00:09:00+00:00",
            "final_answer": "ANALYZER_RETURNED_HYPOTHESIS",
        },
    ]
    (dir_path / "exploit.jsonl").write_text(
        "\n".join(json.dumps(r) for r in exploit), encoding="utf-8"
    )
    (dir_path / "analyzer.jsonl").write_text(
        "\n".join(json.dumps(r) for r in analyzer), encoding="utf-8"
    )
    # An agent that never ran: a `cat: ... No such file` stub (not JSON).
    (dir_path / "critic.jsonl").write_text(
        "cat: '/app/.../critic.jsonl': No such file or directory\n", encoding="utf-8"
    )
    score = {
        "task_ref": {"benchmark": "cybergym", "task_id": "arvo:1065"},
        "success": True,
        "failure_reason": None,
        "details": {"poc_source": "marker"},
    }
    (dir_path / "score.json").write_text(json.dumps(score), encoding="utf-8")


def test_load_picks_root_and_skips_stub(tmp_path: Path) -> None:
    _write_rollout(tmp_path)
    run = load_rollout_dir(tmp_path)

    assert run.benchmark == "cybergym"
    assert run.task_id == "arvo:1065"
    assert run.success is True
    assert run.poc_source == "marker"
    assert run.root_name == "exploit"
    assert run.root_result == "FINAL_ANSWER_MARKER"
    # The non-JSON stub file is skipped, leaving exactly the two real agents.
    assert [a.name for a in run.agents] == ["exploit", "analyzer"]
    assert run.models == ["anthropic/claude-opus-4.6", "openai/gpt-5.5"]


def test_spawn_call_nests_child_under_root_step(tmp_path: Path) -> None:
    _write_rollout(tmp_path)
    run = load_rollout_dir(tmp_path)

    # The root's single iteration calls spawn_analyzer -> analyzer hangs under it.
    assert len(run.root_steps) == 1
    step = run.root_steps[0]
    assert step["delegated"] == ["analyzer"]
    child = step["children"][0]
    assert child["agent"] == "analyzer"
    assert child["returned"] == "ANALYZER_RETURNED_HYPOTHESIS"
    assert child["iters"][0]["blocks"][0]["output"] == "ANALYZER_STEP_OUTPUT"
    # Nothing left dangling: the analyzer session was consumed by the call.
    assert run.unlinked == []


def test_render_html_is_self_contained(tmp_path: Path) -> None:
    _write_rollout(tmp_path)
    html = render_html(load_rollout_dir(tmp_path))

    assert html.startswith("<!DOCTYPE html>")
    # No external resources: the page is fully offline.
    assert "http://" not in html and "https://" not in html
    for needle in (
        "exploit",
        "analyzer",
        "spawn_analyzer",
        "ANALYZER_RETURNED_HYPOTHESIS",
        "FINAL_ANSWER_MARKER",
        "arvo:1065",
    ):
        assert needle in html


def test_missing_dir_raises(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(NotADirectoryError):
        load_rollout_dir(tmp_path / "does-not-exist")
