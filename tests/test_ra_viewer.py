"""Tests for the reusable ra.viewer (framework-level trace viewer + composer).

These exercise the viewer with NO kai/findings involvement, proving any ra
agent can render its run trace.
"""

from __future__ import annotations

import json
from pathlib import Path

from ra.viewer import Panel, load_rollout_dir, render_page, render_trace_html
from ra.viewer.trace import RunTrace


def _write_rollout(dir_path: Path) -> None:
    rollouts = dir_path / "rollouts"
    rollouts.mkdir()
    rows = [
        {
            "type": "metadata",
            "agent": "root",
            "depth": 0,
            "spawn_id": "r1",
            "timestamp": "2026-06-03T00:00:00+00:00",
            "model": "some/model",
        },
        {
            "type": "iteration",
            "agent": "root",
            "iteration": 1,
            "spawn_id": "r1",
            "timestamp": "2026-06-03T00:01:00+00:00",
            "response": "thinking",
            "code_blocks": [],
        },
        {
            "type": "result",
            "agent": "root",
            "iteration": 1,
            "spawn_id": "r1",
            "timestamp": "2026-06-03T00:02:00+00:00",
            "final_answer": "done",
        },
    ]
    (rollouts / "root.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows), encoding="utf-8"
    )


def test_render_trace_html_is_self_contained(tmp_path: Path) -> None:
    _write_rollout(tmp_path)
    html = render_trace_html(load_rollout_dir(tmp_path))

    assert html.startswith("<!DOCTYPE html>")
    assert "http://" not in html and "https://" not in html
    # Trace tab present; no kai Findings tab when used standalone.
    assert 'id="view-trace"' in html
    assert 'id="view-findings"' not in html
    assert "renderTrace();" in html


def test_render_page_escapes_brand_in_shell_chrome() -> None:
    # Regression: brand is a public render_page/render_trace_html input, so it
    # must not be able to break out of the <title> or header markup.
    panel = Panel(
        id="trace",
        label="Trace",
        section='<section class="view" id="view-trace"></section>',
        css="",
        js="",
        render_call="",
    )
    brand = '__DATA__</title><script>alert("x")</script><h1>'
    data = {"title": '<img src=x onerror=alert("data")>', "run": {}}

    html = render_page(data, [panel], brand=brand)

    assert '</title><script>alert("x")</script>' not in html
    assert '<img src=x onerror=alert("data")>' not in html
    assert "__DATA__&lt;/title&gt;&lt;script&gt;alert" in html


def test_render_page_composes_arbitrary_panels() -> None:
    run = RunTrace(
        title="t",
        benchmark=None,
        task_id="t",
        success=None,
        failure_reason=None,
        poc_source=None,
        models=["m"],
        agents=[],
        root_name="root",
        root_result=None,
        root_steps=[],
        unlinked=[],
    )
    custom = Panel(
        id="notes",
        label="Notes",
        section='<section class="view" id="view-notes"><p id="n"></p></section>',
        css=".notes{}",
        js="function renderNotes(){document.getElementById('n').textContent='hi';}",
        render_call="renderNotes();",
    )
    html = render_page(
        {"title": "t", "run": run.as_dict()}, [custom], default_view="notes"
    )
    assert 'id="view-notes"' in html
    assert "renderNotes();" in html
    assert '"id": "notes"' in html or '"id":"notes"' in html
