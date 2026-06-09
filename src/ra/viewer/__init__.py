"""Reusable HTML viewer for ``ra`` agent runs.

Renders a run directory's ``*.jsonl`` rollouts into a single offline HTML page
— a tabbed shell with a built-in causal **Trace** panel and a shared design
system (:mod:`ra.viewer.style`). Domain layers compose extra panels on top via
:func:`ra.viewer.html.render_page`; kai-security, for example, adds a security
**Findings** panel.
"""

from __future__ import annotations

from ra.viewer.html import (
    Panel,
    render_page,
    render_trace_html,
    trace_panel,
    write_trace_html,
)
from ra.viewer.trace import RunTrace, load_rollout_dir

__all__ = [
    "Panel",
    "RunTrace",
    "load_rollout_dir",
    "render_page",
    "render_trace_html",
    "trace_panel",
    "write_trace_html",
]
