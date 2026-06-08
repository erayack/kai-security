"""Self-contained HTML viewer for kai runs (findings + agent trace).

Reads a run directory written by the pipeline -- ``exploits.json`` for the
security findings and ``rollouts/*.jsonl`` (or flat ``*.jsonl``) for the
agent trace -- and renders a single offline HTML file. No server, no
external requests, no live state backend required.
"""

from __future__ import annotations

from kai.viewer.findings import Finding, load_findings
from kai.viewer.html import render_html, write_html
from kai.viewer.trace import RunTrace, load_rollout_dir

__all__ = [
    "Finding",
    "RunTrace",
    "load_findings",
    "load_rollout_dir",
    "render_html",
    "write_html",
]
