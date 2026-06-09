"""Compatibility shim — the rollout viewer now lives in :mod:`kai.viewer`.

The viewer was lifted out of the benchmark harness into the core package so
``kai view`` can render any pipeline run (findings + agent trace), not just
benchmark rollouts. This module is kept so ``evaluation`` keeps importing
``load_rollout_dir`` / ``render_html`` / ``write_html`` from here; new code
should import from :mod:`kai.viewer` directly.
"""

from __future__ import annotations

from ra.viewer.trace import load_rollout_dir

from kai.viewer.html import render_html, write_html

__all__ = ["load_rollout_dir", "render_html", "write_html"]
