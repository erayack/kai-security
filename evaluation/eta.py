"""ETA estimation for in-flight benchmark runs.

Reads the per-agent JSONL status streams the pipeline already writes to
``output/state/<run_id>/status_updates.jsonl`` and projects remaining
iteration time linearly. Only used by the CLI ``watch`` view — the
estimate is intentionally simple so users can tell *roughly* how long a
task has left, not predict cost.
"""

from __future__ import annotations

import json
from pathlib import Path
from statistics import mean
from typing import Any

DEFAULT_MAX_ITERS: dict[str, int] = {
    "exploit": 45,
    "analyzer": 30,
    "verifier": 30,
    "fixer": 25,
    "critic": 10,
    "researcher": 15,
    "poc_auditor": 5,
    "chain_assembler": 20,
    "patch_assembler": 15,
    "setup": 30,
}


def read_status_updates(state_dir: Path) -> list[dict[str, Any]]:
    """Return every status update JSON object from ``state_dir``."""

    path = state_dir / "status_updates.jsonl"
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def estimate_eta_seconds(
    state_dir: Path,
    *,
    max_iters: dict[str, int] | None = None,
) -> float | None:
    """Naive ETA: mean iteration time × remaining iterations.

    Returns ``None`` when there is not enough signal to estimate (no
    updates yet, or no recognised agent).
    """

    updates = read_status_updates(state_dir)
    if not updates:
        return None

    budget = {**DEFAULT_MAX_ITERS, **(max_iters or {})}

    by_agent: dict[str, list[float]] = {}
    last_iter: dict[str, int] = {}
    for u in updates:
        agent = u.get("agent_name") or u.get("agent")
        if not agent:
            continue
        t = u.get("iteration_time") or u.get("duration_ms")
        if t is None:
            continue
        if "duration_ms" in u and "iteration_time" not in u:
            t = float(t) / 1000.0
        by_agent.setdefault(agent, []).append(float(t))
        iter_n = u.get("iteration_num") or u.get("iteration")
        if isinstance(iter_n, int):
            last_iter[agent] = max(last_iter.get(agent, 0), iter_n)

    if not by_agent:
        return None

    eta = 0.0
    for agent, timings in by_agent.items():
        ceiling = budget.get(agent, 20)
        seen = last_iter.get(agent, len(timings))
        remaining = max(0, ceiling - seen)
        if remaining == 0 or not timings:
            continue
        eta += mean(timings) * remaining

    return eta if eta > 0 else None


def format_eta(seconds: float | None) -> str:
    """Format an ETA for display in the watch dashboard."""

    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m{s:02d}s"
    h, rem = divmod(int(seconds), 3600)
    m, _ = divmod(rem, 60)
    return f"{h}h{m:02d}m"
