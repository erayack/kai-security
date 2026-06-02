"""Live status dashboard for an in-flight cybergym run.

Polls Postgres + Railway replicas to surface per-task iter count,
dropped_blocks, sub-agent JSONL inventory, and Solidity contamination
hits. Refreshes every 30s.

Usage::

    DATABASE_URL=... uv run python scripts/watch_run.py <run_id>

Prerequisites: Railway CLI authenticated and linked to the cybergym
project.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass

import psycopg
from psycopg.rows import dict_row

SOLIDITY_RE = re.compile(
    r"solidity|reentran|msg\.sender|payable|swc-|pragma solidity|defi|smart contract",
    re.IGNORECASE,
)


@dataclass
class TaskState:
    task_id: str
    status: str
    worker_id: str | None
    running_s: int | None
    hb_s: int | None


def fetch_state(db_url: str, run_id: str) -> list[TaskState]:
    sql = """
SELECT task_id, status, worker_id,
       EXTRACT(EPOCH FROM (NOW() - claimed_at))::int AS running_s,
       EXTRACT(EPOCH FROM (NOW() - last_heartbeat_at))::int AS hb_s
FROM bench_tasks WHERE run_id=%s ORDER BY task_id
"""
    with psycopg.connect(db_url, row_factory=dict_row) as c:
        cur = c.cursor()
        cur.execute(sql, (run_id,))
        return [
            TaskState(
                task_id=r["task_id"],
                status=r["status"],
                worker_id=r["worker_id"],
                running_s=r["running_s"],
                hb_s=r["hb_s"],
            )
            for r in cur.fetchall()
        ]


def replica_inventory(
    service: str, deployment_instance: str, run_id: str, task_id: str
) -> dict[str, object]:
    """Return per-task rollout inventory from a replica via SSH."""
    cmd = (
        f"d=/app/output/bench/cybergym/run_{run_id}/{task_id}; "
        "for f in $d/state/*/rollouts/*.jsonl; do "
        "[ -f \"$f\" ] && printf '%s\\t%d\\t%d\\t%d\\n' "
        '"$(basename $f .jsonl)" "$(stat -c %s $f)" '
        '"$(grep -c \'\\"type\\": \\"iteration\\"\' $f)" '
        "\"$(grep -ciE 'solidity|reentran|msg\\.sender|payable|swc-|pragma solidity|defi|smart contract' $f)\"; "
        "done"
    )
    try:
        out = subprocess.run(
            [
                "railway",
                "ssh",
                "--service",
                service,
                "--deployment-instance",
                deployment_instance,
                "--",
                cmd,
            ],
            capture_output=True,
            text=True,
            timeout=45,
        )
    except subprocess.TimeoutExpired:
        return {"_error": "ssh timeout"}
    if out.returncode != 0:
        return {"_error": f"ssh rc={out.returncode}"}
    files: dict[str, dict[str, int]] = {}
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        name, size, iters, contam = parts
        try:
            files[name] = {
                "size": int(size),
                "iters": int(iters),
                "contam": int(contam),
            }
        except ValueError:
            continue
    return {"files": files}


def render(states: list[TaskState], inventories: dict[str, dict]) -> str:
    lines = [f"\n=== {time.strftime('%H:%M:%S')} ===\n"]
    header = (
        f"{'task':<14} {'status':<10} {'run_s':>6} {'hb_s':>5} "
        f"{'rollouts':<60} {'contam':>6}"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for s in states:
        inv = inventories.get(s.task_id, {})
        files = inv.get("files", {}) if isinstance(inv, dict) else {}
        err = inv.get("_error") if isinstance(inv, dict) else None
        if err:
            roll = f"<{err}>"
            contam = "?"
        else:
            roll = (
                " ".join(sorted(f"{n}={f['iters']}i" for n, f in files.items()))
                or "(none)"
            )
            contam = str(sum(f.get("contam", 0) for f in files.values()))
        running = "-" if s.running_s is None else f"{s.running_s}"
        hb = "-" if s.hb_s is None else f"{s.hb_s}"
        lines.append(
            f"{s.task_id:<14} {s.status:<10} {running:>6} {hb:>5} {roll:<60} {contam:>6}"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    parser.add_argument(
        "--service", default="kai-bench-cybergym-v2", help="Railway service name"
    )
    parser.add_argument(
        "--interval", type=int, default=30, help="Refresh interval (seconds)"
    )
    parser.add_argument("--once", action="store_true", help="Print once and exit")
    args = parser.parse_args()
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("DATABASE_URL not set", file=sys.stderr)
        return 1
    while True:
        states = fetch_state(db_url, args.run_id)
        inventories: dict[str, dict] = {}
        for s in states:
            if s.status not in ("running", "claimed") or not s.worker_id:
                continue
            inventories[s.task_id] = replica_inventory(
                args.service, s.worker_id, args.run_id, s.task_id
            )
        print(render(states, inventories))
        active = sum(1 for s in states if s.status in ("running", "claimed", "pending"))
        if active == 0:
            print("\n[all tasks terminal]")
            return 0
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
