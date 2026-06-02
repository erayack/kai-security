#!/usr/bin/env bash
# Morning report: one-command roll-up of the overnight benchmark run.
#
# Usage: bash scripts/morning_report.sh [run-id ...]
# If no run IDs are given, the script picks every bench_run in the
# Postgres queue.

set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
    if [[ -f /tmp/.railway_db_url ]]; then
        DATABASE_URL="$(cat /tmp/.railway_db_url)"
        export DATABASE_URL
    else
        echo "DATABASE_URL not set and /tmp/.railway_db_url missing — run:" >&2
        echo "  railway variables --service Postgres --json | jq -r .DATABASE_PUBLIC_URL > /tmp/.railway_db_url" >&2
        exit 1
    fi
fi

uv run python - "$@" <<'PY'
import json
import os
import sys

import psycopg


def fmt_pct(n: int, d: int) -> str:
    return "—" if d == 0 else f"{100 * n / d:.0f}%"


def main(argv: list[str]) -> int:
    url = os.environ["DATABASE_URL"]
    with psycopg.connect(url) as conn, conn.cursor() as cur:
        if argv:
            run_ids = argv
        else:
            cur.execute(
                "SELECT run_id FROM bench_runs ORDER BY started_at DESC LIMIT 20"
            )
            run_ids = [r[0] for r in cur.fetchall()]

        if not run_ids:
            print("No runs found in bench_runs.")
            return 0

        print("== overnight summary ==")
        print(
            f"{'run_id':>26}  {'bench':>11}  {'pend':>4}  {'run':>3}  "
            f"{'done':>4}  {'fail':>4}  {'pass':>5}  {'pass%':>5}"
        )
        totals = {"pending": 0, "running": 0, "done": 0, "failed": 0, "pass": 0}
        for run_id in run_ids:
            cur.execute(
                "SELECT benchmark, status, count(*) FROM bench_tasks "
                "WHERE run_id=%s GROUP BY benchmark, status",
                (run_id,),
            )
            rows = cur.fetchall()
            if not rows:
                continue
            bench = rows[0][0]
            by_status = {r[1]: r[2] for r in rows}
            cur.execute(
                "SELECT count(*) FROM bench_scores "
                "WHERE run_id=%s AND success=1",
                (run_id,),
            )
            passes = cur.fetchone()[0]
            done = by_status.get("done", 0)
            failed = by_status.get("failed", 0)
            pending = by_status.get("pending", 0)
            running = by_status.get("running", 0)
            print(
                f"{run_id:>26}  {bench:>11}  {pending:>4}  {running:>3}  "
                f"{done:>4}  {failed:>4}  {passes:>5}  {fmt_pct(passes, done+failed):>5}"
            )
            totals["pending"] += pending
            totals["running"] += running
            totals["done"] += done
            totals["failed"] += failed
            totals["pass"] += passes
        finished = totals["done"] + totals["failed"]
        print(
            f"{'TOTAL':>26}  {'':>11}  {totals['pending']:>4}  "
            f"{totals['running']:>3}  {totals['done']:>4}  "
            f"{totals['failed']:>4}  {totals['pass']:>5}  "
            f"{fmt_pct(totals['pass'], finished):>5}"
        )
        print()

        cur.execute(
            "SELECT task_id, benchmark, duration_s, score_json FROM bench_scores "
            "WHERE success=1 ORDER BY recorded_at DESC LIMIT 30"
        )
        wins = cur.fetchall()
        if wins:
            print("== recent passes ==")
            for tid, bench, dur, payload in wins:
                p = payload if isinstance(payload, dict) else (
                    json.loads(payload) if payload else {}
                )
                d = p.get("details") or {}
                note = d.get("score_mode") or "verified"
                extra = ""
                if bench == "bountybench":
                    extra = f"reported={d.get('reported_cwes')}"
                elif bench == "cybergym":
                    extra = f"poc_bytes={d.get('poc_bytes')}"
                elif bench == "evmbench":
                    matched = d.get("matched_titles") or []
                    extra = f"matched={len(matched)}"
                print(f"  [{bench:11}] {tid:30}  {dur:6.1f}s  {note:18}  {extra}")
        else:
            print("No successful tasks yet.")
        return 0


sys.exit(main(sys.argv[1:]))
PY
