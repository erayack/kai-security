"""Post-run analysis of a cybergym run.

Pulls per-task rollout aggregates from Railway replicas (via the
``pull_rollouts_per_replica.sh`` companion script's output directory)
or directly via SSH, and reports:

* per-sub-agent JSONL inventory (presence/size/iter count)
* total dropped_blocks per task (cap-firing intensity)
* Solidity / EVM / cross-domain contamination hits
* spawn_verifier call counts (the original R5–R16 failure mode)
* truncation_notice samples

Usage::

    DATABASE_URL=... uv run python scripts/analyze_run.py <run_id>
    # or, after pulling rollouts locally:
    uv run python scripts/analyze_run.py <run_id> \
        --local docs/rollouts-2026-05-23-r18/cybergym
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

CONTAMINATION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bsolidity\b",
        r"\breentran",
        r"\bmsg\.sender\b",
        r"\bpayable\b",
        r"\bswc-",
        r"\bpragma solidity\b",
        r"\buniswap\b",
        r"\bdefi\b",
        r"\bsmart\s+contract\b",
        r"\bERC-?20\b",
        r"\bvault\b",
    ]
]

EXPECTED_SUBAGENTS = (
    "exploit",
    "analyzer",
    "researcher",
    "verifier",
    "critic",
    "fixer",
)


def fetch_workers(db_url: str, run_id: str) -> dict[str, str | None]:
    sql = "SELECT task_id, worker_id FROM bench_tasks WHERE run_id=%s"
    with psycopg.connect(db_url, row_factory=dict_row) as c:
        cur = c.cursor()
        cur.execute(sql, (run_id,))
        return {r["task_id"]: r["worker_id"] for r in cur.fetchall()}


def pull_rollouts_via_ssh(
    service: str, worker_id: str, run_id: str, task_id: str
) -> dict[str, list[str]]:
    """Read each rollout JSONL line into memory. Best on small runs."""
    cmd = (
        f"d=/app/output/bench/cybergym/run_{run_id}/{task_id}; "
        "for f in $d/state/*/rollouts/*.jsonl; do "
        '[ -f "$f" ] && echo "==FILE==$(basename $f .jsonl)" && cat "$f"; done'
    )
    out = subprocess.run(
        [
            "railway",
            "ssh",
            "--service",
            service,
            "--deployment-instance",
            worker_id,
            "--",
            cmd,
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    rolls: dict[str, list[str]] = {}
    current: str | None = None
    for line in out.stdout.splitlines():
        if line.startswith("==FILE=="):
            current = line[len("==FILE==") :].strip()
            rolls.setdefault(current, [])
            continue
        if current is None:
            continue
        rolls[current].append(line)
    return rolls


def load_local(local_root: Path, run_id: str, task_id: str) -> dict[str, list[str]]:
    rolls: dict[str, list[str]] = {}
    task_root = local_root / f"run_{run_id}" / task_id / "state"
    if not task_root.exists():
        return rolls
    for spawn_dir in task_root.iterdir():
        rdir = spawn_dir / "rollouts"
        if not rdir.exists():
            continue
        for jl in rdir.glob("*.jsonl"):
            name = jl.stem
            rolls.setdefault(name, []).extend(jl.read_text().splitlines())
    return rolls


# Heuristics for stripping prompt-echo from text before counting
# contamination. The cybergym DEFAULT_INSTRUCTIONS contains a
# "Cross-task contamination filter" section that enumerates every
# Solidity/EVM keyword we then grep for; whenever the model's
# ``print(context)`` block streams that section back, naïve counting
# yields a flurry of false positives.
PROMPT_ECHO_PHRASES = (
    "Cross-task contamination filter",
    "Cache-busting on re-spawns",
    "Solidity / EVM idioms",
    "Solidity, `pragma solidity`",
    "Do not mention smart contracts",
    "Do NOT mention smart contracts",
    "DISCARD the response as cache",
    "smart contracts, DeFi, Java",
    "C source only. Do not mention",
    "smart contracts, DeFi, Java, or anything unrelated",
    "If the sub-agent output mentions",
    "reentrancy, SWC-, payable, msg.sender, ERC-20, vault, AMM, Uniswap",
    "Solidity (reentrancy, SWC-, payable",
    "Solidity, `pragma solidity`",
)
# Substring of the contamination-filter section we strip wholesale to
# avoid counting each keyword inside our own listing.
_FILTER_BLOCK_RE = re.compile(
    r"(?:Cross-task contamination filter[\s\S]{0,2000}?\n\n)",
    re.IGNORECASE,
)


def _strip_prompt_echo(text: str) -> str:
    """Blank-out known prompt-echo substrings before contamination counting."""
    text = _FILTER_BLOCK_RE.sub(lambda m: " " * len(m.group(0)), text)
    for phrase in PROMPT_ECHO_PHRASES:
        text = text.replace(phrase, " " * len(phrase))
    return text


def count_contamination(text: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    cleaned = _strip_prompt_echo(text)
    for pat in CONTAMINATION_PATTERNS:
        n = len(pat.findall(cleaned))
        if n:
            counts[pat.pattern] += n
    return counts


def summarise(rolls: dict[str, list[str]]) -> dict[str, object]:
    """Return per-task summary stats."""
    inventory: dict[str, dict[str, int]] = {}
    total_dropped = 0
    total_iters = 0
    spawn_verifier_blocks = 0
    truncation_examples: list[str] = []
    contamination = Counter[str]()
    for agent, lines in rolls.items():
        iters = 0
        dropped = 0
        cb_count = 0
        size_bytes = 0
        for line in lines:
            if not line.strip():
                continue
            size_bytes += len(line) + 1
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") != "iteration":
                continue
            iters += 1
            cbs = d.get("code_blocks") or []
            cb_count += len(cbs)
            dropped += int(d.get("dropped_blocks") or 0)
            tn = d.get("truncation_notice")
            if tn and len(truncation_examples) < 3:
                truncation_examples.append(f"{agent}#{d.get('iteration')}: {tn[:200]}")
            for cb in cbs:
                code = cb.get("code", "")
                if agent == "exploit" and "spawn_verifier" in code:
                    spawn_verifier_blocks += 1
            contamination.update(count_contamination(d.get("response", "") or ""))
            for cb in cbs:
                contamination.update(count_contamination(cb.get("output", "") or ""))
        inventory[agent] = {"iters": iters, "cbs": cb_count, "bytes": size_bytes}
        total_dropped += dropped
        total_iters += iters
    return {
        "inventory": inventory,
        "total_dropped_blocks": total_dropped,
        "total_iters": total_iters,
        "spawn_verifier_blocks": spawn_verifier_blocks,
        "missing_subagents": [a for a in EXPECTED_SUBAGENTS if a not in inventory],
        "contamination_hits": dict(contamination),
        "truncation_examples": truncation_examples,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    parser.add_argument(
        "--service", default="kai-bench-cybergym-v2", help="Railway service name"
    )
    parser.add_argument(
        "--local",
        type=Path,
        default=None,
        help="Local rollout root (skips SSH; expects run_<id>/<task>/state/...).",
    )
    args = parser.parse_args()

    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("DATABASE_URL not set", file=sys.stderr)
        return 1
    workers = fetch_workers(db_url, args.run_id)
    if not workers:
        print(f"no tasks for run_id={args.run_id}", file=sys.stderr)
        return 2

    overall_dropped = 0
    overall_verifier = 0
    fail_count = 0
    for task_id in sorted(workers):
        worker_id = workers[task_id]
        print(f"\n=== {task_id} (worker={worker_id or 'none'}) ===")
        if args.local is not None:
            rolls = load_local(args.local, args.run_id, task_id)
        else:
            if not worker_id:
                print("  no worker_id — skipping")
                continue
            try:
                rolls = pull_rollouts_via_ssh(
                    args.service, worker_id, args.run_id, task_id
                )
            except subprocess.TimeoutExpired:
                print("  ssh timeout — skipping")
                continue
        if not rolls:
            print("  (no rollouts found)")
            fail_count += 1
            continue
        summary = summarise(rolls)
        for agent, stats in sorted(summary["inventory"].items()):
            print(
                f"  {agent:<12} iters={stats['iters']:>3} cbs={stats['cbs']:>3} "
                f"size={stats['bytes']:>8}"
            )
        if summary["missing_subagents"]:
            print(f"  missing sub-agents: {', '.join(summary['missing_subagents'])}")
        print(
            f"  total_dropped={summary['total_dropped_blocks']}  "
            f"spawn_verifier blocks={summary['spawn_verifier_blocks']}"
        )
        if summary["contamination_hits"]:
            top = sorted(
                summary["contamination_hits"].items(),
                key=lambda kv: -kv[1],
            )[:5]
            print(f"  contamination: {top}")
        for ex in summary["truncation_examples"]:
            print(f"  trunc: {ex}")
        overall_dropped += int(summary["total_dropped_blocks"])
        overall_verifier += int(summary["spawn_verifier_blocks"])

    print(
        f"\n=== overall: dropped_blocks={overall_dropped} "
        f"spawn_verifier_blocks={overall_verifier} "
        f"tasks_with_no_rollouts={fail_count} ==="
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
