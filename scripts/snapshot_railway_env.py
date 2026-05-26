"""Redacted Railway env snapshot for kai-bench-cybergym-v2.

Runs `railway variables --service <svc> --json`, masks credential-like
values, writes a Markdown table to the given output path. Raw values
never touch the parent process's stdout.

Redaction rules:
* Whitelist (literal): keys matching KAI_*_MODEL, KAI_*_ITERS,
  KAI_*_BACKEND, KAI_RESEARCHER_*, *_REPLICAS, LOG_LEVEL, *_PORT,
  *_TIMEOUT, *_INTERVAL, RAILWAY_*_NAME, RAILWAY_*_ID, BENCHMARK_*,
  DATABASE_HOST (host name only).
* Mask (length + first-2 + last-2): keys matching *KEY*, *TOKEN*,
  *SECRET*, *PASSWORD*, *_URL (DB urls), DATABASE_URL, *_DSN.
* Anything else: mask conservatively (length + first-2 + last-2),
  flag with `(unclassified)` so the reviewer can decide.

Usage:
  python scripts/snapshot_railway_env.py \\
    --service kai-bench-cybergym-v2 \\
    --output docs/env-snapshot-2026-05-19.md
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

LITERAL_PATTERNS = [
    re.compile(p)
    for p in (
        r"^KAI_.*_MODEL$",
        r"^KAI_.*_ITERS$",
        r"^KAI_.*_BACKEND$",
        r"^KAI_RESEARCHER_.*$",
        r".*_REPLICAS$",
        r"^LOG_LEVEL$",
        r".*_PORT$",
        r".*_TIMEOUT$",
        r".*_INTERVAL$",
        r"^RAILWAY_.*_NAME$",
        r"^RAILWAY_.*_ID$",
        r"^BENCHMARK_.*$",
        r"^PYTHONPATH$",
        r"^PYTHONUNBUFFERED$",
        r"^TZ$",
    )
]

MASK_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r".*KEY.*",
        r".*TOKEN.*",
        r".*SECRET.*",
        r".*PASSWORD.*",
        r".*PASSWD.*",
        r".*CREDENTIAL.*",
        r"^DATABASE_URL$",
        r".*_DSN$",
        r".*_URL$",  # generic *_URL caught here; whitelist above wins
    )
]


def classify(key: str) -> str:
    if any(p.match(key) for p in LITERAL_PATTERNS):
        return "literal"
    if any(p.match(key) for p in MASK_PATTERNS):
        return "mask"
    return "unclassified"


def mask_value(value: str) -> str:
    if not value:
        return "<empty>"
    n = len(value)
    if n <= 4:
        return f"<redacted {n} chars>"
    return f"{value[:2]}…{value[-2:]} <redacted {n} chars>"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    proc = subprocess.run(
        ["railway", "variables", "--service", args.service, "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(f"railway CLI failed: {proc.stderr}", file=sys.stderr)
        return proc.returncode

    raw = json.loads(proc.stdout)

    rows: list[tuple[str, str, str]] = []
    counts = {"literal": 0, "mask": 0, "unclassified": 0}
    for key in sorted(raw):
        value = str(raw[key]) if raw[key] is not None else ""
        kind = classify(key)
        counts[kind] += 1
        rendered = value if kind == "literal" else mask_value(value)
        rows.append((key, kind, rendered))

    lines = [
        f"# Railway env snapshot — `{args.service}` ({datetime.utcnow():%Y-%m-%d %H:%MZ})",
        "",
        f"**Service:** `{args.service}`",
        f"**Source:** `railway variables --service {args.service} --json`",
        "**Redaction policy:** see `scripts/snapshot_railway_env.py`.",
        "",
        "| Key | Classification | Value |",
        "| --- | --- | --- |",
    ]
    for key, kind, rendered in rows:
        safe_value = rendered.replace("|", "\\|").replace("`", "\\`")
        lines.append(f"| `{key}` | {kind} | `{safe_value}` |")
    lines.extend(
        [
            "",
            "## Counts",
            "",
            f"* literal: {counts['literal']}",
            f"* masked:  {counts['mask']}",
            f"* unclassified (masked conservatively): {counts['unclassified']}",
            f"* total:   {sum(counts.values())}",
            "",
            "## Notes",
            "",
            "* `literal` = key whitelisted in policy; full value printed.",
            "* `mask` = key matched a secret pattern; only length + 2-char "
            "prefix + 2-char suffix shown.",
            "* `unclassified` = key matched neither list; conservatively "
            "masked. Reviewer should decide whether to add to the whitelist "
            "for future snapshots.",
        ]
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n")
    print(
        f"wrote {sum(counts.values())} keys "
        f"(literal={counts['literal']}, "
        f"masked={counts['mask']}, "
        f"unclassified={counts['unclassified']}) "
        f"to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
