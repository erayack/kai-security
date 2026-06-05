"""Batch checker + scorecard for pulled CyberGym rollouts.

For every ``cybergym-<task>`` rollout dir under ``--dir``, prints one row with
both metrics and writes a markdown + json scorecard:

  adapter     — what the benchmark adapter scored (success / failure_reason)
  found_bug   — SOFT: did the agent's hypothesis match the documented bug
                (cybergym_bugmatch, via an OSS model). NOT a reproduction; at
                level1 the bug is described to the agent, so read it as
                "understood + localized", not "found cold".
  reproduced  — HARD: did a recovered PoC actually crash on the eval server
                (cybergym_recheck — reconstructs bytes via an OSS model and
                submits; the server's exit code is the verdict).

``--skip-hard`` runs only the soft column (no PoC reconstruction). The hard
column runs the OSS-model reconstruction and needs the eval server up.

Usage:
    export OPENROUTER_API_KEY=...
    python -m evaluation.cybergym_check --dir docs/rollouts-<date>-<run> \
        --server http://127.0.0.1:8666 --mask-map ~/cybergym/mask_map.json \
        --model-soft google/gemini-2.5-flash --model-hard deepseek/deepseek-chat
    # soft-only (no reconstruction):
    python -m evaluation.cybergym_check --dir <dir> --skip-hard
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from evaluation.cybergym_bugmatch import bugmatch, load_truth_and_hypothesis
from evaluation.cybergym_recheck import recheck
from evaluation.cybergym_verify import default_mask_map, load_mask_map


def _load_score(rollout_dir: Path) -> dict:
    try:
        data = json.loads((rollout_dir / "score.json").read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _task_id(score: dict) -> str:
    return str(
        (score.get("task_ref") or {}).get("task_id")
        or (score.get("details") or {}).get("task_id")
        or ""
    )


def check_one(
    rollout_dir: Path,
    *,
    server: str,
    mask_map: dict[str, str],
    model_soft: str,
    model_hard: str,
    api_key: str,
    max_attempts: int,
    skip_hard: bool,
) -> dict[str, object]:
    score = _load_score(rollout_dir)
    details = score.get("details") or {}
    task_id = _task_id(score)
    adapter = (
        "pass" if score.get("success") else (score.get("failure_reason") or "fail")
    )

    gt, hyp = load_truth_and_hypothesis(rollout_dir)
    bm = bugmatch(rollout_dir, model_soft, api_key)
    row: dict[str, object] = {
        "dir": rollout_dir.name,
        "task_id": task_id,
        "adapter": adapter,
        "poc_source": details.get("poc_source"),
        "found_bug": bm["verdict"],
        "found_bug_reason": bm.get("reason", ""),
        "ground_truth": gt[:1800],
        "hypothesis": hyp[:1800],
        "reproduced": "skipped",
        "exit_code": None,
        "recheck_source": None,
    }
    if not skip_hard and task_id:
        rc = recheck(
            rollout_dir,
            task_id,
            server,
            mask_map,
            model_hard,
            api_key,
            max_attempts=max_attempts,
        )
        if rc.get("verified"):
            row["reproduced"] = "PASS"
        elif rc.get("http_status") == 200:
            row["reproduced"] = "FAIL"
        else:
            row["reproduced"] = "ERR"
        row["exit_code"] = rc.get("exit_code")
        row["recheck_source"] = rc.get("byte_source")
    return row


def _scorecard_md(rows: list[dict], skip_hard: bool) -> str:
    n = len(rows)
    found = sum(1 for r in rows if r["found_bug"] == "MATCH")
    repro = sum(1 for r in rows if r["reproduced"] == "PASS")
    lines = [
        "# CyberGym rollout scorecard",
        "",
        f"- rollouts: **{n}**",
        f"- found-the-bug (soft): **{found}/{n}** MATCH",
        (
            "- reproduced (hard): _skipped_ (run without --skip-hard)"
            if skip_hard
            else f"- reproduced (hard): **{repro}/{n}** PASS"
        ),
        "",
        "| task | adapter | found_bug (soft) | reproduced (hard) | exit | poc_source | trace |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['task_id'] or r['dir']} | {r['adapter']} | {r['found_bug']} | "
            f"{r['reproduced']} | {r['exit_code'] if r['exit_code'] is not None else ''} | "
            f"{r['poc_source'] or ''} | [trace]({r['dir']}/trace.html) |"
        )
    lines += [
        "",
        "> soft = hypothesis vs documented bug (not a reproduction; "
        "level1 gives the bug to the agent). hard = a recovered PoC "
        "actually crashed the eval server.",
    ]
    return "\n".join(lines) + "\n"


def _scorecard_html(rows: list[dict], skip_hard: bool) -> str:
    """One-click browsable index: scorecard table linking each trace.html."""
    import html as _h

    n = len(rows)
    found = sum(1 for r in rows if r["found_bug"] == "MATCH")
    repro = sum(1 for r in rows if r["reproduced"] == "PASS")
    badge = {
        "MATCH": "#1d6b3a",
        "NO_MATCH": "#7a2b2b",
        "UNKNOWN": "#3a4250",
        "PASS": "#1d6b3a",
        "FAIL": "#7a2b2b",
        "ERR": "#7a5a1f",
        "skipped": "#3a4250",
    }

    def esc(x: object) -> str:
        return _h.escape("" if x is None else str(x))

    trs = []
    for r in rows:
        trs.append(
            "<tr><td>"
            + esc(r["task_id"] or r["dir"])
            + "</td><td>"
            + esc(r["adapter"])
            + '</td><td><span class="b" style="background:'
            + badge.get(str(r["found_bug"]), "#3a4250")
            + '">'
            + esc(r["found_bug"])
            + '</span></td><td><span class="b" style="background:'
            + badge.get(str(r["reproduced"]), "#3a4250")
            + '">'
            + esc(r["reproduced"])
            + "</span></td><td>"
            + esc(r["exit_code"])
            + "</td><td>"
            + esc(r["poc_source"])
            + '</td><td><a href="'
            + esc(r["dir"])
            + '/trace.html">trace</a></td></tr>'
        )
    hard = (
        "reproduced (hard): skipped"
        if skip_hard
        else "reproduced (hard): <b>" + str(repro) + "/" + str(n) + "</b> PASS"
    )
    style = (
        "body{font:14px -apple-system,BlinkMacSystemFont,sans-serif;background:#0e1116;"
        "color:#d6deeb;margin:24px;max-width:1040px}h1{font-size:17px}"
        ".sum{color:#9fb0c3;margin-bottom:16px}table{border-collapse:collapse;width:100%}"
        "th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #232b36}"
        "th{color:#8a99ad;font-size:12px}.b{padding:1px 8px;border-radius:999px;"
        "font-size:12px;color:#eaf3ea}a{color:#7fdbca}"
        "h2{font-size:13px;color:#8a99ad;margin:22px 0 8px}"
        "details{border:1px solid #232b36;border-radius:8px;margin:8px 0;padding:0 12px}"
        "summary{cursor:pointer;padding:9px 0;font-weight:600}"
        ".lbl{font-size:11px;text-transform:uppercase;letter-spacing:.05em;"
        "color:#6f7e92;margin:8px 0 4px}.jr{color:#cdd9e5;margin-bottom:9px}"
        "pre{white-space:pre-wrap;word-break:break-word;background:#0b1620;"
        "border:1px solid #1b2a36;border-radius:6px;padding:9px;font-size:12.5px;margin:0}"
        ".note{color:#6f7e92;font-size:12px;margin-top:14px}"
    )
    dets = []
    for r in rows:
        dets.append(
            "<details><summary>"
            + esc(r["task_id"] or r["dir"])
            + " &mdash; "
            + esc(r["found_bug"])
            + "</summary>"
            + '<div class="lbl">documented bug (ground truth)</div><pre>'
            + esc(r.get("ground_truth") or "(none recorded)")
            + "</pre>"
            + '<div class="lbl">agent hypothesis (what it found / where)</div><pre>'
            + esc(r.get("hypothesis") or "(none)")
            + "</pre>"
            + '<div class="lbl">judge decision</div><div class="jr">'
            + esc(r["found_bug"])
            + " &mdash; "
            + esc(r.get("found_bug_reason") or "")
            + "</div></details>"
        )
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>CyberGym scorecard</title><style>" + style + "</style></head><body>"
        "<h1>CyberGym rollout scorecard</h1>"
        '<div class="sum">'
        + str(n)
        + " rollouts &middot; found-the-bug (soft): <b>"
        + str(found)
        + "/"
        + str(n)
        + "</b> MATCH &middot; "
        + hard
        + "</div>"
        "<table><tr><th>task</th><th>adapter</th><th>found_bug (soft)</th>"
        "<th>reproduced (hard)</th><th>exit</th><th>poc_source</th><th>trace</th></tr>"
        + "".join(trs)
        + "</table>"
        + "<h2>per-task detail &mdash; what the agent found vs the documented bug</h2>"
        + "".join(dets)
        + '<div class="note">soft = hypothesis vs documented bug (not a reproduction; '
        "level1 gives the bug to the agent). hard = a recovered PoC actually crashed "
        "the eval server.</div></body></html>"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="cybergym_check",
        description="Batch soft+hard check over pulled cybergym rollouts; writes a scorecard.",
    )
    ap.add_argument(
        "--dir", required=True, help="parent dir of cybergym-<task> rollouts"
    )
    ap.add_argument("--server", default="http://127.0.0.1:8666")
    ap.add_argument(
        "--mask-map",
        default=default_mask_map(),
        help="path to mask_map.json (or set KAI_CYBERGYM_MASK_MAP)",
    )
    ap.add_argument("--model-soft", default="google/gemini-2.5-flash")
    ap.add_argument("--model-hard", default="deepseek/deepseek-chat")
    ap.add_argument("--max-attempts", type=int, default=1)
    ap.add_argument("--skip-hard", action="store_true", help="soft column only")
    ap.add_argument("--or-key", default=os.environ.get("OPENROUTER_API_KEY", ""))
    ap.add_argument(
        "--out", default=None, help="scorecard path (default <dir>/SCORECARD.md)"
    )
    args = ap.parse_args(argv)
    if not args.or_key:
        print("set OPENROUTER_API_KEY or pass --or-key", file=sys.stderr)
        return 2

    base = Path(args.dir)
    dirs = sorted(p for p in base.glob("cybergym-*") if (p / "score.json").is_file())
    if not dirs:
        print(
            f"no cybergym-* rollout dirs with score.json under {base}", file=sys.stderr
        )
        return 2
    mask_map = load_mask_map(Path(args.mask_map)) if not args.skip_hard else {}

    rows = []
    print(
        f"{'task':16} {'adapter':16} {'found_bug':10} {'reproduced':11} exit",
        file=sys.stderr,
    )
    for d in dirs:
        r = check_one(
            d,
            server=args.server,
            mask_map=mask_map,
            model_soft=args.model_soft,
            model_hard=args.model_hard,
            api_key=args.or_key,
            max_attempts=args.max_attempts,
            skip_hard=args.skip_hard,
        )
        rows.append(r)
        print(
            f"{(r['task_id'] or r['dir']):16} {str(r['adapter'])[:16]:16} "
            f"{str(r['found_bug']):10} {str(r['reproduced']):11} "
            f"{r['exit_code'] if r['exit_code'] is not None else ''}",
            file=sys.stderr,
        )

    out = Path(args.out) if args.out else base / "SCORECARD.md"
    out.write_text(_scorecard_md(rows, args.skip_hard))
    (out.with_suffix(".json")).write_text(json.dumps(rows, indent=2))
    (base / "index.html").write_text(_scorecard_html(rows, args.skip_hard))
    print(
        f"\nwrote {out}, {out.with_suffix('.json')}, {base / 'index.html'}",
        file=sys.stderr,
    )
    print(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
