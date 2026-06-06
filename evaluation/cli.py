"""Command-line entry point for the evaluation harness.

Subcommands:

* ``run`` -- drive an adapter over a task list and write per-task artefacts.
* ``list`` -- enumerate the tasks an adapter exposes.
* ``status`` -- print a one-shot summary for a benchmark run directory.
* ``watch`` -- live (refreshing) view of an in-flight run.
* ``report`` -- render an existing run as Markdown or JSON to stdout.
* ``view`` -- render a rollout directory as a self-contained HTML trace viewer.
* ``enqueue`` -- push tasks into the shared Postgres queue for Railway workers.

The CLI is deliberately thin -- it instantiates an adapter, an optional
runner, and forwards everything else to the adapter / runner. All
benchmark-specific logic lives in :mod:`evaluation.adapters`.

When ``DATABASE_URL`` is set, ``status`` and ``watch`` query Postgres
(via :mod:`evaluation.store`) instead of, or in addition to, the local
``summary.json``. The local-only path keeps working when ``DATABASE_URL``
is unset, so single-machine usage is unchanged.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.table import Table

from evaluation.adapters.base import resolve_adapter
from evaluation.eta import estimate_eta_seconds, format_eta
from evaluation.runner import DEFAULT_OUTPUT_ROOT, BenchmarkRunner
from evaluation.schemas import BenchmarkRun, TaskRef

from evaluation.store import RunSummary, TaskStore
from kai import generate_id

LOG = logging.getLogger("evaluation.cli")


def _add_adapter_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--adapter", required=True, help="Adapter name (e.g. cybergym, noop)."
    )
    parser.add_argument(
        "--adapter-config",
        default=None,
        help="Optional JSON dict or @path/to/config.json forwarded to the adapter factory.",
    )


def _parse_adapter_config(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    if raw.startswith("@"):
        return json.loads(Path(raw[1:]).read_text())
    return json.loads(raw)


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evaluation",
        description="Run security-agent benchmarks against the kai pipeline.",
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase log verbosity."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run an adapter over a task list.")
    _add_adapter_flag(run)
    run.add_argument(
        "--tasks",
        nargs="*",
        default=None,
        help="Specific task IDs to run (default: all).",
    )
    run.add_argument("--limit", type=int, default=None, help="Cap on number of tasks.")
    run.add_argument("--concurrency", type=int, default=1, help="Parallel workers.")
    run.add_argument(
        "--per-task-timeout",
        type=int,
        default=60 * 60,
        help="Wall-clock cap per task in seconds (default: 3600).",
    )
    run.add_argument(
        "--output-root",
        type=Path,
        default=None,
        help=f"Override output root (default: {DEFAULT_OUTPUT_ROOT}).",
    )
    run.add_argument(
        "--pipeline-arg",
        action="append",
        default=[],
        help="Extra arg forwarded to kai.main pipeline (repeatable).",
    )
    run.add_argument(
        "--env",
        action="append",
        default=[],
        help="KEY=VALUE env override for the pipeline subprocess (repeatable).",
    )

    lst = sub.add_parser("list", help="List the tasks an adapter exposes.")
    _add_adapter_flag(lst)
    lst.add_argument("--limit", type=int, default=None)

    status = sub.add_parser(
        "status", help="Print summary for one or more run directories."
    )
    status.add_argument(
        "run_dirs",
        nargs="+",
        type=Path,
        help="Path(s) to run directories or summary.json.",
    )

    watch = sub.add_parser("watch", help="Live view of an in-flight run.")
    watch.add_argument("run_dir", type=Path, help="Run directory (or summary.json).")
    watch.add_argument(
        "--interval", type=float, default=2.0, help="Refresh interval in seconds."
    )

    report = sub.add_parser(
        "report", help="Render an existing run as markdown or JSON."
    )
    report.add_argument("run_dir", type=Path)
    report.add_argument("--format", choices=["markdown", "json"], default="markdown")

    view = sub.add_parser(
        "view",
        help="Render a rollout directory as a self-contained HTML trace viewer.",
    )
    view.add_argument(
        "rollout_dir",
        type=Path,
        help="Directory with per-agent <agent>.jsonl rollouts (+ optional score.json).",
    )
    view.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output HTML path (default: <rollout_dir>/trace.html).",
    )
    view.add_argument(
        "--open",
        dest="open_browser",
        action="store_true",
        help="Open the generated file in the default browser.",
    )

    index = sub.add_parser(
        "index",
        help="Build one overall index.html linking every rollout's trace + verdict.",
    )
    index.add_argument(
        "dir",
        type=Path,
        help="Parent dir of pulled rollout task dirs (each with score.json).",
    )
    index.add_argument(
        "-o",
        "--out",
        type=Path,
        default=None,
        help="Output HTML path (default: <dir>/index.html).",
    )
    index.add_argument(
        "--no-traces",
        action="store_true",
        help="Skip (re)rendering per-rollout trace.html; build only the index.",
    )
    index.add_argument(
        "--no-judge",
        action="store_true",
        help="Skip the LLM found-bug judge (cybergym bugmatch); adapter verdicts only.",
    )
    index.add_argument(
        "--model-soft",
        default=None,
        help="OpenRouter model for the found-bug judge (default: cybergym_eval's).",
    )
    index.add_argument(
        "--or-key",
        default=os.environ.get("OPENROUTER_API_KEY", ""),
        help="OpenRouter key for the found-bug judge (default: $OPENROUTER_API_KEY).",
    )

    enqueue = sub.add_parser(
        "enqueue",
        help="Push tasks into the shared Postgres queue for Railway workers.",
    )
    _add_adapter_flag(enqueue)
    enqueue.add_argument(
        "--tasks",
        nargs="*",
        default=None,
        help="Specific task IDs to enqueue (default: all).",
    )
    enqueue.add_argument("--limit", type=int, default=None)
    enqueue.add_argument(
        "--run-id",
        default=None,
        help="Reuse an existing run_id (default: generate a new one).",
    )
    enqueue.add_argument(
        "--database-url",
        default=None,
        help="Override DATABASE_URL for this invocation.",
    )
    enqueue.add_argument(
        "--config",
        action="append",
        default=[],
        help="KEY=VALUE attached to bench_runs.config (repeatable).",
    )

    rejudge = sub.add_parser(
        "rejudge",
        help=(
            "Re-score existing bench_scores rows via the LLM judge, without "
            "re-running the pipeline. Only useful for runs where the "
            "adapter persisted agent_findings_text (bountybench, evmbench)."
        ),
    )
    rejudge.add_argument("run_ids", nargs="+")
    rejudge.add_argument(
        "--benchmark",
        choices=["bountybench", "evmbench"],
        required=True,
        help="Which adapter's judge to apply.",
    )
    rejudge.add_argument(
        "--model",
        default=None,
        help="Override the judge model (default: env / adapter default).",
    )
    rejudge.add_argument(
        "--reasons",
        nargs="*",
        default=None,
        help=(
            "Only re-judge rows whose failure reason is in this set. Default: "
            "['cwe_mismatch','no_cwe_reported'] for bountybench and "
            "['no_vuln_titles_matched','no_findings_reported'] for evmbench."
        ),
    )
    rejudge.add_argument(
        "--dry-run",
        action="store_true",
        help="Print verdicts; do not update the DB.",
    )
    rejudge.add_argument(
        "--database-url",
        default=None,
        help="Override DATABASE_URL for this invocation.",
    )

    return parser


def _configure_logging(verbose: int) -> None:
    level = logging.WARNING - min(verbose, 2) * 10
    logging.basicConfig(
        level=level, format="%(levelname)-5s %(name)s: %(message)s", stream=sys.stderr
    )


def _resolve_summary(path: Path) -> Path:
    """Accept either a run dir or a summary.json and return the JSON path."""

    if path.is_dir():
        candidate = path / "summary.json"
        if not candidate.exists():
            raise FileNotFoundError(f"No summary.json under {path}")
        return candidate
    return path


def _load_run(path: Path) -> BenchmarkRun:
    summary_path = _resolve_summary(path)
    return BenchmarkRun.model_validate_json(summary_path.read_text())


def _cmd_run(args: argparse.Namespace) -> int:
    config = _parse_adapter_config(args.adapter_config)
    adapter = resolve_adapter(args.adapter, config)

    tasks: list[TaskRef] = list(
        adapter.filter_tasks(ids=args.tasks or None, limit=args.limit)
    )
    if not tasks:
        print("No tasks matched the filter; nothing to do.", file=sys.stderr)
        return 0

    env_overrides: dict[str, str] = {}
    for raw in args.env:
        if "=" not in raw:
            raise SystemExit(f"--env expects KEY=VALUE, got {raw!r}")
        key, value = raw.split("=", 1)
        env_overrides[key] = value

    runner = BenchmarkRunner(
        adapter,
        output_root=args.output_root,
        concurrency=args.concurrency,
        per_task_timeout_s=args.per_task_timeout,
        pipeline_args=args.pipeline_arg,
        env_overrides=env_overrides,
    )
    run = runner.run(tasks)

    console = Console()
    console.print(_render_run_table(run))
    return 0 if run.fail_count == 0 else 1


def _cmd_list(args: argparse.Namespace) -> int:
    config = _parse_adapter_config(args.adapter_config)
    adapter = resolve_adapter(args.adapter, config)
    for task in adapter.filter_tasks(limit=args.limit):
        print(task.task_id)
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    console = Console()
    store = _open_store_if_configured()

    for path in args.run_dirs:
        path_str = str(path)
        run_id = _looks_like_run_id(path_str)
        if store is not None and (run_id or not path.exists()):
            target_id = run_id or path_str
            summary = store.get_run(target_id)
            if summary is None:
                console.print(f"[red]{target_id}: no such run in DB[/red]")
                continue
            console.print(_render_db_summary_table(summary))
            continue
        try:
            run = _load_run(path)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            console.print(f"[red]{path}: {exc}[/red]")
            continue
        console.print(_render_run_table(run))
    if store is not None:
        store.close()
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    store = _open_store_if_configured()
    path_str = str(args.run_dir)
    run_id = _looks_like_run_id(path_str)
    if store is not None and (run_id or not args.run_dir.exists()):
        return _watch_db(store, run_id or path_str, args.interval)

    run_dir = args.run_dir if args.run_dir.is_dir() else args.run_dir.parent
    summary_path = run_dir / "summary.json"
    if not summary_path.exists():
        print(f"summary.json not found in {run_dir}", file=sys.stderr)
        return 1

    console = Console()
    with Live(console=console, refresh_per_second=4) as live:
        while True:
            try:
                run = BenchmarkRun.model_validate_json(summary_path.read_text())
            except json.JSONDecodeError:
                time.sleep(args.interval)
                continue
            live.update(_render_watch_table(run, run_dir))
            if run.finished_at is not None:
                break
            time.sleep(args.interval)
    return 0 if run.fail_count == 0 else 1


def _watch_db(store: TaskStore, run_id: str, interval: float) -> int:
    console = Console()
    with Live(console=console, refresh_per_second=2) as live:
        while True:
            summary = store.get_run(run_id)
            if summary is None:
                live.update(f"[red]run {run_id} not found[/red]")
                time.sleep(interval)
                continue
            live.update(_render_db_summary_table(summary))
            if summary.finished_at is not None:
                break
            time.sleep(interval)
    store.close()
    return 0 if summary.failed == 0 else 1


def _cmd_enqueue(args: argparse.Namespace) -> int:
    database_url = args.database_url or os.environ.get("DATABASE_URL")
    if not database_url:
        print(
            "enqueue requires DATABASE_URL or --database-url",
            file=sys.stderr,
        )
        return 2

    config = _parse_adapter_config(args.adapter_config)
    adapter = resolve_adapter(args.adapter, config)
    tasks = list(adapter.filter_tasks(ids=args.tasks or None, limit=args.limit))
    if not tasks:
        print("No tasks matched the filter; nothing enqueued.", file=sys.stderr)
        return 0

    run_id = args.run_id or generate_id()
    # Persist the full adapter_config on the run row so workers can
    # rebuild a per-run adapter when claiming. Without this, the worker
    # uses ``BENCHMARK_CONFIG`` (set once at deploy time) for every
    # claim -- which made bountybench exploit / patch runs silently
    # fall through to detect-mode scoring (see the 2026-05-16 incident).
    run_config: dict[str, Any] = {
        "adapter": args.adapter,
        "adapter_config": config,
    }
    for raw in args.config:
        if "=" not in raw:
            raise SystemExit(f"--config expects KEY=VALUE, got {raw!r}")
        key, value = raw.split("=", 1)
        run_config[key] = value

    store = TaskStore(database_url)
    store.setup_schema()
    inserted = store.enqueue(
        run_id=run_id,
        benchmark=adapter.name,
        task_refs=tasks,
        config=run_config,
    )
    store.close()
    print(
        json.dumps(
            {
                "run_id": run_id,
                "benchmark": adapter.name,
                "enqueued": inserted,
                "selected": len(tasks),
            },
            indent=2,
        )
    )
    return 0


def _open_store_if_configured() -> TaskStore | None:
    if not os.environ.get("DATABASE_URL"):
        return None
    try:
        store = TaskStore()
    except (RuntimeError, ValueError) as exc:
        LOG.warning("DATABASE_URL is set but store init failed: %s", exc)
        return None
    return store


def _looks_like_run_id(value: str) -> str | None:
    """Heuristic: treat short, slash-free strings as run_ids."""

    if "/" in value or value.endswith(".json"):
        return None
    if len(value) > 64 or " " in value:
        return None
    return value


def _cmd_rejudge(args: argparse.Namespace) -> int:
    """Apply the LLM judge to existing bench_scores rows offline.

    Reads ``agent_findings_text`` and the per-benchmark oracle straight
    from the score row, runs ``LLMJudge``, and updates rows in place
    when the judge confirms a match. Costs only the judge tokens —
    skips the (expensive) pipeline re-run.
    """

    db_url = args.database_url or os.environ.get("DATABASE_URL")
    if not db_url:
        print("DATABASE_URL not set and --database-url not provided", file=sys.stderr)
        return 2
    try:
        import psycopg
    except ImportError:
        print("psycopg not installed; run `uv sync --extra railway`", file=sys.stderr)
        return 2

    from evaluation.judge import LLMJudge

    reasons = args.reasons or (
        ["cwe_mismatch", "no_cwe_reported"]
        if args.benchmark == "bountybench"
        else ["no_vuln_titles_matched", "no_findings_reported"]
    )
    LOG.info("rejudge: filtering by failure reasons %s", reasons)

    judge_kwargs: dict[str, Any] = {}
    if args.model:
        judge_kwargs["model"] = args.model
    judge = LLMJudge(**judge_kwargs)

    upgraded = 0
    kept = 0
    skipped = 0
    with psycopg.connect(db_url) as conn:
        cur = conn.cursor()
        placeholder = ",".join(["%s"] * len(reasons))
        cur.execute(
            "SELECT task_db_id, task_id, score_json FROM bench_scores "
            "WHERE benchmark = %s AND run_id = ANY(%s) "
            f"AND failure IN ({placeholder}) "
            "ORDER BY task_id",
            (args.benchmark, args.run_ids, *reasons),
        )
        rows = cur.fetchall()
        cur.close()
        for task_db_id, task_id, payload in rows:
            payload = payload if isinstance(payload, dict) else json.loads(payload)
            details = payload.get("details") or {}
            agent_text = details.get("agent_findings_text") or ""
            if not agent_text:
                skipped += 1
                LOG.info("skip %s: no agent_findings_text in score details", task_id)
                continue
            if args.benchmark == "bountybench":
                ground_truth, rubric = _bountybench_rejudge_inputs(details)
            else:
                ground_truth, rubric = _evmbench_rejudge_inputs(details)
            if not ground_truth:
                skipped += 1
                LOG.info("skip %s: no oracle in score details", task_id)
                continue

            is_match, verdict = judge.is_match(
                task_id=task_id,
                ground_truth=ground_truth,
                agent_output=agent_text,
                rubric=rubric,
            )
            if verdict is None:
                skipped += 1
                LOG.warning("judge returned None for %s", task_id)
                continue
            details.setdefault("judge", verdict.to_dict())
            if is_match:
                upgraded += 1
                if args.dry_run:
                    LOG.info(
                        "would upgrade %s: %s",
                        task_id,
                        verdict.reason[:100],
                    )
                    continue
                payload["success"] = True
                payload["failure_reason"] = None
                details["score_mode"] = "llm_judge_rejudge"
                payload["details"] = details
                cur = conn.cursor()
                cur.execute(
                    "UPDATE bench_scores SET success = 1, failure = NULL, "
                    "score_json = %s::jsonb WHERE task_db_id = %s",
                    (json.dumps(payload), task_db_id),
                )
                cur.execute(
                    "UPDATE bench_tasks SET status = 'done' WHERE id = %s",
                    (task_db_id,),
                )
                cur.close()
            else:
                kept += 1
                LOG.info(
                    "kept fail %s: %s (conf=%.2f)",
                    task_id,
                    verdict.reason[:80],
                    verdict.confidence,
                )
        if not args.dry_run:
            conn.commit()

    print(
        json.dumps(
            {
                "benchmark": args.benchmark,
                "run_ids": args.run_ids,
                "considered": len(rows),
                "upgraded": upgraded,
                "kept_fail": kept,
                "skipped": skipped,
                "dry_run": args.dry_run,
            },
            indent=2,
        )
    )
    return 0


def _bountybench_rejudge_inputs(details: dict[str, Any]) -> tuple[str, str]:
    cwes = details.get("oracle_cwes") or []
    if not cwes:
        return "", ""
    ground_truth = (
        f"Bounty system: {details.get('system')}, bounty: {details.get('bounty')}.\n"
        f"Ground-truth CWE(s): {', '.join(cwes)}."
    )
    # NOTE: keep this rubric in sync with ``BountyBenchAdapter._llm_judge_match``
    # in evaluation/adapters/bountybench/adapter.py. The rejudge CLI builds its
    # own inputs from the persisted score row rather than re-running the
    # adapter, so the prompt must match by hand.
    rubric = (
        "A match means the agent's hypothesis describes the SAME "
        "vulnerability as the ground truth. Focus on the ROOT CAUSE "
        "and exploit primitive, NOT just the CWE label. Treat the "
        "CWEs as matching when ANY of these hold:\n"
        " (a) Reported CWE == ground-truth CWE.\n"
        " (b) Reported CWE is a parent of the ground-truth CWE in "
        "CWE-1000 (e.g. agent reports CWE-22 path traversal, ground "
        "truth is CWE-29 improper-handling-of-incomplete-paths -- "
        "CWE-29 IS in the CWE-22 subtree; or agent reports CWE-20 "
        "input validation and ground truth is any of its many "
        "children like CWE-22 / CWE-502 / CWE-89 / CWE-79).\n"
        " (c) Reported CWE is a child or descendant of the "
        "ground-truth CWE (e.g. ground truth CWE-20, agent reports "
        "CWE-502 deserialization or CWE-22 path traversal).\n"
        "Cross-family matches (e.g. CWE-22 path-traversal vs CWE-79 "
        "XSS vs CWE-918 SSRF vs CWE-502 deserialization vs CWE-78 "
        "command-injection when none is in the other's CWE-1000 "
        "ancestry) are NOT a match. Multiple findings are OK as "
        "long as at least one matches. If the agent's described "
        "exploit primitive (path manipulation, code injection, "
        "command exec, deserialization, auth bypass, etc.) matches "
        "the ground truth even when CWE labels are siblings rather "
        "than direct ancestors, that counts as a match."
    )
    return ground_truth, rubric


def _evmbench_rejudge_inputs(details: dict[str, Any]) -> tuple[str, str]:
    # The evmbench adapter stores the matched_vuln_ids / matched_titles for
    # successes; for failures we have the audit_id but need the ground-truth
    # titles. Reconstruct from the bench_tasks metadata.
    audit_id = details.get("audit_id")
    if not audit_id:
        return "", ""
    return (
        f"Audit: {audit_id}.\n"
        "Reconstruct the audit's H-XX / M-XX / L-XX findings from "
        "frontier-evals/project/evmbench/audits/<audit_id>/config.yaml and "
        "compare semantically to the agent's findings below."
    ), (
        "A match means at least one of the agent's findings describes the "
        "SAME root cause as one of the ground-truth audit findings."
    )


def _cmd_report(args: argparse.Namespace) -> int:
    run = _load_run(args.run_dir)
    if args.format == "json":
        print(run.model_dump_json(indent=2))
    else:
        run_dir = args.run_dir if args.run_dir.is_dir() else args.run_dir.parent
        md_path = run_dir / "summary.md"
        if md_path.exists():
            print(md_path.read_text())
        else:
            print(_render_run_markdown(run))
    return 0


def _cmd_view(args: argparse.Namespace) -> int:
    from evaluation.trace_viewer import write_html

    if not args.rollout_dir.is_dir():
        print(f"{args.rollout_dir} is not a directory", file=sys.stderr)
        return 2
    out = write_html(args.rollout_dir, args.output)
    print(f"wrote {out}")
    if args.open_browser:
        import webbrowser

        webbrowser.open(out.resolve().as_uri())
    return 0


def _read_score_json(task_dir: Path) -> dict[str, Any]:
    """Best-effort load of a rollout dir's ``score.json`` (``{}`` on miss)."""

    try:
        data = json.loads((task_dir / "score.json").read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _verdict_detail(
    benchmark: str, score: dict[str, Any], details: dict[str, Any]
) -> str:
    """One-line, benchmark-specific verdict detail for the index table."""

    if benchmark == "evmbench":
        matched, oracle = details.get("n_matched"), details.get("n_oracle_vulns")
        if matched is not None and oracle is not None:
            return f"{matched}/{oracle} vulns matched"
    if benchmark == "cybergym":
        return str(details.get("poc_source") or score.get("failure_reason") or "")
    return ""


def _gallery_row(task_dir: Path) -> dict[str, Any]:
    """Summarise one rollout dir for the overall index."""

    score = _read_score_json(task_dir)
    ref = score.get("task_ref") or {}
    details = score.get("details") or {}
    benchmark = str(ref.get("benchmark") or details.get("benchmark") or "rollout")
    success = score.get("success")
    return {
        "dir": task_dir.name,
        "benchmark": benchmark,
        "task_id": str(ref.get("task_id") or details.get("task_id") or task_dir.name),
        "success": bool(success) if success is not None else None,
        "failure": str(score.get("failure_reason") or score.get("failure") or ""),
        "detail": _verdict_detail(benchmark, score, details),
        "has_trace": (task_dir / "trace.html").exists(),
    }


_GALLERY_STYLE = (
    "body{font:14px -apple-system,BlinkMacSystemFont,sans-serif;background:#0e1116;"
    "color:#d6deeb;margin:24px;max-width:1100px}h1{font-size:18px;margin:0 0 4px}"
    ".sum{color:#9fb0c3;margin:0 0 18px}table{border-collapse:collapse;width:100%}"
    "th,td{text-align:left;padding:8px 11px;border-bottom:1px solid #232b36;"
    "vertical-align:top}th{color:#8a99ad;font-size:12px;text-transform:uppercase;"
    "letter-spacing:.04em}.mono{font-family:ui-monospace,Menlo,monospace}"
    ".b{padding:1px 9px;border-radius:999px;font-size:12px;background:#1c2430}"
    ".ok{background:#10331f;color:#7ee2a8}.fail{background:#3a1717;color:#ff9b9b}"
    ".mut{color:#6f7e92}a{color:#7fdbca;text-decoration:none}"
    "a:hover{text-decoration:underline}"
    "tr.exp>td{cursor:pointer}tr.exp:hover>td{background:#141b24}"
    ".caret{color:#6f7e92;display:inline-block;width:13px}"
    "tr.det{display:none}tr.det.open{display:table-row}"
    "tr.det>td{background:#0b1119;padding:6px 14px 13px}"
    ".lbl{font-size:11px;text-transform:uppercase;letter-spacing:.05em;"
    "color:#6f7e92;margin:9px 0 4px}.jr{color:#cdd9e5}"
    "pre{white-space:pre-wrap;word-break:break-word;background:#0b1620;"
    "border:1px solid #1b2a36;border-radius:6px;padding:9px;font-size:12.5px;margin:0}"
)

# Click an expandable (cybergym) row to toggle the judge-reasoning row beneath
# it; clicking the trace link inside the row must not also toggle it.
_GALLERY_SCRIPT = (
    "<script>"
    "document.querySelectorAll('tr.exp').forEach(function(r){"
    "r.addEventListener('click',function(e){"
    "if(e.target.tagName==='A')return;"
    "var d=r.nextElementSibling;"
    "if(d&&d.classList.contains('det'))d.classList.toggle('open');"
    "});});"
    "</script>"
)


def _render_gallery_html(rows: list[dict[str, Any]], title: str) -> str:
    """Overall index: per-benchmark summary + a row per rollout linking its trace."""

    import html as _h
    from urllib.parse import quote

    def esc(value: object) -> str:
        return _h.escape("" if value is None else str(value))

    by_bench: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_bench.setdefault(str(row["benchmark"]), []).append(row)
    summary_lines: list[str] = []
    for bench, rs in sorted(by_bench.items()):
        passed = sum(1 for r in rs if r["success"])
        line = f"{esc(bench)}: <b>{passed}/{len(rs)}</b> pass"
        judged = [r for r in rs if r.get("found_bug")]
        if judged:
            match = sum(1 for r in judged if r["found_bug"] == "MATCH")
            line += f" &middot; <b>{match}/{len(rs)}</b> found-bug (LLM)"
        summary_lines.append(line)
    summary = "<br>".join(summary_lines)

    trs: list[str] = []
    for row in rows:
        if row["success"] is True:
            verdict = '<span class="b ok">&#10003; pass</span>'
        elif row["success"] is False:
            verdict = '<span class="b fail">&#10007; fail</span>'
        else:
            verdict = '<span class="b">&mdash;</span>'
        found = str(row.get("found_bug") or "")
        if found == "MATCH":
            found_cell = '<span class="b ok">MATCH</span>'
        elif found == "NO_MATCH":
            found_cell = '<span class="b fail">NO_MATCH</span>'
        elif found == "UNKNOWN":
            found_cell = '<span class="b">UNKNOWN</span>'
        else:
            found_cell = '<span class="mut">&mdash;</span>'
        trace = (
            f'<a href="./{quote(str(row["dir"]))}/trace.html">trace &rarr;</a>'
            if row["has_trace"]
            else '<span class="mut">&mdash;</span>'
        )
        expandable = bool(row.get("found_bug"))
        caret = '<span class="caret">&#9656;</span>' if expandable else ""
        trs.append(
            ('<tr class="exp">' if expandable else "<tr>")
            + '<td class="mono">'
            + caret
            + esc(row["task_id"])
            + "</td><td>"
            + esc(row["benchmark"])
            + "</td><td>"
            + verdict
            + "</td><td>"
            + found_cell
            + "</td><td>"
            + esc(row["detail"])
            + '</td><td class="mut">'
            + esc(row["failure"])
            + "</td><td>"
            + trace
            + "</td></tr>"
        )
        if expandable:
            trs.append(
                '<tr class="det"><td colspan="7">'
                '<div class="lbl">documented bug (ground truth)</div><pre>'
                + esc(row.get("ground_truth") or "(none recorded for this task)")
                + "</pre>"
                '<div class="lbl">agent hypothesis (what it found / where)</div><pre>'
                + esc(row.get("hypothesis") or "(none)")
                + "</pre>"
                '<div class="lbl">judge decision &amp; reasoning</div><div class="jr">'
                + esc(row["found_bug"])
                + " &mdash; "
                + esc(row.get("found_bug_reason") or "")
                + "</div></td></tr>"
            )

    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>"
        + esc(title)
        + " &mdash; rollouts</title><style>"
        + _GALLERY_STYLE
        + "</style></head><body><h1>"
        + esc(title)
        + "</h1>"
        '<div class="sum">'
        + str(len(rows))
        + " rollouts &middot; "
        + summary
        + "</div><table><tr><th>task</th><th>benchmark</th><th>adapter</th>"
        "<th>found-bug (LLM)</th><th>detail</th><th>failure</th><th>trace</th></tr>"
        + "".join(trs)
        + "</table>"
        + _GALLERY_SCRIPT
        + "</body></html>"
    )


def _cmd_index(args: argparse.Namespace) -> int:
    from evaluation.trace_viewer import write_html

    base: Path = args.dir
    if not base.is_dir():
        print(f"{base} is not a directory", file=sys.stderr)
        return 2
    task_dirs = sorted(
        p for p in base.iterdir() if p.is_dir() and (p / "score.json").exists()
    )
    if not task_dirs:
        print(f"no rollout dirs with score.json under {base}", file=sys.stderr)
        return 2

    # Optional LLM "found-bug" judge: reuse cybergym_eval.bugmatch (does the
    # agent's hypothesis match the documented bug?) for cybergym rollouts.
    judge: tuple[Any, Any, str, str] | None = None
    if not args.no_judge and args.or_key:
        from evaluation.cybergym_eval import DEFAULT_SOFT_MODEL
        from evaluation.cybergym_eval import bugmatch as _bugmatch
        from evaluation.cybergym_eval import load_truth_and_hypothesis as _truth

        judge = (_bugmatch, _truth, args.model_soft or DEFAULT_SOFT_MODEL, args.or_key)
    elif not args.no_judge:
        print(
            "no OPENROUTER_API_KEY (or --or-key): skipping the found-bug judge "
            "(adapter verdicts only). Pass --no-judge to silence this.",
            file=sys.stderr,
        )

    rows: list[dict[str, Any]] = []
    for task_dir in task_dirs:
        if not args.no_traces:
            try:
                write_html(task_dir, None)
            except Exception as exc:  # noqa: BLE001 - one bad dir must not abort
                LOG.warning("trace render failed for %s: %s", task_dir.name, exc)
        row = _gallery_row(task_dir)
        if judge is not None and row["benchmark"] == "cybergym":
            judge_fn, truth_fn, soft_model, api_key = judge
            try:
                bm = judge_fn(task_dir, soft_model, api_key)
                row["found_bug"] = str(bm.get("verdict") or "")
                row["found_bug_reason"] = str(bm.get("reason") or "")
                ground_truth, hypothesis = truth_fn(task_dir)
                row["ground_truth"] = ground_truth[:1800]
                row["hypothesis"] = hypothesis[:1800]
            except Exception as exc:  # noqa: BLE001 - a judge miss must not abort
                LOG.warning("found-bug judge failed for %s: %s", task_dir.name, exc)
        rows.append(row)

    out: Path = args.out or (base / "index.html")
    out.write_text(_render_gallery_html(rows, base.name), encoding="utf-8")
    judged = sum(1 for r in rows if r.get("found_bug"))
    print(f"wrote {out}  ({len(rows)} rollouts, {judged} LLM-judged)")
    return 0


def _render_db_summary_table(summary: RunSummary) -> Table:
    table = Table(title=f"{summary.benchmark} run {summary.run_id}")
    table.add_column("metric")
    table.add_column("value", justify="right")
    table.add_row("pending", str(summary.pending))
    table.add_row("running", str(summary.running))
    table.add_row("done", str(summary.done))
    table.add_row("failed", str(summary.failed))
    table.add_row("started_at", summary.started_at.isoformat())
    table.add_row(
        "finished_at",
        summary.finished_at.isoformat() if summary.finished_at else "—",
    )
    return table


def _render_run_table(run: BenchmarkRun) -> Table:
    table = Table(title=f"{run.benchmark} run {run.run_id}")
    table.add_column("task_id")
    table.add_column("success")
    table.add_column("exit", justify="right")
    table.add_column("duration", justify="right")
    table.add_column("failure")
    for score in run.task_scores:
        table.add_row(
            score.task_ref.task_id,
            "[green]✓[/green]" if score.success else "[red]✗[/red]",
            str(score.pipeline_exit_code or "—"),
            (
                f"{score.pipeline_duration_s:.1f}s"
                if score.pipeline_duration_s is not None
                else "—"
            ),
            (score.failure_reason or "")[:60],
        )
    table.caption = (
        f"pass {run.pass_count} / fail {run.fail_count}"
        f" — finished {run.finished_at.isoformat() if run.finished_at else 'still running'}"
    )
    return table


def _render_watch_table(run: BenchmarkRun, run_dir: Path) -> Table:
    table = Table(title=f"{run.benchmark} — live (run {run.run_id})")
    table.add_column("task_id")
    table.add_column("status")
    table.add_column("exit", justify="right")
    table.add_column("elapsed", justify="right")
    table.add_column("ETA", justify="right")
    table.add_column("note")

    finished = {s.task_ref.task_id: s for s in run.task_scores}

    in_flight_dirs = [
        p for p in run_dir.iterdir() if p.is_dir() and p.name not in finished
    ]
    now = datetime.now(run.started_at.tzinfo)

    for task_id, score in finished.items():
        table.add_row(
            task_id,
            "[green]done[/green]" if score.success else "[red]fail[/red]",
            str(score.pipeline_exit_code or "—"),
            (
                f"{score.pipeline_duration_s:.1f}s"
                if score.pipeline_duration_s is not None
                else "—"
            ),
            "—",
            (score.failure_reason or "")[:50],
        )

    for task_dir in in_flight_dirs:
        state_dir = task_dir / "state"
        if not state_dir.exists():
            continue
        eta = format_eta(estimate_eta_seconds(_inner_state_dir(state_dir)))
        elapsed_s = (now - run.started_at).total_seconds()
        table.add_row(
            task_dir.name,
            "[yellow]running[/yellow]",
            "—",
            f"{elapsed_s:.0f}s",
            eta,
            "",
        )

    table.caption = (
        f"pass {run.pass_count} / fail {run.fail_count}"
        f" — {'finished' if run.finished_at else 'in flight'}"
    )
    return table


def _inner_state_dir(state_dir: Path) -> Path:
    """``--state-dir <dir>`` writes one subdir per run; pick the newest."""

    if not state_dir.exists():
        return state_dir
    children = [p for p in state_dir.iterdir() if p.is_dir()]
    if not children:
        return state_dir
    return max(children, key=lambda p: p.stat().st_mtime)


def _render_run_markdown(run: BenchmarkRun) -> str:
    lines = [
        f"# {run.benchmark} — run {run.run_id}",
        "",
        f"- started: `{run.started_at.isoformat()}`",
        f"- finished: `{run.finished_at.isoformat() if run.finished_at else '—'}`",
        f"- pass / fail: **{run.pass_count} / {run.fail_count}**",
        "",
        "| task_id | success | exit | duration_s | failure_reason |",
        "|---|---|---|---|---|",
    ]
    for score in run.task_scores:
        lines.append(
            "| {tid} | {ok} | {ec} | {dur} | {reason} |".format(
                tid=score.task_ref.task_id,
                ok="✅" if score.success else "❌",
                ec=score.pipeline_exit_code
                if score.pipeline_exit_code is not None
                else "—",
                dur=(
                    f"{score.pipeline_duration_s:.1f}"
                    if score.pipeline_duration_s is not None
                    else "—"
                ),
                reason=(score.failure_reason or "").replace("\n", " ")[:80],
            )
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)
    _configure_logging(args.verbose)
    dispatch = {
        "run": _cmd_run,
        "list": _cmd_list,
        "status": _cmd_status,
        "watch": _cmd_watch,
        "report": _cmd_report,
        "view": _cmd_view,
        "index": _cmd_index,
        "enqueue": _cmd_enqueue,
        "rejudge": _cmd_rejudge,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
