"""Direct enqueue helper that bypasses ``adapter.filter_tasks``.

Used when adapter discovery isn't viable from the laptop (evmbench
needs a splits file the local checkout doesn't ship) or when the
CLI's silent failure path on a missing ``DATABASE_URL`` makes
debugging slow.

Reads ``DATABASE_URL`` from the environment, constructs ``TaskRef``
objects directly from the explicit task-id list, and calls the same
``TaskStore.enqueue`` that the production CLI uses. Always prints
``run_id`` to stdout on success so the user has a value to track.

Usage::

    DATABASE_URL=... uv run python scripts/enqueue_smoke.py \\
        --benchmark cybergym \\
        --adapter-config '{"dataset_source":"huggingface","submit":false}' \\
        --tasks arvo:62425 arvo:1538 arvo:1065 arvo:51124 arvo:58085 \\
        --note v2-prompt-smoke-cybergym-N5-2026-05-20

    DATABASE_URL=... uv run python scripts/enqueue_smoke.py \\
        --benchmark evmbench \\
        --adapter-config '{"setup_mode":"auto"}' \\
        --tasks 2023-07-pooltogether 2023-10-nextgen \\
                2023-12-ethereumcreditguild 2024-01-canto 2024-01-curves \\
        --note v2-prompt-smoke-evmbench-N5-2026-05-20

Self-check (no DB call)::

    uv run python scripts/enqueue_smoke.py --self-check
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (REPO_ROOT, REPO_ROOT / "src"):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

from evaluation.schemas import TaskRef  # noqa: E402
from evaluation.store import TaskStore  # noqa: E402
from kai import generate_id  # noqa: E402


def build_task_refs(benchmark: str, task_ids: list[str]) -> list[TaskRef]:
    if benchmark == "evmbench":
        return [
            TaskRef(benchmark=benchmark, task_id=tid, metadata={"audit_id": tid})
            for tid in task_ids
        ]
    return [TaskRef(benchmark=benchmark, task_id=tid, metadata={}) for tid in task_ids]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--benchmark", required=False)
    p.add_argument("--adapter-config", default="{}")
    p.add_argument("--tasks", nargs="*", default=[])
    p.add_argument("--note", default="")
    p.add_argument("--run-id")
    p.add_argument(
        "--database-url",
        help="Override $DATABASE_URL for this call only.",
    )
    p.add_argument(
        "--self-check",
        action="store_true",
        help="Validate args + build TaskRefs without touching the DB.",
    )
    args = p.parse_args()

    if args.self_check:
        refs = build_task_refs(
            args.benchmark or "cybergym",
            args.tasks or ["arvo:62425", "arvo:1538"],
        )
        rid = generate_id()
        print(f"self-check ok: would enqueue {len(refs)} task(s) under run_id={rid}")
        for r in refs:
            print(f"  - {r.task_id} metadata={r.metadata}")
        return 0

    if not args.benchmark:
        print("err: --benchmark is required", file=sys.stderr)
        return 2

    if not args.tasks:
        print("err: at least one --tasks <id> required", file=sys.stderr)
        return 2

    db_url = args.database_url or os.environ.get("DATABASE_URL")
    if not db_url:
        print(
            "err: DATABASE_URL not set (and --database-url not passed). "
            "Set it via `set -x DATABASE_URL ...` in your shell first.",
            file=sys.stderr,
        )
        return 2

    try:
        adapter_config = json.loads(args.adapter_config)
    except json.JSONDecodeError as exc:
        print(f"err: --adapter-config is not valid JSON: {exc}", file=sys.stderr)
        return 2

    run_id = args.run_id or generate_id()
    run_config: dict[str, object] = {
        "adapter": args.benchmark,
        "adapter_config": adapter_config,
    }
    if args.note:
        run_config["note"] = args.note

    refs = build_task_refs(args.benchmark, args.tasks)

    store = TaskStore(db_url)
    try:
        store.setup_schema()
        inserted = store.enqueue(
            run_id=run_id,
            benchmark=args.benchmark,
            task_refs=refs,
            config=run_config,
        )
    finally:
        store.close()

    print(
        json.dumps(
            {
                "run_id": run_id,
                "benchmark": args.benchmark,
                "enqueued": inserted,
                "selected": len(refs),
            },
            indent=2,
        )
    )
    print(f"-> inserted {inserted} of {len(refs)} task(s)", file=sys.stderr)
    return 0 if inserted == len(refs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
