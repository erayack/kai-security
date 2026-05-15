"""Offline CyberGym verifier.

For every successful cybergym task in the given run(s), pull the PoC
bytes out of ``bench_scores.score_json.details.poc_b64`` and POST them
to a running CyberGym submission server. Update the DB row with the
verifier's actual ``exit_code`` so the soft ``score_mode:
soft_unverified`` becomes ``score_mode: verified`` (or
``verified_rejected`` when the server says no).

This script is intended to run locally — the cybergym submission
server is Docker-based and cannot live on Railway today. You provide:

* ``--server`` — URL of the running ``cybergym.server`` instance
  (e.g. ``http://127.0.0.1:8666``).
* ``--data-dir`` and ``--mask-map`` — paths to the cybergym dataset
  and ``mask_map.json`` (only needed to regenerate per-task
  ``submit.sh`` files via the upstream ``gen_task`` CLI, which is the
  cleanest path to post a PoC). ``--cybergym-pkg-root`` lets you
  point at a checked-out cybergym repo if the package isn't on
  ``PYTHONPATH``.

Usage::

    DATABASE_URL=postgres://... python scripts/cybergym_verify.py <run-id>
        --server http://127.0.0.1:8666
        --data-dir ~/data/cybergym_data/data
        --mask-map ~/src/cybergym/mask_map.json
        --cybergym-pkg-root ~/src/cybergym

The script never deletes anything; it only updates ``bench_scores`` /
``bench_tasks`` rows for rows whose ``details`` already contains
``poc_b64``.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

LOG = logging.getLogger("scripts.cybergym_verify")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_ids", nargs="+", help="bench_runs.run_id values to verify."
    )
    parser.add_argument(
        "--server", required=True, help="cybergym submission server URL."
    )
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--mask-map", required=True, type=Path)
    parser.add_argument(
        "--cybergym-pkg-root",
        type=Path,
        default=None,
        help="optional path to a cybergym checkout (added to PYTHONPATH).",
    )
    parser.add_argument(
        "--difficulty",
        default="level1",
        help="difficulty level passed to gen_task (default level1).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="stop after verifying this many tasks per run (debugging).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be posted; do not call the server or write to DB.",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="override DATABASE_URL (otherwise read from env).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    args = _parse_args(argv)

    db_url = args.database_url or os.environ.get("DATABASE_URL")
    if not db_url:
        LOG.error("DATABASE_URL not set and --database-url not provided")
        return 2

    try:
        import psycopg
    except ImportError:
        LOG.error("psycopg not installed; run `uv sync --extra railway`")
        return 2

    total_attempted = 0
    total_verified_match = 0
    total_verified_no_match = 0
    total_skipped = 0

    with psycopg.connect(db_url) as conn:
        for run_id in args.run_ids:
            LOG.info("=== verifying run=%s ===", run_id)
            rows = _fetch_scores(conn, run_id)
            if args.limit is not None:
                rows = rows[: args.limit]
            for task_db_id, task_id, payload in rows:
                payload = payload if isinstance(payload, dict) else json.loads(payload)
                details = payload.get("details") or {}
                poc_b64 = details.get("poc_b64")
                if not poc_b64:
                    LOG.info("skip %s: no poc_b64 in score details", task_id)
                    total_skipped += 1
                    continue
                try:
                    poc_bytes = base64.b64decode(poc_b64, validate=True)
                except Exception as exc:  # noqa: BLE001
                    LOG.warning("skip %s: poc_b64 decode failed (%s)", task_id, exc)
                    total_skipped += 1
                    continue

                if args.dry_run:
                    LOG.info(
                        "dry-run %s: would POST %d bytes to %s",
                        task_id,
                        len(poc_bytes),
                        args.server,
                    )
                    total_attempted += 1
                    continue

                result = _verify_single_task(
                    task_id=task_id,
                    poc_bytes=poc_bytes,
                    server=args.server,
                    data_dir=args.data_dir,
                    mask_map=args.mask_map,
                    cybergym_pkg_root=args.cybergym_pkg_root,
                    difficulty=args.difficulty,
                )
                total_attempted += 1
                if result is None:
                    LOG.warning("verify failed for %s (server/SDK error)", task_id)
                    continue
                verified, server_payload = result
                _update_score(conn, task_db_id, payload, verified, server_payload)
                if verified:
                    total_verified_match += 1
                else:
                    total_verified_no_match += 1
            conn.commit()

    LOG.info(
        "summary: attempted=%d verified_match=%d verified_no_match=%d skipped=%d",
        total_attempted,
        total_verified_match,
        total_verified_no_match,
        total_skipped,
    )
    return 0


def _fetch_scores(conn: Any, run_id: str) -> list[tuple[int, str, Any]]:
    cur = conn.cursor()
    cur.execute(
        "SELECT task_db_id, task_id, score_json FROM bench_scores "
        "WHERE run_id = %s AND benchmark = 'cybergym' "
        "ORDER BY task_id",
        (run_id,),
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def _update_score(
    conn: Any,
    task_db_id: int,
    payload: dict[str, Any],
    verified: bool,
    server_payload: dict[str, Any],
) -> None:
    details = payload.get("details") or {}
    details["verified"] = verified
    details["score_mode"] = "verified" if verified else "verified_rejected"
    details["verifier_response"] = server_payload
    payload["details"] = details
    payload["success"] = verified
    payload["failure_reason"] = None if verified else "verifier_rejected"
    cur = conn.cursor()
    cur.execute(
        "UPDATE bench_scores SET success = %s, failure = %s, score_json = %s::jsonb "
        "WHERE task_db_id = %s",
        (
            1 if verified else 0,
            None if verified else "verifier_rejected",
            json.dumps(payload),
            task_db_id,
        ),
    )
    cur.execute(
        "UPDATE bench_tasks SET status = %s WHERE id = %s",
        ("done" if verified else "failed", task_db_id),
    )
    cur.close()


def _verify_single_task(
    *,
    task_id: str,
    poc_bytes: bytes,
    server: str,
    data_dir: Path,
    mask_map: Path,
    cybergym_pkg_root: Path | None,
    difficulty: str,
) -> tuple[bool, dict[str, Any]] | None:
    """Regenerate ``submit.sh`` for ``task_id`` and POST ``poc_bytes`` to it.

    Returns ``(verified_match, server_payload)``. ``verified_match`` is
    True when the server's primary ``exit_code`` is 0 (the PoC ran on
    the vulnerable build without erroring). Returns ``None`` on any
    SDK / network error so the caller leaves the score untouched.
    """

    with tempfile.TemporaryDirectory(prefix="cybergym-verify-") as td:
        td_path = Path(td)
        try:
            _gen_task(
                task_id=task_id,
                out_dir=td_path,
                data_dir=data_dir,
                mask_map=mask_map,
                cybergym_pkg_root=cybergym_pkg_root,
                difficulty=difficulty,
                server=server,
            )
        except RuntimeError as exc:
            LOG.warning("gen_task failed for %s: %s", task_id, exc)
            return None

        submit_sh = td_path / "submit.sh"
        if not submit_sh.exists():
            LOG.warning("gen_task produced no submit.sh for %s", task_id)
            return None
        submit_sh.chmod(0o755)

        poc_path = td_path / "poc"
        poc_path.write_bytes(poc_bytes)

        completed = subprocess.run(
            ["bash", str(submit_sh), str(poc_path)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if completed.returncode != 0:
            LOG.warning(
                "submit.sh exited non-zero (%s) for %s: %s",
                completed.returncode,
                task_id,
                (completed.stderr or "").strip()[:200],
            )

        payload: dict[str, Any] = {
            "stdout_tail": (completed.stdout or "")[-1000:],
            "stderr_tail": (completed.stderr or "")[-400:],
            "script_exit_code": completed.returncode,
        }
        try:
            last_line = (completed.stdout or "").strip().splitlines()[-1]
            parsed = json.loads(last_line)
            payload.update(parsed)
        except (IndexError, json.JSONDecodeError):
            pass

        verified = bool(payload.get("exit_code") == 0)
        return verified, payload


def _gen_task(
    *,
    task_id: str,
    out_dir: Path,
    data_dir: Path,
    mask_map: Path,
    cybergym_pkg_root: Path | None,
    difficulty: str,
    server: str,
) -> None:
    cmd = [
        sys.executable,
        "-m",
        "cybergym.task.gen_task",
        "--task-id",
        task_id,
        "--out-dir",
        str(out_dir),
        "--data-dir",
        str(data_dir),
        "--server",
        server,
        "--mask-map",
        str(mask_map),
        "--difficulty",
        difficulty,
    ]
    env = os.environ.copy()
    if cybergym_pkg_root is not None:
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            f"{cybergym_pkg_root / 'src'}{os.pathsep}{existing}"
            if existing
            else str(cybergym_pkg_root / "src")
        )
    completed = subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"gen_task exit={completed.returncode} stderr={completed.stderr[:200]}"
        )


if __name__ == "__main__":
    sys.exit(main())
