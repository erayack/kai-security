"""One-shot env bootstrap for the kai-security-bench Railway project.

Reads ``OPENROUTER_API_KEY`` + ``JINA_API_KEY`` from the local ``.env``
(or env) and applies them — together with all model overrides,
benchmark config, and timeout settings — to the cybergym-v2 and
evmbench worker services. Credentials are kept inside this Python
process; only a success-summary print lands on stdout.

Usage::

    uv run python scripts/bootstrap_railway_env.py \\
        --cybergym-service-id <uuid> \\
        --evmbench-service-id <uuid>

Service IDs come from ``railway status --json`` once the project is
linked locally.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cybergym-service-id", required=True)
    p.add_argument("--evmbench-service-id", required=True)
    p.add_argument(
        "--dburl-ref",
        default="${{Postgres.DATABASE_URL}}",
        help="Railway service-var reference for Postgres DATABASE_URL.",
    )
    args = p.parse_args()

    dotenv = load_env_file(REPO_ROOT / ".env")
    or_key = os.environ.get("OPENROUTER_API_KEY") or dotenv.get("OPENROUTER_API_KEY")
    jina_key = os.environ.get("JINA_API_KEY") or dotenv.get("JINA_API_KEY")
    if not or_key:
        print("err: OPENROUTER_API_KEY missing from env + .env", file=sys.stderr)
        return 2
    if not jina_key:
        print("err: JINA_API_KEY missing from env + .env", file=sys.stderr)
        return 2

    cg_vars = {
        "OPENROUTER_API_KEY": or_key,
        "JINA_API_KEY": jina_key,
        "DATABASE_URL": args.dburl_ref,
        "KAI_BACKEND": "openrouter",
        "KAI_LOG_STRUCTURED": "1",
        "KAI_ROOT_MODEL": "anthropic/claude-opus-4.6",
        "KAI_ANALYZER_MODEL": "anthropic/claude-opus-4.6",
        "KAI_RESEARCHER_MODEL": "anthropic/claude-opus-4.6",
        "KAI_SETUP_MODEL": "anthropic/claude-opus-4.6",
        "KAI_CHAIN_MODEL": "anthropic/claude-opus-4.6",
        "KAI_CRITIC_MODEL": "anthropic/claude-opus-4.6",
        "KAI_PATCH_ASSEMBLER_MODEL": "anthropic/claude-opus-4.6",
        "KAI_POC_AUDITOR_MODEL": "anthropic/claude-opus-4.6",
        "KAI_FIXER_MODEL": "openai/gpt-5.5",
        "KAI_VERIFIER_MODEL": "openai/gpt-5.5",
        "KAI_QUERY_MODEL": "deepseek/deepseek-v4-flash",
        "BENCHMARK_ADAPTER": "cybergym",
        "BENCHMARK_CONFIG": json.dumps(
            {"dataset_source": "huggingface", "submit": False}
        ),
        "BENCHMARK_TASK_TIMEOUT_S": "7200",
    }

    evm_vars = {
        "OPENROUTER_API_KEY": or_key,
        "JINA_API_KEY": jina_key,
        "DATABASE_URL": args.dburl_ref,
        "KAI_BACKEND": "openrouter",
        "KAI_LOG_STRUCTURED": "1",
        "KAI_ANALYZER_MODEL": "anthropic/claude-opus-4.6",
        "KAI_RESEARCHER_MODEL": "anthropic/claude-opus-4.6",
        "KAI_SETUP_MODEL": "anthropic/claude-opus-4.6",
        "BENCHMARK_ADAPTER": "evmbench",
        "BENCHMARK_CONFIG": json.dumps(
            {
                "frontier_evals_root": "/app/frontier-evals/project/evmbench",
                "setup_mode": "auto",
            }
        ),
        "BENCHMARK_PIPELINE_ARGS": json.dumps(["--skip-fixer", "--no-iterative"]),
        "BENCHMARK_TASK_TIMEOUT_S": "14400",
    }

    patch = {
        "services": {
            args.cybergym_service_id: {
                "variables": {k: {"value": v} for k, v in cg_vars.items()},
            },
            args.evmbench_service_id: {
                "variables": {k: {"value": v} for k, v in evm_vars.items()},
            },
        }
    }

    proc = subprocess.run(
        [
            "railway",
            "environment",
            "edit",
            "-m",
            "bootstrap: opus spread + JINA + OPENROUTER + benchmark configs",
            "--json",
        ],
        input=json.dumps(patch),
        text=True,
        capture_output=True,
        timeout=120,
    )
    if proc.returncode != 0:
        print("err: railway environment edit failed", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        return proc.returncode

    print(f"set {len(cg_vars)} vars on cybergym, {len(evm_vars)} vars on evmbench")
    print("railway response (last line):")
    last = [line for line in proc.stdout.splitlines() if line.strip()][-1:]
    print(last[0] if last else "<empty>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
