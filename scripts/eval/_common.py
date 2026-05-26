"""Shared scaffolding for offline prompt-eval scripts under ``scripts/eval/``.

Each eval script is standalone — its own argparse, its own scoring logic — but
the layout boilerplate (where to put outputs, how to find the repo root, how
to make ``src/`` importable) is shared here so adding a third eval is mostly
"write the scoring loop, plug it into the same output dirs."

Convention each eval follows:

    data/<eval_name>/
        inputs.json         # optional, hand-curated inputs
        results.csv         # aggregated per-variant rows
        raw/<variant>/      # per-input raw outputs (one JSON file per slot)

All under ``data/`` which is gitignored — these evals are local-only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def repo_root() -> Path:
    """Return the kai-security repo root regardless of cwd."""
    return Path(__file__).resolve().parents[2]


def ensure_src_on_path() -> None:
    """Make ``src/`` importable (so ``from kai...`` / ``from ra...`` work).

    Idempotent. Each eval script should call this once at module import time.
    """
    src = repo_root() / "src"
    sp = str(src)
    if sp not in sys.path:
        sys.path.insert(0, sp)


def eval_output_dirs(eval_name: str) -> tuple[Path, Path]:
    """Return (eval_dir, raw_dir) for *eval_name*, creating both.

    eval_dir is ``<repo>/data/<eval_name>``; raw_dir is its ``raw/`` subdir.
    """
    eval_dir = repo_root() / "data" / eval_name
    raw_dir = eval_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    return eval_dir, raw_dir


def write_raw(
    raw_dir: Path,
    variant: str,
    slot: str,
    payload: dict,
) -> Path:
    """Write a per-slot raw JSON output for a given prompt variant.

    Path: ``<raw_dir>/<variant>/<slot>.json``. Creates the variant subdir.
    """
    out_dir = raw_dir / variant
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{slot}.json"
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return out_path
