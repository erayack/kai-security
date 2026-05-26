"""Isolated researcher prompt eval — pre-N=5 retrieval-metric pass.

Runs the researcher agent against a curated input set with up to
three system-prompt variants and scores every emitted reference
(URL / SWC / CVE) on existence. Lower hallucination_rate wins.

Usage:
    uv run python -m scripts.eval.researcher_eval --self-test         # smoke checks
    uv run python -m scripts.eval.researcher_eval --variants v0 --limit 1
    uv run python -m scripts.eval.researcher_eval                     # full run

Outputs:
    data/researcher_eval/results.csv
    data/researcher_eval/raw/<variant>/<slot>.json   (per-run agent output)
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Make ``scripts.eval._common`` importable whether this script is run as
# ``python scripts/eval/researcher_eval.py`` or ``python -m scripts.eval.researcher_eval``.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.eval._common import (  # noqa: E402
    ensure_src_on_path,
    eval_output_dirs,
    repo_root,
)

ensure_src_on_path()

from kai.definitions.exploit.config import researcher_config  # noqa: E402
from kai.definitions.exploit.prompt import RESEARCHER_PROMPT  # noqa: E402
from ra.agents.agent import RecursiveAgent  # noqa: E402

REPO_ROOT = repo_root()
EVAL_DIR, RAW_DIR = eval_output_dirs("researcher_eval")
PROMPT_DIR = EVAL_DIR / "prompts"

KNOWN_SWC_IDS = {f"SWC-{n:03d}" for n in range(100, 137)}

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
SWC_RE = re.compile(r"\bSWC-(\d{3})\b")
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b")

USER_AGENT = "kai-researcher-eval/1.0"
HTTP_TIMEOUT = 6.0


# ---------------------------------------------------------------- prompts ----


def build_variants() -> dict[str, str]:
    """Return v0 / v1 / v2 prompt strings, writing snapshots to disk."""
    PROMPT_DIR.mkdir(parents=True, exist_ok=True)

    v0 = RESEARCHER_PROMPT
    (PROMPT_DIR / "v0.txt").write_text(v0)

    v1_rule = (
        "    - VERIFY-BEFORE-CITE: every URL or identifier in a lens's "
        "`references` field MUST first appear in the markdown output of a "
        "`read_url(...)` call you made this session, OR be a verbatim entry "
        "(title + URL) from a `search_web(...)` result set you received. If "
        "you cannot tie a reference back to a tool output, DROP IT. Do not "
        "invent CVEs, SWC numbers, blog posts, or audit reports from memory "
        "— these will be marked as hallucinations and discarded.\n"
    )
    v1 = v0.replace(
        "    ## Output format\n",
        v1_rule + "\n    ## Output format\n",
        1,
    )
    (PROMPT_DIR / "v1.txt").write_text(v1)

    v2_change = (
        '    - **evidence**: a list of `{"source_url": str, "excerpt": '
        "str (<= 200 chars, verbatim from a `read_url` output)}` items. A "
        "lens with zero evidence items will be REJECTED by the scorer. The "
        "`references` field is derived from `evidence` (the list of "
        "`source_url`s); you do not need to populate it separately."
    )
    v2 = v0.replace(
        "    - **references**: source URLs from your web research",
        v2_change,
        1,
    )
    (PROMPT_DIR / "v2.txt").write_text(v2)

    return {"v0": v0, "v1": v1, "v2": v2}


# ---------------------------------------------------------- ref classification ----


def head_check(url: str, timeout: float = HTTP_TIMEOUT) -> bool:
    """Return True if a HEAD/GET request to ``url`` returns 2xx/3xx."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except urllib.error.HTTPError as e:
        if e.code in (405, 501):
            # HEAD not allowed; retry GET with small range
            req = urllib.request.Request(
                url,
                headers={"User-Agent": USER_AGENT, "Range": "bytes=0-1"},
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return 200 <= resp.status < 400
            except Exception:
                return False
        return False
    except Exception:
        return False


def nvd_lookup(cve_id: str, timeout: float = HTTP_TIMEOUT) -> bool:
    """Return True if NVD JSON v2 has a record for ``cve_id``."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return False
            payload = json.loads(resp.read().decode("utf-8"))
            return int(payload.get("totalResults", 0)) > 0
    except Exception:
        return False


def classify_ref(ref: str) -> str:
    """Return one classification label for a single reference string.

    Categories: valid_url, dead_url, valid_swc, invalid_swc,
    valid_cve, invalid_cve, unclassified.

    Priority: URLs first (a URL pointing to swcregistry.io is a URL
    classification, not a bare SWC ID). Bare SWC / CVE identifiers
    only when the string is not a URL.
    """
    ref = ref.strip().rstrip(".,;:)\"'")
    if not ref:
        return "unclassified"

    if url_match := URL_RE.search(ref):
        url = url_match.group(0).rstrip(".,;:)\"'")
        return "valid_url" if head_check(url) else "dead_url"

    if m := SWC_RE.search(ref):
        full = f"SWC-{m.group(1)}"
        return "valid_swc" if full in KNOWN_SWC_IDS else "invalid_swc"

    if m := CVE_RE.search(ref):
        cve_id = f"CVE-{m.group(1)}-{m.group(2)}"
        return "valid_cve" if nvd_lookup(cve_id) else "invalid_cve"

    return "unclassified"


# ---------------------------------------------------------- response parsing ----


def _extract_first_json_block(text: str) -> Any | None:
    """Find the first balanced JSON array or object in ``text``."""
    if not text:
        return None
    for opener, closer in [("[", "]"), ("{", "}")]:
        start = text.find(opener)
        while start != -1:
            depth = 0
            in_str = False
            esc = False
            for i in range(start, len(text)):
                ch = text[i]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                    continue
                if ch == opener:
                    depth += 1
                elif ch == closer:
                    depth -= 1
                    if depth == 0:
                        chunk = text[start : i + 1]
                        try:
                            return json.loads(chunk)
                        except json.JSONDecodeError:
                            break
            start = text.find(opener, start + 1)
    return None


def parse_lenses(response_text: str) -> list[dict]:
    """Pull lens dicts out of the agent's final response string."""
    parsed = _extract_first_json_block(response_text)
    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]
    if isinstance(parsed, dict):
        for key in ("lenses", "result", "items", "findings"):
            v = parsed.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        return [parsed]
    return []


def extract_refs(lenses: list[dict]) -> list[str]:
    """Flatten every reference-shaped string from lens objects."""
    refs: list[str] = []
    for lens in lenses:
        for key in ("references", "refs", "sources", "evidence"):
            val = lens.get(key)
            if not val:
                continue
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        refs.append(item)
                    elif isinstance(item, dict):
                        for sub in ("source_url", "url", "link", "href"):
                            if isinstance(item.get(sub), str):
                                refs.append(item[sub])
                                break
            elif isinstance(val, str):
                refs.append(val)
    return refs


def extract_refs_from_text(text: str) -> list[str]:
    """Fallback: regex-scan raw response text for URLs, SWC IDs, CVE IDs.

    Used when the agent returns prose (the prompt's "specific research"
    branch) rather than a JSON list of lenses. Dedupes while preserving
    order so the classifier processes each reference once.
    """
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []

    def push(ref: str) -> None:
        ref = ref.strip().rstrip(".,;:)\"'")
        if ref and ref not in seen:
            seen.add(ref)
            out.append(ref)

    for m in URL_RE.finditer(text):
        push(m.group(0))
    for m in SWC_RE.finditer(text):
        push(f"SWC-{m.group(1)}")
    for m in CVE_RE.finditer(text):
        push(f"CVE-{m.group(1)}-{m.group(2)}")
    return out


# ---------------------------------------------------------- runner ----


def run_single(
    variant_name: str,
    entry: dict[str, Any],
    prompt_text: str,
) -> dict[str, Any]:
    """Run the researcher once with the given prompt; return the raw response."""
    cfg = dataclasses.replace(researcher_config, system_prompt=prompt_text)
    agent = RecursiveAgent(cfg)
    t0 = time.time()
    result = agent.completion({"query": entry["query"]})
    elapsed = time.time() - t0
    return {
        "variant": variant_name,
        "slot_id": entry["slot_id"],
        "task_id": entry["task_id"],
        "fame_tier": entry["fame_tier"],
        "response": getattr(result, "response", "") or "",
        "elapsed_s": round(elapsed, 1),
    }


def score_run(run: dict[str, Any]) -> dict[str, Any]:
    """Classify every reference in a run; return aggregated row.

    Structured-lens refs come first; if none, fall back to scanning the
    raw response text for URL / SWC / CVE patterns so prose responses
    (the specific-research branch of the researcher prompt) are scored
    rather than dropped.
    """
    lenses = parse_lenses(run["response"])
    refs = extract_refs(lenses)
    if not refs:
        refs = extract_refs_from_text(run["response"])
    classes: dict[str, int] = {}
    for r in refs:
        c = classify_ref(r)
        classes[c] = classes.get(c, 0) + 1
    total = sum(classes.values())
    valid = (
        classes.get("valid_url", 0)
        + classes.get("valid_swc", 0)
        + classes.get("valid_cve", 0)
    )
    hallucinated = (
        classes.get("dead_url", 0)
        + classes.get("invalid_swc", 0)
        + classes.get("invalid_cve", 0)
    )
    rate = hallucinated / max(total, 1)
    return {
        "variant": run["variant"],
        "slot_id": run["slot_id"],
        "task_id": run["task_id"],
        "fame_tier": run["fame_tier"],
        "elapsed_s": run["elapsed_s"],
        "lens_count": len(lenses),
        "total_refs": total,
        "valid_refs": valid,
        "hallucinated_refs": hallucinated,
        "unclassified_refs": classes.get("unclassified", 0),
        "hallucination_rate": round(rate, 3),
        **{f"n_{k}": v for k, v in classes.items()},
    }


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    if not rows:
        path.write_text("")
        return
    keys: list[str] = []
    seen: set[str] = set()
    for r in rows:
        for k in r:
            if k not in seen:
                seen.add(k)
                keys.append(k)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def print_summary(rows: list[dict[str, Any]]) -> None:
    per_variant: dict[str, dict[str, int]] = {}
    for r in rows:
        v = r["variant"]
        agg = per_variant.setdefault(
            v, {"runs": 0, "total_refs": 0, "valid": 0, "halluc": 0}
        )
        agg["runs"] += 1
        agg["total_refs"] += r["total_refs"]
        agg["valid"] += r["valid_refs"]
        agg["halluc"] += r["hallucinated_refs"]

    print("\n=== summary ===")
    print(
        f"{'variant':<6} {'runs':>5} {'refs':>6} {'valid':>6} {'halluc':>7} {'rate':>6}"
    )
    for v in sorted(per_variant):
        a = per_variant[v]
        rate = a["halluc"] / max(a["total_refs"], 1)
        print(
            f"{v:<6} {a['runs']:>5} {a['total_refs']:>6} "
            f"{a['valid']:>6} {a['halluc']:>7} {rate:>6.2%}"
        )


# ---------------------------------------------------------- self-test ----


def run_self_test() -> int:
    """Smoke-check classify_ref + parse_lenses without spawning an agent."""
    ok = True

    def check(label: str, got: Any, expected: Any) -> None:
        nonlocal ok
        if got == expected:
            print(f"  pass  {label}")
        else:
            print(f"  FAIL  {label}: got {got!r}, expected {expected!r}")
            ok = False

    print("classify_ref checks")
    check(
        "valid SWC-107",
        classify_ref("SWC-107"),
        "valid_swc",
    )
    check(
        "invalid SWC-999",
        classify_ref("SWC-999"),
        "invalid_swc",
    )
    check(
        "invalid CVE-1111-2222 (likely 404)",
        classify_ref("CVE-1111-2222"),
        "invalid_cve",
    )
    check(
        "valid swcregistry URL",
        classify_ref("https://swcregistry.io/docs/SWC-107"),
        "valid_url",
    )
    check(
        "dead URL example.invalid",
        classify_ref("https://example.invalid/missing"),
        "dead_url",
    )
    check(
        "unclassified prose",
        classify_ref("audit report by some firm"),
        "unclassified",
    )

    print("\nparse_lenses checks")
    sample = '[{"focus": "x", "references": ["https://swcregistry.io/docs/SWC-107"]}]'
    lenses = parse_lenses(sample)
    check("parse list-of-dicts", len(lenses), 1)
    check("extract refs", extract_refs(lenses), ["https://swcregistry.io/docs/SWC-107"])

    return 0 if ok else 1


# ---------------------------------------------------------- main ----


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--inputs", default=str(EVAL_DIR / "inputs.json"))
    p.add_argument("--out", default=str(EVAL_DIR / "results.csv"))
    p.add_argument("--variants", nargs="+", default=["v0", "v1", "v2"])
    p.add_argument("--limit", type=int, help="max inputs to run per variant")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()

    if args.self_test:
        return run_self_test()

    if not os.environ.get("OPENROUTER_API_KEY") and not os.environ.get(
        "ANTHROPIC_API_KEY"
    ):
        print(
            "warn: neither OPENROUTER_API_KEY nor ANTHROPIC_API_KEY set",
            file=sys.stderr,
        )

    inputs_path = Path(args.inputs)
    if not inputs_path.exists():
        print(f"err: inputs file not found: {inputs_path}", file=sys.stderr)
        return 2
    entries: list[dict[str, Any]] = json.loads(inputs_path.read_text())
    if args.limit:
        entries = entries[: args.limit]

    variants = build_variants()
    selected = {k: variants[k] for k in args.variants if k in variants}
    if not selected:
        print(f"err: no known variants in {args.variants}", file=sys.stderr)
        return 2

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for v_name, p_text in selected.items():
        for entry in entries:
            print(f"-> {v_name} / {entry['slot_id']} ({entry['task_id']})")
            try:
                run = run_single(v_name, entry, p_text)
            except Exception as exc:
                print(f"   exc: {type(exc).__name__}: {exc}", file=sys.stderr)
                run = {
                    "variant": v_name,
                    "slot_id": entry["slot_id"],
                    "task_id": entry["task_id"],
                    "fame_tier": entry["fame_tier"],
                    "response": "",
                    "elapsed_s": 0.0,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            (RAW_DIR / v_name).mkdir(parents=True, exist_ok=True)
            (RAW_DIR / v_name / f"{entry['slot_id']}.json").write_text(
                json.dumps(run, indent=2, default=str)
            )
            rows.append(score_run(run))

    out_path = Path(args.out)
    write_csv(rows, out_path)
    print(f"\nwrote {len(rows)} rows to {out_path}")
    print_summary(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
