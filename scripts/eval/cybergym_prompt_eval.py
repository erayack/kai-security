"""Offline prompt eval for the cybergym reminder + BLOCKED messages.

Mirrors ``researcher_eval.py`` but instead of scoring agent output
for hallucination, this script replays cybergym root-agent contexts
from locally-pulled rollouts and scores whether the model would
commit to the action a given reminder asks for.

Currently evaluates two targets:

* ``critic_reminder`` — the soft_verified-record / iter≥8 nudge.
  Score: did the response contain ``spawn_critic(``?
* ``verifier_reminder`` — the iter≥4 no-spawn_verifier nudge.
  Score: did the response contain ``spawn_verifier(``?

Inputs come from R23 rollouts under
``docs/rollouts-2026-05-24-r23/cybergym/run_<id>/<task>/state/<spawn>/rollouts/exploit.jsonl``
— specifically iterations where the original truncation_notice
contained a harness reminder. The original prompt (message history
up to that iter) is reconstructed and the reminder is replaced
with each variant under test.

Usage::

    python scripts/cybergym_prompt_eval.py --self-test
    python scripts/cybergym_prompt_eval.py --target critic_reminder
    python scripts/cybergym_prompt_eval.py --target both --limit 3

Outputs::

    data/cybergym_prompt_eval/results.csv
    data/cybergym_prompt_eval/raw/<target>/<variant>/<run_task_iter>.json
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
from pathlib import Path
from typing import Any

# Make ``scripts.eval._common`` importable whether this script is run as
# ``python scripts/eval/cybergym_prompt_eval.py`` or ``python -m scripts.eval.cybergym_prompt_eval``.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.eval._common import (  # noqa: E402
    ensure_src_on_path,
    eval_output_dirs,
    repo_root,
)

ensure_src_on_path()

from ra.clients.openai import OpenAIClient  # noqa: E402

REPO_ROOT = repo_root()
EVAL_DIR, RAW_DIR = eval_output_dirs("cybergym_prompt_eval")
ROLLOUT_ROOTS = [
    REPO_ROOT
    / "docs"
    / "rollouts-2026-05-24-r23"
    / "cybergym"
    / "run_ef6b6b0f892cd679c53a87af",
]

DEFAULT_MODEL = "anthropic/claude-opus-4.6"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


# ---------------------------------------------------------------- variants ----


def _verifier_reminder_v0(iter_num: int) -> str:
    """Current production phrasing (cybergym_gate.reminder_text)."""
    if iter_num >= 8:
        level, body = (
            "FORCED",
            (
                "Next iteration MUST call spawn_verifier. The harness will "
                "block further file reads / sub-agent spawns until it does."
            ),
        )
    elif iter_num >= 6:
        level, body = (
            "WARNING",
            (
                "By iteration 8 the harness will REQUIRE spawn_verifier "
                "before accepting any FINAL_VAR. Call it now."
            ),
        )
    else:
        level, body = (
            "REMINDER",
            (
                "spawn_verifier is the strict-pass mechanism. Call it now "
                "even with a rough hypothesis + best-guess bytes; iterate "
                "on the bytes after the verifier reports the crash signal."
            ),
        )
    return (
        f"[harness {level}] Iteration {iter_num} — you have NOT called "
        f"spawn_verifier yet. {body} Recommended: "
        "spawn_verifier(hypothesis='...', file='src-vul/.../...', "
        "function='...', poc_code='__POC_BYTES__b64=<base64>')."
    )


def _verifier_reminder_v1(iter_num: int) -> str:
    """Variant: lead with one example invocation, explain after."""
    return (
        f"[harness ENFORCED iter {iter_num}] Required next action: "
        "spawn_verifier(hypothesis='<one-sentence-of-what-you-think>', "
        "file='src-vul/.../<file>', function='<func>', "
        "poc_code='__POC_BYTES__b64=<base64-of-your-best-guess-bytes>'). "
        "You have NOT called spawn_verifier yet and the harness blocks "
        "every other action (read_file, spawn_analyzer, "
        "spawn_researcher) until you do. The verifier's crash signal "
        "drives all strict-pass byte mutations — without it your PoC is "
        "a guess."
    )


def _verifier_reminder_v2(iter_num: int) -> str:
    """Variant: very short + imperative."""
    return (
        f"[harness] Iter {iter_num}: call spawn_verifier(...) NOW. "
        "Your task scores 0 unless you do."
    )


def _critic_reminder_v0(iter_num: int) -> str:
    """Current production phrasing."""
    return (
        f"[harness REMINDER] Iteration {iter_num} — you have a verified "
        "(or soft_verified) finding but have NOT called spawn_critic. "
        "The critic does adversarial review (severity, exploitability, "
        "edge cases). Recommended: "
        "spawn_critic(exploit_index=<your verified candidate index>). "
        "This is a quality boost on top of the verifier's confirmation."
    )


def _critic_reminder_v1(iter_num: int) -> str:
    """Variant: consequence-framed (FINAL_VAR rejection)."""
    return (
        f"[harness ENFORCED iter {iter_num}] You have a verified finding "
        "but have NOT called spawn_critic. FINAL_VAR(verified_exploits) "
        "will be REJECTED by the harness until spawn_critic has run on "
        "at least one verified candidate. Required next action: "
        "spawn_critic(exploit_index=0) — pick your strongest "
        "verified candidate. Critic catches wrong-bug-class hypotheses "
        "before strict-verify and the strict-pass run that found "
        "json_parse_const in R21 always called critic at least once."
    )


def _critic_reminder_v2(iter_num: int) -> str:
    """Variant: pattern-match from successful runs."""
    return (
        f"[harness] Iter {iter_num}: spawn_critic(exploit_index=0) NOW. "
        "Every strict-pass cybergym task in R11 and R15 invoked "
        "spawn_critic ≥1 time per verified candidate. Skipping critic "
        "is the documented R18-R22 failure mode that produced 0 critic "
        "rollouts and 0 fixer rollouts. Don't skip."
    )


def _critic_reminder_v3(iter_num: int) -> str:
    """Variant: very short + imperative."""
    return (
        f"[harness] Iter {iter_num}: call spawn_critic(exploit_index=N) "
        "NOW on your strongest verified candidate. Required before "
        "FINAL_VAR."
    )


CRITIC_VARIANTS: dict[str, Any] = {
    "v0_current": _critic_reminder_v0,
    "v1_consequence": _critic_reminder_v1,
    "v2_pattern": _critic_reminder_v2,
    "v3_short": _critic_reminder_v3,
}

VERIFIER_VARIANTS: dict[str, Any] = {
    "v0_current": _verifier_reminder_v0,
    "v1_lead_example": _verifier_reminder_v1,
    "v2_short": _verifier_reminder_v2,
}


# ----------------------------------------------------------- rollout I/O ----


@dataclasses.dataclass
class IterContext:
    """One reminder-firing iteration replayed from an exploit.jsonl."""

    run_id: str
    task_id: str
    iteration_num: int
    target: str  # critic_reminder or verifier_reminder
    message_history: list[dict[str, Any]]
    original_reminder: str

    def slot_id(self) -> str:
        return f"{self.task_id.replace(':', '_')}_iter{self.iteration_num}"


def _is_critic_reminder(text: str) -> bool:
    return "spawn_critic" in text and "harness" in text.lower()


def _is_verifier_reminder(text: str) -> bool:
    return "spawn_verifier yet" in text


def _gather_contexts(target: str, limit: int | None = None) -> list[IterContext]:
    """Walk the locally-pulled R23 rollouts and pull every iter that
    has a truncation_notice containing the target reminder."""
    out: list[IterContext] = []
    for root in ROLLOUT_ROOTS:
        if not root.exists():
            continue
        for task_dir in sorted(root.iterdir()):
            if not task_dir.is_dir():
                continue
            for spawn_dir in sorted((task_dir / "state").iterdir()):
                ep = spawn_dir / "rollouts" / "exploit.jsonl"
                if not ep.exists():
                    continue
                history: list[dict[str, Any]] = []
                for line in ep.read_text().splitlines():
                    if not line.strip():
                        continue
                    obj = json.loads(line)
                    if obj.get("type") != "iteration":
                        continue
                    iter_num = obj.get("iteration", 0)
                    tn = obj.get("truncation_notice") or ""
                    matches = (
                        target == "critic_reminder" and _is_critic_reminder(tn)
                    ) or (target == "verifier_reminder" and _is_verifier_reminder(tn))
                    response = obj.get("response", "") or ""
                    # The prompt for THIS iter is whatever the model was
                    # given before producing `response`. We snapshot
                    # history up to this point — which is the assistant
                    # turn (response) + code-block outputs from the
                    # PRIOR iter. Approximate this by accumulating
                    # response-summaries as we walk forward.
                    if matches:
                        out.append(
                            IterContext(
                                run_id=root.name.replace("run_", ""),
                                task_id=task_dir.name,
                                iteration_num=iter_num,
                                target=target,
                                message_history=list(history),
                                original_reminder=tn,
                            )
                        )
                    history.append({"role": "assistant", "content": response})
                    # synthesize a short user turn capturing what
                    # happened (truncation notice from this iter goes
                    # into the NEXT iter's prompt by design).
                    if tn:
                        history.append({"role": "user", "content": tn})
    if limit:
        out = out[:limit]
    return out


# ---------------------------------------------------------------- eval ----


@dataclasses.dataclass
class Result:
    target: str
    variant: str
    slot_id: str
    task_id: str
    iter_num: int
    elapsed_s: float
    response_len: int
    # Binary score (any mention).
    mentioned: bool
    # Tighter: actual ``spawn_X(`` invocation outside comments.
    invoked: bool
    # Strongest signal: the FIRST code block (or non-prose chunk) in
    # the response contains the target spawn — i.e. the model
    # committed to the action without procrastinating.
    committed_first: bool
    response_preview: str


_SPAWN_CALL_PATTERNS = {
    "critic_reminder": re.compile(r"^[^#\n]*\bspawn_critic\s*\(", re.MULTILINE),
    "verifier_reminder": re.compile(r"^[^#\n]*\bspawn_verifier\s*\(", re.MULTILINE),
}
_FIRST_BLOCK_RE = re.compile(r"```(?:repl|python)?\s*\n(.*?)```", re.DOTALL)


def _score_response(target: str, response: str) -> tuple[bool, bool, bool]:
    """Return ``(mentioned, invoked, committed_first)`` for ``response``.

    * mentioned: substring ``spawn_X`` appears anywhere.
    * invoked: an ``spawn_X(`` call appears outside a Python comment.
    * committed_first: the FIRST fenced code block contains the call —
      a strong signal the model committed to the action immediately.
    """
    needle = "spawn_critic" if target == "critic_reminder" else "spawn_verifier"
    mentioned = needle in response
    pattern = _SPAWN_CALL_PATTERNS.get(target)
    invoked = bool(pattern.search(response)) if pattern else False
    committed_first = False
    m = _FIRST_BLOCK_RE.search(response)
    if m and pattern and pattern.search(m.group(1)):
        committed_first = True
    return mentioned, invoked, committed_first


def _build_prompt(ctx: IterContext, variant_text: str) -> list[dict[str, Any]]:
    """Replace the original reminder in ctx.message_history with the variant.

    Then append a short instruction to elicit the model's next code
    blocks (without the full root system prompt — we're testing
    reminder copy, not the whole agent).
    """
    new_history: list[dict[str, Any]] = []
    for msg in ctx.message_history:
        content = msg.get("content", "")
        if (
            msg.get("role") == "user"
            and ctx.original_reminder
            and (ctx.original_reminder in content)
        ):
            content = content.replace(ctx.original_reminder, variant_text)
        new_history.append({"role": msg.get("role"), "content": content})
    # If the last user message isn't the reminder (e.g. reminder was on
    # the iteration whose response we're evaluating), append it now.
    if not any(
        msg.get("role") == "user" and variant_text in (msg.get("content") or "")
        for msg in new_history
    ):
        new_history.append({"role": "user", "content": variant_text})
    new_history.append(
        {
            "role": "user",
            "content": (
                "Emit your next iteration's response (single code block "
                "preferred). Remember: cybergym root agent, you have "
                "`spawn_analyzer`, `spawn_researcher`, `spawn_verifier`, "
                "`spawn_critic`, `spawn_fixer`, `read_file`, "
                "`search_files`, `list_dir`, `write_file`, `llm_query` "
                "available in your REPL. Respond as the root agent "
                "would. Wrap any code in ```repl ... ``` blocks."
            ),
        }
    )
    return new_history


def _run_one(
    client: OpenAIClient, ctx: IterContext, variant: str, variant_fn: Any
) -> tuple[Result, str]:
    text = variant_fn(ctx.iteration_num)
    prompt = _build_prompt(ctx, text)
    t0 = time.perf_counter()
    response = client.completion(prompt)
    elapsed = time.perf_counter() - t0
    mentioned, invoked, committed_first = _score_response(ctx.target, response)
    return (
        Result(
            target=ctx.target,
            variant=variant,
            slot_id=ctx.slot_id(),
            task_id=ctx.task_id,
            iter_num=ctx.iteration_num,
            elapsed_s=elapsed,
            response_len=len(response),
            mentioned=mentioned,
            invoked=invoked,
            committed_first=committed_first,
            response_preview=response[:400].replace("\n", " "),
        ),
        response,
    )


def _save_raw(target: str, variant: str, slot_id: str, response: str) -> None:
    out = RAW_DIR / target / variant
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{slot_id}.json").write_text(json.dumps({"response": response}, indent=2))


def _write_csv(results: list[Result]) -> Path:
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    out = EVAL_DIR / "results.csv"
    fields = [
        "target",
        "variant",
        "slot_id",
        "task_id",
        "iter_num",
        "elapsed_s",
        "response_len",
        "mentioned",
        "invoked",
        "committed_first",
        "response_preview",
    ]
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            row = dataclasses.asdict(r)
            for k in ("mentioned", "invoked", "committed_first"):
                row[k] = "1" if row[k] else "0"
            row["elapsed_s"] = f"{row['elapsed_s']:.2f}"
            w.writerow(row)
    return out


def _aggregate(results: list[Result]) -> dict[tuple[str, str], dict[str, Any]]:
    agg: dict[tuple[str, str], dict[str, Any]] = {}
    for r in results:
        key = (r.target, r.variant)
        bucket = agg.setdefault(
            key,
            {
                "n": 0,
                "mentioned": 0,
                "invoked": 0,
                "committed_first": 0,
                "elapsed_total": 0.0,
            },
        )
        bucket["n"] += 1
        bucket["mentioned"] += int(r.mentioned)
        bucket["invoked"] += int(r.invoked)
        bucket["committed_first"] += int(r.committed_first)
        bucket["elapsed_total"] += r.elapsed_s
    for bucket in agg.values():
        n = bucket["n"] or 1
        bucket["mention_rate"] = bucket["mentioned"] / n
        bucket["invoke_rate"] = bucket["invoked"] / n
        bucket["commit_first_rate"] = bucket["committed_first"] / n
        bucket["avg_elapsed_s"] = bucket["elapsed_total"] / n
    return agg


# --------------------------------------------------------------- CLI ----


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        choices=("critic_reminder", "verifier_reminder", "both"),
        default="both",
    )
    parser.add_argument(
        "--variants",
        nargs="*",
        default=None,
        help="Filter variants by name (e.g. v0_current v1_consequence)",
    )
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        # Cheap smoke test: just validate the variants render without
        # error and the rollout walker can find at least one context.
        for vname, vfn in CRITIC_VARIANTS.items():
            assert "spawn_critic" in vfn(8), vname
        for vname, vfn in VERIFIER_VARIANTS.items():
            assert "spawn_verifier" in vfn(5), vname
        ctxs = _gather_contexts("critic_reminder", limit=2)
        print(f"self-test OK: critic contexts={len(ctxs)}")
        ctxs_v = _gather_contexts("verifier_reminder", limit=2)
        print(f"self-test OK: verifier contexts={len(ctxs_v)}")
        return 0

    if not os.environ.get("OPENROUTER_API_KEY"):
        print("OPENROUTER_API_KEY not set", file=sys.stderr)
        return 1

    targets = (
        ["critic_reminder", "verifier_reminder"]
        if args.target == "both"
        else [args.target]
    )
    variant_sets = {
        "critic_reminder": CRITIC_VARIANTS,
        "verifier_reminder": VERIFIER_VARIANTS,
    }

    client = OpenAIClient(
        model_name=args.model,
        base_url=args.base_url,
    )

    all_results: list[Result] = []
    for target in targets:
        contexts = _gather_contexts(target, limit=args.limit)
        if not contexts:
            print(f"[{target}] no contexts found in rollouts; skipping")
            continue
        variants = variant_sets[target]
        if args.variants:
            variants = {k: v for k, v in variants.items() if k in args.variants}
        print(
            f"[{target}] {len(contexts)} contexts × {len(variants)} variants = "
            f"{len(contexts) * len(variants)} LLM calls"
        )
        for ctx in contexts:
            for vname, vfn in variants.items():
                try:
                    r, response = _run_one(client, ctx, vname, vfn)
                except Exception as exc:
                    print(
                        f"  FAIL {target}/{vname}/{ctx.slot_id()}: {exc}",
                        flush=True,
                    )
                    continue
                _save_raw(target, vname, ctx.slot_id(), response)
                all_results.append(r)
                marker = "✓" if r.committed_first else ("·" if r.invoked else "✗")
                print(
                    f"  {marker} {target} variant={vname} slot={ctx.slot_id()} "
                    f"elapsed={r.elapsed_s:.1f}s len={r.response_len} "
                    f"mentioned={r.mentioned} invoked={r.invoked} "
                    f"commit_first={r.committed_first}",
                    flush=True,
                )

    out = _write_csv(all_results)
    print(f"\nresults written to {out}")
    agg = _aggregate(all_results)
    print("\n=== aggregate ===")
    print(
        f"{'target':<22} {'variant':<20} {'n':>3} {'mention':>8} "
        f"{'invoke':>8} {'first':>8} {'avg_s':>7}"
    )
    for (target, variant), bucket in sorted(agg.items()):
        print(
            f"{target:<22} {variant:<20} {bucket['n']:>3} "
            f"{bucket['mention_rate']:>7.0%} {bucket['invoke_rate']:>7.0%} "
            f"{bucket['commit_first_rate']:>7.0%} {bucket['avg_elapsed_s']:>7.1f}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
