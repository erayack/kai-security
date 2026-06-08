# BountyBench adapter - one-time setup

BountyBench (https://github.com/bountybench/bountybench, Apache-2.0) is a
40-task benchmark across 25 systems with three evaluation modes -
DETECT, EXPLOIT and PATCH. This adapter wires up all three modes, with
soft scoring (no upstream Docker stack / `verify.sh` invocation):

- **DETECT** (default): kai inspects a codebase, reports findings, and
  the adapter scores a task as successful when at least one ground-truth
  CWE appears in the reported result. Strict CWE-exact match by default;
  `judge_mode: "llm"` falls back to an LLMJudge that compares the
  agent's hypothesis against the bounty's writeup.
- **EXPLOIT**: kai produces an exploit artefact (free-form text /
  pseudo-PoC). Scored exclusively via the LLM judge, which compares the
  artefact against the upstream reference exploit description. The judge
  is forced on for this mode (strict matching isn't meaningful for
  free-form output).
- **PATCH**: kai produces a patch artefact (diff / explanation). Scored
  exclusively via the LLM judge against the upstream reference patch.
  Judge is forced on for the same reason as EXPLOIT.

EXPLOIT / PATCH soft-scoring is **a proxy**: the upstream BountyBench
strict metric requires running the bounty's Docker stack with
`verify.sh` to confirm the exploit succeeds on the vulnerable commit
*and* fails on the patched commit. That harness invocation is out of
scope for this adapter; soft-judge scores are useful for ranking but
not comparable to the upstream leaderboard.

## 1. Fetch the bountytasks corpus

BountyBench uses a `bountytasks` submodule that hosts the per-system
codebases and bounty metadata. Clone it standalone:

```bash
git clone https://github.com/bountybench/bountytasks.git ~/data/bountytasks
```

Initialise the per-system `codebase/` submodules for the systems you
want to evaluate against - they are git submodules of the bountytasks
repo:

```bash
cd ~/data/bountytasks
git submodule update --init --recursive lunary
git submodule update --init --recursive django
# ...one per system you plan to run
```

The full corpus is large; only initialise the systems you actually need.

## 2. Configure this adapter

Create an adapter config JSON (paths must be absolute):

```json
{
  "bountybench_root": "/Users/you/data/bountytasks",
  "mode": "detect",
  "systems": ["lunary", "django"],
  "copy_codebase": true
}
```

Save it somewhere gitignored (for example
`evaluation/adapters/bountybench/local_config.json`).

Config keys:

- `bountybench_root` (**required**): path to the `bountytasks/` clone
  from step 1 (the directory containing `<system>/` folders, not the
  outer `bountybench/` repo).
- `mode` (default `"detect"`): one of `"detect"` / `"exploit"` / `"patch"`.
  EXPLOIT and PATCH force `judge_mode: "llm"` (strict matching isn't
  meaningful for free-form artefacts).
- `systems` (optional): whitelist of system names to enumerate. Leave
  unset to enumerate every bounty under `bountybench_root`.
- `copy_codebase` (default `true`): when `true`, the prepare step
  `cp -r`s the codebase into the per-task workdir. Set `false` to
  symlink for speed; only use this if you are sure the pipeline will
  not mutate the canonical checkout.

## 3. Drive the adapter

The adapter registers itself on first import. From the CLI you can list
tasks and run a single bounty end-to-end with:

```bash
uv run python -m evaluation.cli list \
    --adapter bountybench \
    --adapter-config @evaluation/adapters/bountybench/local_config.json

uv run python -m evaluation.cli run \
    --adapter bountybench \
    --adapter-config @evaluation/adapters/bountybench/local_config.json \
    --tasks lunary/bounty_0 \
    --limit 1
```

Task IDs use the canonical `<system>/<bounty_N>` form.

## 4. How DETECT scoring works

For DETECT mode the adapter:

1. Reads each bounty's `bounty_metadata.json` and extracts every
   `CWE-NNN` identifier from the `CWE` field. The full descriptive
   string (e.g. `"CWE-639: Authorization Bypass Through User-Controlled
   Key"`) is preserved in the task's oracle blob.
2. Materialises the system's `codebase/` directory into the task
   workdir as `repo/`.
3. Builds a `prompt_extras` block that includes the task-level setup
   notes from `metadata.json['info']`, the bounty's optional
   `exploit_prompt` hint and, when available, the human-written
   `writeup/writeup.html`.
4. Hands the pipeline JSON result back to the adapter. The adapter
   scans every text-bearing field of each `ExploitRecord`-shaped dict
   (`hypothesis`, `exploit_sketch`, `category`, `severity`,
   `cvss_justification`, ...) for `CWE-NNN` strings.
5. Declares success if the intersection of reported CWEs and oracle
   CWEs is non-empty. Failure modes are reported as
   `no_pipeline_result`, `no_cwe_reported`, `cwe_mismatch` or
   `oracle_missing_cwe`.

This is intentionally a lenient match - the upstream BountyBench
"detect indicator" metric is stricter (it requires the exploit to
succeed on the vulnerable commit *and* fail on the patched commit).
That metric needs the Docker stack and `verify.sh`, both of which are
EXPLOIT-mode follow-up work.

## 5. Known limitations

- Soft scoring only: no Docker setup, no `verify.sh`, no patch
  differential. Comparisons against upstream BountyBench leaderboards
  are not apples-to-apples — DETECT uses lenient CWE substring matching
  (vs upstream's exploit-must-succeed-and-patched-must-fail metric);
  EXPLOIT / PATCH use an LLM-judge soft proxy against the reference
  artefact rather than running the upstream verifier.
- The adapter does not initialise the bounty's setup containers, so
  any task whose codebase analysis depends on a running service will
  produce reduced-quality findings. This is acceptable for DETECT mode
  - the CWE comparison only needs the static codebase. For EXPLOIT /
  PATCH modes the missing service may bias the agent toward static
  hypotheses.
- A small handful of bounties record multiple CWEs in one metadata
  string (e.g. composio); the adapter extracts every `CWE-NNN` match
  and treats them as alternatives (success if any one matches).
