# PR #95 reviewer guide

This PR adds the evaluation harness and Railway worker, then makes a set of
shared runtime changes needed by the benchmark runs. Review it in two passes:
first the new eval surface under `evaluation/`, then the shared `src/kai` and
`src/ra` behavior that can affect normal pipeline runs.

## Directory map

### `evaluation/`

New benchmark harness: CLI, runner, schemas, local/Postgres task store, worker
loop, ETA/reporting, and LLM judge. This is the public interface reviewers
should treat as the benchmark API.

Key behavior to review:

- `evaluation.runner` shells out to `python -m kai.main pipeline` per task and
  writes isolated task artifacts under `output/bench/...`.
- `evaluation.store` owns the Railway shared queue with Postgres
  `FOR UPDATE SKIP LOCKED` claims plus a SQLite local/test fallback.
- `evaluation.worker` is benchmark-agnostic: it claims a row, rebuilds the
  adapter from the run's stored config, runs one task, heartbeats, and stores
  the score.
- `evaluation.judge` is opt-in and conservative; adapters must explicitly use
  `judge_mode: "llm"`.

### `evaluation/adapters/cybergym/`

CyberGym task materialization and scoring. The adapter supports local upstream
`cybergym.task.gen_task` mode and HuggingFace mode. HuggingFace mode is
soft-only because it has no strict verifier server.

Review notes:

- PoC scoring is binary-input oriented: the adapter looks for a `poc` file or
  `__POC_BYTES__b64/hex` markers.
- Strict verification is separate from soft scoring. Offline verification is in
  `scripts/cybergym_verify.py`; in-pipeline strict feedback uses
  `submit_to_cybergym_harness` when `KAI_CYBERGYM_HARNESS_URL` is set.
- The large prompt additions are benchmark-specific guidance to force
  verifier usage and prevent source-code/script PoCs.

### `evaluation/adapters/evmbench/`

EVMbench DETECT adapter. It enumerates frontier-evals audits, clones audit
source repos lazily, and can run either a pre-baked recipe path or
`setup_mode="auto"` so Foundry projects get `forge install/build`.

Why EVM eval changes are expected:

- The worker image now bakes Foundry so EVM `setup_mode=auto` can populate
  dependencies.
- Shared cybergym gates are guarded by `KAI_BENCHMARK=cybergym`; EVM should not
  receive cybergym file-read/spawn restrictions.

### `evaluation/adapters/bountybench/`

BountyBench supports `detect`, `exploit`, and `patch` modes.

Review notes:

- `detect` remains strict CWE matching by default, with optional LLM judge.
- `exploit` and `patch` are soft LLM-judge proxies against upstream reference
  artifacts. They do not run upstream Docker stacks or `verify.sh`, so scores
  are not leaderboard-comparable.

### `src/kai/`

Pipeline/state/workspace changes. These are the highest-risk changes outside
the new harness.

Review notes:

- Cybergym-only behavior is guarded by `KAI_BENCHMARK=cybergym`.
- `src/kai/state/cybergym_gate.py` tracks pre-verifier spawn/file-read caps.
- `src/kai/workspace/tools.py` adds sibling-task path isolation and the
  cybergym strict-harness submission tool.
- `src/kai/main.py` runs cybergym post-pipeline critic/fixer stages for
  soft-verified records, but the post-pipeline fixer now honors
  `--skip-fixer`.

### `src/ra/`

Shared recursive-agent runtime. This can affect all benchmarks and normal use.

Review notes:

- OpenAI/OpenRouter calls retry transient errors, including empty/malformed
  response content inside the retry boundary.
- RLM iterations have wall-clock and code-block caps with truncation notices.
- Cancel handling now avoids misleading fallback answers when a sub-agent was
  already cancelled.
- LocalREPL cwd locking is cybergym-only to avoid regressing EVM/Bounty
  concurrency.

### `Dockerfile`, `railway.json`, `.env.example`, `docs/railway-deploy.md`

Railway worker deployment surface.

Review notes:

- `.dockerignore` excludes local secrets, output, tests, docs, caches, and
  heavy artifacts from the image.
- Runtime image includes Foundry and clones BountyBench/frontier-evals task
  metadata; refs are build args and currently default to `main`.
- `railway.json` sets 5 replicas. Reviewers should decide whether that is an
  intended committed production default or should be environment-specific.

## Regression checks added

- OpenAI empty-content completion retries at the completion boundary.
- CyberGym post-pipeline fixer respects `--skip-fixer`.

## Verification

Run:

```bash
uv run ruff check .
uv run pytest evaluation/tests tests/test_openai_retry.py \
  tests/test_cybergym_cancel_decouple.py tests/test_cybergym_chain_assembler.py \
  tests/test_cybergym_harness_tool.py tests/test_cybergym_post_pipeline_critic.py \
  tests/test_cybergym_post_pipeline_fixer.py tests/test_cybergym_soft_verified.py \
  tests/test_cybergym_verifier_gate.py tests/test_log_file_printers.py \
  tests/test_path_isolation.py tests/test_ra_cancel_event.py tests/test_recipe.py \
  tests/test_rlm_iter_cap.py tests/test_state_integration.py
```
