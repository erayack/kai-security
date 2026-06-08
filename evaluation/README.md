# evaluation/

Benchmark harness for `kai-security`. Drives the production `kai.main
pipeline` CLI as a subprocess across a list of tasks, captures every
per-task artefact under `output/bench/<benchmark>/run_<id>/<task_id>/`,
and aggregates results into `summary.json` + `summary.md`.

The harness is intentionally thin — it knows nothing about specific
benchmarks. Each benchmark is a `BenchAdapter` plugin under
`evaluation/adapters/<name>/` that owns task enumeration, materialisation,
prompt context, and scoring.

## CLI

```bash
# enumerate tasks for an adapter
uv run python -m evaluation.cli list --adapter noop

# run an adapter over a task list, optionally in parallel
uv run python -m evaluation.cli run \
    --adapter noop \
    --limit 2 \
    --concurrency 2

# live dashboard for an in-flight run (auto-refreshing)
uv run python -m evaluation.cli watch output/bench/noop/run_<id>

# one-shot summary
uv run python -m evaluation.cli status output/bench/noop/run_<id>

# render Markdown report to stdout (or --format json for machine use)
uv run python -m evaluation.cli report output/bench/noop/run_<id>
```

`--pipeline-arg` is repeatable and forwards extra flags through to
`kai.main pipeline`, e.g. `--pipeline-arg=--skip-fixer --pipeline-arg=--no-iterative`.

`--env KEY=VALUE` is repeatable and overrides environment variables only
for the pipeline subprocess (useful to dial down agent iteration budgets
for cheap dry-runs: `--env KAI_ROOT_ITERS=10`).

## Output layout

```
output/bench/<benchmark>/run_<run_id>/
├── summary.json            # BenchmarkRun (continuously updated)
├── summary.md              # human-readable summary (final)
└── <task_id>/
    ├── command.txt         # exact pipeline command executed
    ├── prepared.json       # what the adapter materialised
    ├── stdout.log          # pipeline stdout
    ├── stderr.log          # pipeline stderr (incl. timeout marker)
    ├── log.jsonl           # structured pipeline events
    ├── run.json            # kai.main result JSON
    ├── state/              # pipeline state dir (RunRecord, exploits, rollouts)
    └── score.json          # adapter's TaskScore
```

## Post-hoc grading & inspection

Each adapter writes a `score.json` inline, but cybergym's authoritative
scoring is decoupled into `evaluation.cybergym_eval` so it can run after a
batch finishes, against a CyberGym server you run yourself. The LLM judges
default to an OSS model on OpenRouter (`$OPENROUTER_API_KEY`).

| subcommand   | what it answers                                                              | reads               |
|--------------|-----------------------------------------------------------------------------|---------------------|
| `verify`     | Do these PoC bytes actually crash the target? (the oracle)                  | a PoC file / base64 |
| `recheck`    | Can we reproduce the crash from a pulled rollout?                           | rollout + server    |
| `bugmatch`   | Does the agent's *final hypothesis* match the documented bug?               | `score.json`        |
| `trajectory` | How close did the agent's *exploration* get — PROMISING / PARTIAL / OFF_TRACK? Credits a blind run that reached the right code but timed out before concluding. | full rollout transcript |
| `check`      | Batch soft + hard scorecard over many pulled rollouts.                      | a dir of rollouts   |

```bash
# how close did a blind run get to the bug?
uv run python -m evaluation.cybergym_eval trajectory --from-rollout <task_dir>

# agent's final hypothesis vs the documented bug
uv run python -m evaluation.cybergym_eval bugmatch --from-rollout <task_dir>

# batch scorecard (the hard column needs the CyberGym server)
uv run python -m evaluation.cybergym_eval check --dir <rollouts_parent> \
    --server http://127.0.0.1:8666 --mask-map mask_map.json
```

Build a browsable gallery — an overall index plus a per-rollout trace
viewer, with the found-bug judge inline — over any dir of pulled rollouts:

```bash
uv run python -m evaluation.cli index <rollouts_dir>/   # writes <rollouts_dir>/index.html
```

For distributed runs across a worker fleet (enqueue → workers → pull), see
[`docs/railway-deploy.md`](../docs/railway-deploy.md).

## Built-in adapters

| name          | status       | notes                                                                                            |
|---------------|--------------|--------------------------------------------------------------------------------------------------|
| `noop`        | ✅ available | Plumbing test — always succeeds.                                                                 |
| `cybergym`    | ✅ available | UC Berkeley CyberGym crash-repro tasks; run blind (`level0`) or with the bug description given (`level1`). |
| `bountybench` | ✅ available | Real-world bug-bounty tasks; scores on the found CWE + PoC.                                       |
| `evmbench`    | ✅ available | EVM/Solidity audit tasks (frontier-evals + Foundry baked into the image).                         |

## Adding a new adapter

1. Create `evaluation/adapters/<name>/adapter.py`.
2. Subclass `BenchAdapter` and implement `list_tasks`, `prepare`, `score`.
3. Register the factory with `@register_adapter("<name>")`.
4. Add the module path to `_BUILTIN_MODULES` in `evaluation/adapters/base.py`.

`evaluation/adapters/noop/adapter.py` is the minimal working reference.
