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

## Built-in adapters

| name       | status        | notes                                          |
|------------|---------------|------------------------------------------------|
| `noop`     | ✅ available  | Plumbing test — always succeeds.               |
| `cybergym` | 🚧 in progress | UC Berkeley CyberGym (1,507 repro tasks).      |

## Adding a new adapter

1. Create `evaluation/adapters/<name>/adapter.py`.
2. Subclass `BenchAdapter` and implement `list_tasks`, `prepare`, `score`.
3. Register the factory with `@register_adapter("<name>")`.
4. Add the module path to `_BUILTIN_MODULES` in `evaluation/adapters/base.py`.

`evaluation/adapters/noop/adapter.py` is the minimal working reference.
