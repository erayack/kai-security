# scripts/eval — offline prompt-eval harnesses

Small, hand-rolled A/B evaluators for individual prompts in this repo. They
score prompt-variant effectiveness on a curated input set without touching the
benchmark pipeline. **Local-only**: outputs go under `data/<eval_name>/` which
is gitignored.

| Script | What it scores | Default inputs |
|---|---|---|
| `researcher_eval.py` | Hallucination rate of the researcher agent's URL / SWC / CVE references across 3 system-prompt variants. | `data/researcher_eval/inputs.json` (curated) |
| `cybergym_prompt_eval.py` | "Does the model commit to spawn_critic / spawn_verifier?" for the cybergym reminder + BLOCKED-message variants, replayed offline against R23 rollouts. | `docs/rollouts-2026-05-24-r23/cybergym/...` |

## Run

```bash
# self-tests (no network, no LLM)
uv run python -m scripts.eval.researcher_eval --self-test
uv run python -m scripts.eval.cybergym_prompt_eval --self-test

# real runs (LLM calls — costs apply)
uv run python -m scripts.eval.researcher_eval --variants v0 v1 v2 --limit 5
uv run python -m scripts.eval.cybergym_prompt_eval --target both --limit 3

# direct invocation works too
uv run python scripts/eval/researcher_eval.py --help
```

Both write:

- `data/<eval_name>/results.csv` — one row per (input, variant) with score columns
- `data/<eval_name>/raw/<variant>/<slot>.json` — raw agent output per slot

## Adding a third eval

Drop a new module under `scripts/eval/`, import the shared helpers:

```python
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.eval._common import (
    ensure_src_on_path,
    eval_output_dirs,
    repo_root,
)

ensure_src_on_path()
EVAL_DIR, RAW_DIR = eval_output_dirs("my_new_eval")
```

Then write your scoring loop. The shared helpers handle pathing + output dirs;
everything else (CLI, scoring logic, input format) is up to the individual eval.

Convention each script follows:

- Has a `--self-test` flag (no network, no LLM) that exits 0 on healthy parsing logic
- Has `--variants` and `--limit` flags so partial runs are cheap
- Writes CSV + raw JSON under `data/<eval_name>/`
- Imports models / configs from `src/kai/` and `src/ra/` (NOT a copy)
