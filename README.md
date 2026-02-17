# Kai

Automated vulnerability discovery, verification, and patching using recursive language models.

Kai runs a multi-stage pipeline: a **setup agent** clones and builds the target project, then an **exploit agent** orchestrates sub-agents (recon, analysis, verification, patching) to find and confirm vulnerabilities with working proof-of-concept exploits.

Built on [ra](src/ra/), a recursive language model framework where LLMs write code that launches other LLMs.

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
# Clone the repo
git clone https://github.com/firstbatch/exploit-agent.git
cd exploit-agent

# Install dependencies
uv sync

# Copy and fill in API keys
cp .env.example .env
```

### API keys

| Key | Required | Used by |
|---|---|---|
| `OPENROUTER_API_KEY` | Yes | LLM calls (sub-agents) |
| `JINA_API_KEY` | Optional | Web search and URL reading (researcher agent) |

## Usage

### Full pipeline (setup + exploit)

Point Kai at a repository. The setup agent clones it, installs dependencies, builds it, and produces a workspace recipe. The exploit agent then analyzes the codebase for vulnerabilities.

```bash
# From a local repo path
uv run python -m kai.main pipeline --repo-path /path/to/target --verbose

# With logging to file
uv run python -m kai.main pipeline --repo-path /path/to/target --verbose --log-file run.log
```

### Skip setup (use a saved recipe)

If you already have a workspace recipe from a previous setup run:

```bash
uv run python -m kai.main pipeline --recipe recipe.json --verbose
```

### Run a single agent

```bash
# Run the setup agent alone
uv run python -m kai.main agent setup --input '{"repo_path": "/path/to/target", "master_dir": "/tmp/master"}'

# Run the exploit agent alone (needs a recipe injected separately)
uv run python -m kai.main agent exploit --input '{"master_path": "/tmp/master"}' --verbose
```

### CLI options

| Flag | Description |
|---|---|
| `--output PATH`, `-o` | Save result JSON to PATH (default: `output/run_<timestamp>.json`) |
| `--verbose` | Rich console output showing each iteration |
| `--log-file PATH` | Save verbose output to a file |
| `--backend NAME` | Override LLM backend (agent mode) |
| `--model NAME` | Override model name (agent mode) |
| `--max-iterations N` | Override iteration budget (agent mode) |

### Output

Results are always saved to disk as JSON. By default they go to `output/run_<timestamp>.json`. Use `--output` / `-o` to choose a custom path:

```bash
# Default — writes to output/run_20250101T120000Z.json
uv run python -m kai.main pipeline --repo-path /path/to/target

# Custom path
uv run python -m kai.main pipeline --repo-path /path/to/target -o results/my_run.json
```

The JSON file contains:

```json
{
  "model": "...",
  "execution_time": 123.4,
  "usage": { "model_usage_summaries": { ... } },
  "result": [ ... ]
}
```

## Supported Languages

The dependency graph indexes source files using [tree-sitter](https://tree-sitter.github.io/) grammars. The following languages are supported:

| Language | Extensions |
|---|---|
| Solidity | `.sol` |
| Rust | `.rs` |
| Python | `.py` |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` |
| Go | `.go` |
| C | `.c`, `.h` |

## Architecture

```
pipeline --repo-path /path/to/target
    |
    v
[Setup Agent]  — clones repo, installs deps, builds, produces recipe
    |
    v
[Exploit Agent] (root RLM, depth 0)
    |-- dep_* tools (dependency graph navigation)
    |-- llm_query (single-shot LLM calls)
    |-- spawn_recon(...)       -> [Recon Agent]      (depth 1, workspace)
    |-- spawn_analyzer(...)    -> [Analyzer Agent]    (depth 1, workspace)
    |-- spawn_verifier(...)    -> [Verifier Agent]    (depth 1, workspace)
    |-- spawn_researcher(...)  -> [Researcher Agent]  (depth 1, web tools)
    |-- spawn_fixer(...)       -> [Fixer Agent]       (depth 1, workspace)
```

Each sub-agent is a full RLM with its own REPL, iteration budget, and `llm_query` access. The root orchestrator decides how to partition work and which agents to spawn — there is no fixed pipeline.

## Development

```bash
# Run tests
uv run --with pytest --with pytest-asyncio -- pytest tests/ -q

# Format
uvx ruff format src

# Lint
uvx ruff check src

# Type check
uvx ty check src
```
