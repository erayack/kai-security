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

### Model configuration

Each agent's model can be overridden via environment variables. Set these in `.env` or export them:

| Variable | Default | Agent |
|---|---|---|
| `KAI_ROOT_MODEL` | `anthropic/claude-opus-4.5` | Root exploit orchestrator |
| `KAI_RECON_MODEL` | `openai/gpt-5.2` | Reconnaissance |
| `KAI_ANALYZER_MODEL` | `minimax/minimax-m2.5` | Vulnerability analysis |
| `KAI_VERIFIER_MODEL` | `openai/gpt-5.2` | PoC verification |
| `KAI_FIXER_MODEL` | `openai/gpt-5.2` | Patch generation |
| `KAI_RESEARCHER_MODEL` | `minimax/minimax-m2.5` | Web research |
| `KAI_SETUP_MODEL` | `minimax/minimax-m2.5` | Project setup |

All models are routed through OpenRouter. Before deploying a new model, run the REPL compliance test to verify it can follow the interaction pattern:

```bash
uv run --with pytest --with python-dotenv -- pytest tests/test_model_repl.py -v
```

### Iteration budgets

Each agent's iteration limit can be tuned independently:

| Variable | Default | Agent |
|---|---|---|
| `KAI_ROOT_ITERS` | `45` | Root exploit orchestrator |
| `KAI_RECON_ITERS` | `15` | Reconnaissance |
| `KAI_ANALYZER_ITERS` | `30` | Vulnerability analysis |
| `KAI_VERIFIER_ITERS` | `30` | PoC verification |
| `KAI_FIXER_ITERS` | `25` | Patch generation |
| `KAI_RESEARCHER_ITERS` | `15` | Web research |
| `KAI_SETUP_ITERS` | `30` | Project setup |

### Timeouts

| Variable | Default | Controls |
|---|---|---|
| `KAI_EXEC_TIMEOUT` | `600` | REPL code execution (seconds) |
| `KAI_SOCKET_TIMEOUT` | `300` | LLM request socket (seconds) |
| `KAI_SHELL_TIMEOUT` | `300` | Shell command subprocess (seconds) |

## Usage

### Full pipeline (setup + exploit)

Point Kai at a repository. The setup agent clones it, installs dependencies, builds it, and produces a workspace recipe. The exploit agent then analyzes the codebase for vulnerabilities.

```bash
# From a local repo path
uv run python -m kai.main pipeline --repo-path /path/to/target --verbose

# With logging to file
uv run python -m kai.main pipeline --repo-path /path/to/target --verbose --log-file run.log
```

### Iterative fix-and-re-audit

Use `--max-rounds` to run multiple passes. After each round, verified patches are applied to the codebase and the exploit agent re-audits the updated code to find deeper bugs that were hidden behind the first-round issues.

```bash
# Three rounds of analysis
uv run python -m kai.main pipeline --repo-path /path/to/target --max-rounds 3 --verbose --log-file audit.log
```

With `--log-file` and multiple rounds, each round gets its own log: `audit_round1.log`, `audit_round2.log`, etc. Intermediate results are saved to `output/` after each round so no work is lost.

Only findings whose patches apply cleanly are passed as context to subsequent rounds — the agent won't skip bugs that failed to patch.

### Extra instructions

Pass free-text guidance to steer the exploit agent:

```bash
uv run python -m kai.main pipeline --recipe recipe.json --instructions "Focus on economic invariants and fee arithmetic"
```

### Threat context

A threat context file tells Kai **who** can interact with the target, **what** trust boundaries exist, and **what** operational constraints apply. This dramatically improves finding quality — without it, the agent may flag admin-only operations as exploits or report economically infeasible attacks as critical.

```bash
uv run python -m kai.main pipeline --repo-path /path/to/target --threat-context threat_context.yaml
```

The file is YAML or JSON with these fields:

```yaml
# Required — what kind of project is this?
deployment_type: smart-contract  # smart-contract | web-app | cli-tool | library | ...
environment: on-chain            # on-chain | server | local | cloud | ...

# Who can interact with the system and how trusted are they?
access_roles:
  - name: anyone
    trust: none          # none | low | medium | high
    description: "Permissionless caller — any EOA or contract"
  - name: admin
    trust: high
    description: "Multisig owner with upgrade authority"

# Where are the trust boundaries?
boundaries:
  - "User input → contract storage (validation boundary)"
  - "Cross-chain message relay (L1 ↔ L2)"
  - "Proxy upgrade boundary (owner-only)"

# Operational constraints the agent should respect
known_constraints:
  - "Max realistic single-tx value: 10000 ETH (total supply ~120M)"
  - "Deployment-only functions: initialize, setup"
  - "Rate limiters cap per-period volume to 1000 tokens"
  - "Upgradeable proxies — owner can pause within 1 hour"
```

#### Field reference

| Field | Type | Required | Description |
|---|---|---|---|
| `deployment_type` | string | Yes | Project kind (`smart-contract`, `web-app`, `cli-tool`, `library`, etc.) |
| `environment` | string | No | Runtime environment (`on-chain`, `server`, `local`, `cloud`) |
| `access_roles` | list | No | Actors that interact with the system. Each has `name`, `trust` level (`none`/`low`/`medium`/`high`), and `description` |
| `boundaries` | list | No | Trust boundaries where privilege transitions occur |
| `known_constraints` | list | No | Operational limits, lifecycle constraints, economic bounds |

#### How it affects analysis

- **access_roles**: The verifier checks whether an exploit requires a high-trust actor. If so, it downgrades the finding from `active_exploit` to `trust_assumption_violation` — a real issue, but not exploitable by an unprivileged attacker.
- **boundaries**: Guides the analyzer toward the most security-critical code paths.
- **known_constraints**: The verifier checks PoC preconditions against these. For example, if a constraint says "max realistic single-tx value: 10000 ETH" and a PoC requires 79M ETH, the finding is reclassified as `theoretical_bounds`. Functions listed as deployment-only are reclassified as `deployment_hazard`.

#### Finding categories

| Category | Meaning | Gets fix? |
|---|---|---|
| `active_exploit` | Exploitable by an unprivileged attacker at runtime | Yes |
| `trust_assumption_violation` | Requires a trusted actor to misbehave | No (verify-only) |
| `deployment_hazard` | Only exploitable during initial deployment | No (verify-only) |
| `theoretical_bounds` | Economically or physically infeasible | No (verify-only) |
| `admin_misconfiguration` | Requires admin to misconfigure the system | No (verify-only) |
| `upgrade_hygiene` | Related to upgrade/migration safety | No (verify-only) |

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

| Flag | Mode | Description |
|---|---|---|
| `--output PATH`, `-o` | both | Save result JSON to PATH (default: `output/run_<timestamp>.json`) |
| `--verbose` | both | Rich console output showing each iteration |
| `--log-file PATH` | both | Save verbose output to a file |
| `--instructions TEXT` | pipeline | Extra instructions for the exploit agent |
| `--max-rounds N` | pipeline | Fix-and-re-audit rounds (default: 1) |
| `--backend NAME` | agent | Override LLM backend |
| `--model NAME` | agent | Override model name |
| `--max-iterations N` | agent | Override iteration budget |

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
