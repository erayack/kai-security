# Kai - Exploit Agent

Automated smart contract vulnerability discovery and fix generation.

## Architecture

Kai v2 uses a **Dispatcher** that orchestrates the full pipeline:

```
┌─────────────────────────────────────────────────────────────────────┐
│                           DISPATCHER                                 │
├─────────────────────────────────────────────────────────────────────┤
│  BOOT (Preprocessing)                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐│
│  │  Setup   │→ │  Graph   │→ │ Profiler │→ │  Actors  │→ │Invars  ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └────────┘│
├─────────────────────────────────────────────────────────────────────┤
│  RUN LOOP (Mission Execution)                                        │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Missions → STATE/QUANT Agents → ExploitCandidates            │   │
│  │                                         ↓                     │   │
│  │                                   Verifier (inline)           │   │
│  │                                         ↓                     │   │
│  │                                     Verdicts                  │   │
│  └──────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│  POST-LOOP (Fix Generation)                                          │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Verified Exploits → FixerAgent → Fixes (patches)             │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Environment

Create a `.env` file with:

```bash
OPENROUTER_API_KEY="sk-or-v1-your-key-here"
MONGO_URI="localhost"  # Optional, for persistence
```

## Installation

```bash
make install
```

## Quick Start

### Using the Dispatcher (Recommended)

Run the full pipeline on a target repository:

```bash
uv run python scripts/playground_dispatcher.py --repo-path ./path/to/contracts
```

Options:
- `--model`: Model to use (default: `google/gemini-3-flash-preview`)
- `--concurrent`: Max concurrent agents (default: 2)
- `--max-turns`: Max turns per agent (default: 32)
- `--exploration`: Enable blackbox/gamified phases
- `--iterative`: Enable iterative mode and snapshot reuse
- `--no-fixer`: Disable fix generation

### Using Make Targets

```bash
make run REPO_PATH=./path/to/contracts
make run-exploration REPO_PATH=./path/to/contracts
make run-iterative REPO_PATH=./path/to/contracts
```

## Project Structure

```
kai/
├── agents/                 # Agent implementations
│   ├── agent_types/        # StateAgent, QuantAgent, VerifierAgent, FixerAgent
│   ├── tools/              # Tool functions for agents
│   └── base.py             # BaseAgent class
├── dispatcher/             # Dispatcher (mission control)
│   ├── core.py             # Main Dispatcher class
│   ├── planner.py          # Mission planning
│   ├── workspace.py        # Workspace provisioning
│   └── agent_factories.py  # Agent creation
├── processes/              # Preprocessing steps
│   ├── envsetup.py         # Environment setup
│   ├── profiler.py         # Protocol profiling
│   ├── actors.py           # Actor analysis
│   ├── invariants.py       # Invariant discovery
│   └── verifier.py         # Exploit verification
├── prompts/                # Agent prompt templates
├── schemas.py              # Pydantic models
├── state_manager.py        # Persistence interface
└── utils/                  # Utilities (dependency graph, workspace adapters)

scripts/
├── playground_dispatcher.py  # E2E dispatcher demo
└── install.sh                # Bootstrap script
```

## Pipeline Stages

### 1. Boot (Preprocessing)

- **EnvironmentSetup**: Clone repo, detect framework, compile
- **DependencyGraph**: Static analysis of code structure
- **Profiler**: Understand protocol purpose and mechanics
- **ActorAnalysis**: Identify roles and privileges
- **InvariantDiscovery**: Find security properties to test

### 2. Run Loop (Mission Execution)

- **StateAgent**: Finds state/ordering violations (reentrancy, access control)
- **QuantAgent**: Finds numeric violations (overflow, precision loss)
- **Verifier**: Validates exploit candidates inline

### 3. Fix Generation (Post-Loop)

- **FixerAgent**: Generates patches for verified exploits
- Produces unified diffs with reasoning
- Validates fixes compile and tests pass

## Output

Results are saved to `output/`:

```
output/
├── playground/{repo}_{timestamp}/
│   ├── results.json    # Full report
│   ├── fixes.json      # Generated patches
│   └── workspaces/     # Agent workspaces
└── e2e_runs/           # Detailed E2E runs
```

## Configuration

`DispatcherConfig` options:

| Option | Default | Description |
|--------|---------|-------------|
| `max_concurrent_agents` | 2 | Parallel agent limit |
| `max_invariants_per_cluster` | 5 | Invariants per campaign |
| `max_campaigns` | 10 | Campaign limit |
| `include_exploration` | True | Enable BlackBox agents |
| `model` | `google/gemini-3-flash-preview` | Model for agents |
| `workspace_dir` | `./kai_workspaces` | Workspace location |

## Development

```bash
# Run tests
make test

# Run lint checks
make lint

# Run type checks
make typecheck

# Format code
make format
```
