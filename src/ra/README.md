# ra — Recursive Agent Framework

`ra` is a recursive language model (RLM) framework that replaces `llm.completion(prompt)` with an agentic loop. The LLM gets a Python REPL where context is loaded as a variable, writes code to inspect and process it, and can make sub-calls to other LLMs. This is a ReAct-style loop: **reason -> act -> observe -> repeat**.

## Architecture

```
RLM.completion(prompt)
│
├── LMHandler (TCP socket server on 127.0.0.1:<auto-port>)
│   ├── default_client (depth=0, primary model)
│   ├── other_backend_client (depth=1, cheaper model)
│   └── clients dict (named model overrides)
│
├── Environment (REPL)
│   ├── LocalREPL  — exec() in sandboxed namespace
│   └── DockerREPL — container with HTTP proxy
│
└── Iteration Loop
    ├── LLM call via lm_handler.completion()
    ├── Code extraction via find_code_blocks()
    ├── Code execution via environment.execute_code()
    ├── Answer detection via find_final_answer()
    └── History formatting via format_iteration()
```

### Data Flow

```
User Input
    ↓
RLM.completion(prompt)
    ↓
Spawn LM Handler (TCP server) + Environment (REPL)
    ↓
Iteration Loop:
    ├─ Build message history with context metadata
    ├─ Call LM via socket
    ├─ Extract code blocks from response
    ├─ Execute code in REPL
    ├─ Collect stdout/stderr/locals/sub-LLM calls
    ├─ Check for FINAL answer
    └─ Format iteration, add to history, repeat
    ↓
Return RLMChatCompletion (response + usage + timing)
```

## Module Overview

### `core/`

The heart of the framework.

| File | Description |
|---|---|
| `rlm.py` | `RLM` class — main orchestrator. Runs the iterative completion loop, manages environments and LM handlers, supports persistent multi-turn sessions. |
| `lm_handler.py` | `LMHandler` — multi-threaded TCP socket server that routes LM requests by model name and depth. Supports named client overrides and depth-based routing (depth=0 -> primary, depth=1 -> secondary). |
| `comms_utils.py` | Socket protocol (4-byte length prefix + JSON). Message types: `LMRequest`, `LMResponse`. Helpers for single and batched requests. |
| `types.py` | Core dataclasses: `UsageSummary`, `RLMIteration`, `RLMChatCompletion`, `REPLResult`, `CodeBlock`, `RLMMetadata`, `QueryMetadata`. Also defines `ClientBackend` and `EnvironmentType` literals. |

### `clients/`

LM provider implementations behind a common `BaseLM` interface.

| File | Provider |
|---|---|
| `base_lm.py` | `BaseLM` — abstract interface (`completion()`, `acompletion()`, `get_usage_summary()`) |
| `openai.py` | OpenAI, vLLM, OpenRouter, Vercel AI Gateway |
| `anthropic.py` | Anthropic API |
| `azure_openai.py` | Azure OpenAI deployments |
| `gemini.py` | Google Gemini (google-genai SDK) |
| `portkey.py` | Portkey unified gateway |


All clients track per-model token usage. A `get_client(backend, **kwargs)` factory routes backend types to the appropriate class.

### `environments/`

Sandboxed Python execution environments for the agentic loop.

| File | Description |
|---|---|
| `base_env.py` | `BaseEnv` abstract class, `IsolatedEnv` / `NonIsolatedEnv` variants, and the `SupportsPersistence` protocol for multi-turn sessions. |
| `local_repl.py` | `LocalREPL` — sandboxed `exec()` with restricted builtins. Provides `llm_query()`, `llm_query_batched()`, and `FINAL_VAR()` in the REPL namespace. Thread-safe with locking. |
| `docker_repl.py` | `DockerREPL` — runs code in a Docker container with an HTTP proxy for LLM requests. |

**Persistence protocol**: Environments implementing `SupportsPersistence` support versioned contexts (`context_0`, `context_1`, ...) and message histories (`history_0`, `history_1`, ...) for multi-turn workflows.

### `agents/`

Hierarchical multi-agent layer built on top of RLM.

| File | Description |
|---|---|
| `config.py` | `RecursiveAgentConfig` — dataclass defining an agent node: name, system prompt, tools, sub-agents, backend config, iteration budget. Includes validation (no duplicate names, no tool/spawn collisions, all functions documented in prompt). |
| `agent.py` | `RecursiveAgent` — wraps an RLM instance with tool injection and sub-agent spawning. Each sub-agent config becomes a `spawn_<name>()` callable in the REPL. Sub-agents run at depth+1 and their token usage bubbles up to the parent. |
| `registry.py` | `AgentRegistry` — optional utility for dynamic agent registration and lookup. |

**Spawn mechanics**: `spawn_<name>()` functions are closures that create a new `RecursiveAgent` at depth+1 with its own system prompt, tools, and iteration budget. Failures are caught as `SpawnError` so they don't crash the parent.

### `logger/`

| File | Description |
|---|---|
| `ra_logger.py` | `RecursiveAgentLogger` — JSON-lines file logger. Writes timestamped entries for metadata and each `RLMIteration`. |
| `verbose.py` | `VerbosePrinter` — rich console output with iteration progress, code execution results, and usage summaries. No-ops when `verbose=False`. |

### `utils/`

| File | Description |
|---|---|
| `parsing.py` | Code block extraction (`find_code_blocks`), final answer detection (`find_final_answer` for `FINAL()` / `FINAL_VAR()` markers), and iteration formatting. |
| `prompts.py` | `RLM_SYSTEM_PROMPT` template, `QueryMetadata` for analyzing prompt structure, and builders for system/user messages. |
| `rlm_utils.py` | `filter_sensitive_keys()` for stripping API keys from logs, `generate_id()` for random hex IDs. |

### `exceptions.py`

Exception hierarchy rooted at `RecursiveAgentError`:

- `SetupRLMError` — setup failures
- `RootRLMError` — root RLM failures
- `SubRLMError` — sub-agent failures
- `LMError` — LM request failures
- `SpawnError` — sub-agent spawning failures
- `SerializationError` — serialization failures

## Key Concepts

### Depth-Based Routing

Agents form a tree with configurable depth:

- **depth=0**: Root orchestrator, uses the primary backend
- **depth=1+**: Sub-agents, can use a cheaper secondary backend
- **max_depth**: When reached, falls back to a single-shot LM call (no REPL)

### REPL Namespace

Code executed in the REPL has access to:

- `context` — the input data loaded as a Python variable
- `llm_query(prompt, model=None)` — make a sub-call to an LLM
- `llm_query_batched(prompts, model=None)` — concurrent batch queries
- `FINAL(answer)` — signal the final answer as a string
- `FINAL_VAR(variable_name)` — signal a variable's value as the final answer
- `spawn_<name>(data)` — spawn a sub-agent (when agents are configured)
- Any custom tools injected via `RecursiveAgentConfig.tools`

### Persistent Sessions

With `persistent=True`, the RLM reuses its environment across multiple `completion()` calls, enabling multi-turn conversations with versioned contexts and histories.

## Quick Start

```python
from ra.core.rlm import RLM

rlm = RLM(
    backend="openai",
    backend_kwargs={"model": "gpt-4o", "api_key": "..."},
    environment="local",
    max_iterations=10,
)

result = rlm.completion("Analyze the data and summarize key trends.")
print(result.response)
```

### With Agents

```python
from ra.agents.config import RecursiveAgentConfig
from ra.agents.agent import RecursiveAgent

config = RecursiveAgentConfig(
    name="analyzer",
    system_prompt="You are a data analysis agent. ...",
    tools={"fetch_data": fetch_data_fn},
    agents=[
        RecursiveAgentConfig(
            name="summarizer",
            system_prompt="You summarize data. ...",
        )
    ],
    backend="openai",
    backend_kwargs={"model": "gpt-4o"},
    max_iterations=15,
)

agent = RecursiveAgent(config)
result = agent.completion(my_data)
```
