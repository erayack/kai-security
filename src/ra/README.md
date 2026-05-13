# ra - Recursive Agent Framework

`ra` is the lightweight recursive agent framework used by Kai. It wraps an LLM
with a Python REPL loop so the model can inspect context, execute code, call
tools, ask nested LLM questions, and spawn configured sub-agents.

This package is primarily an internal library for `kai-security`; most users
should start from the root [README](../../README.md).

## What It Provides

- `RLM`: the core loop that calls a model, extracts Python code blocks, executes
  them in a REPL environment, and returns the final answer.
- `RecursiveAgent`: a structured wrapper around `RLM` with tools, sub-agents,
  model settings, iteration budgets, logging, and result processors.
- LLM clients for OpenAI-compatible APIs, Anthropic, Azure OpenAI, Gemini,
  Portkey, vLLM, OpenRouter, and Vercel AI Gateway.
- REPL environments:
  - `local`: default, actively used by Kai.
  - `docker`: available for container-backed execution when Docker is running.

## Minimal Example

```python
from ra.core.rlm import RLM

rlm = RLM(
    backend="openai",
    backend_kwargs={"model_name": "gpt-5.4"},
    environment="local",
    max_iterations=10,
)

result = rlm.completion("Summarize the main risk in this code snippet.")
print(result.response)
```

## Agent Example

```python
from ra.agents.agent import RecursiveAgent
from ra.agents.config import RecursiveAgentConfig

config = RecursiveAgentConfig(
    name="analyzer",
    system_prompt="You analyze the provided context and return concise findings.",
    backend="openai",
    backend_kwargs={"model_name": "gpt-5.4"},
    max_iterations=10,
)

agent = RecursiveAgent(config)
result = agent.completion({"files": ["src/example.py"]})
print(result.response)
```

## Runtime Notes

- The REPL namespace includes `context`, `llm_query()`, `llm_query_batched()`,
  `FINAL(answer)`, and `FINAL_VAR(variable_name)`.
- Tools configured on `RecursiveAgentConfig.tools` are injected into the REPL.
- Sub-agents configured on `RecursiveAgentConfig.agents` are exposed as
  `spawn_<name>(**kwargs)` functions.
- Use `verbose=True` or `log_structured=True` on configs when you need run
  visibility for debugging or evaluation.
