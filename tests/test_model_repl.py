"""Smoke-test models for REPL interaction pattern compliance.

These tests make real API calls via OpenRouter and are skipped
unless OPENROUTER_API_KEY is set.  Run explicitly with::

    uv run pytest tests/test_model_repl.py -v

Each test gives a model a trivial task (sum a list of numbers)
that requires reading the REPL context, computing in a code block,
and returning the result with FINAL_VAR.  Models that reason
internally without writing ```repl blocks will fail.
"""

from __future__ import annotations

import os

import pytest

from ra.agents.agent import RecursiveAgent
from ra.agents.config import RecursiveAgentConfig

# ------------------------------------------------------------------
# Minimal prompt — just enough to explain the REPL contract.
# ------------------------------------------------------------------

_PROMPT = """\
You are a compute agent. You work in a REPL environment where \
a `context` variable (dict) is pre-loaded.

To execute code, wrap it in triple backticks with `repl`:
```repl
print(context)
```

When done, provide your final answer OUTSIDE a code block.
Use FINAL_VAR(variable_name) to return a REPL variable.

Task: compute the sum of context["numbers"], store the result \
in a variable called `answer`, then return it with \
FINAL_VAR(answer).
"""

# ------------------------------------------------------------------
# Models to evaluate — add new candidates here before deploying.
# ------------------------------------------------------------------

_MODELS = [
    "minimax/minimax-m2.5",
    "anthropic/claude-sonnet-4.6",
    "anthropic/claude-opus-4.5",
    "openai/gpt-5.2",
]

_INPUT = {"numbers": [3, 7, 5]}
_EXPECTED = 15


@pytest.fixture(autouse=True)
def _require_api_key() -> None:
    # Load .env if python-dotenv is available.
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass
    if not os.environ.get("OPENROUTER_API_KEY"):
        pytest.skip("OPENROUTER_API_KEY not set")


@pytest.mark.parametrize("model", _MODELS)
def test_repl_sum(model: str) -> None:
    """Model must read context, compute in REPL, return via FINAL_VAR."""
    config = RecursiveAgentConfig(
        name="compute",
        system_prompt=_PROMPT,
        backend="openrouter",
        backend_kwargs={"model_name": model},
        max_iterations=5,
    )
    agent = RecursiveAgent(config)
    result = agent.completion(_INPUT)

    response = result.response if hasattr(result, "response") else str(result)
    assert response is not None, f"{model}: no response"
    assert "Error" not in response, f"{model}: got error — {response}"

    # Accept "15" or "15.0" — either means the model computed correctly.
    try:
        value = int(float(response.strip()))
    except (ValueError, TypeError):
        pytest.fail(f"{model}: non-numeric response — {response!r}")

    assert value == _EXPECTED, (
        f"{model}: expected {_EXPECTED}, got {value} (raw: {response!r})"
    )
