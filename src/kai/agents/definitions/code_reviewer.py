"""Example agent: code reviewer with simple source analysis tools."""

import re

from kai.agents.config import AgentConfig


# --- Tool functions available in the sub-agent's REPL ---


def count_lines(code: str) -> int:
    """Count the number of lines in a code string."""
    return len(code.strip().splitlines())


def search_pattern(code: str, pattern: str) -> list[str]:
    """Return all lines in code matching a regex pattern."""
    return [line for line in code.splitlines() if re.search(pattern, line)]


def list_functions(code: str) -> list[str]:
    """Extract function/method names from Python source code."""
    return re.findall(r"def\s+(\w+)\s*\(", code)


# --- System prompt ---

SYSTEM_PROMPT = """\
You are a code review agent. You analyze source code for quality issues.

You have access to the following tool functions in your REPL:

- count_lines(code: str) -> int
    Count the number of lines in a code string.

- search_pattern(code: str, pattern: str) -> list[str]
    Return all lines matching a regex pattern.

- list_functions(code: str) -> list[str]
    Extract function/method names from Python source code.

- llm_query(prompt: str) -> str
    Ask an LLM a question (single-shot, for quick lookups).

Your input is in the `context` variable. Analyze the code using your tools,
then return your findings with FINAL(...) or FINAL_VAR(variable_name).
"""

# --- Config ---

config = AgentConfig(
    name="code_reviewer",
    system_prompt=SYSTEM_PROMPT,
    tools={
        "count_lines": count_lines,
        "search_pattern": search_pattern,
        "list_functions": list_functions,
    },
    backend="openai",
    backend_kwargs={"model_name": "gpt-4o-mini"},
    max_iterations=10,
)
