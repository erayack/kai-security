"""
Parsing utilities for RLM trjaectories.
"""

import re
from typing import TYPE_CHECKING

from ra.core.types import REPLResult, RLMIteration

if TYPE_CHECKING:
    from ra.environments.base_env import BaseEnv


def find_code_blocks(text: str) -> list[str]:
    """
    Find REPL code blocks in text wrapped in triple backticks and return List of content(s).
    Returns None if no code blocks are found.
    """
    pattern = r"```repl\s*\n(.*?)\n```"
    results = []

    for match in re.finditer(pattern, text, re.DOTALL):
        code_content = match.group(1).strip()
        results.append(code_content)

    return results


def _extract_balanced_parens(text: str, start: int) -> str | None:
    """Extract content between balanced parentheses.

    *start* must point at the opening ``(``.  Returns the content
    between the matching pair, or ``None`` if the parens are unbalanced.
    """
    if start >= len(text) or text[start] != "(":
        return None
    depth = 1
    i = start + 1
    while i < len(text) and depth > 0:
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
        i += 1
    if depth == 0:
        return text[start + 1 : i - 1]
    return None


def find_final_answer(text: str, environment: "BaseEnv | None" = None) -> str | None:
    """
    Find FINAL(...) or FINAL_VAR(...) statement in response and return the final answer string.

    If FINAL_VAR is found and an environment is provided, executes code to retrieve the variable value.
    Returns None if neither pattern is found.

    Uses balanced parenthesis matching so that content containing
    ``)``, such as ``toJSON()`` inside a JSON string, is not treated
    as the closing delimiter.

    Args:
        text: The response text to parse
        environment: Optional environment to execute code for FINAL_VAR retrieval

    Returns:
        The final answer string, or None if no final answer pattern is found
    """
    # Check for FINAL_VAR pattern first - must be at start of line
    match = re.search(r"^\s*FINAL_VAR\(", text, re.MULTILINE)
    if match:
        content = _extract_balanced_parens(text, match.end() - 1)
        if content is not None:
            variable_name = content.strip().strip('"').strip("'")
            if environment is not None:
                result = environment.execute_code(
                    f"print(FINAL_VAR({variable_name!r}))"
                )
                final_answer = result.stdout.strip()
                if final_answer == "":
                    final_answer = result.stderr.strip() or ""
                return final_answer
        return None

    # Check for FINAL pattern - must be at start of line
    match = re.search(r"^\s*FINAL\(", text, re.MULTILINE)
    if match:
        content = _extract_balanced_parens(text, match.end() - 1)
        if content is not None:
            return content.strip()

    return None


def format_iteration(
    iteration: RLMIteration, max_character_length: int = 20000
) -> list[dict[str, str]]:
    """
    Format an RLM iteration (including all code blocks) to append to the message history for
    the prompt of the LM in the next iteration. We also truncate code execution results
    that exceed the max_character_length.

    Args:
        iteration: The iteration to format
        max_character_length: The maximum character length of the result

    Returns:
        A list of messages to add to the next prompt
    """
    messages = [{"role": "assistant", "content": iteration.response}]

    for code_block in iteration.code_blocks:
        code = code_block.code
        result = code_block.result
        result = format_execution_result(result)
        if len(result) > max_character_length:
            result = (
                result[:max_character_length]
                + f"... + [{len(result) - max_character_length} chars...]"
            )

        execution_message = {
            "role": "user",
            "content": f"Code executed:\n```python\n{code}\n```\n\nREPL output:\n{result}",
        }
        messages.append(execution_message)
    return messages


def format_execution_result(result: REPLResult) -> str:
    """Format the execution result as a string for display.

    Uses structured delta fields when available (added_vars,
    changed_vars, removed_vars, out_value, exception_name) to give
    the model a precise view of what changed.  Falls back to the
    legacy flat variable list for results from non-local REPLs that
    don't populate deltas.
    """
    result_parts: list[str] = []

    if result.stdout:
        result_parts.append(f"\n{result.stdout}")

    if result.stderr:
        result_parts.append(f"\n{result.stderr}")

    # Structured deltas (from LocalREPL)
    has_deltas = result.added_vars or result.changed_vars or result.removed_vars

    if has_deltas:
        delta_lines: list[str] = []
        if result.added_vars:
            delta_lines.append(f"  + {', '.join(result.added_vars)}")
        if result.changed_vars:
            delta_lines.append(f"  ~ {', '.join(result.changed_vars)}")
        if result.removed_vars:
            delta_lines.append(f"  - {', '.join(result.removed_vars)}")
        result_parts.append("Variable changes:\n" + "\n".join(delta_lines))
    elif not result.has_error:
        # Legacy fallback: flat variable list
        important_vars = [
            key
            for key, value in result.locals.items()
            if not key.startswith("_")
            and key not in ("__builtins__", "__name__", "__doc__")
            and isinstance(value, (str, int, float, bool, list, dict, tuple))
        ]
        if important_vars:
            result_parts.append(f"REPL variables: {important_vars}\n")

    if result.out_value is not None:
        result_parts.append(f"Last expression: {result.out_value}")

    if result.exception_name:
        result_parts.append(f"Exception: {result.exception_name}")

    return "\n\n".join(result_parts) if result_parts else "No output"


def check_for_final_answer(response: str, repl_env, logger) -> str | None:
    """Check if response contains a final answer."""
    # Use the new find_final_answer function which handles both FINAL and FINAL_VAR
    return find_final_answer(response, environment=repl_env)


def convert_context_for_repl(context):
    """
    Convert REPL context to either some
    """
    if isinstance(context, dict):
        context_data = context
        context_str = None
    elif isinstance(context, str):
        context_data = None
        context_str = context
    elif isinstance(context, list):
        if len(context) > 0 and isinstance(context[0], dict):
            if "content" in context[0]:
                context_data = [msg.get("content", "") for msg in context]
            else:
                context_data = context
            context_str = None
        else:
            context_data = context
            context_str = None
    else:
        context_data = context
        context_str = None

    return context_data, context_str
