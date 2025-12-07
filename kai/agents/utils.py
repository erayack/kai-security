from enum import Enum
import os
import pathspec
import re
from typing import Optional

from kai.agents import settings


class AgentType(Enum):
    FINDER = "finder"
    NON_DUPLICATE_VERIFIER = "non_duplicate_verifier"
    TEST_GENERATOR = "test_generator"
    SETUP = settings.SETUP_AGENT_PROMPT_PATH
    FIXER = "fixer"


def agent_type_to_kind(agent_type: AgentType) -> str:
    """Convert AgentType enum to kind string for database storage."""
    if agent_type == AgentType.SETUP:
        return "setup"
    return "unknown"


def load_system_prompt(
    agent_type: AgentType,
    is_sub_agent: bool = False,
    scope_path: str = "",
    task_description: str = "",
    max_turns: int = settings.MAX_TOOL_TURNS,
    depth: int = 0,
    max_depth: int = settings.MAX_DEPTH,
) -> str:
    """
    Load the system prompt from the file (only SETUP supported in this migration).
    """
    if agent_type != AgentType.SETUP:
        raise ValueError(f"Unsupported agent type for Kai v2 base/setup scope: {agent_type}")

    prompt_path = agent_type.value
    try:
        with open(prompt_path, "r") as f:
            system_prompt = f.read()
            system_prompt = system_prompt.replace(
                "{{max_tool_turns}}", str(settings.MAX_TOOL_TURNS - 1)
            )

            if is_sub_agent:
                system_prompt = system_prompt.replace("{{scope_path}}", scope_path)
                system_prompt = system_prompt.replace("{{task_description}}", task_description)
                system_prompt = system_prompt.replace("{{max_turns}}", str(max_turns))
                system_prompt = system_prompt.replace("{{depth}}", str(depth))
                system_prompt = system_prompt.replace("{{max_depth}}", str(max_depth))

            return system_prompt
    except FileNotFoundError:
        raise FileNotFoundError(f"System prompt file not found at {prompt_path}")


def extract_python_code(response: str) -> str:
    """
    Extract the python code from the response and format it with Black.
    """
    if "<python>" in response and "</python>" in response:
        response = response.split("<python>")[1].split("</python>")[0]
        if "```" in response:
            code = response.split("```")[1].split("```")[0]
        else:
            code = response

        return code
    else:
        return ""


def extract_thoughts(response: str) -> str:
    """
    Extract the thoughts from the response.
    """
    if "<think>" in response and "</think>" in response:
        return response.split("<think>")[1].split("</think>")[0]
    else:
        return ""


def extract_decision(response: str) -> bool:
    """
    Extract the decision from the response.
    """
    if "<decision>" in response and "</decision>" in response:
        return response.split("<decision>")[1].split("</decision>")[0] == "True"
    else:
        return False


def extract_test_script(response: str) -> str:
    """
    Extract the test script from the response.
    """
    if "<test_script>" in response and "</test_script>" in response:
        return response.split("<test_script>")[1].split("</test_script>")[0]
    else:
        return ""


def extract_suggest_fix(response: str) -> str:
    """
    Extract the suggested fix from the response.
    """
    if "<suggest_fix>" in response and "</suggest_fix>" in response:
        return response.split("<suggest_fix>")[1].split("</suggest_fix>")[0]

    # Fallback: capture the first ```diff block even if the agent forgot the wrapper
    diff_match = re.search(r"```diff[\\s\\S]+?```", response)
    if diff_match:
        return diff_match.group(0)

    return ""


def check_done(response: str) -> bool:
    """
    Check if the response contains the <done> tag.
    """
    if "<done>" in response and "</done>" in response:
        return True
    else:
        return False


def format_results_and_remaining_turns(
    results: dict, error_msg: str = "", remaining_turns: int = 0
) -> str:
    """
    Format the results into a string and add the remaining turns to the string.
    """
    return (
        "<result>\\n("
        + str(results)
        + ", {"
        + error_msg
        + "})\\n</result>\\n<remaining_turns>\\n"
        + str(remaining_turns - 1)
        + "\\n</remaining_turns>"
        if error_msg
        else "<result>\\n"
        + str(results)
        + "\\n</result>\\n<remaining_turns>\\n"
        + str(remaining_turns - 1)
        + "\\n</remaining_turns>"
    )


def load_gitignore_spec(directory: str) -> Optional[pathspec.PathSpec]:
    """
    Load and parse .gitignore file from a directory.
    """
    gitignore_path = os.path.join(directory, ".gitignore")
    if not os.path.exists(gitignore_path):
        return None

    try:
        with open(gitignore_path, "r") as f:
            gitignore_content = f.read()
        return pathspec.PathSpec.from_lines("gitwildmatch", gitignore_content.splitlines())
    except Exception:
        return None


def should_ignore_path(path: str, root_dir: str, gitignore_spec: Optional[pathspec.PathSpec]) -> bool:
    """
    Check if a path should be ignored based on gitignore patterns.
    """
    if gitignore_spec is None:
        return False

    try:
        rel_path = os.path.relpath(path, root_dir)
        return gitignore_spec.match_file(rel_path)
    except Exception:
        return False

