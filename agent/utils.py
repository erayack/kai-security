from agent.settings import (
    FINDER_AGENT_PROMPT_PATH,
    FINDER_SUBAGENT_PROMPT_PATH,
    NON_DUPLICATE_VERIFIER_PROMPT_PATH,
    TEST_GENERATOR_PROMPT_PATH,
    SETUP_AGENT_PROMPT_PATH,
    FIXER_AGENT_PROMPT_PATH,
    MAX_TOOL_TURNS,
    MAX_DEPTH,
)

from enum import Enum
import os
import pathspec
from typing import Optional

class AgentType(Enum):
    FINDER = FINDER_AGENT_PROMPT_PATH
    NON_DUPLICATE_VERIFIER = NON_DUPLICATE_VERIFIER_PROMPT_PATH
    TEST_GENERATOR = TEST_GENERATOR_PROMPT_PATH
    SETUP = SETUP_AGENT_PROMPT_PATH
    FIXER = FIXER_AGENT_PROMPT_PATH

def load_system_prompt(agent_type: AgentType, is_sub_agent: bool = False, 
                       scope_path: str = "", task_description: str = "", 
                       max_turns: int = MAX_TOOL_TURNS, depth: int = 0, 
                       max_depth: int = MAX_DEPTH) -> str:
    """
    Load the system prompt from the file.

    Args:
        agent_type: The type of agent.
        is_sub_agent: Whether this is a sub-agent (uses condensed prompt).
        scope_path: The scope path for sub-agents.
        task_description: The task description for sub-agents.
        max_turns: Maximum turns allocated.
        depth: Current depth in hierarchy.
        max_depth: Maximum depth allowed.

    Returns:
        The system prompt as a string.
    """
    try:
        # Use condensed prompt for sub-agents of FINDER type
        if is_sub_agent and agent_type == AgentType.FINDER:
            prompt_path = FINDER_SUBAGENT_PROMPT_PATH
        else:
            prompt_path = agent_type.value
            
        with open(prompt_path, "r") as f:
            system_prompt = f.read()

            # Replace placeholders
            if agent_type in (AgentType.FINDER, AgentType.TEST_GENERATOR, AgentType.SETUP):
                system_prompt = system_prompt.replace("{{max_tool_turns}}", str(MAX_TOOL_TURNS - 1))
            
            # Sub-agent specific replacements
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

    Args:
        response: The response from the model.

    Returns:
        The formatted python code from the response.
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
    else:
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
    results: dict, 
    error_msg: str = "", 
    remaining_turns: int = 0
) -> str:
    """
    Format the results into a string and add the remaining turns to the string.

    Args:
        results: The results from the tools.
        error_msg: The error message from the tools.
        remaining_turns: The number of remaining turns.

    Returns:
        The formatted string.
    """
    return (
        "<result>\n(" + str(results) + ", {" + error_msg + "})\n</result>\n<remaining_turns>\n" + str(remaining_turns - 1) + "\n</remaining_turns>"
        if error_msg
        else "<result>\n" + str(results) + "\n</result>\n<remaining_turns>\n" + str(remaining_turns - 1) + "\n</remaining_turns>"
    )

def load_gitignore_spec(directory: str) -> Optional[pathspec.PathSpec]:
    """
    Load and parse .gitignore file from a directory.
    
    Args:
        directory: The directory to look for .gitignore file.
    
    Returns:
        A PathSpec object that can be used to match paths against gitignore patterns,
        or None if no .gitignore file is found.
    """
    gitignore_path = os.path.join(directory, '.gitignore')
    if not os.path.exists(gitignore_path):
        return None
    
    try:
        with open(gitignore_path, 'r') as f:
            gitignore_content = f.read()
        return pathspec.PathSpec.from_lines('gitwildmatch', gitignore_content.splitlines())
    except Exception:
        return None

def should_ignore_path(path: str, root_dir: str, gitignore_spec: Optional[pathspec.PathSpec]) -> bool:
    """
    Check if a path should be ignored based on gitignore patterns.
    
    Args:
        path: The absolute path to check.
        root_dir: The root directory (where .gitignore is located).
        gitignore_spec: The PathSpec object for gitignore patterns.
    
    Returns:
        True if the path should be ignored, False otherwise.
    """
    if gitignore_spec is None:
        return False
    
    # Get relative path from root directory
    try:
        rel_path = os.path.relpath(path, root_dir)
        # Check if this path matches any gitignore pattern
        return gitignore_spec.match_file(rel_path)
    except Exception:
        return False