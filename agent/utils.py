from agent.settings import (
    FINDER_AGENT_PROMPT_PATH,
    NON_DUPLICATE_VERIFIER_PROMPT_PATH,
    MAX_TOOL_TURNS,
)

from enum import Enum

class AgentType(Enum):
    FINDER = FINDER_AGENT_PROMPT_PATH
    NON_DUPLICATE_VERIFIER = NON_DUPLICATE_VERIFIER_PROMPT_PATH

def load_system_prompt(agent_type: AgentType) -> str:
    """
    Load the system prompt from the file.

    Returns:
        The system prompt as a string.
    """
    try:
        with open(agent_type.value, "r") as f:
            system_prompt = f.read()

            if agent_type == AgentType.FINDER:
                system_prompt = system_prompt.replace("{{max_tool_turns}}", str(MAX_TOOL_TURNS - 1))

            return system_prompt
    except FileNotFoundError:
        raise FileNotFoundError(f"System prompt file not found at {agent_type.value}")

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
        "<result>\n(" + str(results) + ", {" + error_msg + "})\n</result>\n<remaining_turns>\n" + str(remaining_turns) + "\n</remaining_turns>"
        if error_msg
        else "<result>\n" + str(results) + "\n</result>\n<remaining_turns>\n" + str(remaining_turns) + "\n</remaining_turns>"
    )