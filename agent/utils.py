from agent.settings import (
    SYSTEM_PROMPT_PATH
)


def load_system_prompt() -> str:
    """
    Load the system prompt from the file.

    Returns:
        The system prompt as a string.
    """
    try:
        with open(SYSTEM_PROMPT_PATH, "r") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"System prompt file not found at {SYSTEM_PROMPT_PATH}")

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


def extract_reply(response: str) -> str:
    """
    Extract the reply from the response.
    """
    if "<reply>" in response and "</reply>" in response:
        return response.split("<reply>")[1].split("</reply>")[0]
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


def format_results(results: dict, error_msg: str = "") -> str:
    """
    Format the results into a string.
    """
    return (
        "<result>\n(" + str(results) + ", {" + error_msg + "})\n</result>"
        if error_msg
        else "<result>\n" + str(results) + "\n</result>"
    )