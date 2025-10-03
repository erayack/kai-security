from agent.utils import load_system_prompt, AgentType, extract_python_code, extract_decision
from agent.model import get_model_response
from agent.settings import VERIFICATION_SCRIPTS_PATH, EXPLOITS_PATH, OPENROUTER_GEMINI_FLASH
from agent.schemas import Exploit, ExploitLocation, ExploitSeverity

import json
import os
import uuid
from typing import List

VERIFIER_INSTRUCTION = """
Here is the new exploit:
<exploit>
{exploit}
</exploit>

And here is the `exploits.json` file containing all the previously found exploits:
<previous_exploits>
{exploits}
</previous_exploits>

Now you can decide whether the exploit is a non-duplicate or not.
"""

def construct_verifier_instruction(exploit: Exploit, exploits_json_string: str) -> str:
    """
    Construct the verifier instruction.

    Args:
        exploit: The exploit to verify.
        exploits_json_string: The string representation of the exploits.json file.

    Returns:
        The verifier instruction.
    """
    return VERIFIER_INSTRUCTION.format(exploit=exploit, exploits=exploits_json_string)

def verify_non_duplicate(exploit: Exploit, exploits_json_string: str) -> bool:
    """
    Verify if the exploit is a duplicate.

    Args:
        exploit: The exploit to verify.
        exploits_json_string: The string representation of the exploits.json file.

    Returns:
        True if the exploit is a duplicate, False otherwise.
    """
    verifier_instruction = construct_verifier_instruction(exploit, exploits_json_string)
    response = get_model_response(
        system_prompt=load_system_prompt(AgentType.NON_DUPLICATE_VERIFIER),
        message=verifier_instruction,
        model=OPENROUTER_GEMINI_FLASH
    )
    return extract_decision(response)