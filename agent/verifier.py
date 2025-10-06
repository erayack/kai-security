from agent.utils import load_system_prompt, AgentType, extract_python_code, extract_decision, extract_test_script
from agent.model import get_model_response
from agent.settings import EXPLOITS_PATH, OPENROUTER_GEMINI_FLASH
from agent.schemas import Exploit, ExploitLocation, ExploitSeverity
from agent.agent import Agent

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

GENERATOR_INSTRUCTION = """
Here is the exploit:
<exploit>
{exploit}
</exploit>

Start exploring the codebase and generate a test script for the exploit.
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

def construct_generator_instruction(exploit: dict) -> str:
    """
    Construct the generator instruction.
    """
    return GENERATOR_INSTRUCTION.format(exploit=json.dumps(exploit))

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


def generate_test_script(exploit: dict, repo_path: str, max_tool_turns: int = 16, model: str = None) -> str:
    """
    Generate a test script for the exploit.

    Args:
        exploit: The exploit to generate a test script for.
        repo_path: The path to the repo.
        max_tool_turns: The maximum number of tool turns allowed.
        model: The model to use for generation.

    Returns:
        The test script.
    """
    # Initialize the agent
    agent = Agent(
        agent_type=AgentType.TEST_GENERATOR, 
        repo_path=repo_path,
        max_tool_turns=max_tool_turns,
        model=model
    )
    # Construct the instruction
    instruction = construct_generator_instruction(exploit)
    # Generate the test script
    response = agent.chat(instruction)
    # Save the conversation
    agent.save_conversation(save_folder="generator_conversations", prefix="generator")
    return response.test_script