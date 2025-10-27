import os
import tempfile
import uuid
import json
import subprocess
from pathlib import Path
from typing import Union, Optional, List

from agent.schemas import GrepResponse, Exploit, ExploitLocation, ExploitSeverity
from agent.settings import EXPLOITS_PATH
from agent.tools.tools import read_file, list_files, grep

def add_exploit(exploit: Exploit) -> str:
    """
    Add an exploit to the exploits.json file.

    Args:
        exploit: The exploit to add.

    Returns:
        A string indicating whether the exploit 
        was added successfully or not.
    """
    # Inline verification of non-duplicate
    exploits_json_string = read_file(EXPLOITS_PATH)
    
    from agent.model import get_model_response
    from agent.settings import OPENROUTER_GEMINI_FLASH
    from agent.utils import load_system_prompt, extract_decision, AgentType
    
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
    
    verifier_instruction = VERIFIER_INSTRUCTION.format(exploit=exploit, exploits=exploits_json_string)
    response = get_model_response(
        system_prompt=load_system_prompt(AgentType.NON_DUPLICATE_VERIFIER),
        message=verifier_instruction,
        model=OPENROUTER_GEMINI_FLASH
    )
    is_duplicate = extract_decision(response)
    
    if is_duplicate:
        return "Exploit is a duplicate"
    
    # Generate a short ID for the exploit if it doesn't have one
    exploit_id = exploit.id if exploit.id else str(uuid.uuid4())[:6]
    exploit.id = exploit_id

    try:
        path = Path(EXPLOITS_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.touch(exist_ok=True)

        try:
            raw = path.read_text(encoding="utf-8") if path.stat().st_size else ""
            data = json.loads(raw) if raw else []
            exploits = (
                data if isinstance(data, list)
                else [data] if isinstance(data, dict)
                else []
            )
        except Exception:
            exploits = []

        new_data = exploits + [exploit.model_dump()]
        with tempfile.NamedTemporaryFile("w", delete=False, dir=str(path.parent), encoding="utf-8") as tmp:
            json.dump(new_data, tmp, indent=2)
            tmp.flush()
            os.fsync(tmp.fileno())
            temp_name = tmp.name
        os.replace(temp_name, path)
    except Exception as e:
        return f"Error: {e}"
    return "Exploit added successfully"

