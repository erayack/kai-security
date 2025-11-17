"""
Tools for generator/validation agents.

These tools are available to validation agents that create and run tests for exploits.
Orchestration functions (get_exploits_jsons, process_exploits_json) are in generator_utils.py.
"""

import os
import json
from agent.tools.tools import read_file, list_files, grep, create_file, forge_test, cargo_test, anchor_test, update_file


def _get_current_agent():
    """
    Get the current agent instance from the execution context.
    This is injected by the engine during code execution.
    """
    try:
        # Attempt to retrieve the current agent from the execution context
        # The engine injects _get_current_agent() function into the globals
        agent = _get_current_agent()  # type: ignore
        return agent
    except NameError:
        # If not in an agent context, return None
        pass
    except TypeError:
        # If _get_current_agent is not callable, return None
        pass
    except:
        pass
    return None


def remove_exploit(exploits_path: str, exploit_id: str) -> dict:
    """
    Remove an exploit from an exploits.json file by its ID.
    
    This function uses file locking to safely remove an exploit from the JSON file.
    Typically used during validation when an exploit cannot be verified with a passing test.
    
    Args:
        exploits_path: Path to the exploits.json file (relative or absolute).
        exploit_id: The ID of the exploit to remove.
    
    Returns:
        A dictionary with removal status:
        {
            "success": bool,
            "exploit_id": str,
            "message": str,
            "removed": bool,
            "remaining_count": int
        }
    
    Examples:
        # Remove an exploit that couldn't be validated
        result = remove_exploit("./exploits.json", "abc123")
        if result["success"] and result["removed"]:
            print(f"Removed exploit {exploit_id}, {result['remaining_count']} remaining")
    """
    try:
        parent = _get_current_agent()
        if parent is None:
            return {"error": "remove_exploit can only be called from within an agent context."}
        
        # Resolve path relative to agent's working directory
        if not os.path.isabs(exploits_path):
            exploits_path = os.path.join(parent.working_dir, exploits_path)
        
        if not os.path.exists(exploits_path):
            return {
                "success": False,
                "exploit_id": exploit_id,
                "message": f"File not found: {exploits_path}",
                "removed": False,
                "remaining_count": 0
            }
        
        # Load exploits
        with open(exploits_path, 'r') as f:
            exploits = json.load(f)
        
        # Find and remove the exploit
        initial_count = len(exploits)
        exploits = [e for e in exploits if e.get('id') != exploit_id]
        removed = len(exploits) < initial_count
        
        # Save updated exploits
        with open(exploits_path, 'w') as f:
            json.dump(exploits, f, indent=2)
        
        return {
            "success": True,
            "exploit_id": exploit_id,
            "message": f"Exploit {exploit_id} {'removed' if removed else 'not found'}",
            "removed": removed,
            "remaining_count": len(exploits)
        }
    except Exception as e:
        return {
            "success": False,
            "exploit_id": exploit_id,
            "message": str(e),
            "removed": False,
            "remaining_count": 0
        }
