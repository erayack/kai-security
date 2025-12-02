import os
import tempfile
import uuid
import json
import subprocess
import fcntl
import time
import copy
from pathlib import Path
from typing import Union, Optional, List
from bson import ObjectId

from agent.schemas import GrepResponse, Exploit, ExploitLocation, ExploitSeverity
from agent import settings as agent_settings
from agent.tools.tools import read_file, list_files, grep
from tqdm import tqdm
from logger import logging
from logger.mongo_logger import log_exploit_discovered


def _get_current_agent():
    """
    Get the current agent instance from the global registry.
    This is set during sandboxed code execution.
    """
    try:
        # Try to get from local scope first (passed via execute_sandboxed_code)
        import inspect

        frame = inspect.currentframe()
        while frame:
            if "_agent_instance" in frame.f_locals:
                return frame.f_locals["_agent_instance"]
            frame = frame.f_back
    except:
        pass
    return None


def _clone_exploits(exploits: Optional[List[dict]]) -> List[dict]:
    """Return a deep-copied list of exploit dicts (handles None)."""
    if not exploits:
        return []
    return [copy.deepcopy(e) for e in exploits if isinstance(e, dict)]


def _aggregate_exploit_stats(exploits: List[dict]) -> dict:
    """Summarize exploits by severity."""
    stats: dict[str, int] = {}
    for exploit in exploits:
        severity = exploit.get("severity", "unknown")
        stats[severity] = stats.get(severity, 0) + 1
    return stats


def _collect_child_exploits(sub_reports: Optional[List[dict]]) -> List[dict]:
    """Gather combined exploits from child sub-agent reports."""
    combined: List[dict] = []
    if not sub_reports:
        return combined
    for report in sub_reports:
        child_exploits = report.get("combined_exploits")
        if child_exploits is None:
            child_exploits = report.get("exploits", [])
        combined.extend(_clone_exploits(child_exploits))
    return combined


async def delegate_to_sub_agent(
    scope_path: str,
    task_description: str,
) -> dict:
    """
    Spawn a sub-agent to explore a specific scope and return exploits found.

    This function creates a new FinderAgent instance with restricted scope and limited
    turn budget to explore a specific directory or area of the codebase. The sub-agent
    can recursively spawn its own sub-agents up to the maximum depth limit.

    The sub-agent writes its findings to an exploits.json file in its scope directory,
    which is then read and returned as a dict containing all exploits found.

    Args:
        scope_path: Path to directory or file (relative to repo root) to explore.
                   Example: "programs/store/src/instructions/"
        task_description: Specific task for the sub-agent.
                         Example: "Find all unchecked arithmetic operations"

    Returns:
        A dict with the following structure:
        {
            "exploits": [...],  # List of exploit dicts from exploits.json
            "scope_path": "...",  # The scope that was explored
            "summary": "...",  # Brief summary of what was found
            "sub_agent_id": "..."  # ID of the sub-agent for tracking
        }

    Examples:
        # Delegate exploration of a large directory
        result = delegate_to_sub_agent(
            scope_path="programs/store/src/instructions/",
            task_description="Find access control vulnerabilities"
        )
        # Access exploits: result["exploits"]

        # Focus on specific module
        result = delegate_to_sub_agent(
            scope_path="programs/store/src/states/market/",
            task_description="Analyze state management for race conditions"
        )
        # result["exploits"] contains all vulnerabilities found
    """
    max_turns = agent_settings.MAX_SUBAGENT_TURNS

    # Access parent agent from execution context (injected by engine)
    try:
        parent = _get_current_agent()
        if parent is None:
            return "Error: delegate_to_sub_agent can only be called from within an agent context."
    except (NameError, TypeError):
        return "Error: delegate_to_sub_agent can only be called from within an agent context."

    # Check depth limit
    if not parent.can_spawn_sub_agent():
        return {
            "exploits": [],
            "scope_path": scope_path,
            "summary": f"Error: Maximum recursion depth ({parent.max_depth}) reached. Cannot spawn sub-agent.",
            "sub_agent_id": "none",
            "turns_used": 0,
            "turns_allocated": 0,
            "error": "max_depth_reached",
        }

    # Import FinderAgent here to avoid circular imports
    from agent.agents import FinderAgent

    # Calculate sibling index (how many sub-agents parent has already spawned)
    sibling_index = (
        len(parent.sub_agent_reports) if hasattr(parent, "sub_agent_reports") else 0
    )

    # Create sub-agent with restricted scope and incremented depth
    # Get execution_id from parent (or parent's execution_id if parent is also a sub-agent)
    execution_id = parent.execution_id if parent.execution_id else parent.agent_id

    sub_agent = FinderAgent(
        repo_path=parent.repo_path,
        model=parent.model,
        max_tool_turns=max_turns,
        use_openai=parent.use_openai,
        use_vllm=parent.use_vllm,
        scope_paths=[scope_path],  # Restrict access to this path only
        parent_agent_id=parent.agent_id,  # Track hierarchy
        depth=parent.depth + 1,  # Increment depth
        max_depth=parent.max_depth,  # Propagate limit
        execution_id=execution_id,  # NEW: pass execution_id to sub-agent
    )

    # Use the sub-agent's normalized working_dir for exploits.json path
    # This ensures path consistency after normalization in agent.py
    sub_agent_exploits_path = sub_agent.exploits_path

    # Ensure the scope directory exists
    os.makedirs(os.path.dirname(sub_agent_exploits_path), exist_ok=True)

    # Initialize empty exploits.json for sub-agent
    if not os.path.exists(sub_agent_exploits_path):
        with open(sub_agent_exploits_path, "w") as f:
            json.dump([], f)

    # Track sub-agent for cleanup
    try:
        _created_sub_agents.append(sub_agent)
    except (NameError, AttributeError):
        pass  # _created_sub_agents not available in this context

    # Build short instruction to minimize context
    can_delegate = sub_agent.can_spawn_sub_agent()

    instruction = f"""Focused exploration of: {scope_path}
Task: {task_description}

{'You can delegate to sub-agents for large areas. Sub-agents are encouraged for better coverage!' if can_delegate else 'Max depth reached - direct exploration only.'}

Start exploring and add exploits as you find them using add_exploit(). Use your full turn budget to find as many vulnerabilities as possible.
"""

    # Create conversation directory with ABSOLUTE PATH
    # Need to find project root - go up from repo_path
    project_root = Path(
        parent.repo_path
    ).parent.parent  # Go up from repos/<repo> to project root
    repo_slug = os.path.basename(parent.repo_path) if parent.repo_path else "unknown"
    convo_dir = os.path.join(str(project_root), "output", repo_slug, "sub_agent_convos")
    os.makedirs(convo_dir, exist_ok=True)

    # Notify parent about sub-agent spawn (only at depth 0)
    if parent.depth == 0:
        print(f"\n🔀 Spawning sub-agent for: {scope_path}")

    try:
        await sub_agent.chat(instruction)
    except Exception as e:
        # Save sub-agent's conversation on error for debugging
        error_msg = str(e)

        # Check if this is a context length error
        is_context_error = (
            "context length" in error_msg.lower()
            or "maximum context" in error_msg.lower()
            or "tokens" in error_msg.lower()
            or "400" in error_msg
        )

        # Save the sub-agent's conversation
        sub_agent.save_conversation(
            save_folder=convo_dir,
            prefix=f"error_subagent_depth{sub_agent.depth}_{scope_path.replace('/', '_')}",
        )

        # Provide helpful error message
        error_summary = ""
        if is_context_error:
            error_summary = (
                f"Error: Sub-agent exceeded context limit while exploring {scope_path}. "
                f"The scope may be too large or complex for a single sub-agent. "
                f"Suggestions: Break down {scope_path} into smaller subdirectories, "
                f"explore this area directly with targeted read_file() calls, or "
                f"use grep to find specific patterns before diving deep."
            )
        else:
            error_summary = f"Error: Sub-agent execution failed: {error_msg}"

        # Return error as dict
        return {
            "exploits": [],
            "scope_path": scope_path,
            "summary": error_summary,
            "sub_agent_id": sub_agent.agent_id,
            "turns_used": 0,
            "turns_allocated": max_turns,
            "error": error_msg,
        }
    finally:
        # CRITICAL: Close sub-agent's HTTP client to prevent resource leaks
        # This must happen before we return to avoid accumulating open connections
        try:
            await sub_agent.close()
        except Exception:
            pass  # Ignore errors during cleanup

    # Save sub-agent's conversation after successful completion
    sub_agent.save_conversation(
        save_folder=convo_dir,
        prefix=f"subagent_depth{sub_agent.depth}_{scope_path.replace('/', '_')}",
    )

    # Read the exploits.json from the sub-agent's scope directory
    exploits_found = []
    try:
        if os.path.exists(sub_agent_exploits_path):
            with open(sub_agent_exploits_path, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    exploits_found = data
                elif isinstance(data, dict):
                    exploits_found = [data]
    except Exception:
        exploits_found = []

    # Generate summary
    if exploits_found:
        summary = (
            f"Sub-agent explored {scope_path} and found {len(exploits_found)} exploits."
        )
        severity_counts = {}
        for exploit in exploits_found:
            sev = exploit.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if severity_counts:
            summary += f" Severity breakdown: {', '.join(f'{count} {sev}' for sev, count in severity_counts.items())}."
    else:
        summary = f"Sub-agent explored {scope_path} but found no exploits."

    # Extract result data before deleting sub-agent
    # Determine if this sub-agent has its own sub-agents
    has_sub_agents = len(sub_agent.sub_agent_reports) > 0

    # For time_used, include combined_time_spent if sub-agent has sub-agents,
    # otherwise just time_spent
    time_used_dict = {"time_spent": sub_agent.time_spent}
    if has_sub_agents:
        # Calculate sub-agent total time
        sub_agent_total_time = 0.0
        for sub_report in sub_agent.sub_agent_reports:
            if "time_used" in sub_report:
                sub_agent_total_time += sub_report["time_used"].get(
                    "combined_time_spent",
                    sub_report["time_used"].get("time_spent", 0.0),
                )
        time_used_dict["sub_agent_total_time"] = sub_agent_total_time
        time_used_dict["combined_time_spent"] = (
            sub_agent.time_spent + sub_agent_total_time
        )

    result = {
        "exploits": exploits_found,
        "scope_path": scope_path,
        "summary": summary,
        "sub_agent_id": sub_agent.agent_id,
        "turns_used": sub_agent.max_tool_turns - sub_agent._get_remaining_turns(),
        "turns_allocated": sub_agent.max_tool_turns,
        "budget_used": {
            "total_cost": sub_agent.estimated_cost,
            "tokens": sub_agent.total_tokens,
        },
        "time_used": time_used_dict,
    }

    # Compute combined exploit metadata for hierarchical aggregation
    child_combined_exploits = _collect_child_exploits(sub_agent.sub_agent_reports)
    combined_exploits = _clone_exploits(exploits_found) + child_combined_exploits
    result["combined_exploits"] = combined_exploits
    result["combined_exploit_stats"] = _aggregate_exploit_stats(combined_exploits)

    # Store result in parent's sub_reports list for tracking
    parent.sub_agent_reports.append(result)

    # Force garbage collection to free memory
    # This is important when many sub-agents are spawned
    del sub_agent
    import gc

    gc.collect()

    return result


async def add_exploit(exploit: Exploit) -> str:
    """
    Add an exploit to the exploits.json file.

    Args:
        exploit: The exploit to add.

    Returns:
        A string indicating whether the exploit
        was added successfully or not.
    """
    # Get agent instance to access dynamic exploits path
    try:
        agent = _get_current_agent()
        if agent is None:
            return "Error: add_exploit can only be called from within an agent context."
        exploits_path = agent.exploits_path
    except (NameError, TypeError):
        return "Error: add_exploit can only be called from within an agent context."

    # Inline verification of non-duplicate
    # Only send last 50 exploits to verifier to avoid context length issues
    from agent.model import get_model_response
    from agent.settings import OPENROUTER_GEMINI_FLASH
    from agent.utils import load_system_prompt, extract_decision, AgentType

    # Read existing exploits (limited)
    existing_exploits = []
    try:
        if os.path.exists(exploits_path) and os.path.getsize(exploits_path) > 0:
            with open(exploits_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Only use last 50 exploits for comparison to avoid huge context
                    existing_exploits = data[-50:] if len(data) > 50 else data
    except Exception:
        existing_exploits = []

    exploits_json_string = json.dumps(existing_exploits, indent=2)

    VERIFIER_INSTRUCTION = """
Here is the new exploit:
<exploit>
{exploit}
</exploit>

And here are the most recent exploits from the `exploits.json` file:
<previous_exploits>
{exploits}
</previous_exploits>

Now you can decide whether the exploit is a non-duplicate or not.
"""

    verifier_instruction = VERIFIER_INSTRUCTION.format(
        exploit=exploit.model_dump_json(indent=2), exploits=exploits_json_string
    )
    response, _ = await get_model_response(
        system_prompt=load_system_prompt(AgentType.NON_DUPLICATE_VERIFIER),
        message=verifier_instruction,
        model=OPENROUTER_GEMINI_FLASH,
    )
    is_duplicate = extract_decision(response)

    if is_duplicate:
        return "Exploit is a duplicate"

    exploit_id = exploit.id if exploit.id else str(ObjectId())
    exploit.id = exploit_id

    # Use file locking to prevent concurrent writes from corrupting the file
    lock_path = Path(exploits_path).parent / ".exploits.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    max_retries = 10
    retry_delay = 0.5

    for attempt in range(max_retries):
        try:
            # Create and acquire lock file
            with open(lock_path, "w") as lock_file:
                try:
                    # Try to acquire exclusive lock with timeout
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    else:
                        return (
                            "Error: Could not acquire file lock after multiple retries"
                        )

                try:
                    path = Path(exploits_path)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if not path.exists():
                        path.touch(exist_ok=True)

                    # Read existing exploits
                    try:
                        raw = (
                            path.read_text(encoding="utf-8")
                            if path.stat().st_size
                            else ""
                        )
                        data = json.loads(raw) if raw else []
                        exploits = (
                            data
                            if isinstance(data, list)
                            else [data] if isinstance(data, dict) else []
                        )
                    except Exception:
                        exploits = []

                    # Add timestamp to exploit before saving
                    import datetime

                    exploit_dict = exploit.model_dump()
                    exploit_dict["created_at"] = datetime.datetime.now().isoformat()

                    # Add new exploit
                    new_data = exploits + [exploit_dict]

                    # Write atomically using temp file
                    with tempfile.NamedTemporaryFile(
                        "w", delete=False, dir=str(path.parent), encoding="utf-8"
                    ) as tmp:
                        json.dump(new_data, tmp, indent=2)
                        tmp.flush()
                        os.fsync(tmp.fileno())
                        temp_name = tmp.name
                    os.replace(temp_name, path)

                    # Log the exploit to Loki
                    try:
                        # Get agent ID for filtering and correlation
                        agent_id = agent.agent_id if agent else "unknown"

                        # Get line_end from first location if available
                        line_end = None
                        line_end = exploit.location.line_end

                        log_exploit_discovered(
                            agent_id=agent_id,
                            exploit_id=exploit.id or "unknown",
                            category=exploit.category,
                            severity=exploit.severity.value,
                            file_path=(
                                exploit.location.file_path
                                if exploit.location
                                else "unknown"
                            ),
                            line_start=(
                                exploit.location.line_start if exploit.location else 0
                            ),
                            line_end=line_end,
                            description=exploit.description,
                            class_name=(
                                exploit.location.class_name
                                if exploit.location and exploit.location.class_name
                                else None
                            ),
                            function_name=(
                                exploit.location.function_name
                                if exploit.location and exploit.location.function_name
                                else None
                            ),
                            suggested_fix=exploit.suggested_fix,
                        )
                    except Exception:
                        # Don't fail the operation if logging fails
                        pass

                    # Success - break out of retry loop
                    return "Exploit added successfully"

                finally:
                    # Release lock
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            else:
                return f"Error: {e}"

    return "Error: Failed to add exploit after multiple retries"
