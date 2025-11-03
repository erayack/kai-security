import os
import tempfile
import uuid
import json
import subprocess
from pathlib import Path
from typing import Union, Optional, List

from agent.schemas import GrepResponse, Exploit, ExploitLocation, ExploitSeverity, report_to_string
from agent.settings import EXPLOITS_PATH, MAX_TOOL_TURNS
from agent.tools.tools import read_file, list_files, grep

def delegate_to_sub_agent(
    scope_path: str,
    task_description: str,
) -> str:
    """
    Spawn a sub-agent to explore a specific scope and return a structured report.
    
    This function creates a new FinderAgent instance with restricted scope and limited
    turn budget to explore a specific directory or area of the codebase. The sub-agent
    can recursively spawn its own sub-agents up to the maximum depth limit.
    
    Args:
        scope_path: Path to directory or file (relative to repo root) to explore.
                   Example: "programs/store/src/instructions/"
        task_description: Specific task for the sub-agent.
                         Example: "Find all unchecked arithmetic operations"
        
    Returns:
        A formatted string representation of the SubAgentReport containing:
        - Files explored and exploits found
        - Code references for follow-up investigation
        - Summary of findings
        - Nested sub-reports if the sub-agent delegated further
        
    Examples:
        # Delegate exploration of a large directory
        report = delegate_to_sub_agent(
            scope_path="programs/store/src/instructions/",
            task_description="Find access control vulnerabilities"
        )
        
        # Focus on specific module
        report = delegate_to_sub_agent(
            scope_path="programs/store/src/states/market/",
            task_description="Analyze state management for race conditions"
        )
    """
    max_turns = MAX_TOOL_TURNS / 2
    # Access parent agent from execution context (injected by engine)
    try:
        parent = _get_current_agent()
        if parent is None:
            return "Error: delegate_to_sub_agent can only be called from within an agent context."
    except (NameError, TypeError):
        return "Error: delegate_to_sub_agent can only be called from within an agent context."
    
    # Check depth limit
    if not parent.can_spawn_sub_agent():
        return f"Error: Maximum recursion depth ({parent.max_depth}) reached. Cannot spawn sub-agent."
    
    # Import FinderAgent here to avoid circular imports
    from agent.agents import FinderAgent
    
    # Create sub-agent with restricted scope and incremented depth
    sub_agent = FinderAgent(
        repo_path=parent.repo_path,
        model=parent.model,
        max_tool_turns=max_turns,
        use_openai=parent.use_openai,
        use_vllm=parent.use_vllm,
        scope_paths=[scope_path],        # Restrict access to this path only
        parent_agent_id=parent.agent_id, # Track hierarchy
        depth=parent.depth + 1,          # Increment depth
        max_depth=parent.max_depth       # Propagate limit
    )
    
    # Build instruction based on depth and capability
    instruction = f"""You are a SUB-AGENT working on a focused exploration task.

Your scope is limited to: {scope_path}
Task: {task_description}
Depth: {sub_agent.depth} (max depth: {parent.max_depth})
Turn budget: {max_turns} turns

IMPORTANT: You are using the same tools and prompt as the main FinderAgent, but with restricted scope.
"""
    
    if sub_agent.can_spawn_sub_agent():
        instruction += """
You CAN delegate to further sub-agents if needed:
- Large subdirectories (>10 files) requiring focused analysis
- Complex modules that need deeper investigation  
- Large files (>500 lines) that need section-by-section review

Use delegate_to_sub_agent() strategically to partition work.
"""
    else:
        instruction += """
You are at MAXIMUM DEPTH and CANNOT spawn further sub-agents.
Focus on thorough direct exploration of your assigned scope.
"""
    
    instruction += """
Explore this area and find exploits. Add them using add_exploit() as you discover them.

When you complete your exploration, you MUST produce a <sub_agent_report> tag with your findings summary.
This will signal completion and return control to the parent agent.

Start your search now.
"""
    
    # Execute sub-agent
    try:
        sub_agent.chat(instruction)
    except Exception as e:
        return f"Error: Sub-agent execution failed: {str(e)}"
    
    # Generate structured report
    report = sub_agent.generate_report()
    
    # Store report in parent's sub_reports list
    parent.sub_agent_reports.append(report)
    
    # Convert to formatted string for parent's context
    return report_to_string(report)


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
    
    verifier_instruction = VERIFIER_INSTRUCTION.format(exploit=exploit.model_dump_json(indent=2), exploits=exploits_json_string)
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

