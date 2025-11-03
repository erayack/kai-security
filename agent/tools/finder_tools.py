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
from tqdm import tqdm

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
    max_turns = int((MAX_TOOL_TURNS / 4) * 3)
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
    
    # Build short instruction to minimize context
    can_delegate = sub_agent.can_spawn_sub_agent()
    
    instruction = f"""Focused exploration of: {scope_path}
Task: {task_description}

{'You can delegate to sub-agents for large areas.' if can_delegate else 'Max depth reached - direct exploration only.'}

Start exploring and add exploits as you find them. When done, create a <sub_agent_report>.
"""
    
    # Execute sub-agent with progress indication
    print(f"\n{'  ' * parent.depth}🔀 Spawning sub-agent for: {scope_path}")
    
    # Create conversation directory
    import os
    repo_slug = os.path.basename(parent.repo_path) if parent.repo_path else "unknown"
    convo_dir = os.path.join("output", repo_slug, "sub_agent_convos")
    os.makedirs(convo_dir, exist_ok=True)
    
    try:
        sub_agent.chat(instruction)
    except Exception as e:
        # Save sub-agent's conversation on error for debugging
        error_msg = str(e)
        
        # Check if this is a context length error
        is_context_error = (
            "context length" in error_msg.lower() or 
            "maximum context" in error_msg.lower() or 
            "tokens" in error_msg.lower() or
            "400" in error_msg
        )
        
        # Save the sub-agent's conversation
        sub_agent.save_conversation(
            save_folder=convo_dir,
            prefix=f"error_subagent_depth{sub_agent.depth}_{scope_path.replace('/', '_')}"
        )
        
        print(f"{'  ' * parent.depth}❌ Sub-agent failed: {error_msg}")
        print(f"{'  ' * parent.depth}   Conversation saved to: {convo_dir}")
        
        # Provide helpful error message
        if is_context_error:
            return (
                f"Error: Sub-agent exceeded context limit while exploring {scope_path}.\n"
                f"The scope may be too large or complex for a single sub-agent.\n"
                f"Suggestions:\n"
                f"1. Break down {scope_path} into smaller subdirectories\n"
                f"2. Explore this area directly with targeted read_file() calls\n"
                f"3. Use grep to find specific patterns before diving deep\n"
                f"Conversation saved for debugging."
            )
        else:
            return f"Error: Sub-agent execution failed: {error_msg}\nConversation saved for debugging."
    
    # Save sub-agent's conversation after successful completion
    sub_agent.save_conversation(
        save_folder=convo_dir,
        prefix=f"subagent_depth{sub_agent.depth}_{scope_path.replace('/', '_')}"
    )
    print(f"{'  ' * parent.depth}💾 Sub-agent conversation saved to: {convo_dir}")
    
    # Generate structured report
    try:
        report = sub_agent.generate_report()
    except Exception as e:
        # If report generation fails, create a minimal report
        print(f"{'  ' * parent.depth}⚠️  Report generation failed: {e}")
        from agent.schemas import SubAgentReport
        report = SubAgentReport(
            agent_id=sub_agent.agent_id,
            parent_agent_id=parent.agent_id,
            depth=sub_agent.depth,
            scope_path=scope_path,
            task_description=task_description,
            turns_used=sub_agent.max_tool_turns - sub_agent._get_remaining_turns(),
            turns_allocated=sub_agent.max_tool_turns,
            summary=f"Sub-agent encountered an error and could not complete exploration: {str(e)}",
            exploration_complete=False,
            requires_followup=True
        )
    
    # Store report in parent's sub_reports list
    parent.sub_agent_reports.append(report)
    
    print(f"{'  ' * parent.depth}✓ Sub-agent completed: {len(report.exploits_found)} exploits found\n")
    
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

