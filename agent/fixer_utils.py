"""
Utility functions for fixer orchestration.

These functions are used for batch processing and fixing exploits.json files.
"""

import os
import json
import asyncio
import datetime
from typing import List
from pathlib import Path
from agent.settings import MAX_SUBAGENT_TURNS, MAX_DEPTH
from logger.mongo_logger import log_exploit_fixed
from agent import settings as agent_settings


async def process_fix_exploits(
    exploits_path: str,
    repo_path: str,
    model: str,
    use_openai: bool = False,
    use_vllm: bool = False,
    execution_id: str = None,
) -> dict:
    """
    Fix all exploits in an exploits.json file by spawning fixer sub-agents.

    This function iterates over each exploit in the given exploits.json file and spawns
    a depth=MAX_DEPTH sub-agent to fix the exploit.

    Args:
        exploits_path: Absolute path to the exploits.json file to fix.
        repo_path: Absolute path to the repository root.
        model: Model name to use for fixer agents.
        use_openai: Whether to use OpenAI API (default False).
        use_vllm: Whether to use vLLM (default False).

    Returns:
        A dictionary with fix results.
    """
    try:
        if not os.path.exists(exploits_path):
            return {
                "error": f"File not found: {exploits_path}",
                "exploits_file": exploits_path,
                "total_exploits": 0,
                "fixed_exploits": 0,
                "failed_exploits": 0,
                "success_rate": 0.0,
                "details": [],
                "total_cost": 0.0,
                "total_time": 0.0,
                "saved_convo_paths": [],
            }

        # Load exploits
        with open(exploits_path, "r") as f:
            exploits = json.load(f)

        total_exploits = len(exploits)
        fixed_count = 0
        failed_count = 0
        details = []
        total_cost = 0.0
        total_time = 0.0
        saved_convo_paths = []  # Track all saved conversation paths

        # Import dependencies
        from agent.agents import FixerAgent

        # Setup save directory - save to repo_path like generator
        repo_slug = os.path.basename(repo_path) if repo_path else "unknown"

        # Helper function to fix a single exploit
        async def fix_single_exploit(exploit):
            """Fix a single exploit by spawning a sub-agent."""
            exploit_id = exploit.get("id", "unknown")
            category = exploit.get("category", "unknown")
            severity = exploit.get("severity", "unknown")

            # Create a depth=MAX_DEPTH sub-agent to fix this single exploit
            # This ensures it cannot spawn more sub-agents
            sub_agent = FixerAgent(
                repo_path=repo_path,
                model=model,
                max_tool_turns=agent_settings.MAX_SUBAGENT_TURNS,
                use_openai=use_openai,
                use_vllm=use_vllm,
                scope_paths=None,  # No scope restriction
                parent_agent_id=None,  # No parent (this is orchestration level)
                depth=MAX_DEPTH,  # Set to max_depth so it can't spawn more
                max_depth=MAX_DEPTH,
                execution_id=execution_id,  # Pass execution_id for logging
            )

            # Construct task message for single exploit fix
            exploit_json = json.dumps(exploit, indent=2)
            task_message = f"""
Here is the exploit:
<exploit>
{exploit_json}
</exploit>

Start exploring the codebase and fix the exploit.
"""

            # Run sub-agent fix
            exception_occurred = False
            suggested_fix = None

            try:
                response = await sub_agent.chat(task_message)
                suggested_fix = response.suggest_fix

            except Exception as e:
                exception_occurred = True
            finally:
                # Determine prefix based on outcome
                prefix = f"fix_exploit_{exploit_id}"
                if exception_occurred:
                    prefix = f"error_fix_exploit_{exploit_id}"

                # Add validation metadata to sub_agent before saving (reusing validation_result field for consistency)
                sub_agent.validation_result = {
                    "fixed": bool(suggested_fix) and not exception_occurred,
                    "exploit_id": exploit_id,
                    "exception_occurred": exception_occurred,
                    "suggested_fix": suggested_fix,
                }

                convo_path = sub_agent.save_conversation(
                    save_folder=repo_path, prefix=prefix
                )
                saved_convo_paths.append(
                    {"agent_id": sub_agent.agent_id, "convo_path": convo_path}
                )

                # Extract cost and time
                agent_cost = sub_agent.estimated_cost
                agent_time = sub_agent.time_spent

                # Close sub-agent
                try:
                    await sub_agent.close()
                except Exception:
                    pass

            return {
                "exploit_id": exploit_id,
                "category": category,
                "severity": severity,
                "fixed": bool(suggested_fix) and not exception_occurred,
                "exception_occurred": exception_occurred,
                "suggested_fix": suggested_fix,
                "sub_agent_id": sub_agent.agent_id,
                "cost": agent_cost,
                "time": agent_time,
                "convo_path": convo_path if "convo_path" in locals() else None,
            }

        # Process exploits in parallel
        tasks = [fix_single_exploit(exploit) for exploit in exploits]

        # Process tasks as they complete
        for coro in asyncio.as_completed(tasks):
            result = await coro

            exploit_id = result["exploit_id"]
            category = result["category"]
            severity = result["severity"]
            fixed = result["fixed"]
            exception_occurred = result["exception_occurred"]
            suggested_fix = result["suggested_fix"]

            # Accumulate costs and time
            total_cost += result.get("cost", 0.0)
            total_time += result.get("time", 0.0)

            # Update statistics and details
            if fixed:
                fixed_count += 1
                details.append(
                    {
                        "exploit_id": exploit_id,
                        "category": category,
                        "severity": severity,
                        "status": "fixed",
                        "sub_agent_id": result["sub_agent_id"],
                        "fixed_at": datetime.datetime.now().isoformat(),
                    }
                )

                # Save suggested fix to suggested_fixes.json
                _save_suggested_fix(repo_path, exploit_id, suggested_fix)

                # Log exploit fix to MongoDB
                # Clean the suggested_fix_snippet by removing diff header (--- and +++ lines)
                cleaned_snippet = _clean_diff_header(suggested_fix)

                log_exploit_fixed(
                    exploit_id=exploit_id,
                    fixed_by_agent_id=result["sub_agent_id"],
                    suggested_fix_snippet=cleaned_snippet,
                )

            else:
                failed_count += 1
                details.append(
                    {
                        "exploit_id": exploit_id,
                        "category": category,
                        "severity": severity,
                        "status": "failed",
                        "reason": (
                            "exception" if exception_occurred else "no_fix_suggested"
                        ),
                        "sub_agent_id": result["sub_agent_id"],
                        "fixed_at": datetime.datetime.now().isoformat(),
                    }
                )

        return {
            "exploits_file": exploits_path,
            "total_exploits": total_exploits,
            "fixed_exploits": fixed_count,
            "failed_exploits": failed_count,
            "success_rate": fixed_count / total_exploits if total_exploits > 0 else 0.0,
            "details": details,
            "total_cost": total_cost,
            "total_time": total_time,
            "saved_convo_paths": saved_convo_paths,
        }
    except Exception as e:
        import traceback

        return {
            "error": str(e),
            "traceback": traceback.format_exc(),
            "exploits_file": exploits_path,
            "total_exploits": 0,
            "fixed_exploits": 0,
            "failed_exploits": 0,
            "success_rate": 0.0,
            "details": [],
            "total_cost": 0.0,
            "total_time": 0.0,
            "saved_convo_paths": [],
        }


def _clean_diff_header(suggested_fix: str) -> str:
    """
    Clean diff header from suggested fix snippet.
    Removes:
    - Code fence markers (```diff and ```)
    - Diff header lines (---, +++, index)

    Args:
        suggested_fix: The raw suggested fix with potential diff headers

    Returns:
        Cleaned suggested fix without diff headers and code fences
    """
    if not suggested_fix:
        return suggested_fix

    lines = suggested_fix.split("\n")
    cleaned_lines = []

    for line in lines:
        stripped = line.strip()
        # Skip code fence markers
        if stripped == "```diff" or stripped == "```":
            continue
        # Skip diff header lines (---, +++, and index lines)
        if (
            line.startswith("---")
            or line.startswith("+++")
            or line.startswith("index ")
        ):
            continue
        cleaned_lines.append(line)

    return "\n".join(cleaned_lines).strip()


def _save_suggested_fix(repo_path: str, exploit_id: str, suggested_fix: str):
    """
    Internal helper to save a suggested fix to suggested_fixes.json.
    """
    try:
        fixes_path = os.path.join(repo_path, "suggested_fixes.json")

        # Load existing fixes
        if os.path.exists(fixes_path):
            with open(fixes_path, "r") as f:
                try:
                    suggested_fixes = json.load(f)
                except json.JSONDecodeError:
                    suggested_fixes = []
        else:
            suggested_fixes = []

        # Append new fix
        suggested_fixes.append({exploit_id: suggested_fix})

        # Save back
        with open(fixes_path, "w") as f:
            json.dump(suggested_fixes, f, indent=2)

    except Exception:
        pass  # Ignore errors during saving
