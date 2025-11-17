"""
Utility functions for generator orchestration.

These functions are used for batch processing and validating exploits.json files.
They are NOT exposed to validation agents - only used by the orchestration layer.
"""

import os
import json
import datetime
from typing import List
from pathlib import Path
from tqdm.asyncio import tqdm as tqdm_asyncio
from agent.settings import MAX_SUBAGENT_TURNS, MAX_DEPTH


def get_exploits_jsons(repo_path: str) -> List[str]:
    """
    Recursively find all exploits.json files in a repository.
    
    This function traverses the directory tree starting from the repository root
    and returns a list of absolute paths to all exploits.json files found.
    
    Args:
        repo_path: The repository root path (absolute path).
    
    Returns:
        A list of absolute paths to all exploits.json files found.
        Returns an empty list if no files are found or if the path doesn't exist.
        
    Examples:
        # Find all exploits.json in repo
        files = get_exploits_jsons("/path/to/repo")
    """
    try:
        if not os.path.exists(repo_path):
            return []
        
        exploits_files = []
        for root, dirs, files in os.walk(repo_path):
            if "exploits.json" in files:
                exploits_files.append(os.path.join(root, "exploits.json"))
        
        return exploits_files
    except Exception:
        return []


async def process_exploits_json(
    exploits_path: str,
    repo_path: str,
    model: str,
    use_openai: bool = False,
    use_vllm: bool = False
) -> dict:
    """
    Validate all exploits in an exploits.json file by spawning validation sub-agents.
    
    This function iterates over each exploit in the given exploits.json file and spawns
    a depth=MAX_DEPTH sub-agent to generate and validate a test script for the exploit. 
    If the sub-agent cannot produce a passing test, the exploit is removed from the file.
    
    IMPORTANT: This validates existing exploits, it does NOT find new ones.
    
    Args:
        exploits_path: Absolute path to the exploits.json file to validate.
        repo_path: Absolute path to the repository root.
        model: Model name to use for validation agents.
        use_openai: Whether to use OpenAI API (default False).
        use_vllm: Whether to use vLLM (default False).
    
    Returns:
        A dictionary with validation results:
        {
            "exploits_file": str,
            "total_exploits": int,
            "verified_exploits": int,
            "removed_exploits": int,
            "success_rate": float,
            "details": list[dict],
            "exploit_stats": dict,  # Severity-based stats with verified/unverified
            "total_cost": float,  # Total cost from all validation agents
            "total_time": float   # Total time spent
        }
        
    Examples:
        # Validate exploits in a file
        result = await process_exploits_json(
            "/path/to/repo/exploits.json",
            "/path/to/repo",
            "gpt-4",
            use_openai=True
        )
        print(f"Verified {result['verified_exploits']}/{result['total_exploits']} exploits")
    """
    try:
        if not os.path.exists(exploits_path):
            return {
                "error": f"File not found: {exploits_path}",
                "exploits_file": exploits_path,
                "total_exploits": 0,
                "verified_exploits": 0,
                "removed_exploits": 0,
                "success_rate": 0.0,
                "details": [],
                "exploit_stats": {},
                "total_cost": 0.0,
                "total_time": 0.0
            }
        
        # Load exploits
        with open(exploits_path, 'r') as f:
            exploits = json.load(f)
        
        total_exploits = len(exploits)
        verified_count = 0
        removed_count = 0
        details = []
        exploit_stats_by_severity = {}
        total_cost = 0.0
        total_time = 0.0
        
        # Import dependencies
        from agent.agents import GeneratorAgent
        
        # Setup save directory for per-exploit validation conversations
        project_root = Path(repo_path).parent.parent
        repo_slug = os.path.basename(repo_path) if repo_path else "unknown"
        save_folder = os.path.join(str(project_root), "output", repo_slug, "exploit_validation_convos")
        os.makedirs(save_folder, exist_ok=True)
        
        # Helper function to validate a single exploit
        async def validate_single_exploit(exploit):
            """Validate a single exploit by spawning a sub-agent."""
            exploit_id = exploit.get('id', 'unknown')
            category = exploit.get('category', 'unknown')
            severity = exploit.get('severity', 'unknown')
            
            # Create a depth=MAX_DEPTH sub-agent to validate this single exploit
            # This ensures it cannot spawn more sub-agents
            sub_agent = GeneratorAgent(
                repo_path=repo_path,
                model=model,
                max_tool_turns=MAX_SUBAGENT_TURNS,
                use_openai=use_openai,
                use_vllm=use_vllm,
                scope_paths=None,  # No scope restriction
                parent_agent_id=None,  # No parent (this is orchestration level)
                depth=MAX_DEPTH,  # Set to max_depth so it can't spawn more
                max_depth=MAX_DEPTH
            )
            
            # Construct task message for single exploit validation
            exploit_json = json.dumps(exploit, indent=2)
            task_message = f"""
You are validating a SINGLE exploit by creating a test that demonstrates it exists.

Exploit to validate:
{exploit_json}

Your task:
1. Understand the vulnerability described
2. Locate the vulnerable code files
3. Determine the project type (Solidity/Rust/Anchor)
4. Create a test file that PASSES if the exploit exists
5. Run the test (forge_test/cargo_test/anchor_test)
6. Complete with your verdict:
   - If test passes → <done>True</done> (exploit is validated)
   - If test fails or cannot be created → <done>False</done> (exploit cannot be validated)

CRITICAL: The test should PASS (return 0) if the vulnerability exists.
Finish with <done>True</done> if validated, or <done>False</done> if not.
"""
            
            # Run sub-agent validation
            exception_occurred = False
            test_passed = False
            completed_properly = False
            
            try:
                response = await sub_agent.chat(task_message)
                
                # Check the LAST assistant message for <done> tag and extract verdict
                from agent.schemas import Role
                import re
                
                for msg in reversed(sub_agent.messages):
                    try:
                        role = msg.get('role') if isinstance(msg, dict) else getattr(msg, 'role', None)
                        content = msg.get('content', '') if isinstance(msg, dict) else getattr(msg, 'content', '')
                    except:
                        continue
                    
                    if role == Role.ASSISTANT or role == 'assistant':
                        # Check if there's a <done> tag
                        if '<done>' in content and '</done>' in content:
                            completed_properly = True
                            
                            # Extract content inside <done> tags
                            done_match = re.search(r'<done>\s*(.*?)\s*</done>', content, re.IGNORECASE | re.DOTALL)
                            if done_match:
                                done_content = done_match.group(1).strip()
                                # Only check for explicit True/False verdict
                                if done_content.lower() == 'true':
                                    test_passed = True
                                elif done_content.lower() == 'false':
                                    test_passed = False
                                # If anything else or empty, test_passed remains False
                        break
                
            except Exception as e:
                exception_occurred = True
            finally:
                # Determine prefix based on outcome
                prefix = f"exploit_{exploit_id}"
                if exception_occurred:
                    prefix = f"error_exploit_{exploit_id}"
                elif test_passed:
                    prefix = f"verified_exploit_{exploit_id}"
                else:
                    prefix = f"failed_exploit_{exploit_id}"
                
                # Add validation metadata to sub_agent before saving
                sub_agent.validation_result = {
                    "verified": test_passed and not exception_occurred,
                    "exploit_id": exploit_id,
                    "test_passed": test_passed,
                    "exception_occurred": exception_occurred
                }
                
                sub_agent.save_conversation(save_folder=save_folder, prefix=prefix)
                
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
                "test_passed": test_passed,
                "exception_occurred": exception_occurred,
                "sub_agent_id": sub_agent.agent_id,
                "cost": agent_cost,
                "time": agent_time
            }
        
        # Process exploits in parallel with progress bar
        tasks = [validate_single_exploit(exploit) for exploit in exploits]
        
        # Use tqdm to show progress as exploits complete
        for coro in tqdm_asyncio.as_completed(tasks, desc=f"Validating {os.path.basename(os.path.dirname(exploits_path))}", total=len(tasks)):
            result = await coro
            
            exploit_id = result["exploit_id"]
            category = result["category"]
            severity = result["severity"]
            test_passed = result["test_passed"]
            exception_occurred = result["exception_occurred"]
            
            # Accumulate costs and time
            total_cost += result.get("cost", 0.0)
            total_time += result.get("time", 0.0)
            
            # Initialize severity stats if needed
            if severity not in exploit_stats_by_severity:
                exploit_stats_by_severity[severity] = {"verified": 0, "unverified": 0}
        
            # Update statistics and details
            if test_passed and not exception_occurred:
                verified_count += 1
                exploit_stats_by_severity[severity]["verified"] += 1
                details.append({
                    "exploit_id": exploit_id,
                    "category": category,
                    "severity": severity,
                    "status": "verified",
                    "sub_agent_id": result["sub_agent_id"],
                    "validated_at": datetime.datetime.now().isoformat()
                })
            else:
                # Remove failed exploit
                removed_count += 1
                exploit_stats_by_severity[severity]["unverified"] += 1
                details.append({
                    "exploit_id": exploit_id,
                    "category": category,
                    "severity": severity,
                    "status": "removed",
                    "reason": "exception" if exception_occurred else "test_failed",
                    "sub_agent_id": result["sub_agent_id"],
                    "validated_at": datetime.datetime.now().isoformat()
                })
                
                # Remove from exploits.json
                _remove_exploit_from_file(exploits_path, exploit_id)
        
        # Reload to get the updated list after removals
        with open(exploits_path, 'r') as f:
            verified_exploits_final = json.load(f)
        
        return {
            "exploits_file": exploits_path,
            "total_exploits": total_exploits,
            "verified_exploits": verified_count,
            "removed_exploits": removed_count,
            "success_rate": verified_count / total_exploits if total_exploits > 0 else 0.0,
            "details": details,
            "exploit_stats": exploit_stats_by_severity,
            "total_cost": total_cost,
            "total_time": total_time
        }
    except Exception as e:
        import traceback
        return {
            "error": str(e),
            "traceback": traceback.format_exc(),
            "exploits_file": exploits_path,
            "total_exploits": 0,
            "verified_exploits": 0,
            "removed_exploits": 0,
            "success_rate": 0.0,
            "details": [],
            "exploit_stats": {},
            "total_cost": 0.0,
            "total_time": 0.0
        }


def _remove_exploit_from_file(exploits_path: str, exploit_id: str) -> dict:
    """
    Internal helper to remove an exploit from an exploits.json file by its ID.
    
    Args:
        exploits_path: Absolute path to the exploits.json file.
        exploit_id: The ID of the exploit to remove.
    
    Returns:
        A dictionary with removal status.
    """
    try:
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

