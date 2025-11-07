from agent.engine import execute_sandboxed_code
from agent.model import get_model_response, create_openai_client, create_vllm_client, get_model_pricing
from agent.utils import (
    load_system_prompt,
    extract_python_code,
    format_results_and_remaining_turns,
    extract_thoughts,
    AgentType,
)
from agent.settings import (
    SAVE_CONVERSATION_PATH,
    MAX_TOOL_TURNS,
    VLLM_HOST,
    VLLM_PORT,
    OPENROUTER_STRONG_MODEL,
    OPENAI_STRONG_MODEL,
    MAX_DEPTH,
)
from agent.schemas import ChatMessage, Role, AgentResponse
from tqdm import tqdm
import asyncio

from typing import Union, Tuple, Optional, Dict
from abc import ABC, abstractmethod

import json
import os
import uuid


class BaseAgent(ABC):
    """Abstract base class for all agents."""
    
    def __init__(
        self,
        max_tool_turns: int = MAX_TOOL_TURNS,
        repo_path: str = None,
        use_vllm: bool = False,
        model: str = None,
        agent_type: AgentType = None,
        use_openai: bool = False,
        scope_paths: list[str] = None,  # NEW: Restrict file access to these paths
        parent_agent_id: str = None,    # NEW: Track hierarchy
        depth: int = 0,                  # NEW: Depth in hierarchy
        max_depth: int = MAX_DEPTH,              # NEW: Maximum recursion depth
    ):
        self.agent_type = agent_type
        
        # Agent identification and hierarchy (NEW)
        self.agent_id = str(uuid.uuid4())
        self.parent_agent_id = parent_agent_id
        self.depth = depth
        self.max_depth = max_depth
        
        # Scope restriction (NEW)
        self.scope_paths = scope_paths
        self.repo_path = os.path.abspath(repo_path) if repo_path else None
        
        if scope_paths:
            self.restricted_scope = True
            # Convert scope paths to absolute paths
            self.allowed_paths = []
            for p in scope_paths:
                # If path is already absolute and within repo_path, use it as-is
                if os.path.isabs(p):
                    abs_p = os.path.abspath(p)
                    if abs_p.startswith(self.repo_path):
                        self.allowed_paths.append(abs_p)
                    else:
                        # Absolute path outside repo - shouldn't happen but handle it
                        self.allowed_paths.append(abs_p)
                else:
                    # Relative path - join with repo_path
                    # Remove any leading repo directory names to avoid duplication
                    # e.g. if p is "repos/xxx/programs/store/" and repo_path ends with "repos/xxx"
                    clean_p = p
                    repo_name = os.path.basename(self.repo_path)
                    if clean_p.startswith('repos/'):
                        # Strip everything up to and including the repo name
                        parts = clean_p.split('/')
                        if repo_name in parts:
                            idx = parts.index(repo_name)
                            clean_p = '/'.join(parts[idx+1:])
                    self.allowed_paths.append(os.path.abspath(os.path.join(self.repo_path, clean_p)))
            # For sub-agents with single scope, use that as working directory
            # This allows tools to work with relative paths naturally
            if len(scope_paths) == 1:
                self.working_dir = self.allowed_paths[0]
            else:
                self.working_dir = self.repo_path
        else:
            self.restricted_scope = False
            self.allowed_paths = []
            self.working_dir = self.repo_path
        
        # Track sub-agents spawned by this agent (NEW)
        self.sub_agent_reports: list = []  # Will hold SubAgentReport objects
        
        # Set exploits.json path based on working directory (dynamic per agent)
        self.exploits_path = os.path.join(self.working_dir, "exploits.json")
        
        # Load the system prompt and add it to the conversation history
        # Use condensed prompt for sub-agents
        is_sub_agent = depth > 0
        scope_path_str = scope_paths[0] if scope_paths else ""
        self.system_prompt = load_system_prompt(
            agent_type, 
            is_sub_agent=is_sub_agent,
            scope_path=scope_path_str,
            task_description="",  # Will be set in delegation instruction
            max_turns=max_tool_turns,
            depth=depth,
            max_depth=max_depth
        )
        self.messages: list[ChatMessage] = [
            ChatMessage(role=Role.SYSTEM, content=self.system_prompt)
        ]

        # Set the maximum number of tool turns and use_vllm flag
        self.max_tool_turns = max_tool_turns
        self.use_vllm = use_vllm
        self.use_openai = use_openai
        
        # Budget tracking
        self.total_tokens = {"prompt_tokens": 0, "completion_tokens": 0}
        self.estimated_cost = 0.0
        
        # Time tracking
        self.time_spent = 0.0  # Time spent by this agent only (seconds)
        self.start_time = None  # Will be set when chat() starts

        # Set model: use provided model, or fallback to OPENROUTER_STRONG_MODEL
        if model:
            self.model = model
        else:
            if use_openai:
                self.model = OPENAI_STRONG_MODEL
            else:   
                self.model = OPENROUTER_STRONG_MODEL

        # Each Agent instance gets its own clients to avoid bottlenecks
        if use_vllm:
            self._client = create_vllm_client(host=VLLM_HOST, port=VLLM_PORT)
        else:
            self._client = create_openai_client(use_openai=use_openai)

    def can_spawn_sub_agent(self) -> bool:
        """Check if this agent can spawn sub-agents based on depth."""
        return self.depth < self.max_depth
    
    def calculate_cost(self, usage_data: Dict[str, int]) -> float:
        """
        Calculate cost from usage data using dynamic pricing.
        
        Args:
            usage_data: Dict with prompt_tokens and completion_tokens
            
        Returns:
            Cost in dollars
        """
        pricing = get_model_pricing(self.model, self.use_openai)
        prompt_cost = usage_data.get("prompt_tokens", 0) * pricing["prompt"]
        completion_cost = usage_data.get("completion_tokens", 0) * pricing["completion"]
        return prompt_cost + completion_cost
    
    def update_budget(self, usage_data: Dict[str, int]):
        """
        Update token usage and estimated cost.
        
        Args:
            usage_data: Dict with prompt_tokens, completion_tokens, total_tokens
        """
        self.total_tokens["prompt_tokens"] += usage_data.get("prompt_tokens", 0)
        self.total_tokens["completion_tokens"] += usage_data.get("completion_tokens", 0)
        cost = self.calculate_cost(usage_data)
        self.estimated_cost += cost
    
    def _get_remaining_turns(self) -> int:
        """Get the number of remaining turns for this agent."""
        # Count assistant messages with python code to determine turns used
        turns_used = sum(
            1 for msg in self.messages 
            if msg.role == Role.ASSISTANT and "<python>" in msg.content
        )
        return self.max_tool_turns - turns_used
    
    @abstractmethod
    def check_termination(self, response: str, python_code: str) -> bool:
        """
        Check if the agent should terminate based on the response.
        
        Args:
            response: The full response from the model.
            python_code: The extracted python code from the response.
            
        Returns:
            True if the agent should terminate, False otherwise.
        """
        pass
    
    @abstractmethod
    def get_tools_module(self) -> str:
        """
        Get the tools module name for execute_sandboxed_code.
        
        Returns:
            The module name to import for tools.
        """
        pass
    
    @abstractmethod
    def extract_final_result(self, thoughts: str, python_code: str, response: str) -> AgentResponse:
        """
        Extract the final result from the agent's work.
        
        Args:
            thoughts: The extracted thoughts.
            python_code: The extracted python code.
            response: The full response.
            
        Returns:
            An AgentResponse object with the final result.
        """
        pass

    def _add_message(self, message: Union[ChatMessage, dict]):
        """Add a message to the conversation history."""
        if isinstance(message, dict):
            self.messages.append(ChatMessage(**message))
        elif isinstance(message, ChatMessage):
            self.messages.append(message)
        else:
            raise ValueError("Invalid message type")

    def extract_response_parts(self, response: str) -> Tuple[str, str]:
        """
        Extract the thoughts and python code from the response.

        Args:
            response: The response from the agent.

        Returns:
            A tuple of the thoughts and python code.
        """
        thoughts = extract_thoughts(response)
        python_code = extract_python_code(response)

        return thoughts, python_code

    async def chat(self, message: str) -> AgentResponse:
        """
        Chat with the agent (async).

        Args:
            message: The message to chat with the agent.

        Returns:
            The response from the agent.
        """
        import time
        
        # Start timing if this is the first call to chat()
        if self.start_time is None:
            self.start_time = time.time()
        
        # Add the user message to the conversation history
        self._add_message(ChatMessage(role=Role.USER, content=message))

        # Get the response from the agent using this instance's clients
        response, usage_data = await get_model_response(
            messages=self.messages,
            model=self.model,
            client=self._client,
            use_vllm=self.use_vllm,
            use_openai=self.use_openai,
        )
        
        # Update budget tracking
        self.update_budget(usage_data)

        # Extract the thoughts and python code from the response
        thoughts, python_code = self.extract_response_parts(response)

        # CRITICAL ERROR HANDLING: Check if initial response is empty or malformed
        response_is_empty = not response or not response.strip()
        response_is_malformed = not thoughts and not python_code and not response_is_empty
        
        if response_is_empty or response_is_malformed:
            # Provide clear error feedback for malformed initial response
            error_feedback = (
                "ERROR: Your response was empty or missing required tags.\n\n"
                "REMINDER: EVERY response MUST follow this EXACT structure:\n"
                "1. Start with <think>...</think> - Your reasoning\n"
                "2. Follow with <python>...</python> - Python code to use tools\n\n"
                "Please provide a valid response with both <think> and <python> blocks."
            )
            # Add error feedback and retry
            self._add_message(ChatMessage(role=Role.USER, content=error_feedback))
            
            # Get a new response
            response, usage_data = await get_model_response(
                messages=self.messages,
                model=self.model,
                client=self._client,
                use_vllm=self.use_vllm,
                use_openai=self.use_openai,
            )
            self.update_budget(usage_data)
            thoughts, python_code = self.extract_response_parts(response)

        # Execute the code from the agent's response
        result = ({}, "")
        if python_code:
            result = execute_sandboxed_code(
                code=python_code,
                allowed_path=self.working_dir,  # Use working_dir instead of repo_path for scoped agents
                import_module=self.get_tools_module(),
                agent_instance=self,  # NEW: Pass agent instance for sub-agent delegation
            )
            # Handle None result (shouldn't happen but be defensive)
            if result is None:
                result = ({}, "Error: Code execution returned None")
            # Check if execution timed out
            elif result[0] is None and "TimeoutError" in result[1]:
                error_msg = f"{result[1]}\nPlease try simpler operations or break down the task."
                result = ({}, error_msg)

        # Add the agent's response to the conversation history
        self._add_message(ChatMessage(role=Role.ASSISTANT, content=response))

        # Check if we should terminate immediately after first response
        if self.check_termination(response, python_code):
            return self.extract_final_result(thoughts, python_code, response)

        remaining_tool_turns = self.max_tool_turns
        
        # Only enter loop if there was Python code in the first response (except for finder agent)
        # Setup progress bar
        agent_desc = f"{'Sub-' if self.depth > 0 else ''}Agent (Depth {self.depth})"
        if self.scope_paths:
            agent_desc += f" [{self.scope_paths[0]}]"
        
        with tqdm(total=self.max_tool_turns, desc=agent_desc, unit="turn", 
                  leave=True, position=self.depth, ncols=100) as pbar:
            # Update to show initial turn
            turns_done = self.max_tool_turns - remaining_tool_turns
            pbar.update(turns_done)
            
            while remaining_tool_turns > 0 and (python_code or self.agent_type == AgentType.FINDER):
                self._add_message(
                    ChatMessage(role=Role.USER, content=format_results_and_remaining_turns(result[0], result[1], remaining_tool_turns))
                )
                response, usage_data = await get_model_response(
                    messages=self.messages,
                    model=self.model,  
                    client=self._client,
                    use_vllm=self.use_vllm,
                    use_openai=self.use_openai,
                )
                
                # Update budget tracking
                self.update_budget(usage_data)

                # Extract the thoughts and python code from the response
                thoughts, python_code = self.extract_response_parts(response)

                # CRITICAL ERROR HANDLING: Check if response is empty or malformed
                # The model MUST provide either <think> or <python> blocks per the system prompt
                response_is_empty = not response or not response.strip()
                response_is_malformed = not thoughts and not python_code and not response_is_empty
                
                if response_is_empty or response_is_malformed:
                    # Don't add the malformed response to conversation
                    # Instead, provide clear feedback to the model about the format violation
                    error_feedback = (
                        "ERROR: Your previous response was empty or missing required tags.\n\n"
                        "REMINDER: EVERY response MUST follow this EXACT structure:\n"
                        "1. Start with <think>...</think> - Your reasoning\n"
                        "2. Follow with <python>...</python> - Python code to use tools\n\n"
                        "Please provide a valid response with both <think> and <python> blocks."
                    )
                    self._add_message(ChatMessage(role=Role.USER, content=error_feedback))
                    # Don't decrement remaining_tool_turns for this error case
                    # Give the model another chance to provide a valid response
                    continue

                # Add the assistant message BEFORE checking termination
                self._add_message(ChatMessage(role=Role.ASSISTANT, content=response))

                # Check if we should terminate
                if self.check_termination(response, python_code):
                    pbar.set_postfix_str("✓ Completed (terminated early)")
                    break

                # Execute python code if present
                if python_code:
                    result = execute_sandboxed_code(
                        code=python_code,
                        allowed_path=self.working_dir,  # Use working_dir instead of repo_path for scoped agents
                        import_module=self.get_tools_module(),
                        agent_instance=self,  # NEW: Pass agent instance for sub-agent delegation
                    )
                    # Handle None result (shouldn't happen but be defensive)
                    if result is None:
                        result = ({}, "Error: Code execution returned None")
                    # Check if execution timed out
                    elif result[0] is None and "TimeoutError" in result[1]:
                        error_msg = f"{result[1]}\nPlease try simpler operations or break down the task."
                        result = ({}, error_msg)
                    remaining_tool_turns -= 1
                    pbar.update(1)
                    
                    # Update postfix with exploit count
                    exploit_count = len(self.sub_agent_reports) if hasattr(self, 'sub_agent_reports') else 0
                    pbar.set_postfix_str(f"Exploits: {exploit_count}")
                    
                    # Small delay to allow event loop to process cleanup tasks
                    # This helps with memory management when spawning many sub-agents
                    await asyncio.sleep(0.01)
                else:
                    if self.agent_type == AgentType.FINDER:
                        self._add_message(ChatMessage(role=Role.USER, content="Don't stop yet, keep searching for exploits."))
                    else:
                        # Other agents terminate when there's no more python code to execute
                        pbar.set_postfix_str("✓ Completed (no more code)")
                        break
            
            # Final update
            if remaining_tool_turns == 0:
                pbar.set_postfix_str("✓ Completed (max turns)")

        # Update time_spent when chat() finishes
        if self.start_time is not None:
            self.time_spent = time.time() - self.start_time
        
        return self.extract_final_result(thoughts, python_code, response)

    def save_conversation(
        self, 
        log: bool = False, 
        save_folder: str = None,
        prefix: Optional[str] = None,
    ):
        """
        Save the conversation messages to a JSON file in
        the output/conversations directory.
        
        For agents with sub-agent reports, the conversation will include
        nested sub-agent data for building a hierarchical web viewer.
        """
        # Always create the save folder if it doesn't exist
        if save_folder:
            folder_path = save_folder
            if not os.path.exists(folder_path):
                os.makedirs(folder_path, exist_ok=True)
        else:
            if not os.path.exists(SAVE_CONVERSATION_PATH):
                os.makedirs(SAVE_CONVERSATION_PATH, exist_ok=True)
            folder_path = SAVE_CONVERSATION_PATH

        unique_id = uuid.uuid4()
        if prefix:
            file_path = os.path.join(folder_path, f"{prefix}_{unique_id}.json")
        else:
            file_path = os.path.join(folder_path, f"convo_{unique_id}.json")

        # Convert the execution result messages to tool role
        messages = [
            (
                ChatMessage(role=Role.TOOL, content=message.content)
                if message.content.startswith("<result>")
                else ChatMessage(role=message.role, content=message.content)
            )
            for message in self.messages
        ]
        
        # Load exploits from exploits.json if it exists
        found_exploits = []
        exploit_stats = {}
        try:
            if os.path.exists(self.exploits_path):
                with open(self.exploits_path, 'r') as f:
                    found_exploits = json.load(f)
                    # Calculate exploit stats by severity
                    for exploit in found_exploits:
                        severity = exploit.get('severity', 'unknown')
                        exploit_stats[severity] = exploit_stats.get(severity, 0) + 1
        except Exception:
            pass  # If file doesn't exist or can't be read, leave empty
        
        # Aggregate sub-agent costs, exploits, and time
        sub_agent_total_cost = 0.0
        sub_agent_total_tokens = {"prompt_tokens": 0, "completion_tokens": 0}
        sub_agent_total_time = 0.0
        sub_agent_exploits = []
        sub_agent_exploit_stats = {}
        
        for sub_report in self.sub_agent_reports:
            if "budget_used" in sub_report:
                sub_agent_total_cost += sub_report["budget_used"].get("total_cost", 0.0)
                tokens = sub_report["budget_used"].get("tokens", {})
                sub_agent_total_tokens["prompt_tokens"] += tokens.get("prompt_tokens", 0)
                sub_agent_total_tokens["completion_tokens"] += tokens.get("completion_tokens", 0)
            if "time_used" in sub_report:
                # time_used contains combined_time_spent for sub-agents with their own sub-agents
                sub_agent_total_time += sub_report["time_used"].get("combined_time_spent", 
                                                                     sub_report["time_used"].get("time_spent", 0.0))
            if "exploits" in sub_report:
                exploits_list = sub_report["exploits"]
                sub_agent_exploits.extend(exploits_list)
                # Aggregate exploit stats from sub-agents
                for exploit in exploits_list:
                    severity = exploit.get('severity', 'unknown')
                    sub_agent_exploit_stats[severity] = sub_agent_exploit_stats.get(severity, 0) + 1
        
        # Calculate combined totals
        combined_total_cost = self.estimated_cost + sub_agent_total_cost
        combined_total_tokens = {
            "prompt_tokens": self.total_tokens["prompt_tokens"] + sub_agent_total_tokens["prompt_tokens"],
            "completion_tokens": self.total_tokens["completion_tokens"] + sub_agent_total_tokens["completion_tokens"]
        }
        combined_total_time = self.time_spent + sub_agent_total_time
        
        # Calculate combined exploit stats (this agent + all sub-agents)
        combined_exploit_stats = {}
        for severity, count in exploit_stats.items():
            combined_exploit_stats[severity] = combined_exploit_stats.get(severity, 0) + count
        for severity, count in sub_agent_exploit_stats.items():
            combined_exploit_stats[severity] = combined_exploit_stats.get(severity, 0) + count
        
        # Build the conversation data structure
        conversation_data = {
            "agent_id": self.agent_id,
            "parent_agent_id": self.parent_agent_id,
            "depth": self.depth,
            "max_depth": self.max_depth,
            "model": self.model,
            "repo_path": self.repo_path,
            "scope_paths": self.scope_paths,
            "messages": [message.model_dump() for message in messages],
            # Budget tracking - this agent only
            "total_tokens": self.total_tokens,
            "estimated_cost": self.estimated_cost,
            # Budget tracking - sub-agents only
            "sub_agent_total_tokens": sub_agent_total_tokens,
            "sub_agent_total_cost": sub_agent_total_cost,
            # Budget tracking - combined (this agent + all sub-agents)
            "combined_total_tokens": combined_total_tokens,
            "combined_total_cost": combined_total_cost,
            # Time tracking - this agent only
            "time_spent": self.time_spent,
            # Time tracking - sub-agents only
            "sub_agent_total_time": sub_agent_total_time,
            # Time tracking - combined (this agent + all sub-agents)
            "combined_time_spent": combined_total_time,
            # Exploit tracking - this agent only
            "found_exploits": found_exploits,
            "exploit_stats": exploit_stats,
            # Exploit tracking - sub-agents only
            "sub_agent_exploits": sub_agent_exploits,
            "sub_agent_exploit_stats": sub_agent_exploit_stats,
            # Exploit tracking - combined (this agent + all sub-agents)
            "combined_exploits": found_exploits + sub_agent_exploits,
            "combined_exploit_stats": combined_exploit_stats,
        }
        
        try:
            with open(file_path, "w") as f:
                json.dump(conversation_data, f, indent=4)
            if log:
                print(f"Conversation saved to {file_path}")
        except Exception as e:
            error_msg = f"Error saving conversation: {e}"
            if log:
                print(error_msg)
            # Try to save error info at least
            try:
                with open(file_path + ".error", "w") as f:
                    f.write(error_msg)
            except:
                pass
    
    async def close(self):
        """
        Clean up resources used by the agent, including closing the HTTP client.
        Should be called when the agent is no longer needed.
        """
        try:
            if hasattr(self, '_client') and self._client is not None:
                await self._client.aclose()
                self._client = None
        except Exception:
            pass  # Ignore errors during cleanup