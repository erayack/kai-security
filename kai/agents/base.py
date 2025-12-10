from kai.agents.engine import execute_sandboxed_code
from kai.inference import (
    get_model_response,
    create_openai_client,
    create_vllm_client,
    get_model_pricing,
)
from kai.agents.utils import (
    load_system_prompt,
    extract_python_code,
    format_results_and_remaining_turns,
    extract_thoughts,
    AgentType,
    agent_type_to_kind,
)
from kai.agents.settings import (
    SAVE_CONVERSATION_PATH,
    MAX_TOOL_TURNS,
    VLLM_HOST,
    VLLM_PORT,
    OPENROUTER_STRONG_MODEL,
    OPENAI_STRONG_MODEL,
    MAX_DEPTH,
)
from kai.schemas import ChatMessage, Role, AgentResponse
import asyncio
from logger import logger

from typing import Union, Tuple, Optional, Dict
from abc import ABC, abstractmethod

import json
import os
import uuid
from bson import ObjectId

from logger.mongo_logger import (
    log_agent_started,
    log_agent_metrics,
    log_agent_complete,
)
import copy


class BaseAgent(ABC):
    """Abstract base class for all agents."""

    def __init__(
        self,
        max_tool_turns: Optional[int] = None,
        repo_path: Optional[str] = None,
        use_vllm: bool = False,
        model: Optional[str] = None,
        agent_type: Optional[AgentType] = None,
        use_openai: bool = False,
        scope_paths: Optional[list[str]] = None,  # NEW: Restrict file access to these paths
        parent_agent_id: Optional[str] = None,  # NEW: Track hierarchy
        depth: int = 0,  # NEW: Depth in hierarchy
        max_depth: int = MAX_DEPTH,  # NEW: Maximum recursion depth
        system_prompt_tools_schema: str | None = None,
    ):
        if agent_type is None:
            raise ValueError("agent_type must be provided")
        self.agent_type: AgentType = agent_type

        # Agent identification and hierarchy (NEW)
        self.agent_id = str(ObjectId())  # Convert to string for JSON serialization
        self.parent_agent_id = parent_agent_id
        self.depth = depth
        self.max_depth = max_depth

        # For sub-agents, store execution_id
        self.execution_id = None  # Will be set for sub-agents

        # Scope restriction (NEW)
        self.scope_paths = scope_paths
        self.repo_path = os.path.abspath(repo_path) if repo_path else os.getcwd()

        if scope_paths:
            self.restricted_scope = True
            # Convert scope paths to absolute paths
            self.allowed_paths = []
            for p in scope_paths:
                # If path is already absolute and within repo_path, use it as-is
                if os.path.isabs(p):
                    abs_p = os.path.abspath(p)
                    if self.repo_path and abs_p.startswith(self.repo_path):
                        self.allowed_paths.append(abs_p)
                    else:
                        # Absolute path outside repo - shouldn't happen but handle it
                        self.allowed_paths.append(abs_p)
                else:
                    # Relative path - join with repo_path
                    # Remove any leading repo directory names to avoid duplication
                    # e.g. if p is "repos/xxx/programs/store/" and repo_path ends with "repos/xxx"
                    clean_p = p
                    repo_name = os.path.basename(self.repo_path) if self.repo_path else ""
                    if clean_p.startswith("repos/"):
                        # Strip everything up to and including the repo name
                        parts = clean_p.split("/")
                        if repo_name in parts:
                            idx = parts.index(repo_name)
                            clean_p = "/".join(parts[idx + 1 :])
                    self.allowed_paths.append(
                        os.path.abspath(os.path.join(self.repo_path, clean_p))
                    )
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

        # Configure tool turn budget early for downstream consumers
        self.max_tool_turns = (
            max_tool_turns if max_tool_turns is not None else MAX_TOOL_TURNS
        )

        # Set exploits.json path based on working directory (dynamic per agent)
        self.exploits_path = os.path.join(self.working_dir, "exploits.json")

        # Load the system prompt and add it to the conversation history
        # Use condensed prompt for sub-agents
        is_sub_agent = depth > 0
        scope_path_str = scope_paths[0] if scope_paths else ""
        self.system_prompt = load_system_prompt(
            self.agent_type,
            is_sub_agent=is_sub_agent,
            scope_path=scope_path_str,
            task_description="",  # Will be set in delegation instruction
            max_turns=self.max_tool_turns,
            depth=depth,
            max_depth=max_depth,
            tools_schema=system_prompt_tools_schema,
        )
        self.messages: list[ChatMessage] = [
            ChatMessage(role=Role.SYSTEM, content=self.system_prompt)
        ]

        # Fixer-specific format enforcement state
        self._pending_feedback: Optional[str] = None
        self._fixer_completion_warnings = 0
        self._max_completion_warnings = 3

        # Set the maximum number of tool turns and use_vllm flag
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
            1
            for msg in self.messages
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
    def extract_final_result(
        self, thoughts: str, python_code: str, response: str
    ) -> AgentResponse:
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

    def _missing_suggest_fix(self, python_code: str, response: str) -> bool:
        """Determine if the fixer agent tried to finish without a <suggest_fix> block."""
        if self.agent_type != AgentType.FIXER:
            return False
        if python_code:
            return False
        return "<suggest_fix>" not in response or "</suggest_fix>" not in response

    def _reset_fixer_completion_warnings(self, python_code: str, response: str):
        """Reset fixer completion warnings when the agent complies with the format."""
        if self.agent_type != AgentType.FIXER:
            return
        has_fix = "<suggest_fix>" in response and "</suggest_fix>" in response
        if python_code or has_fix:
            self._fixer_completion_warnings = 0
            if has_fix:
                self._pending_feedback = None

    def _handle_missing_suggest_fix(self) -> bool:
        """
        Queue feedback for fixer agents that attempt to finish without <suggest_fix>.

        Returns:
            True if the maximum number of warnings has been reached (conversation should end).
        """
        if self.agent_type != AgentType.FIXER:
            return False

        self._fixer_completion_warnings += 1
        if self._fixer_completion_warnings >= self._max_completion_warnings:
            self._pending_feedback = None
            return True

        remaining = self._max_completion_warnings - self._fixer_completion_warnings
        plural = "" if remaining == 1 else "s"
        attempt = self._fixer_completion_warnings
        self._pending_feedback = (
            f"FORMAT VIOLATION ({attempt}/{self._max_completion_warnings}): "
            "When you are done you must respond with <suggest_fix>...</suggest_fix> containing a ```diff``` patch. "
            "Either continue with a <python> block to keep investigating or provide the final fix now.\n"
            f"You have {remaining} more attempt{plural} before this exploit is marked as failed."
        )
        return False

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

            # Log execution in_progress (if main agent) and agent start
            try:
                # Log agent start (creates agent document)
                # For main agent, execution_id = agent_id
                # For sub-agents, execution_id should be passed from parent
                execution_id = self.execution_id if self.execution_id else self.agent_id

                # Format scope paths properly
                scope_paths_str = ""
                if self.scope_paths:
                    scope_paths_str = " | ".join(self.scope_paths)

                log_agent_started(
                    agent_id=self.agent_id,
                    execution_id=execution_id,
                    kind=(
                        agent_type_to_kind(self.agent_type)
                        if self.agent_type
                        else "unknown"
                    ),
                    parent_agent_id=self.parent_agent_id,
                    depth=self.depth,
                    scope_paths=scope_paths_str,
                )
            except Exception:
                pass  # Don't fail if logging fails

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

        # Log real-time metrics after each API call
        try:
            log_agent_metrics(
                agent_id=self.agent_id,
                current_cost=self.estimated_cost,
                prompt_tokens=self.total_tokens.get("prompt_tokens", 0),
                completion_tokens=self.total_tokens.get("completion_tokens", 0),
                total_tokens=self.total_tokens.get("prompt_tokens", 0)
                + self.total_tokens.get("completion_tokens", 0),
            )
        except Exception:
            pass  # Don't fail if logging fails

        # Extract the thoughts and python code from the response
        thoughts, python_code = self.extract_response_parts(response)
        self._reset_fixer_completion_warnings(python_code, response)
        violation_limit_reached = False
        if self._missing_suggest_fix(python_code, response):
            violation_limit_reached = self._handle_missing_suggest_fix()

        # CRITICAL ERROR HANDLING: Check if initial response is empty or completely malformed
        # At minimum, need either <python>, <done>, or meaningful content
        response_is_empty = not response or not response.strip()
        has_done_tag = "<done>" in response and "</done>" in response
        has_any_structure = python_code or has_done_tag or thoughts
        response_is_malformed = not has_any_structure and not response_is_empty

        if response_is_empty or response_is_malformed:
            # Provide clear error feedback for malformed initial response
            error_feedback = (
                "ERROR: Your response was empty or had no recognizable structure.\n\n"
                "REMINDER: Include at least one of these in your response:\n"
                "- <think>...</think> for your reasoning\n"
                "- <python>...</python> for code to execute\n"
                "- <done>...</done> when finished\n\n"
                "Please provide a valid response with at least one structured tag."
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

        if violation_limit_reached:
            return self.extract_final_result(thoughts, python_code, response)

        # Check if we should terminate immediately after first response
        if self.check_termination(response, python_code):
            return self.extract_final_result(thoughts, python_code, response)

        remaining_tool_turns = self.max_tool_turns
        is_finder_agent = self.agent_type == AgentType.FINDER

        # Only enter loop if there was Python code in the first response (except for finder agent)
        # Setup progress bar
        # Concise format: (Setup <id> at depth 0)
        agent_type_str = (
            self.agent_type.name.title()
            if hasattr(self.agent_type, "name")
            else str(self.agent_type).title()
        )
        # Handle AgentType.SETUP -> Setup if it's an enum
        if "." in agent_type_str:
            agent_type_str = agent_type_str.split(".")[-1].title()

        agent_desc = f"({agent_type_str} {self.agent_id} at depth {self.depth})"

        ## Commented due to unnecessary
        # if self.scope_paths:
        #     agent_desc += f" [{self.scope_paths[0]}]"

        # Only enter loop if there was Python code in the first response (except for finder agent)
        while remaining_tool_turns > 0 and (
            python_code or is_finder_agent or self._pending_feedback
        ):
            # Log current turn and agent
            current_turn = self.max_tool_turns - remaining_tool_turns + 1
            logger.info(f"{current_turn}/{self.max_tool_turns} - {agent_desc}")

            if self._pending_feedback:
                self._add_message(
                    ChatMessage(role=Role.USER, content=self._pending_feedback)
                )
                self._pending_feedback = None
            else:
                self._add_message(
                    ChatMessage(
                        role=Role.USER,
                        content=format_results_and_remaining_turns(
                            result[0], result[1], remaining_tool_turns
                        ),
                    )
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
            self._reset_fixer_completion_warnings(python_code, response)

            # CRITICAL ERROR HANDLING: Check if response is empty or completely malformed
            # At minimum, need either <python>, <done>, or meaningful content
            response_is_empty = not response or not response.strip()
            has_done_tag = "<done>" in response and "</done>" in response
            has_any_structure = python_code or has_done_tag or thoughts
            response_is_malformed = not has_any_structure and not response_is_empty

            # Track consecutive malformed responses to prevent infinite loops
            if not hasattr(self, "_malformed_count"):
                self._malformed_count = 0

            if response_is_empty or response_is_malformed:
                self._malformed_count += 1

                # If the malformed response comes after a successful tool execution,
                # treat it as intentional completion rather than an error
                last_message_was_tool_result = (
                    len(self.messages) > 0
                    and self.messages[-1].role == Role.USER
                    and self.messages[-1].content.startswith("<result>")
                )

                if last_message_was_tool_result and not is_finder_agent:
                    # Model returned nothing right after a tool result; nudge it to finish properly
                    self._add_message(
                        ChatMessage(
                            role=Role.USER,
                            content=(
                                "You just received tool results. Continue with "
                                "<think> reasoning and finish with a <done>{...}</done> "
                                "containing the required JSON."
                            ),
                        )
                    )
                    continue

                # If we get too many malformed responses in a row, terminate gracefully
                if self._malformed_count >= 3 and not is_finder_agent:
                    logger.info(
                        f"{agent_desc} - Completed (no more structured responses)"
                    )
                    break

                # Don't add the malformed response to conversation
                # Instead, provide clear feedback to the model about the format violation
                error_feedback = (
                    "ERROR: Your previous response was empty or had no recognizable structure.\n\n"
                    "REMINDER: Include at least one of these in your response:\n"
                    "- <think>...</think> for your reasoning\n"
                    "- <python>...</python> for code to execute\n"
                    "- <done>...</done> when finished\n\n"
                    "Please provide a valid response with at least one structured tag."
                )
                self._add_message(ChatMessage(role=Role.USER, content=error_feedback))
                # Don't decrement remaining_tool_turns for this error case
                # Give the model another chance to provide a valid response
                continue
            else:
                # Reset counter on successful response
                self._malformed_count = 0

            # Add the assistant message BEFORE checking termination
            self._add_message(ChatMessage(role=Role.ASSISTANT, content=response))

            if self._missing_suggest_fix(python_code, response):
                violation_limit_reached = self._handle_missing_suggest_fix()
                if violation_limit_reached:
                    logger.info(f"{agent_desc} - Format violation")
                    break
                logger.warning(f"{agent_desc} - Requires <suggest_fix>")
                continue

            # Check if we should terminate
            if self.check_termination(response, python_code):
                logger.info(f"{agent_desc} - Completed (terminated early)")
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

                # Small delay to allow event loop to process cleanup tasks
                # This helps with memory management when spawning many sub-agents
                await asyncio.sleep(0.01)
            else:
                if self.agent_type == AgentType.FINDER:
                    self._add_message(
                        ChatMessage(
                            role=Role.USER,
                            content="Don't stop yet, keep searching for exploits.",
                        )
                    )
                else:
                    # Other agents terminate when there's no more python code to execute
                    logger.info(f"{agent_desc} - Completed (no more code)")
                    break

        # Final update
        if remaining_tool_turns == 0:
            logger.info(f"{agent_desc} - Completed (max turns)")

        # Update time_spent when chat() finishes
        if self.start_time is not None:
            self.time_spent = time.time() - self.start_time

            # Log agent completion
            try:
                total_tokens = self.total_tokens.get(
                    "prompt_tokens", 0
                ) + self.total_tokens.get("completion_tokens", 0)
                log_agent_complete(self.agent_id, self.estimated_cost, total_tokens)
            except Exception:
                pass  # Don't fail if logging fails

        return self.extract_final_result(thoughts, python_code, response)

    def save_conversation(
        self,
        log: bool = False,
        save_folder: Optional[str] = None,
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

        # Load exploits from exploits.json if it exists (ONLY for finder agent)
        found_exploits = []
        exploit_stats = {}
        try:
            # Only load exploits for finder agent
            if self.agent_type == AgentType.FINDER and os.path.exists(
                self.exploits_path
            ):
                with open(self.exploits_path, "r") as f:
                    found_exploits = json.load(f)

                    # Finder agent: severity-based stats
                    for exploit in found_exploits:
                        severity = exploit.get("severity", "unknown")
                        exploit_stats[severity] = exploit_stats.get(severity, 0) + 1
            # Generator agent gets exploit_stats from sub-agent reports, not from exploits.json
            # (exploit_stats will be populated from sub_agent_reports below)
        except Exception:
            pass  # If file doesn't exist or can't be read, leave empty

        # Helper utilities for aggregating exploit metadata
        def _stats_from_exploits(exploits: list[dict]) -> dict[str, int]:
            stats: dict[str, int] = {}
            for exploit in exploits:
                if not isinstance(exploit, dict):
                    continue
                severity = exploit.get("severity", "unknown")
                stats[severity] = stats.get(severity, 0) + 1
            return stats

        def _merge_stats(target: dict, addition: dict):
            for key, value in addition.items():
                if isinstance(value, dict):
                    nested = target.setdefault(key, {"verified": 0, "unverified": 0})
                    nested["verified"] += value.get("verified", 0)
                    nested["unverified"] += value.get("unverified", 0)
                else:
                    target[key] = target.get(key, 0) + value

        combined_exploits = copy.deepcopy(found_exploits)
        combined_exploit_stats: dict = copy.deepcopy(exploit_stats)

        # Aggregate sub-agent costs and time
        sub_agent_total_cost = 0.0
        sub_agent_total_tokens = {"prompt_tokens": 0, "completion_tokens": 0}
        sub_agent_total_time = 0.0

        for sub_report in self.sub_agent_reports:
            if "budget_used" in sub_report:
                sub_agent_total_cost += sub_report["budget_used"].get("total_cost", 0.0)
                tokens = sub_report["budget_used"].get("tokens", {})
                sub_agent_total_tokens["prompt_tokens"] += tokens.get(
                    "prompt_tokens", 0
                )
                sub_agent_total_tokens["completion_tokens"] += tokens.get(
                    "completion_tokens", 0
                )
            if "time_used" in sub_report:
                # time_used contains combined_time_spent for sub-agents with their own sub-agents
                sub_agent_total_time += sub_report["time_used"].get(
                    "combined_time_spent",
                    sub_report["time_used"].get("time_spent", 0.0),
                )
            # Merge sub-agent exploit stats into main exploit_stats
            if "exploit_stats" in sub_report:
                sub_stats = sub_report["exploit_stats"]
                # Check if it's generator-style (severity with verified/unverified) or finder-style (severity counts)
                first_value = (
                    next(iter(sub_stats.values()), None) if sub_stats else None
                )
                if isinstance(first_value, dict):
                    # Generator-style: severity-based with verified/unverified
                    for severity, stats in sub_stats.items():
                        if severity not in exploit_stats:
                            exploit_stats[severity] = {"verified": 0, "unverified": 0}
                        exploit_stats[severity]["verified"] += stats.get("verified", 0)
                        exploit_stats[severity]["unverified"] += stats.get(
                            "unverified", 0
                        )
                else:
                    # Finder-style: severity-based counts
                    for severity, count in sub_stats.items():
                        exploit_stats[severity] = exploit_stats.get(severity, 0) + count
            elif "exploits" in sub_report:
                sub_stats = _stats_from_exploits(sub_report.get("exploits", []))
                for severity, count in sub_stats.items():
                    exploit_stats[severity] = exploit_stats.get(severity, 0) + count

            # Track combined exploit metadata for this agent (own + descendants)
            if "combined_exploits" in sub_report:
                combined_exploits.extend(copy.deepcopy(sub_report["combined_exploits"]))
            elif "exploits" in sub_report:
                combined_exploits.extend(copy.deepcopy(sub_report["exploits"]))

            if "combined_exploit_stats" in sub_report:
                _merge_stats(
                    combined_exploit_stats, sub_report["combined_exploit_stats"]
                )
            elif "exploit_stats" in sub_report:
                _merge_stats(combined_exploit_stats, sub_report["exploit_stats"])
            elif "exploits" in sub_report:
                _merge_stats(
                    combined_exploit_stats,
                    _stats_from_exploits(sub_report.get("exploits", [])),
                )

        # Calculate combined totals
        combined_total_cost = self.estimated_cost + sub_agent_total_cost
        combined_total_tokens = {
            "prompt_tokens": self.total_tokens["prompt_tokens"]
            + sub_agent_total_tokens["prompt_tokens"],
            "completion_tokens": self.total_tokens["completion_tokens"]
            + sub_agent_total_tokens["completion_tokens"],
        }
        combined_total_time = self.time_spent + sub_agent_total_time

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
            # Exploit tracking
            # For finder agents: {"critical": 2, "high": 5, ...}
            # For generator agents: {"severity": {"verified": int, "unverified": int}, ...}
            # Includes this agent + all sub-agents
            "exploit_stats": exploit_stats,
            "combined_exploit_stats": combined_exploit_stats,
            "combined_exploits": combined_exploits,
        }

        # Add validation result if this is a per-exploit validation sub-agent
        if hasattr(self, "validation_result"):
            conversation_data["validation_result"] = self.validation_result

        # Only include found_exploits for finder agents
        if self.agent_type == AgentType.FINDER:
            conversation_data["found_exploits"] = found_exploits

        try:
            with open(file_path, "w") as f:
                json.dump(conversation_data, f, indent=4)
            # Store the conversation path for potential use by sub-agents
            self.conversation_path = file_path
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
            except Exception:
                pass

        return file_path

    async def close(self):
        """
        Clean up resources used by the agent, including closing the HTTP client.
        Should be called when the agent is no longer needed.
        """
        try:
            if hasattr(self, "_client") and self._client is not None:
                await self._client.aclose()
                self._client = None
        except Exception:
            pass  # Ignore errors during cleanup
