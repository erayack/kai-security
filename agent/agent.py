from agent.engine import execute_sandboxed_code
from agent.model import get_model_response, create_openai_client, create_vllm_client
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
)
from agent.schemas import ChatMessage, Role, AgentResponse
from tqdm import tqdm

from typing import Union, Tuple, Optional
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
        max_depth: int = 3,              # NEW: Maximum recursion depth
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
            self.allowed_paths = [
                os.path.abspath(os.path.join(self.repo_path, p)) 
                for p in scope_paths
            ]
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

    def chat(self, message: str) -> AgentResponse:
        """
        Chat with the agent.

        Args:
            message: The message to chat with the agent.

        Returns:
            The response from the agent.
        """
        # Add the user message to the conversation history
        self._add_message(ChatMessage(role=Role.USER, content=message))

        # Get the response from the agent using this instance's clients
        response = get_model_response(
            messages=self.messages,
            model=self.model,
            client=self._client,
            use_vllm=self.use_vllm,
            use_openai=self.use_openai,
        )

        # Extract the thoughts and python code from the response
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
                response = get_model_response(
                    messages=self.messages,
                    model=self.model,  
                    client=self._client,
                    use_vllm=self.use_vllm,
                    use_openai=self.use_openai,
                )

                # Extract the thoughts and python code from the response
                thoughts, python_code = self.extract_response_parts(response)

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
            "sub_agent_reports": [],  # Will hold nested sub-agent reports
            "message_count": len(messages),
        }
        
        # Add sub-agent reports if they exist (NEW)
        if self.sub_agent_reports:
            for report in self.sub_agent_reports:
                # Convert SubAgentReport to dict for JSON serialization
                try:
                    conversation_data["sub_agent_reports"].append(report.model_dump())
                except AttributeError:
                    # If report is already a dict, use it as-is
                    conversation_data["sub_agent_reports"].append(report)
        
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
