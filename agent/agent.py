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
)
from agent.schemas import ChatMessage, Role, AgentResponse

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
    ):
        self.agent_type = agent_type
        # Load the system prompt and add it to the conversation history
        self.system_prompt = load_system_prompt(agent_type)
        self.messages: list[ChatMessage] = [
            ChatMessage(role=Role.SYSTEM, content=self.system_prompt)
        ]

        # Set the maximum number of tool turns and use_vllm flag
        self.max_tool_turns = max_tool_turns
        self.use_vllm = use_vllm

        # Set model: use provided model, or fallback to OPENROUTER_STRONG_MODEL
        if model:
            self.model = model
        else:
            self.model = OPENROUTER_STRONG_MODEL

        # Each Agent instance gets its own clients to avoid bottlenecks
        if use_vllm:
            self._client = create_vllm_client(host=VLLM_HOST, port=VLLM_PORT)
        else:
            self._client = create_openai_client()

        # Set memory_path: use provided path or fall back to default MEMORY_PATH
        self.repo_path = repo_path

        # Ensure memory_path is absolute for consistency
        self.repo_path = os.path.abspath(self.repo_path)

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
        )

        # Extract the thoughts and python code from the response
        thoughts, python_code = self.extract_response_parts(response)

        # Execute the code from the agent's response
        result = ({}, "")
        if python_code:
            result = execute_sandboxed_code(
                code=python_code,
                allowed_path=self.repo_path,
                import_module=self.get_tools_module(),
            )

        # Add the agent's response to the conversation history
        self._add_message(ChatMessage(role=Role.ASSISTANT, content=response))

        # Check if we should terminate immediately after first response
        if self.check_termination(response, python_code):
            return self.extract_final_result(thoughts, python_code, response)

        remaining_tool_turns = self.max_tool_turns
        
        # Only enter loop if there was Python code in the first response
        while remaining_tool_turns > 0 and python_code:
            self._add_message(
                ChatMessage(role=Role.USER, content=format_results_and_remaining_turns(result[0], result[1], remaining_tool_turns))
            )
            response = get_model_response(
                messages=self.messages,
                model=self.model,  
                client=self._client,
                use_vllm=self.use_vllm,
            )

            # Extract the thoughts and python code from the response
            thoughts, python_code = self.extract_response_parts(response)

            # Add the assistant message BEFORE checking termination
            self._add_message(ChatMessage(role=Role.ASSISTANT, content=response))

            # Check if we should terminate
            if self.check_termination(response, python_code):
                break

            # Execute python code if present
            if python_code:
                result = execute_sandboxed_code(
                    code=python_code,
                    allowed_path=self.repo_path,
                    import_module=self.get_tools_module(),
                )
                remaining_tool_turns -= 1
            else:
                # No more python code to execute, we're done
                break

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
        """
        if not os.path.exists(SAVE_CONVERSATION_PATH) and not save_folder:
            os.makedirs(SAVE_CONVERSATION_PATH, exist_ok=True)

        unique_id = uuid.uuid4()
        if not save_folder:
            file_path = os.path.join(SAVE_CONVERSATION_PATH, f"convo_{unique_id}.json")
        else:
            folder_path = save_folder
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
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
        try:
            with open(file_path, "w") as f:
                json.dump([message.model_dump() for message in messages], f, indent=4)
        except Exception as e:
            if log:
                print(f"Error saving conversation: {e}")
        if log:
            print(f"Conversation saved to {file_path}")
