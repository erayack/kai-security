from agent.agent import BaseAgent
from agent.utils import AgentType, check_done
from agent.schemas import AgentResponse

class SetupAgent(BaseAgent):
    """Agent for setting up a codebase."""
    
    def __init__(
        self,
        max_tool_turns: int = None,
        repo_path: str = None,
        use_vllm: bool = False,
        model: str = None,
        use_openai: bool = False,
    ):

        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            use_vllm=use_vllm,
            model=model,
            agent_type=AgentType.SETUP,
            use_openai=use_openai,
        )
    
    def check_termination(self, response: str, python_code: str) -> bool:
        """
        Setup agent terminates when it produces a done block.
        """
        done_present = check_done(response)
        return bool(done_present and not python_code)
    
    def get_tools_module(self) -> str:
        """
        Get the tools module for setup agent.
        """
        return "agent.tools.setup_tools"

    def extract_final_result(self, thoughts: str, python_code: str, response: str) -> AgentResponse:
        """
        Extract the final result for setup agent.
        """
        return AgentResponse(thoughts=thoughts, python_block=python_code)