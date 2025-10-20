from agent.agent import BaseAgent
from agent.utils import AgentType
from agent.schemas import AgentResponse


class FinderAgent(BaseAgent):
    """Agent for finding exploits in a codebase."""
    
    def __init__(
        self,
        max_tool_turns: int = None,
        repo_path: str = None,
        use_vllm: bool = False,
        model: str = None,
        use_openai: bool = False,
    ):
        from agent.settings import MAX_TOOL_TURNS
        if max_tool_turns is None:
            max_tool_turns = MAX_TOOL_TURNS
            
        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            use_vllm=use_vllm,
            model=model,
            use_openai=use_openai,
            agent_type=AgentType.FINDER,
        )
    
    def check_termination(self, response: str, python_code: str) -> bool:
        """
        Finder agent terminates when there's no more python code to execute.
        
        Args:
            response: The full response from the model.
            python_code: The extracted python code from the response.
            
        Returns:
            False - finder agent never terminates early, it runs until max_tool_turns.
        """
        return False
    
    def get_tools_module(self) -> str:
        """
        Get the tools module for finder agent.
        
        Returns:
            The tools module name.
        """
        return "agent.tools.finder_tools"
    
    def extract_final_result(self, thoughts: str, python_code: str, response: str) -> AgentResponse:
        """
        Extract the final result for finder agent.
        
        Args:
            thoughts: The extracted thoughts.
            python_code: The extracted python code.
            response: The full response.
            
        Returns:
            An AgentResponse with thoughts and python_block.
        """
        return AgentResponse(thoughts=thoughts, python_block=python_code, test_script="")

