from agent.agent import BaseAgent
from agent.utils import AgentType, check_done
from agent.schemas import AgentResponse

class GeneratorAgent(BaseAgent):
    """Agent for generating test scripts for exploits."""
    
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
            agent_type=AgentType.TEST_GENERATOR,
            use_openai=use_openai,
        )
    
    def check_termination(self, response: str, python_code: str) -> bool:
        """
        Generator agent terminates when it produces a test script without python code.
        
        Args:
            response: The full response from the model.
            python_code: The extracted python code from the response.
            
        Returns:
            True if we have a test script and no more python code, False otherwise.
        """
        done_present = check_done(response)
        return bool(done_present and not python_code)
    
    def get_tools_module(self) -> str:
        """
        Get the tools module for generator agent.
        
        Returns:
            The tools module name.
        """
        return "agent.tools.generator_tools"
    
    def extract_final_result(self, thoughts: str, python_code: str, response: str) -> AgentResponse:
        """
        Extract the final result for generator agent.
        
        Args:
            thoughts: The extracted thoughts.
            python_code: The extracted python code.
            response: The full response.
            
        Returns:
            An AgentResponse with thoughts, python_block, and test_script.
        """
        return AgentResponse(thoughts=thoughts, python_block=python_code)

