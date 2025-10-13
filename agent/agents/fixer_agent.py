from agent.agent import BaseAgent
from agent.utils import AgentType, extract_suggest_fix
from agent.schemas import AgentResponse

class FixerAgent(BaseAgent):
    """Agent for fixing exploits in a codebase."""
    
    def __init__(
        self,
        max_tool_turns: int = None,
        repo_path: str = None,
        use_vllm: bool = False,
        model: str = None,
    ):
        from agent.settings import MAX_TOOL_TURNS
        if max_tool_turns is None:
            max_tool_turns = MAX_TOOL_TURNS
            
        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            use_vllm=use_vllm,
            model=model,
            agent_type=AgentType.FIXER,
        )
        
    def check_termination(self, response: str, python_code: str) -> bool:
        """
        Fixer agent terminates when it produces a suggest_fix block.
        """
        suggest_fix_present = bool(extract_suggest_fix(response))
        return bool(suggest_fix_present and not python_code)
    
    def get_tools_module(self) -> str:
        """
        Get the tools module for fixer agent.
        """
        return "agent.tools.fixer_tools"

    def extract_final_result(self, thoughts: str, python_code: str, response: str) -> AgentResponse:
        """
        Extract the final result for fixer agent.
        """
        return AgentResponse(thoughts=thoughts, python_block=python_code, test_script="", suggest_fix=extract_suggest_fix(response))