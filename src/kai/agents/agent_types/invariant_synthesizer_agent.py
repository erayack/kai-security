from typing import Optional, Dict, Any

from kai.agents.base import BaseAgent
from kai.agents.utils import AgentType
from kai.schemas import AgentResponse, ProtocolManifesto


class InvariantSynthesizerAgent(BaseAgent):
    """
    Agent that synthesizes a Tentative Invariant from a Blackbox Observation.
    """

    def __init__(
        self,
        protocol_manifesto: Optional[ProtocolManifesto] = None,
        max_tool_turns: Optional[int] = None,
        repo_path: Optional[str] = None,
        use_vllm: bool = False,
        model: Optional[str] = None,
        use_openai: bool = False,
        execution_id: Optional[str] = None,
    ):
        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            use_vllm=use_vllm,
            model=model,
            agent_type=AgentType.INVARIANT_SYNTHESIZER,
            use_openai=use_openai,
        )

        self.protocol_manifesto = protocol_manifesto
        self._finalized_invariant_draft: Optional[Dict[str, Any]] = None
        self._finalized_no_invariant_reason: Optional[str] = None

        if execution_id:
            self.execution_id = execution_id

    def check_termination(self, response: str, python_code: str) -> bool:
        """
        InvariantSynthesizerAgent terminates when it stops calling tools.
        The caller (process) will check if a finalize tool was called.
        """
        return False

    def get_tools_module(self) -> str:
        """
        Get the tools module for invariant synthesizer agent.
        """
        return "kai.agents.tools.invariant_synthesizer_tools"

    def extract_final_result(
        self, thoughts: str, python_code: str, response: str
    ) -> AgentResponse:
        """
        Extract the final result for invariant synthesizer agent.
        """
        return AgentResponse(
            thoughts=thoughts,
            python_block=python_code,
        )
