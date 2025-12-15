from typing import Optional, List, Any

from kai.agents.base import BaseAgent
from kai.agents.utils import AgentType, generate_tool_schema
from kai.schemas import (
    AgentResponse,
    BlackboxBrief,
    Observation,
)


class BlackboxAgent(BaseAgent):
    """
    Agent that runs blackbox experiments and packages findings.
    """

    def __init__(
        self,
        campaign_brief: BlackboxBrief,
        dependency_graph: Any = None,
        max_tool_turns: Optional[int] = None,
        repo_path: Optional[str] = None,
        use_vllm: bool = False,
        model: Optional[str] = None,
        use_openai: bool = False,
        execution_id: Optional[str] = None,
    ):
        tools_schema = generate_tool_schema("kai.agents.tools.blackbox_tools")
        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            use_vllm=use_vllm,
            model=model,
            agent_type=AgentType.BLACKBOX,
            use_openai=use_openai,
            system_prompt_tools_schema=tools_schema,
        )

        self.campaign_brief = campaign_brief
        self.master_context = campaign_brief.master_context
        self.dependency_graph = self._coerce_dependency_graph(dependency_graph)
        self.blackbox_observations: List[Observation] = []

        if execution_id:
            self.execution_id = execution_id

    def check_termination(self, response: str, python_code: str) -> bool:
        # Blackbox sessions do not use <done> or explicit finalization.
        # They should continue until the tool-turn budget is exhausted by the runtime.
        return False

    def get_tools_module(self) -> str:
        return "kai.agents.tools.blackbox_tools"

    def extract_final_result(
        self, thoughts: str, python_code: str, response: str
    ) -> AgentResponse:
        return AgentResponse(
            thoughts=thoughts,
            python_block=python_code,
            master_context=self.master_context,
        )

    @staticmethod
    def _coerce_dependency_graph(graph: Any):
        """
        Ensure dependency_graph is a DependencyGraph instance when possible so
        graph-based tools (GraphQueryEngine) function correctly.
        """
        try:
            from kai.utils.dependency.graph import DependencyGraph
        except Exception:
            return graph

        if graph is None:
            return None
        if isinstance(graph, DependencyGraph):
            return graph
        if isinstance(graph, dict):
            try:
                return DependencyGraph.from_dict(graph)
            except Exception:
                return graph
        return graph
