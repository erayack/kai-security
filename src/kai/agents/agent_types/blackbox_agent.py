from pathlib import Path
from typing import Optional, List, Any

from kai.agents.base import BaseAgent
from kai.agents.utils import AgentType, generate_tool_schema
from kai.schemas import (
    AgentResponse,
    BlackboxBrief,
    CampaignBrief,
    ChatMessage,
    Observation,
    Role,
)

# Path to toolcalling prompt template
TOOLCALLING_PROMPT_PATH = (
    Path(__file__).parent.parent.parent / "prompts" / "blackbox_agent_prompt.txt"
)


class BlackboxAgent(BaseAgent):
    """
    Agent that runs blackbox experiments and packages findings.
    """

    def __init__(
        self,
        campaign_brief: BlackboxBrief | CampaignBrief,
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

    def get_observations(self) -> List[Observation]:
        """Get all observations recorded during blackbox exploration."""
        return self.blackbox_observations

    def set_toolcalling_prompt(self):
        """Replace system prompt with the native toolcalling template."""
        try:
            template = TOOLCALLING_PROMPT_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            template = (
                "You are BlackboxAgent. Run investigations and record observations."
            )

        # Get framework-specific PoC guidance from adapter
        poc_guidance = ""
        if self.master_context:
            try:
                from kai.utils.tool_adapters import get_tool_adapter

                adapter_name = (
                    getattr(self.master_context, "adapter", None) or "foundry"
                )
                tool_adapter = get_tool_adapter(adapter_name)
                poc_guidance = tool_adapter.get_poc_guidance()
            except Exception:
                pass

        replacements = {
            "{{max_tool_turns}}": str(self.max_tool_turns),
            "{{poc_guidance}}": poc_guidance,
        }
        prompt = template
        for key, value in replacements.items():
            prompt = prompt.replace(key, value)

        self.system_prompt = prompt
        self.messages = [ChatMessage(role=Role.SYSTEM, content=prompt)]

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
