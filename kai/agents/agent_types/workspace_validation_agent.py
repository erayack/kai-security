from typing import Optional, Any, Dict

from kai.agents.base import BaseAgent
from kai.agents.utils import AgentType, generate_tool_schema
from kai.schemas import AgentResponse, MasterContext, WorkspaceValidationResult


class WorkspaceValidationAgent(BaseAgent):
    """
    Agent that validates a provisioned workspace by writing a smoke test,
    compiling, running the test, and registering the result.

    Intended to be driven by WorkspaceValidationProcess (boot-time validation).
    """

    def __init__(
        self,
        *,
        max_tool_turns: Optional[int] = None,
        repo_path: Optional[str] = None,
        use_vllm: bool = False,
        model: Optional[str] = None,
        use_openai: bool = False,
        scope_paths: Optional[list[str]] = None,
        execution_id: Optional[str] = None,
        master_context: Optional[MasterContext] = None,
        dependency_graph: Any = None,
    ):
        tools_schema = generate_tool_schema("kai.agents.tools.workspace_validation_tools")
        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            use_vllm=use_vllm,
            model=model,
            agent_type=AgentType.WORKSPACE_VALIDATION,
            use_openai=use_openai,
            scope_paths=scope_paths,
            system_prompt_tools_schema=tools_schema,
        )

        if execution_id:
            self.execution_id = execution_id

        self.master_context = master_context
        self.dependency_graph = dependency_graph
        self._registered_workspace_validation_result: Optional[
            WorkspaceValidationResult
        ] = None

    def check_termination(self, response: str, python_code: str) -> bool:
        # Tool-calling loop controls termination; stop when the model stops calling tools.
        return False

    def get_tools_module(self) -> str:
        return "kai.agents.tools.workspace_validation_tools"

    def extract_final_result(
        self, thoughts: str, python_code: str, response: str
    ) -> AgentResponse:
        return AgentResponse(
            thoughts=thoughts,
            python_block=python_code,
            master_context=self.master_context,
        )

    def get_validation_result(self) -> Optional[WorkspaceValidationResult]:
        return getattr(self, "_registered_workspace_validation_result", None)

    def _set_validation_result(self, result: WorkspaceValidationResult) -> None:
        self._registered_workspace_validation_result = result

    # Backwards-compatible accessor for tools (if needed).
    def _register_workspace_validation_result(self, payload: Dict) -> None:
        self._set_validation_result(WorkspaceValidationResult(**payload))


