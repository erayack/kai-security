from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from kai.agents.base import BaseAgent
from kai.agents.utils import AgentType
from kai.schemas import (
    AgentResponse,
    ChatMessage,
    ExploitCandidate,
    MasterContext,
    Role,
    Verdict,
)


TOOLCALLING_PROMPT_PATH = (
    Path(__file__).parent.parent.parent / "prompts" / "fixer_agent_prompt.txt"
)


class FixerAgent(BaseAgent):
    """
    Agent that proposes and registers code fixes after a verified exploit.

    Notes on termination:
    - The tool-calling loop (chat_with_tools) ends when the model stops calling tools.
    - We additionally consider the fix flow "complete" once at least one fix has been
      registered via register_fix (stored on `self._registered_fixes`).
    """

    def __init__(
        self,
        *,
        exploit_candidate: ExploitCandidate,
        verdict: Verdict,
        master_context: Optional[MasterContext] = None,
        dependency_graph: Any = None,
        max_tool_turns: Optional[int] = None,
        repo_path: Optional[str] = None,
        use_vllm: bool = False,
        model: Optional[str] = None,
        use_openai: bool = False,
        execution_id: Optional[str] = None,
        scope_paths: Optional[list[str]] = None,
    ):
        # AgentType.FIXER is not currently supported by load_system_prompt(), so we
        # initialize with a supported agent_type and then replace the system prompt.
        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            use_vllm=use_vllm,
            model=model,
            agent_type=AgentType.STATE,
            use_openai=use_openai,
            scope_paths=scope_paths,
        )

        # Set the real agent type (for logging/semantics).
        self.agent_type = AgentType.FIXER

        if execution_id:
            self.execution_id = execution_id

        self.exploit_candidate = exploit_candidate
        self.master_context = master_context
        self.dependency_graph = dependency_graph

        # Store verdict in the same field used by VerifierAgent tools.
        self._verdict: Verdict = verdict

        # Will be populated by register_fix tool.
        self._registered_fixes: List[Dict[str, Any]] = []

        self.set_toolcalling_prompt()

    def set_toolcalling_prompt(self) -> None:
        """
        Replace system prompt with the Fixer toolcalling template.

        The template file is optional; if missing/empty we fall back to a minimal prompt.
        """
        try:
            template = TOOLCALLING_PROMPT_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise FileNotFoundError(f"Toolcalling prompt file not found: {TOOLCALLING_PROMPT_PATH}")

        sev = getattr(self._verdict, "severity", None)
        severity_str = (
            sev.value if hasattr(sev, "value") else (str(sev) if sev else "unknown")
        )

        replacements = {
            "{{max_tool_turns}}": str(self.max_tool_turns),
            "{{mission_id}}": self.exploit_candidate.mission_id,
            "{{invariant_id}}": self.exploit_candidate.invariant_id,
            "{{mechanism}}": self.exploit_candidate.mechanism,
            "{{poc_path}}": self.exploit_candidate.target_file or "N/A",
            "{{poc_code}}": self.exploit_candidate.poc_code or "N/A",
            "{{verdict_is_valid}}": str(bool(self._verdict.is_valid)),
            "{{verdict_severity}}": severity_str,
            "{{verdict_reasoning}}": self._verdict.reasoning or "N/A",
        }

        prompt = template
        for k, v in replacements.items():
            prompt = prompt.replace(k, v)

        self.system_prompt = prompt
        self.messages = [ChatMessage(role=Role.SYSTEM, content=prompt)]

    def check_termination(self, response: str, python_code: str) -> bool:
        """
        Consider the Fixer flow complete after at least one registered fix.
        """
        return len(getattr(self, "_registered_fixes", []) or []) > 0

    def get_tools_module(self) -> str:
        return "kai.agents.tools.fixer_tools"

    def extract_final_result(
        self, thoughts: str, python_code: str, response: str
    ) -> AgentResponse:
        fixes = getattr(self, "_registered_fixes", []) or []
        latest_diff = fixes[-1].get("canonical_diff") if fixes else None

        return AgentResponse(
            thoughts=thoughts,
            python_block=python_code,
            suggest_fix=latest_diff,
            master_context=self.master_context,
        )

    def get_registered_fixes(self) -> List[Dict[str, Any]]:
        return list(getattr(self, "_registered_fixes", []) or [])
