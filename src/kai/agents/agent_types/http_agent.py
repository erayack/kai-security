"""
HTTPAgent - HTTP-based exploitation agent for live network services.

Makes actual HTTP requests to running services (e.g., in Docker containers)
and produces PoC code that can be wrapped for verification.
"""

from pathlib import Path
from typing import Optional, Dict, Any, List

from kai.agents import settings
from kai.agents.base import BaseAgent
from kai.agents.utils import AgentType
from kai.schemas import (
    ActorMatrix,
    AgentResponse,
    MasterContext,
    Mission,
    ExploitCandidate,
    ChatMessage,
    Role,
)


class HTTPAgentResult:
    """Result container for HTTPAgent - supports multiple findings."""

    def __init__(
        self,
        mission_id: str,
        exploits: Optional[List[Dict[str, Any]]] = None,
        request_count: int = 0,
    ):
        self.mission_id = mission_id
        self.exploits = exploits or []
        self.request_count = request_count

    @property
    def has_exploit(self) -> bool:
        """Return True if any exploit was found."""
        return len(self.exploits) > 0

    def to_exploit_candidates(self, worker_id: str) -> List[ExploitCandidate]:
        """Convert all exploits to ExploitCandidates.

        HTTP exploits are always marked as compiled=True since they don't
        need compilation - they're Python scripts that make HTTP requests.
        """
        candidates = []
        for exploit in self.exploits:
            candidates.append(
                ExploitCandidate(
                    mission_id=self.mission_id,
                    worker_id=worker_id,
                    invariant_id=exploit.get("invariant_id", ""),
                    mechanism=exploit.get("mechanism", "http_exploit"),
                    poc_code=exploit.get("poc_code", ""),
                    target_file="",  # HTTP exploits don't have a target file
                    target_function="",
                    description=exploit.get("reasoning", ""),
                    compiled=True,  # HTTP exploits are always "compiled" (Python scripts)
                    logs=exploit.get("logs", []),
                )
            )
        return candidates


class HTTPAgent(BaseAgent):
    """
    Agent that exploits live network services via HTTP requests.

    Given a mission with target host and vulnerability hints, it:
    1. Analyzes the target using code analysis tools (if dependency graph available)
    2. Makes HTTP requests to probe for vulnerabilities
    3. Produces standalone Python PoC scripts using requests library
    4. Returns ExploitCandidate if successful, None otherwise
    """

    def __init__(
        self,
        mission: Mission,
        master_context: MasterContext,
        target_hosts: Optional[dict[str, str]] = None,
        dependency_graph=None,
        actor_matrix: Optional[ActorMatrix] = None,
        max_tool_turns: Optional[int] = None,
        repo_path: Optional[str] = None,
        model: Optional[str] = None,
        use_openai: bool = False,
        execution_id: Optional[str] = None,
    ):
        # Initialize with minimal system prompt - will be replaced by set_toolcalling_prompt()
        super().__init__(
            max_tool_turns=max_tool_turns,
            repo_path=repo_path,
            model=model,
            agent_type=AgentType.HTTP,
            use_openai=use_openai,
        )

        # Store mission context
        self.mission = mission
        self.master_context = master_context
        self.dependency_graph = dependency_graph
        self.actor_matrix = actor_matrix
        self.workspace_path: Optional[str] = repo_path

        # HTTP-specific configuration - dict of service name -> URL
        self.target_hosts = target_hosts or {}

        if execution_id:
            self.execution_id = execution_id

        # Track HTTP requests made
        self._request_count = 0

    def set_toolcalling_prompt(
        self,
        extra_instructions: str = "",
    ):
        """
        Replace system prompt with the HTTP agent toolcalling template.

        This should be called before chat_with_tools() to set up
        the proper prompt format for native OpenAI tool calling.

        Args:
            extra_instructions: Additional instructions (e.g., task-specific hints)
        """
        try:
            template = settings.HTTP_AGENT_PROMPT_PATH.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise FileNotFoundError(
                f"HTTP agent prompt not found at {settings.HTTP_AGENT_PROMPT_PATH}"
            )

        # Get invariant info if available
        invariant = self.mission.invariant if self.mission else None
        invariant_id = invariant.id if invariant else "N/A"
        invariant_rule = invariant.rule if invariant else "N/A"

        # Format actor context for auth/privilege analysis
        actor_lines = []
        if self.actor_matrix:
            for role in self.actor_matrix.roles:
                privs = [p.name for p in role.privileges[:5]]
                if len(role.privileges) > 5:
                    privs.append(f"... +{len(role.privileges) - 5} more")
                actor_lines.append(
                    f"- {role.name} (trust: {role.trust}): can call [{', '.join(privs)}]"
                )
        actor_context = (
            "\n".join(actor_lines) if actor_lines else "No actor information available"
        )

        # Format target hosts for display
        target_hosts_display = (
            "\n".join(f"  - {name}: {url}" for name, url in self.target_hosts.items())
            if self.target_hosts
            else "  (none configured)"
        )

        # Substitute template variables
        replacements = {
            "{{max_tool_turns}}": str(self.max_tool_turns),
            "{{target_hosts}}": target_hosts_display,
            "{{invariant_id}}": invariant_id,
            "{{invariant_rule}}": invariant_rule,
            "{{actor_context}}": actor_context,
            "{{extra_instructions}}": extra_instructions,
        }
        prompt = template
        for key, value in replacements.items():
            prompt = prompt.replace(key, value)

        # Replace system message
        self.system_prompt = prompt
        self.messages = [ChatMessage(role=Role.SYSTEM, content=prompt)]

    def check_termination(self, response: str, python_code: str) -> bool:
        """HTTPAgent with native tool calling terminates when model stops calling tools."""
        # Termination is handled by chat_with_tools() when no more tool calls
        return False

    def get_tools_module(self) -> str:
        """Return the tools module for HTTPAgent."""
        return "kai.agents.tools.http_tools"

    def extract_final_result(
        self, thoughts: str, python_code: str, response: str
    ) -> AgentResponse:
        """
        Extract the final result from HTTPAgent's work.

        Reads findings from _registered_exploits populated by register_http_exploit tool.
        """
        import json
        from datetime import datetime

        # Get findings from register_http_exploit tool calls
        registered = getattr(self, "_registered_exploits", [])
        mission_id = self.mission.mission_id if self.mission else "unknown"

        # Store result for later retrieval
        self.http_result = HTTPAgentResult(
            mission_id=mission_id,
            exploits=registered,
            request_count=self._request_count,
        )

        # Save findings to JSON
        if registered:
            output_dir = (
                Path(self.repo_path).parent if self.repo_path else Path("output")
            )
            output_dir = output_dir / "findings"
            output_dir.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = output_dir / f"http_{mission_id}_{timestamp}.json"

            output_data = {
                "mission_id": mission_id,
                "target_hosts": self.target_hosts,
                "timestamp": timestamp,
                "request_count": self._request_count,
                "exploits": registered,
            }

            with open(output_file, "w") as f:
                json.dump(output_data, f, indent=2, default=str)

        return AgentResponse(
            thoughts=thoughts,
            python_block=python_code,
            master_context=self.master_context,
        )

    def get_exploit_candidates(self) -> List[ExploitCandidate]:
        """
        Get all ExploitCandidates found.

        Call this after chat() completes.
        """
        if not hasattr(self, "http_result"):
            return []
        return self.http_result.to_exploit_candidates(self.agent_id)

    def get_result(self) -> Optional[HTTPAgentResult]:
        """Get the full HTTPAgentResult after chat() completes."""
        return getattr(self, "http_result", None)

    def increment_request_count(self) -> None:
        """Increment the HTTP request counter."""
        self._request_count += 1
