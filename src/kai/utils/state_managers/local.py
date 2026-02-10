from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from kai.schemas import (
    ActorMatrix,
    CampaignBrief,
    ExploitCandidate,
    Fix,
    Invariant,
    MasterContext,
    Mission,
    Observation,
    ProtocolManifesto,
    Verdict,
)
from kai.state_manager import BootArtifacts, KaiStateManager


# ---------------------------------------------------------------------------
# Local-only snapshot model (internal persistence format)
# ---------------------------------------------------------------------------


class _RunSnapshot(BaseModel):
    """Internal snapshot format for JSON persistence. Not exported."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    graph_hash: str
    source_hash: str = ""
    adapter: str = ""
    master_context: Optional[MasterContext] = None
    invariants: List[Invariant] = Field(default_factory=list)
    verdicts: List[Verdict] = Field(default_factory=list)
    manifesto: Optional[ProtocolManifesto] = None
    actor_matrix: Optional[ActorMatrix] = None
    dependency_graph: Optional[Any] = None
    timestamp: str = ""

    @model_validator(mode="before")
    @classmethod
    def _deserialize_graph(cls, data: Any) -> Any:
        if isinstance(data, dict):
            raw = data.get("dependency_graph")
            if isinstance(raw, dict):
                from kai.utils.dependency.graph import DependencyGraph

                data["dependency_graph"] = DependencyGraph.from_dict(raw)
        return data

    def model_dump(self, **kwargs: Any) -> Dict[str, Any]:
        d = super().model_dump(**kwargs)
        if self.dependency_graph is not None:
            d["dependency_graph"] = self.dependency_graph.to_dict()
        return d


# ---------------------------------------------------------------------------
# Source-file hashing (local-only change detection)
# ---------------------------------------------------------------------------

_SOURCE_EXTENSIONS: dict[str, list[str]] = {
    "solidity": [".sol", ".toml"],
    "python": [".py", ".toml", ".cfg"],
    "typescript": [".ts", ".tsx"],
    "javascript": [".js", ".jsx"],
    "c": [".c", ".h", ".cmake"],
}

_CONFIG_FILES: dict[str, list[str]] = {
    "solidity": ["remappings.txt"],
    "python": ["pyproject.toml", "setup.cfg", "setup.py"],
    "typescript": ["package.json", "tsconfig.json"],
    "javascript": ["package.json"],
    "c": ["CMakeLists.txt", "Makefile"],
}

_SKIP_DIRS = {
    "test", "tests", "lib", "node_modules", "out", "build",
    "cache", "artifacts", ".git", "__pycache__", "script",
}


def _hash_source_files(repo_path: str, adapter: str) -> str:
    """Hash source files to detect changes without compilation."""
    exts = _SOURCE_EXTENSIONS.get(adapter.lower(), [])
    if not exts:
        return ""

    root = Path(repo_path).resolve()
    hasher = hashlib.sha256()

    for ext in sorted(exts):
        for f in sorted(root.rglob(f"*{ext}")):
            parts = set(f.relative_to(root).parts)
            if parts & _SKIP_DIRS:
                continue
            hasher.update(str(f.relative_to(root)).encode())
            hasher.update(f.read_bytes())

    for cfg in sorted(_CONFIG_FILES.get(adapter.lower(), [])):
        cfg_path = root / cfg
        if cfg_path.exists():
            hasher.update(cfg.encode())
            hasher.update(cfg_path.read_bytes())

    return hasher.hexdigest()[:24]


# ---------------------------------------------------------------------------
# LocalStateManager
# ---------------------------------------------------------------------------


class LocalStateManager(KaiStateManager):
    """
    Local JSON-backed KaiStateManager.

    Currently, only `save_conversation` is used by tests. Other methods are implemented
    as minimal no-ops to satisfy the abstract interface without expanding scope.
    """

    def __init__(
        self,
        execution_id: str,
        *,
        output_dir: Optional[str | Path] = None,
        repo_path: Optional[str | Path] = None,
    ):
        super().__init__(execution_id=execution_id)
        self._output_dir = Path(output_dir) if output_dir is not None else None
        self._repo_path = str(Path(repo_path).resolve()) if repo_path else None

    def _project_root(self) -> Path:
        # kai/utils/state_managers/local.py -> .../kai/utils/state_managers -> .../kai/utils -> .../kai -> <repo_root>
        return Path(__file__).resolve().parents[3]

    def _conversations_root(self) -> Path:
        if self._output_dir is not None:
            return self._output_dir
        return self._project_root() / "output" / "conversations"

    def _normalize_relative_convo_path(self, rel: str) -> Path:
        """
        Normalize caller-provided relative path so it is rooted under output/conversations.

        Examples:
        - "conversations/fixer_convo.json" -> "fixer_convo.json"
        - "output/conversations/fixer_convo.json" -> "fixer_convo.json"
        """
        p = Path(rel)
        parts = list(p.parts)
        if parts[:1] == ["conversations"]:
            parts = parts[1:]
        if parts[:2] == ["output", "conversations"]:
            parts = parts[2:]
        return Path(*parts) if parts else Path("conversation.json")

    async def update_state(
        self, state: Literal["setup", "profiler", "invariant"]
    ) -> None:
        return None

    async def save_campaigns(self, campaigns: List[CampaignBrief]) -> bool:
        return True

    async def save_dependency_graph(self, graph_data: Dict[str, Any]) -> bool:
        return True

    async def save_actor_matrix(self, actor_matrix: ActorMatrix) -> bool:
        return True

    async def save_invariants(self, invariants: List[Invariant]) -> bool:
        return True

    async def save_missions(self, missions: List[Mission]) -> bool:
        return True

    async def update_mission_status(
        self,
        mission_id: str,
        status: str,
        error: Optional[str] = None,
    ) -> bool:
        return True

    async def save_exploit_candidate(self, candidate: ExploitCandidate) -> bool:
        return True

    async def save_verdict(self, verdict: Verdict) -> bool:
        return True

    async def save_fix(self, fix: Fix) -> bool:
        return True

    async def save_observations(self, observations: List[Observation]) -> bool:
        return True

    async def update_exploit_dedupe_id(
        self,
        mission_id: str,
        invariant_id: str,
        dedupe_id: str,
    ) -> bool:
        return True

    async def save_master_context(self, context: MasterContext) -> bool:
        return True

    async def save_protocol_manifesto(self, manifesto: ProtocolManifesto) -> bool:
        return True

    # ------------------------------------------------------------------
    # Iterative-run queries (local JSON-backed)
    # ------------------------------------------------------------------

    def _load_snapshot(self) -> Optional[_RunSnapshot]:
        """Load the prior snapshot from disk."""
        if self._output_dir is None:
            return None
        path = self._output_dir / "snapshot.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return _RunSnapshot.model_validate(data)

    async def has_prior_run(self) -> bool:
        return self._load_snapshot() is not None

    async def has_source_changed(self, repo_path: str) -> bool:
        snapshot = self._load_snapshot()
        if not snapshot or not snapshot.source_hash or not snapshot.adapter:
            return True  # Unknown → assume changed
        # Always hash the original repo (where user applies fixes),
        # not the testbed workspace (master_context.root_path).
        current = _hash_source_files(repo_path, snapshot.adapter)
        return current != snapshot.source_hash

    async def has_graph_changed(self, graph_hash: str) -> bool:
        snapshot = self._load_snapshot()
        if not snapshot:
            return True
        return snapshot.graph_hash != graph_hash

    async def get_prior_invariants(
        self, *, exclude_blocked: bool = False
    ) -> List[Invariant]:
        snapshot = self._load_snapshot()
        if not snapshot:
            return []
        if not exclude_blocked:
            return list(snapshot.invariants)
        blocked_ids = {
            v.invariant_id for v in snapshot.verdicts if v.blocked_by_root_cause
        }
        return [inv for inv in snapshot.invariants if inv.id not in blocked_ids]

    async def get_prior_verdicts(self) -> List[Verdict]:
        snapshot = self._load_snapshot()
        if not snapshot:
            return []
        return list(snapshot.verdicts)

    async def get_prior_boot_artifacts(self) -> Optional[BootArtifacts]:
        snapshot = self._load_snapshot()
        if not snapshot or not snapshot.actor_matrix or not snapshot.master_context:
            return None
        return BootArtifacts(
            master_context=snapshot.master_context,
            actor_matrix=snapshot.actor_matrix,
            manifesto=snapshot.manifesto,
            dependency_graph=snapshot.dependency_graph,
        )

    async def save_run_data(
        self,
        *,
        graph_hash: str,
        adapter: str,
        master_context: Optional[MasterContext],
        invariants: List[Invariant],
        verdicts: List[Verdict],
        manifesto: Optional[ProtocolManifesto],
        actor_matrix: Optional[ActorMatrix],
        dependency_graph: Any,
    ) -> bool:
        if self._output_dir is None:
            return False

        source_hash = ""
        if self._repo_path and adapter:
            source_hash = _hash_source_files(self._repo_path, adapter)

        snapshot = _RunSnapshot(
            graph_hash=graph_hash,
            source_hash=source_hash,
            adapter=adapter,
            master_context=master_context,
            invariants=invariants,
            verdicts=verdicts,
            manifesto=manifesto,
            actor_matrix=actor_matrix,
            dependency_graph=dependency_graph,
        )
        self._output_dir.mkdir(parents=True, exist_ok=True)
        (self._output_dir / "snapshot.json").write_text(
            json.dumps(snapshot.model_dump(), indent=2, default=str),
            encoding="utf-8",
        )
        return True

    async def save_conversation(
        self,
        agent_id: str,
        agent_type: str,
        messages: List[Dict[str, Any]],
        metadata: Dict[str, Any],
    ) -> Optional[str]:
        """
        Save an agent's conversation history to a JSON file.

        If `metadata` contains a `conversation_path` key, we treat it as a caller-provided
        relative path (e.g. "conversations/fixer_convo.json") and normalize it under
        output/conversations.
        """
        try:
            convo_root = self._conversations_root()
            convo_root.mkdir(parents=True, exist_ok=True)

            requested = metadata.get("conversation_path") or metadata.get("path")
            if isinstance(requested, str) and requested.strip():
                rel = self._normalize_relative_convo_path(requested.strip())
                out_path = convo_root / rel
            else:
                out_path = convo_root / f"{agent_type}_{agent_id}.json"

            out_path.parent.mkdir(parents=True, exist_ok=True)

            payload = {
                "execution_id": self.execution_id,
                "agent_id": agent_id,
                "agent_type": agent_type,
                "metadata": metadata,
                "messages": messages,
            }

            def _json_default(obj: Any):
                # Make persistence robust to common non-JSON-native types (Enums, Paths,
                # and Pydantic models). Fallback to string for anything else.
                if isinstance(obj, Enum):
                    return obj.value
                if isinstance(obj, Path):
                    return str(obj)
                if isinstance(obj, BaseModel):
                    return obj.model_dump(mode="json")
                return str(obj)

            out_path.write_text(
                json.dumps(payload, indent=2, default=_json_default), encoding="utf-8"
            )
            return str(out_path)
        except Exception:
            return None
