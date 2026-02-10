"""
Abstract state manager for Kai persistence operations.

Implementations can handle local file storage, MongoDB/S3, or other backends.
Passed to Dispatcher to decouple business logic from persistence.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Literal

from kai.schemas import (
    ActorMatrix,
    ExploitCandidate,
    Fix,
    Invariant,
    Mission,
    Observation,
    Verdict,
    CampaignBrief,
    MasterContext,
    ProtocolManifesto,
)


@dataclass
class BootArtifacts:
    """Cached boot artifacts returned by get_prior_boot_artifacts()."""

    master_context: MasterContext
    actor_matrix: ActorMatrix
    manifesto: Optional[ProtocolManifesto] = None
    dependency_graph: Any = None  # DependencyGraph (avoid circular import)


class KaiStateManager(ABC):
    """
    Abstract state manager for Kai persistence operations.

    Implementations handle where/how data is stored (local files, MongoDB, S3, etc.).
    The Dispatcher and agents call these methods at appropriate points without
    needing to know the storage details.

    Example implementations:
        - LocalStateManager: Saves to JSON files in output/
        - MongoStateManager: Saves to MongoDB collections + S3 for large blobs
    """

    def __init__(self, execution_id: str):
        """
        Args:
            execution_id: The execution identifier this manager is bound to
        """
        self.execution_id = execution_id

    @abstractmethod
    async def update_state(
        self, state: Literal["setup", "profiler", "invariant"]
    ) -> None:
        pass

    @abstractmethod
    async def save_campaigns(self, campaigns: List[CampaignBrief]) -> bool:
        """
        Save campaign briefs.

        Args:
            campaigns: List of campaign briefs to save

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_dependency_graph(self, graph_data: Dict[str, Any]) -> bool:
        """
        Save the dependency graph.

        Args:
            graph_data: Serialized dependency graph data

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_actor_matrix(self, actor_matrix: ActorMatrix) -> bool:
        """
        Save the actor matrix.

        Args:
            actor_matrix: The actor matrix to save

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_invariants(self, invariants: List[Invariant]) -> bool:
        """
        Save discovered invariants.

        Args:
            invariants: List of invariants to save

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_missions(self, missions: List[Mission]) -> bool:
        """
        Save missions.

        Args:
            missions: List of missions to save

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def update_mission_status(
        self,
        mission_id: str,
        status: str,
        error: Optional[str] = None,
    ) -> bool:
        """
        Update a mission's status.

        Args:
            mission_id: The mission identifier
            status: New status (pending, in_progress, completed, failed)
            error: Optional error message if failed

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_exploit_candidate(self, candidate: ExploitCandidate) -> bool:
        """
        Save an exploit candidate.

        Args:
            candidate: The exploit candidate to save

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_verdict(self, verdict: Verdict) -> bool:
        """
        Save a verification verdict.

        Args:
            verdict: The verdict to save

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_fix(self, fix: Fix) -> bool:
        """
        Save a code fix for a verified exploit.

        Args:
            fix: The Fix object to save

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def update_exploit_dedupe_id(
        self,
        mission_id: str,
        invariant_id: str,
        dedupe_id: str,
    ) -> bool:
        """
        Update the dedupe_id field on an exploit candidate.

        Called during deduplication to mark duplicate exploits.
        The implementation should find the representative exploit by its
        mission_id and use that exploit's document ID as the dedupeId.

        Args:
            mission_id: The mission_id of the duplicate exploit
            invariant_id: The invariant_id of the duplicate exploit
            dedupe_id: The mission_id of the representative/original exploit

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_observations(self, observations: List[Observation]) -> bool:
        """
        Save observations from blackbox exploration.

        Args:
            observations: List of observations to save

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_conversation(
        self,
        agent_id: str,
        agent_type: str,
        messages: List[Dict[str, Any]],
        metadata: Dict[str, Any],
    ) -> Optional[str]:
        """
        Save an agent's conversation history.

        Args:
            agent_id: The agent's unique identifier
            agent_type: Type of agent (state, quant, blackbox, verifier, etc.)
            messages: List of conversation messages
            metadata: Additional metadata (tokens, cost, time, etc.)

        Returns:
            Path or URI where conversation was saved, or None if failed
        """
        pass

    @abstractmethod
    async def save_master_context(
        self,
        context: MasterContext,
    ) -> bool:
        """
        Save the master context for the current execution.

        Args:
            context: The MasterContext object to save
        Returns:
            True if successful
        """
        pass

    @abstractmethod
    async def save_protocol_manifesto(
        self,
        manifesto: ProtocolManifesto,
    ) -> bool:
        """
        Save the protocol manifesto.

        Args:
            manifesto: The ProtocolManifesto object to save
        Returns:
            True if successful
        """
        pass

    # ------------------------------------------------------------------
    # Iterative-run query methods
    # ------------------------------------------------------------------
    # These replace direct snapshot loading. The state manager owns the
    # comparison logic (commit hash in prod, source-file hash locally).

    @abstractmethod
    async def has_prior_run(self) -> bool:
        """Whether a prior run snapshot exists for this repo."""
        pass

    @abstractmethod
    async def has_source_changed(self, repo_path: str) -> bool:
        """
        Whether source code changed since the last run.

        Backend implementations compare commit hashes; local implementations
        may fall back to source-file hashing.

        Args:
            repo_path: Path to the repository (used by local fallback).

        Returns:
            True if source changed or unknown (safe default).
        """
        pass

    @abstractmethod
    async def has_graph_changed(self, graph_hash: str) -> bool:
        """
        Whether the dependency graph changed since the last run.

        Args:
            graph_hash: Hash of the current dependency graph.

        Returns:
            True if graph changed or no prior exists.
        """
        pass

    @abstractmethod
    async def get_prior_invariants(
        self, *, exclude_blocked: bool = False
    ) -> List[Invariant]:
        """
        Return invariants from the prior run.

        Args:
            exclude_blocked: If True, omit invariants whose verdicts were
                blocked by a root-cause issue (so they can be re-eligible).
        """
        pass

    @abstractmethod
    async def get_prior_verdicts(self) -> List[Verdict]:
        """Return all verdicts from the prior run."""
        pass

    @abstractmethod
    async def get_prior_boot_artifacts(self) -> Optional[BootArtifacts]:
        """
        Return cached boot artifacts from the prior run.

        Used to rebuild BootResult when skipping LLM steps.
        Returns None if no prior run or artifacts are incomplete.
        """
        pass

    @abstractmethod
    async def save_graph_hash(self, graph_hash: str) -> bool:
        """
        Register the dependency-graph hash for the current run.

        All actual data (invariants, verdicts, boot artifacts) is persisted
        individually via their own ``save_*`` methods during the pipeline.
        This only stores the graph hash so future runs can detect changes.
        """
        pass
