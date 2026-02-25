"""Abstract base class for state management."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kai.state.models import (
    ExploitRecord,
    FixRecord,
    RunRecord,
    StatusUpdate,
)


class StateManager(ABC):
    """Abstract interface for persisting run state.

    Implementations may store data in local files, MongoDB, etc.
    All methods are synchronous — callers are responsible for
    wrapping in async if needed.
    """

    # -- Run lifecycle --

    @abstractmethod
    def create_run(self, record: RunRecord) -> None:
        """Persist a new run record."""

    @abstractmethod
    def update_run(self, run_id: str, **fields: object) -> None:
        """Update fields on an existing run record."""

    @abstractmethod
    def get_run(self, run_id: str) -> RunRecord | None:
        """Return the run record, or ``None`` if not found."""

    # -- Progress tracking --

    @abstractmethod
    def add_status_update(self, update: StatusUpdate) -> None:
        """Append a status update for a run."""

    @abstractmethod
    def get_status_updates(
        self,
        run_id: str,
        last_n: int = 1,
    ) -> list[StatusUpdate]:
        """Return the last *n* status updates for a run."""

    # -- Exploits --

    @abstractmethod
    def add_exploit(self, exploit: ExploitRecord) -> None:
        """Persist a new exploit record."""

    @abstractmethod
    def update_exploit(self, run_id: str, exploit_id: str, **fields: object) -> None:
        """Update fields on an existing exploit record."""

    @abstractmethod
    def find_exploit(
        self,
        run_id: str,
        hypothesis: str,
        file: str,
        function: str,
    ) -> ExploitRecord | None:
        """Look up an exploit by its identifying triple."""

    @abstractmethod
    def get_exploits(
        self,
        run_id: str,
        status: str | None = None,
    ) -> list[ExploitRecord]:
        """Return exploits for a run, optionally filtered by status."""

    # -- Fixes --

    @abstractmethod
    def add_fix(self, fix: FixRecord) -> None:
        """Persist a new fix record."""

    @abstractmethod
    def get_fixes(self, run_id: str) -> list[FixRecord]:
        """Return all fixes for a run."""

    # -- Rollouts --

    @abstractmethod
    def open_rollout(
        self,
        run_id: str,
        agent_name: str,
        depth: int,
        metadata: dict[str, object],
    ) -> None:
        """Write a metadata entry to start a new rollout file."""

    @abstractmethod
    def save_rollout_iteration(
        self,
        run_id: str,
        agent_name: str,
        iteration: dict[str, object],
        num: int,
    ) -> None:
        """Append an iteration entry to an agent's rollout file."""

    @abstractmethod
    def save_rollout_result(
        self,
        run_id: str,
        agent_name: str,
        result: dict[str, object],
    ) -> None:
        """Append a final-result entry to an agent's rollout file."""

    # -- Summarization --

    @abstractmethod
    def summarize_progress(self, run_id: str) -> str:
        """Return a human-readable progress summary for a run."""
