"""
Blackbox Metrics Collector.

Collects metrics and records throughout the Blackbox Agent evaluation pipeline.
Tracks: Observation -> Synthesized Invariant

Note: Duplicate detection is handled post-hoc by PostHocDeduplicator.
"""

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional

from evaluation.schemas import (
    BlackboxEvaluationMetrics,
    BlackboxEvaluationReport,
    EvaluationRecord,
)
from kai.schemas import Invariant, Observation


class BlackboxMetricsCollector:
    """
    Collects metrics and records throughout the Blackbox Agent evaluation pipeline.

    Tracks: Observation -> Synthesized Invariant

    Note: Duplicate detection is handled post-hoc by PostHocDeduplicator.
    """

    def __init__(
        self,
        execution_id: str,
        baseline_invariant_ids: Optional[List[str]] = None,
    ):
        """
        Initialize the metrics collector.

        Args:
            execution_id: Unique identifier for this evaluation run.
            baseline_invariant_ids: List of baseline invariant IDs for reference.
        """
        self.execution_id = execution_id
        self.baseline_invariant_ids = baseline_invariant_ids or []

        # Unified records indexed by observation ID
        self._records: Dict[str, EvaluationRecord] = {}

        # Running counters
        self._metrics = BlackboxEvaluationMetrics()

    def _generate_observation_id(self, obs: Observation) -> str:
        """Generate deterministic ID for observation."""
        raw = f"{obs.worker_id}|{obs.mission_id}|{obs.description[:100]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def record_observation(self, obs: Observation) -> str:
        """
        Record an observation from Blackbox Agent.

        Args:
            obs: The observation to record.

        Returns:
            Generated observation ID.
        """
        obs_id = self._generate_observation_id(obs)

        # Create unified record
        self._records[obs_id] = EvaluationRecord(
            observation_id=obs_id,
            mission_id=obs.mission_id,
            worker_id=obs.worker_id,
            description_preview=obs.description[:200] if obs.description else "",
            anomaly_type=obs.anomaly_type,
        )

        self._metrics.total_observations += 1

        return obs_id

    def record_synthesis_result(
        self,
        obs_id: str,
        invariant: Optional[Invariant],
        error: Optional[str] = None,
    ) -> None:
        """
        Record result of invariant synthesis from observation.

        Args:
            obs_id: The observation ID.
            invariant: The synthesized invariant (None if synthesis failed).
            error: Error message if synthesis failed.
        """
        if obs_id not in self._records:
            return

        record = self._records[obs_id]

        if invariant:
            record.synthesis_success = True
            record.invariant_id = invariant.id
            record.invariant_type = (
                invariant.type.value
                if hasattr(invariant.type, "value")
                else str(invariant.type)
            )
            record.rule = invariant.rule
            record.confidence = invariant.confidence
            record.target_function_count = len(invariant.target_function_ids or [])
            record.target_var_count = len(invariant.target_var_ids or [])
            record.target_file_count = len(invariant.target_file_ids or [])
            self._metrics.observations_with_synthesis += 1
            self._metrics.total_synthesized += 1
        else:
            record.synthesis_success = False
            record.synthesis_error = error
            self._metrics.observations_without_synthesis += 1

    def compute_final_metrics(self) -> BlackboxEvaluationMetrics:
        """Compute final aggregated metrics."""
        metrics = self._metrics

        # Compute rates
        if metrics.total_observations > 0:
            metrics.observation_to_invariant_rate = (
                metrics.total_synthesized / metrics.total_observations
            )

        return metrics

    def generate_report(
        self,
        repo_path: Optional[str] = None,
    ) -> BlackboxEvaluationReport:
        """
        Generate complete evaluation report.

        Note: Duplicate detection is handled post-hoc by PostHocDeduplicator.

        Args:
            repo_path: Path to the repository being evaluated.

        Returns:
            Complete evaluation report.
        """
        return BlackboxEvaluationReport(
            execution_id=self.execution_id,
            generated_at=datetime.now(timezone.utc),
            repo_path=repo_path,
            metrics=self.compute_final_metrics(),
            records=list(self._records.values()),
            baseline_invariant_count=len(self.baseline_invariant_ids),
            baseline_invariant_ids=self.baseline_invariant_ids,
        )
