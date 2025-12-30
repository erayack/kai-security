"""
Blackbox Agent Evaluation Package.

Provides tools for evaluating the Blackbox Agent -> Invariant Synthesizer pipeline:
- Post-hoc duplicate detection (parallel LLM-based)
- Metrics collection and reporting
- Standalone execution
"""

from evaluation.schemas import (
    EvaluationRecord,
    BlackboxEvaluationMetrics,
    BlackboxEvaluationReport,
)
from evaluation.evaluator import BlackboxEvaluator
from evaluation.post_hoc_deduplicator import PostHocDeduplicator
from evaluation.metrics_collector import BlackboxMetricsCollector
from evaluation.runner import BlackboxEvaluationRunner

__all__ = [
    # Schemas
    "EvaluationRecord",
    "BlackboxEvaluationMetrics",
    "BlackboxEvaluationReport",
    # Core components
    "BlackboxEvaluator",
    "PostHocDeduplicator",
    "BlackboxMetricsCollector",
    # Runner
    "BlackboxEvaluationRunner",
]
