"""Report generation for BountyBench runs.

This module generates comprehensive JSON reports from Kai dispatcher
results and BountyBench verification outcomes.
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from kai.dispatcher.core import Dispatcher
    from kai.schemas import ExploitCandidate, Verdict

    from evaluation.bountybench_adapter.detect_indicator import DetectIndicatorResult
    from evaluation.bountybench_adapter.invariant_runner import InvariantResult
    from evaluation.bountybench_adapter.task_loader import TaskLoader
    from evaluation.bountybench_adapter.verifier import VerificationResult

logger = logging.getLogger(__name__)


@dataclass
class BountyResult:
    """Result for a single bounty."""

    bounty_id: str
    cwe: str
    cve: str
    severity: float
    claimed: bool  # Exploit was generated
    verified: bool  # Verified by verify.sh
    disclosure_bounty_usd: float = 0.0
    exploit_script_path: str | None = None
    verification_output: str | None = None
    error: str | None = None


@dataclass
class BountyBenchReport:
    """Comprehensive report for a BountyBench run."""

    # Task metadata
    task_name: str
    target_host: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_seconds: float = 0.0

    # Summary counts
    total_bounties: int = 0
    bounties_claimed: int = 0  # Exploits generated
    bounties_verified: int = 0  # Verified by verify.sh

    # Bounty dollar tracking
    total_bounty_available_usd: float = 0.0  # Sum of all bounty disclosure values
    total_bounty_claimed_usd: float = 0.0  # Sum of verified bounty disclosure values

    # Kai findings summary
    total_findings: int = 0
    verified_findings: int = 0  # Verified by Kai's verifier

    # Cost tracking
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_cost_usd: float = 0.0

    # Detailed results
    bounty_results: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)  # ExploitCandidates
    verdicts: list[dict[str, Any]] = field(default_factory=list)  # Kai Verdicts
    fixes: list[dict[str, Any]] = field(default_factory=list)  # Generated fixes

    # Token usage breakdown
    token_usage_by_phase: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Invariant results
    invariant_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    invariants_passed: bool = True

    # Detect Indicator results
    detect_indicator_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    detect_indicator_passed: int = 0


class ReportGenerator:
    """Generate comprehensive reports from dispatcher results."""

    def generate(
        self,
        task_loader: "TaskLoader",
        dispatcher: "Dispatcher",
        verification_results: list["VerificationResult"],
        duration: float,
        target_host: str,
        invariant_results: dict[str, "InvariantResult"] | None = None,
        detect_indicator_results: dict[str, "DetectIndicatorResult"] | None = None,
    ) -> BountyBenchReport:
        """Generate report from dispatcher results.

        Args:
            task_loader: TaskLoader for bounty metadata
            dispatcher: Completed Dispatcher instance
            verification_results: BountyBench verification results
            duration: Total execution time in seconds
            target_host: Target host URL used
            invariant_results: Optional invariant check results
            detect_indicator_results: Optional Detect Indicator results

        Returns:
            Complete BountyBenchReport
        """
        # Get bounty info
        bounties = task_loader.get_all_bounties()
        task_name = task_loader.get_task_name()

        # Build verification lookup
        verification_lookup = {r.bounty_id: r for r in verification_results}

        # Map exploits to bounties (simplified - in practice would need better matching)
        exploit_candidates = dispatcher.exploit_candidates
        verdicts = dispatcher.verdicts
        fixes = dispatcher.fixes

        # Build bounty results
        bounty_results = []
        bounties_claimed = 0
        bounties_verified = 0

        for bounty in bounties:
            verification = verification_lookup.get(bounty.bounty_id)

            # Check if we have an exploit for this bounty
            claimed = verification is not None
            verified = verification.success if verification else False

            if claimed:
                bounties_claimed += 1
            if verified:
                bounties_verified += 1

            result = BountyResult(
                bounty_id=bounty.bounty_id,
                cwe=bounty.cwe,
                cve=bounty.cve,
                severity=bounty.severity,
                claimed=claimed,
                verified=verified,
                disclosure_bounty_usd=bounty.disclosure_bounty,
                verification_output=verification.verify_output
                if verification
                else None,
                error=verification.error if verification else None,
            )
            bounty_results.append(asdict(result))

        # Calculate bounty dollar totals
        total_bounty_available = sum(b.disclosure_bounty for b in bounties)
        total_bounty_claimed = sum(
            b.disclosure_bounty
            for b in bounties
            if verification_lookup.get(b.bounty_id)
            and verification_lookup[b.bounty_id].success
        )

        # Convert findings to dicts
        findings_dicts = []
        for candidate in exploit_candidates:
            findings_dicts.append(self._exploit_to_dict(candidate))

        # Convert verdicts to dicts
        verdicts_dicts = []
        for verdict in verdicts:
            verdicts_dicts.append(self._verdict_to_dict(verdict))

        # Convert fixes to dicts
        fixes_dicts = []
        for fix in fixes:
            fixes_dicts.append(self._fix_to_dict(fix))

        # Count verified findings (by Kai's verifier)
        verified_findings = sum(1 for v in verdicts if v.is_valid)

        # Get token usage
        total_tokens = dispatcher.total_tokens
        total_cost = dispatcher.total_cost
        token_usage_by_phase = dispatcher.token_usage_by_phase

        # Process invariant results
        invariant_dicts: dict[str, dict[str, Any]] = {}
        invariants_passed = True
        if invariant_results:
            for key, result in invariant_results.items():
                invariant_dicts[key] = {
                    "success": result.success,
                    "scores": result.scores,
                    "thresholds": result.thresholds,
                    "failures": result.failures,
                }
                if not result.success:
                    invariants_passed = False

        # Process Detect Indicator results
        detect_dicts: dict[str, dict[str, Any]] = {}
        detect_passed = 0
        if detect_indicator_results:
            for bounty_id, result in detect_indicator_results.items():
                detect_dicts[bounty_id] = {
                    "success": result.success,
                    "vulnerable_passed": result.vulnerable_passed,
                    "patched_failed": result.patched_failed,
                    "reason": result.reason,
                }
                if result.success:
                    detect_passed += 1

        return BountyBenchReport(
            task_name=task_name,
            target_host=target_host,
            duration_seconds=duration,
            total_bounties=len(bounties),
            bounties_claimed=bounties_claimed,
            bounties_verified=bounties_verified,
            total_bounty_available_usd=total_bounty_available,
            total_bounty_claimed_usd=total_bounty_claimed,
            total_findings=len(exploit_candidates),
            verified_findings=verified_findings,
            total_prompt_tokens=total_tokens.get("prompt_tokens", 0),
            total_completion_tokens=total_tokens.get("completion_tokens", 0),
            total_cost_usd=total_cost,
            bounty_results=bounty_results,
            findings=findings_dicts,
            verdicts=verdicts_dicts,
            fixes=fixes_dicts,
            token_usage_by_phase=token_usage_by_phase,
            invariant_results=invariant_dicts,
            invariants_passed=invariants_passed,
            detect_indicator_results=detect_dicts,
            detect_indicator_passed=detect_passed,
        )

    def _exploit_to_dict(self, candidate: "ExploitCandidate") -> dict[str, Any]:
        """Convert ExploitCandidate to dictionary."""
        return {
            "mission_id": candidate.mission_id,
            "worker_id": candidate.worker_id,
            "invariant_id": candidate.invariant_id,
            "invariant_ids": candidate.invariant_ids,
            "mechanism": candidate.mechanism,
            "poc_code": candidate.poc_code,
            "target_file": candidate.target_file,
            "target_function": candidate.target_function,
            "description": candidate.description,
            "compiled": candidate.compiled,
            "logs": candidate.logs,
        }

    def _verdict_to_dict(self, verdict: "Verdict") -> dict[str, Any]:
        """Convert Verdict to dictionary."""
        return {
            "mission_id": verdict.mission_id,
            "invariant_id": verdict.invariant_id,
            "worker_id": verdict.worker_id,
            "is_valid": verdict.is_valid,
            "severity": verdict.severity.value,
            "vulnerability_class": verdict.vulnerability_class,
        }

    def _fix_to_dict(self, fix: Any) -> dict[str, Any]:
        """Convert Fix to dictionary."""
        if hasattr(fix, "model_dump"):
            return fix.model_dump()
        elif hasattr(fix, "__dict__"):
            return fix.__dict__
        else:
            return {"value": str(fix)}

    def save(self, report: BountyBenchReport, output_path: str | Path) -> Path:
        """Save report as JSON.

        Args:
            report: Report to save
            output_path: Path to save the JSON file

        Returns:
            Path to saved file
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        report_dict = asdict(report)

        with open(path, "w") as f:
            json.dump(report_dict, f, indent=2, default=str)

        logger.info(f"Report saved to {path}")
        return path

    def print_summary(self, report: BountyBenchReport) -> None:
        """Print a human-readable summary of the report."""
        print("\n" + "=" * 60)
        print(f"BountyBench Report: {report.task_name}")
        print("=" * 60)

        print(f"\nTarget: {report.target_host}")
        print(f"Duration: {report.duration_seconds:.1f}s")

        print("\n--- Bounty Results ---")
        print(f"Total bounties: {report.total_bounties}")
        print(f"Exploits generated: {report.bounties_claimed}")
        print(f"Bounties verified: {report.bounties_verified}")

        if report.total_bounties > 0:
            success_rate = (report.bounties_verified / report.total_bounties) * 100
            print(f"Success rate: {success_rate:.1f}%")

        print("\n--- Kai Findings ---")
        print(f"Total findings: {report.total_findings}")
        print(f"Verified by Kai: {report.verified_findings}")

        print("\n--- Cost ---")
        print(f"Prompt tokens: {report.total_prompt_tokens:,}")
        print(f"Completion tokens: {report.total_completion_tokens:,}")
        print(f"Total cost: ${report.total_cost_usd:.4f}")

        print("\n--- Bounty Value ---")
        print(f"Available: ${report.total_bounty_available_usd:,.2f}")
        print(f"Claimed: ${report.total_bounty_claimed_usd:,.2f}")
        if report.total_cost_usd > 0:
            roi = report.total_bounty_claimed_usd / report.total_cost_usd
            print(f"ROI: {roi:.1f}x")

        if report.bounty_results:
            print("\n--- Per-Bounty Details ---")
            for br in report.bounty_results:
                status = (
                    "VERIFIED"
                    if br["verified"]
                    else ("CLAIMED" if br["claimed"] else "MISSED")
                )
                print(f"  {br['bounty_id']}: {status} ({br['cwe']})")

        # Invariant results
        if report.invariant_results:
            print("\n--- Invariant Results ---")
            print(f"Invariants passed: {'YES' if report.invariants_passed else 'NO'}")
            for key, result in report.invariant_results.items():
                status = "PASSED" if result["success"] else "FAILED"
                print(f"  {key}: {status}")
                if result["failures"]:
                    for failure in result["failures"]:
                        print(f"    - {failure}")

        # Detect Indicator results
        if report.detect_indicator_results:
            print("\n--- Detect Indicator Results ---")
            print(
                f"Passed: {report.detect_indicator_passed}/{len(report.detect_indicator_results)}"
            )
            for bounty_id, result in report.detect_indicator_results.items():
                status = "PASSED" if result["success"] else "FAILED"
                print(f"  {bounty_id}: {status}")
                if not result["success"]:
                    print(f"    Reason: {result['reason']}")

        print("\n" + "=" * 60)
