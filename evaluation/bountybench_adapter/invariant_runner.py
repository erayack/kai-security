"""BountyBench invariant execution and validation.

This module handles running BountyBench's invariant scripts and checking
results against defined thresholds to ensure exploits don't break invariants.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from evaluation.bountybench_adapter.task_loader import TaskLoader

logger = logging.getLogger(__name__)


@dataclass
class InvariantResult:
    """Result of running invariant checks."""

    success: bool
    scores: dict[str, float] = field(default_factory=dict)
    thresholds: dict[str, float] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    output: str = ""


class InvariantRunner:
    """Execute and validate BountyBench invariant scripts.

    BountyBench uses invariant scripts to ensure that:
    1. Exploits don't break core functionality
    2. Patches maintain invariants while fixing vulnerabilities

    Invariant scripts output scores to invariant_scores.json, which
    are compared against thresholds defined in metadata.
    """

    TIMEOUT = 5400  # 90 minutes (matches BountyBench default)
    RETRIES = 3

    def __init__(self, task_loader: "TaskLoader"):
        """Initialize invariant runner.

        Args:
            task_loader: TaskLoader for accessing task metadata
        """
        self.task_loader = task_loader

    def run_repo_invariants(self) -> InvariantResult:
        """Execute run_repo_invariants.sh and validate against thresholds.

        Returns:
            InvariantResult with scores, thresholds, and validation status
        """
        script = self.task_loader.task_dir / "run_repo_invariants.sh"
        if not script.exists():
            logger.debug(f"No repo invariants script at {script}")
            return InvariantResult(success=True)  # No invariants = pass

        # Get thresholds from metadata
        metadata = self.task_loader.get_task_metadata()
        thresholds = metadata.get("invariant_thresholds", {})

        # Run script (with retries)
        scores, output = self._run_invariant_script(script)

        # Check thresholds (script existed since we got here)
        success, failures = self._check_thresholds(
            scores, thresholds, script_existed=True
        )

        return InvariantResult(
            success=success,
            scores=scores,
            thresholds=thresholds,
            failures=failures,
            output=output,
        )

    def run_bounty_invariants(self, bounty_id: str) -> InvariantResult:
        """Execute run_bounty_invariants.sh for a specific bounty.

        Args:
            bounty_id: Bounty identifier

        Returns:
            InvariantResult with scores and validation status
        """
        script = (
            self.task_loader.task_dir
            / "bounties"
            / bounty_id
            / "run_bounty_invariants.sh"
        )
        if not script.exists():
            logger.debug(f"No bounty invariants script for {bounty_id}")
            return InvariantResult(success=True)

        # Bounty metadata doesn't currently have thresholds, use empty dict
        # Future: could extract from bounty.metadata if available
        thresholds: dict[str, float] = {}

        # Run script
        scores, output = self._run_invariant_script(script)

        # Check thresholds (script existed since we got here)
        success, failures = self._check_thresholds(
            scores, thresholds, script_existed=True
        )

        return InvariantResult(
            success=success,
            scores=scores,
            thresholds=thresholds,
            failures=failures,
            output=output,
        )

    def _run_invariant_script(self, script: Path) -> tuple[dict[str, float], str]:
        """Run invariant script and parse output.

        Args:
            script: Path to the invariant script

        Returns:
            Tuple of (scores dict, combined output string)
        """
        combined_output = ""

        for attempt in range(self.RETRIES):
            try:
                logger.info(
                    f"Running invariant script (attempt {attempt + 1}/{self.RETRIES}): {script}"
                )
                result = subprocess.run(
                    ["bash", str(script)],
                    cwd=script.parent,
                    capture_output=True,
                    text=True,
                    timeout=self.TIMEOUT,
                )

                combined_output = result.stdout + result.stderr

                # Parse invariant_scores.json from script directory
                scores_file = script.parent / "invariant_scores.json"
                if scores_file.exists():
                    try:
                        data = json.loads(scores_file.read_text())
                        scores = data.get("invariant_scores", {})
                        # Ensure all scores are floats
                        scores = {
                            k: float(v)
                            for k, v in scores.items()
                            if isinstance(v, (int, float))
                        }
                        logger.info(f"Invariant scores: {scores}")
                        return scores, combined_output
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse invariant_scores.json: {e}")
                else:
                    logger.warning(f"No invariant_scores.json found at {scores_file}")

            except subprocess.TimeoutExpired:
                logger.warning(
                    f"Invariant script timed out (attempt {attempt + 1}/{self.RETRIES})"
                )
            except Exception as e:
                logger.warning(f"Invariant script failed (attempt {attempt + 1}): {e}")

        logger.error(f"All {self.RETRIES} invariant attempts failed")
        return {}, combined_output

    def _check_thresholds(
        self,
        scores: dict[str, float],
        thresholds: dict[str, float],
        script_existed: bool = True,
    ) -> tuple[bool, list[str]]:
        """Compare scores against thresholds.

        Args:
            scores: Actual scores from invariant script
            thresholds: Required minimum thresholds
            script_existed: Whether an invariant script was found and run

        Returns:
            Tuple of (success bool, list of failure messages)
        """
        failures: list[str] = []

        # CRITICAL FIX (8.2): If invariant script ran but returned no scores,
        # that's suspicious and should be flagged as a failure rather than
        # silently passing due to empty thresholds.
        if script_existed and not scores:
            failures.append(
                "Invariant script ran but returned no scores - script may have failed"
            )
            logger.warning("Invariant script returned no scores - treating as failure")

        for key, threshold in thresholds.items():
            if key not in scores:
                failures.append(f"Missing score for '{key}'")
            elif not isinstance(scores[key], (int, float)):
                failures.append(f"Non-numeric score for '{key}': {scores[key]}")
            elif scores[key] < threshold:
                failures.append(f"{key}: {scores[key]} < {threshold} (threshold)")

        if failures:
            logger.warning(f"Invariant threshold failures: {failures}")
        else:
            logger.info("All invariant thresholds passed")

        return len(failures) == 0, failures
