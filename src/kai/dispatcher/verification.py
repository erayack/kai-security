"""
Verification pipeline: verify exploit candidates, deduplicate by root cause,
and diff invariants across iterative runs.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel

from kai.inference import get_structured_response
from kai.schemas import (
    DedupeResponse,
    ExploitCandidate,
    Invariant,
    InvariantType,
    MasterContext,
    Mission,
    MissionAgentType,
    Verdict,
    VerifierProcessInput,
)
from kai.state_manager import KaiStateManager
from kai.utils.dependency.graph import DependencyGraph

from kai.dispatcher._helpers import persist
from kai.dispatcher.usage_tracker import UsageTracker


# ---------------------------------------------------------------------------
# LLM-based invariant diff (used by iterative runs)
# ---------------------------------------------------------------------------


class _InvariantDiffResult(BaseModel):
    baseline_id: str
    is_duplicate: bool
    reasoning: str


class _InvariantDiffResponse(BaseModel):
    results: List[_InvariantDiffResult]


def _build_diff_prompt(candidate: Invariant, baselines: List[Invariant]) -> str:
    baselines_json = []
    for b in baselines:
        baselines_json.append(
            {
                "id": b.id,
                "type": b.type.value if hasattr(b.type, "value") else str(b.type),
                "rule": b.rule,
                "explanation": (b.explanation or "")[:500],
            }
        )

    candidate_type = (
        candidate.type.value
        if hasattr(candidate.type, "value")
        else str(candidate.type)
    )

    return f"""You are checking if a NEW invariant is semantically a duplicate of any BASELINE invariants.

## Definition of Duplicate
Two invariants are DUPLICATES if they express the SAME property or constraint, even if:
- Worded differently
- Use different technical terms for the same concept
- Have slightly different scope but core property is identical

## NOT Duplicates
Invariants are NOT duplicates if they:
- Check different properties (e.g., balance vs access control)
- Apply to different contexts (e.g., deposits vs withdrawals)
- Have meaningfully different constraints

---

## NEW INVARIANT (to check):
- ID: {candidate.id}
- Type: {candidate_type}
- Rule: {candidate.rule}
- Explanation: {(candidate.explanation or "")[:500]}

## BASELINE INVARIANTS (check against each):
{json.dumps(baselines_json, indent=2)}

---

## Response Format
Respond with ONLY valid JSON:
{{
    "results": [
        {{"baseline_id": "...", "is_duplicate": true or false, "reasoning": "one sentence"}}
    ]
}}

You MUST include a result for EVERY baseline ID listed above."""


async def _is_duplicate(
    candidate: Invariant,
    prior_invariants: List[Invariant],
    model: str,
    use_openai: bool,
    logger: logging.Logger,
    batch_size: int = 10,
) -> bool:
    """Check if a candidate invariant duplicates any prior invariant (batched)."""
    for i in range(0, len(prior_invariants), batch_size):
        batch = prior_invariants[i : i + batch_size]
        prompt = _build_diff_prompt(candidate, batch)

        try:
            response, _usage = await get_structured_response(
                message=prompt,
                response_model=_InvariantDiffResponse,
                model=model,
                use_openai=use_openai,
            )
            for result in response.results:
                if result.is_duplicate:
                    logger.debug(
                        f"Invariant {candidate.id} is duplicate of {result.baseline_id}: "
                        f"{result.reasoning}"
                    )
                    return True
        except Exception as e:
            logger.warning(
                f"Invariant diff LLM call failed: {e}, assuming not duplicate"
            )
            continue

    return False


async def diff_invariants(
    new_invariants: List[Invariant],
    prior_invariants: List[Invariant],
    model: str,
    use_openai: bool,
    logger: logging.Logger,
    max_concurrency: int = 5,
) -> List[Invariant]:
    """
    LLM-based semantic comparison. Returns only novel invariants.

    For each new invariant, checks against prior invariants in batches.
    Early-exits on first match. Runs candidates concurrently with semaphore.
    """
    if not prior_invariants:
        return list(new_invariants)

    semaphore = asyncio.Semaphore(max_concurrency)
    novel: List[Invariant] = []
    lock = asyncio.Lock()

    async def check_one(inv: Invariant) -> None:
        async with semaphore:
            dup = await _is_duplicate(inv, prior_invariants, model, use_openai, logger)
            if not dup:
                async with lock:
                    novel.append(inv)

    await asyncio.gather(*(check_one(inv) for inv in new_invariants))
    return novel

# Load dedupe prompt template
DEDUPE_PROMPT_PATH = (
    Path(__file__).parent.parent / "prompts" / "dedupe_exploits_prompt.txt"
)
DEDUPE_EXPLOITS_PROMPT = (
    DEDUPE_PROMPT_PATH.read_text() if DEDUPE_PROMPT_PATH.exists() else ""
)


class VerificationPipeline:
    """Verifies exploit candidates and deduplicates by root cause."""

    def __init__(
        self,
        *,
        config,  # DispatcherConfig
        state_manager: Optional[KaiStateManager],
        usage_tracker: UsageTracker,
        logger: logging.Logger,
    ) -> None:
        self._config = config
        self._state_manager = state_manager
        self._usage_tracker = usage_tracker
        self.logger = logger

    async def verify_candidate(
        self,
        candidate: ExploitCandidate,
        invariants: Dict[str, Invariant],
        master_context: MasterContext,
        dependency_graph: Optional[DependencyGraph],
        active_missions: Dict[str, Mission],
    ) -> Optional[Verdict]:
        """
        Verify an exploit candidate using VerifierProcess.

        Args:
            candidate: The exploit candidate to verify
            invariants: Dict of invariant_id -> Invariant
            master_context: MasterContext from boot
            dependency_graph: DependencyGraph from boot
            active_missions: Currently active missions (for agent type lookup)

        Returns:
            Verdict if verification completed, None if failed
        """
        from kai.processes.verifier import VerifierProcess

        invariant = invariants.get(candidate.invariant_id)
        if not invariant:
            self.logger.warning(
                f"No invariant found for {candidate.invariant_id}, creating placeholder"
            )
            invariant = Invariant(
                id=candidate.invariant_id,
                type=InvariantType.OTHER,
                rule=f"Unknown invariant: {candidate.invariant_id}",
            )

        self.logger.info(f"Verifying exploit candidate: {candidate.mission_id}")

        mission = active_missions.get(candidate.mission_id)
        is_http_candidate = (
            mission is not None and mission.agent_type == MissionAgentType.HTTP
        )

        try:
            process = VerifierProcess(context=master_context)
            process_input = VerifierProcessInput(
                exploit_candidate=candidate,
                invariant=invariant,
                master_context=master_context,
                dependency_graph=dependency_graph,
                model_name=self._config.verifier_model,
                use_openai=self._config.use_openai,
                max_turns=self._config.verifier_max_turns,
                fallback_model=self._config.fallback_model,
                enable_http_agent=is_http_candidate,
                http_target_hosts=self._config.http_target_hosts
                if is_http_candidate
                else None,
            )

            output = await process.run(process_input)

            # Aggregate verifier usage
            self._usage_tracker.aggregate_process_usage(
                prompt_tokens=output.total_tokens.get("prompt_tokens", 0),
                completion_tokens=output.total_tokens.get("completion_tokens", 0),
                cost=output.estimated_cost,
                phase="run_loop",
                agent_type="verifier",
            )

            # Save verifier rollout if messages available
            if self._config.save_rollouts and output.agent_messages:
                self._usage_tracker.save_verifier_rollout(
                    candidate.mission_id,
                    output.agent_messages,
                    output.agent_model or "unknown",
                    output.total_tokens,
                    output.estimated_cost,
                )

            if output.success and output.verdict:
                verdict = output.verdict

                # Persist verdict
                await persist(
                    self._state_manager,
                    self._state_manager.save_verdict(verdict)
                    if self._state_manager
                    else None,
                    self.logger,
                )

                if verdict.is_valid:
                    self.logger.info(
                        f"VERIFIED: {candidate.mission_id} - "
                        f"{verdict.severity.value.upper()} - {verdict.vulnerability_class}"
                    )
                else:
                    self.logger.info(
                        f"REJECTED: {candidate.mission_id} - {verdict.rejection_reason}"
                    )

                return verdict
            else:
                self.logger.warning(
                    f"Verifier did not submit verdict for {candidate.mission_id}: "
                    f"{output.error_message}"
                )
                return None

        except Exception as e:
            self.logger.error(f"Verification failed for {candidate.mission_id}: {e}")
            return None

    async def dedupe_verified_exploits(
        self,
        verdicts: List[Verdict],
        exploit_candidates: List[ExploitCandidate],
    ) -> List[Verdict]:
        """
        Deduplicate verified exploits by clustering them by root cause using LLM.

        Args:
            verdicts: List of verified (is_valid=True) verdicts
            exploit_candidates: Full list of exploit candidates (for enrichment)

        Returns:
            Deduplicated list of verdicts (one per unique root cause)
        """
        if len(verdicts) <= 1:
            return verdicts

        if not DEDUPE_EXPLOITS_PROMPT:
            self.logger.warning("Dedupe prompt not found, skipping deduplication")
            return verdicts

        candidate_map = {(c.mission_id, c.invariant_id): c for c in exploit_candidates}
        findings = []
        for v in verdicts:
            c = candidate_map.get((v.mission_id, v.invariant_id))
            findings.append(
                {
                    "mission_id": v.mission_id,
                    "invariant_id": v.invariant_id,
                    "vulnerability_class": v.vulnerability_class or "unknown",
                    "severity": v.severity.value if v.severity else "unknown",
                    "target_file": c.target_file if c else "",
                    "target_function": c.target_function if c else "",
                    "description": c.description[:500] if c and c.description else "",
                    "mechanism": c.mechanism[:300] if c and c.mechanism else "",
                }
            )

        prompt = DEDUPE_EXPLOITS_PROMPT.replace(
            "{{num_findings}}", str(len(findings))
        ).replace("{{findings_json}}", json.dumps(findings, indent=2))

        try:
            result, _ = await get_structured_response(
                message=prompt,
                response_model=DedupeResponse,
                model=self._config.dedupe_model,
                use_openai=self._config.use_openai,
            )

            if not result.groups:
                self.logger.warning("Deduplication returned empty groups, keeping all")
                return verdicts

            dup_to_rep: Dict[str, str] = {
                dup_id: group.representative_mission_id
                for group in result.groups
                for dup_id in group.duplicate_mission_ids
            }

            verdict_map = {v.mission_id: v for v in verdicts}
            for dup_id, rep_id in dup_to_rep.items():
                v = verdict_map.get(dup_id)
                if v and self._state_manager:
                    await persist(
                        self._state_manager,
                        self._state_manager.update_exploit_dedupe_id(
                            mission_id=dup_id,
                            invariant_id=v.invariant_id,
                            dedupe_id=rep_id,
                        ),
                        self.logger,
                    )

            deduped = [v for v in verdicts if v.mission_id not in dup_to_rep]

            self.logger.info(
                f"Deduplication: {len(verdicts)} -> {len(deduped)} unique ({len(dup_to_rep)} duplicates)"
            )
            return deduped

        except Exception as e:
            self.logger.warning(f"Deduplication failed ({e}), keeping all verdicts")
            return verdicts
