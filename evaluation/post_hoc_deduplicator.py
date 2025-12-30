"""
Post-Hoc Deduplicator.

Bulk deduplication of synthesized invariants against baseline invariants
using parallel LLM calls for speed.
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from kai.inference import create_openai_client, get_model_pricing
from kai.schemas import Invariant

logger = logging.getLogger(__name__)


@dataclass
class CandidateResult:
    """Result of checking a single candidate invariant."""

    invariant: Invariant
    is_duplicate: bool
    duplicate_of_id: Optional[str] = None
    reasoning: Optional[str] = None
    llm_calls_made: int = 0
    baselines_compared: int = 0
    llm_cost: float = 0.0
    llm_tokens: Dict[str, int] = field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0}
    )


@dataclass
class DeduplicationResult:
    """Result of bulk deduplication."""

    novel_invariants: List[Invariant]
    duplicate_invariants: List[Tuple[Invariant, str]]  # (invariant, duplicate_of_id)
    total_candidates: int
    novel_count: int
    duplicate_count: int
    processing_time_seconds: float
    total_llm_calls: int
    total_llm_cost: float
    total_llm_tokens: Dict[str, int]
    model_name: str
    batch_size: int
    max_concurrent: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_output_dict(self) -> Dict[str, Any]:
        """Convert to output JSON format."""
        return {
            "metadata": {
                "total_candidates": self.total_candidates,
                "duplicates_removed": self.duplicate_count,
                "novel_count": self.novel_count,
                "processing_time_seconds": round(self.processing_time_seconds, 2),
                "llm_cost": round(self.total_llm_cost, 6),
                "llm_tokens": self.total_llm_tokens,
                "model_name": self.model_name,
                "batch_size": self.batch_size,
                "max_concurrent": self.max_concurrent,
                "timestamp": self.timestamp.isoformat(),
            },
            "novel_invariants": [inv.model_dump() for inv in self.novel_invariants],
            "duplicates": [
                {"invariant_id": inv.id, "duplicate_of": dup_id}
                for inv, dup_id in self.duplicate_invariants
            ],
        }


class PostHocDeduplicator:
    """
    Bulk deduplication with parallel LLM calls.

    Checks synthesized invariants against baseline invariants to identify
    semantic duplicates. Uses parallel processing for speed.
    """

    DEFAULT_BATCH_SIZE = 10
    DEFAULT_MAX_CONCURRENT = 5

    def __init__(
        self,
        baseline_invariants: List[Invariant],
        model_name: str = "z-ai/glm-4.7",
        use_openai: bool = False,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        # Testing hooks (dependency injection)
        _client_factory: Optional[Callable[..., Any]] = None,
        _pricing_factory: Optional[Callable[[str, bool], Dict[str, float]]] = None,
    ):
        """
        Initialize the deduplicator.

        Args:
            baseline_invariants: List of baseline invariants to compare against.
            model_name: Model to use for semantic comparison.
            use_openai: Whether to use OpenAI API directly.
            batch_size: Number of baselines per LLM call.
            max_concurrent: Maximum concurrent LLM calls.
            _client_factory: (Testing) Factory function to create OpenAI client.
            _pricing_factory: (Testing) Factory function to get model pricing.
        """
        self.baseline_invariants = {inv.id: inv for inv in baseline_invariants}
        self.baseline_ids = list(self.baseline_invariants.keys())
        self.model_name = model_name
        self.use_openai = use_openai
        self.batch_size = batch_size
        self.max_concurrent = max_concurrent

        # Semaphore for concurrency control
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Testing hooks
        self._client_factory = _client_factory or create_openai_client
        self._pricing_factory = _pricing_factory or get_model_pricing

        self.logger = logger.getChild("PostHocDeduplicator")

    async def deduplicate(
        self,
        candidates: List[Invariant],
    ) -> DeduplicationResult:
        """
        Check all candidates against baseline in parallel.

        Args:
            candidates: List of candidate invariants to check.

        Returns:
            DeduplicationResult with novel and duplicate invariants.
        """
        start_time = time.time()

        if not self.baseline_invariants:
            # No baselines - all candidates are novel
            return DeduplicationResult(
                novel_invariants=candidates,
                duplicate_invariants=[],
                total_candidates=len(candidates),
                novel_count=len(candidates),
                duplicate_count=0,
                processing_time_seconds=time.time() - start_time,
                total_llm_calls=0,
                total_llm_cost=0.0,
                total_llm_tokens={"prompt_tokens": 0, "completion_tokens": 0},
                model_name=self.model_name,
                batch_size=self.batch_size,
                max_concurrent=self.max_concurrent,
            )

        self.logger.info(
            f"Starting deduplication: {len(candidates)} candidates vs "
            f"{len(self.baseline_invariants)} baselines "
            f"(batch_size={self.batch_size}, max_concurrent={self.max_concurrent})"
        )

        # Process all candidates concurrently (bounded by semaphore)
        tasks = [self._check_candidate(candidate) for candidate in candidates]
        results: List[CandidateResult] = await asyncio.gather(*tasks)

        # Aggregate results
        novel = []
        duplicates = []
        total_llm_calls = 0
        total_cost = 0.0
        total_tokens = {"prompt_tokens": 0, "completion_tokens": 0}

        for result in results:
            if result.is_duplicate:
                duplicates.append((result.invariant, result.duplicate_of_id))
            else:
                novel.append(result.invariant)

            total_llm_calls += result.llm_calls_made
            total_cost += result.llm_cost
            total_tokens["prompt_tokens"] += result.llm_tokens["prompt_tokens"]
            total_tokens["completion_tokens"] += result.llm_tokens["completion_tokens"]

        processing_time = time.time() - start_time

        self.logger.info(
            f"Deduplication complete: {len(novel)} novel, {len(duplicates)} duplicates "
            f"in {processing_time:.1f}s ({total_llm_calls} LLM calls, ${total_cost:.4f})"
        )

        return DeduplicationResult(
            novel_invariants=novel,
            duplicate_invariants=duplicates,
            total_candidates=len(candidates),
            novel_count=len(novel),
            duplicate_count=len(duplicates),
            processing_time_seconds=processing_time,
            total_llm_calls=total_llm_calls,
            total_llm_cost=total_cost,
            total_llm_tokens=total_tokens,
            model_name=self.model_name,
            batch_size=self.batch_size,
            max_concurrent=self.max_concurrent,
        )

    async def _check_candidate(self, candidate: Invariant) -> CandidateResult:
        """
        Check single candidate against ALL baselines (batched).

        Uses semaphore to limit concurrency.
        """
        async with self.semaphore:
            return await self._batched_llm_check(candidate)

    async def _batched_llm_check(self, candidate: Invariant) -> CandidateResult:
        """
        Check candidate against all baselines in batches.

        Early exits when a duplicate is found.
        """
        llm_calls = 0
        baselines_compared = 0
        total_cost = 0.0
        total_tokens = {"prompt_tokens": 0, "completion_tokens": 0}

        # Process baselines in batches
        for i in range(0, len(self.baseline_ids), self.batch_size):
            batch_ids = self.baseline_ids[i : i + self.batch_size]

            (
                is_duplicate,
                duplicate_id,
                reasoning,
                cost,
                tokens,
            ) = await self._llm_batch_check(candidate, batch_ids)

            llm_calls += 1
            baselines_compared += len(batch_ids)
            total_cost += cost
            total_tokens["prompt_tokens"] += tokens["prompt_tokens"]
            total_tokens["completion_tokens"] += tokens["completion_tokens"]

            if is_duplicate:
                self.logger.info(
                    f"Found duplicate in batch {llm_calls}, stopping early "
                    f"(checked {baselines_compared} of {len(self.baseline_ids)} baselines)"
                )
                return CandidateResult(
                    invariant=candidate,
                    is_duplicate=True,
                    duplicate_of_id=duplicate_id,
                    reasoning=reasoning,
                    llm_calls_made=llm_calls,
                    baselines_compared=baselines_compared,
                    llm_cost=total_cost,
                    llm_tokens=total_tokens,
                )

        # Not a duplicate of any baseline
        return CandidateResult(
            invariant=candidate,
            is_duplicate=False,
            llm_calls_made=llm_calls,
            baselines_compared=baselines_compared,
            llm_cost=total_cost,
            llm_tokens=total_tokens,
        )

    async def _llm_batch_check(
        self,
        candidate: Invariant,
        batch_ids: List[str],
    ) -> Tuple[bool, Optional[str], Optional[str], float, Dict[str, int]]:
        """
        Make single LLM call to check candidate against a batch of baselines.

        Returns:
            Tuple of (is_duplicate, duplicate_of_id, reasoning, cost, tokens)
        """
        prompt = self._build_batch_prompt(candidate, batch_ids)

        client = self._client_factory(use_openai=self.use_openai)
        pricing = self._pricing_factory(self.model_name, self.use_openai)

        try:
            response = await client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
            )

            content = response.choices[0].message.content or ""

            # Calculate cost
            usage = response.usage
            tokens = {"prompt_tokens": 0, "completion_tokens": 0}
            cost = 0.0
            if usage:
                tokens["prompt_tokens"] = usage.prompt_tokens
                tokens["completion_tokens"] = usage.completion_tokens
                cost = (
                    usage.prompt_tokens * pricing["prompt"]
                    + usage.completion_tokens * pricing["completion"]
                )

            # Parse response
            results = self._parse_batch_response(content, batch_ids)

            # Check for duplicates
            for baseline_id, is_dup, reasoning in results:
                if is_dup:
                    return True, baseline_id, reasoning, cost, tokens

            return False, None, None, cost, tokens

        except Exception as e:
            self.logger.error(f"LLM call failed: {e}")
            # On error, assume not duplicate (conservative)
            return False, None, None, 0.0, {"prompt_tokens": 0, "completion_tokens": 0}

    def _build_batch_prompt(self, candidate: Invariant, batch_ids: List[str]) -> str:
        """Build prompt for batch comparison."""
        baselines_json = []
        for bid in batch_ids:
            baseline = self.baseline_invariants[bid]
            baselines_json.append(
                {
                    "id": baseline.id,
                    "type": (
                        baseline.type.value
                        if hasattr(baseline.type, "value")
                        else str(baseline.type)
                    ),
                    "rule": baseline.rule,
                    "explanation": (baseline.explanation or "")[:500],
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

    def _parse_batch_response(
        self,
        content: str,
        batch_ids: List[str],
    ) -> List[Tuple[str, bool, str]]:
        """
        Parse LLM response into list of (baseline_id, is_duplicate, reasoning).

        Handles JSON parsing and missing baselines gracefully.
        """
        # Try to extract JSON from markdown code blocks
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content)
        if json_match:
            content = json_match.group(1)

        try:
            data = json.loads(content.strip())
            results_list = data.get("results", [])

            # Build lookup from response
            response_lookup = {}
            for item in results_list:
                bid = item.get("baseline_id")
                if bid:
                    response_lookup[bid] = (
                        item.get("is_duplicate", False),
                        item.get("reasoning", ""),
                    )

            # Build results for all batch_ids
            results = []
            for bid in batch_ids:
                if bid in response_lookup:
                    is_dup, reasoning = response_lookup[bid]
                    results.append((bid, is_dup, reasoning))
                else:
                    # Missing from response - assume not duplicate
                    results.append((bid, False, "Not included in LLM response"))

            return results

        except json.JSONDecodeError:
            self.logger.warning(
                f"Failed to parse LLM response as JSON: {content[:200]}"
            )
            # On parse error, assume all not duplicates
            return [(bid, False, "JSON parse error") for bid in batch_ids]
