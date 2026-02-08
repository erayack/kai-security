"""
Iterative-run utilities: graph hashing and LLM-based invariant diffing.
"""

import asyncio
import hashlib
import json
import logging
from typing import List

from pydantic import BaseModel

from kai.schemas import Invariant
from kai.utils.dependency.graph import DependencyGraph


# ---------------------------------------------------------------------------
# Graph hashing
# ---------------------------------------------------------------------------

def hash_graph(graph: DependencyGraph) -> str:
    """Deterministic hash of sorted node IDs + edge tuples."""
    nodes = sorted(graph._nodes.keys())
    edges = sorted(
        (s, k.value, d) for (s, k, d) in graph._edges.keys()
    )
    payload = json.dumps([nodes, edges], sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()[:24]


# ---------------------------------------------------------------------------
# LLM-based invariant diff
# ---------------------------------------------------------------------------

class InvariantDiffResult(BaseModel):
    baseline_id: str
    is_duplicate: bool
    reasoning: str


class InvariantDiffResponse(BaseModel):
    results: List[InvariantDiffResult]


def _build_diff_prompt(candidate: Invariant, baselines: List[Invariant]) -> str:
    """Build prompt for comparing a candidate invariant against baselines."""
    baselines_json = []
    for b in baselines:
        baselines_json.append({
            "id": b.id,
            "type": b.type.value if hasattr(b.type, "value") else str(b.type),
            "rule": b.rule,
            "explanation": (b.explanation or "")[:500],
        })

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
    from kai.inference import get_structured_response

    for i in range(0, len(prior_invariants), batch_size):
        batch = prior_invariants[i : i + batch_size]
        prompt = _build_diff_prompt(candidate, batch)

        try:
            response, _usage = await get_structured_response(
                message=prompt,
                response_model=InvariantDiffResponse,
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
            logger.warning(f"Invariant diff LLM call failed: {e}, assuming not duplicate")
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
