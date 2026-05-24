"""Callback factories for RLM iteration interception."""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone
from typing import Callable

from kai import generate_id

from ra.core.types import RLMIteration, SpawnRecord

from kai.state import cybergym_gate
from kai.state.base import StateManager
from kai.state.models import StatusUpdate

log = logging.getLogger(__name__)


def make_on_early_stop_hook(
    state_manager: StateManager,
    run_id: str,
) -> Callable[[int], str | None]:
    """Suppress early termination when unverified candidates remain.

    When the root agent tries to finalize but there are still exploit
    candidates at ``status="candidate"``, returns a nudge prompt that
    is injected into the conversation to redirect the agent back to
    verification work.
    """

    def _on_early_stop(current_iteration: int) -> str | None:
        candidates = state_manager.get_exploits(run_id, status="candidate")
        failed = state_manager.get_exploits(run_id, status="failed")
        pending = candidates + failed
        # Only block finalization for actionable active exploits;
        # non-active categories (trust_assumption_violation, etc.)
        # should not hold up the pipeline.
        actionable = [p for p in pending if p.category == "active_exploit"]
        if not actionable:
            return None
        bullets = "\n".join(
            f"  - [{p.file}:{p.function}] {p.hypothesis[:120]}" for p in actionable
        )
        log.info(
            "on_early_stop: %d actionable candidate(s) at iteration %d, "
            "injecting nudge",
            len(actionable),
            current_iteration,
        )
        return (
            f"Do not finalize yet. There are {len(actionable)} exploit "
            f"candidate(s) still pending verification:\n{bullets}\n\n"
            f"Continue by verifying and fixing these candidates before "
            f"producing your final answer."
        )

    return _on_early_stop


def make_on_iteration_hook(
    state_manager: StateManager,
    run_id: str,
    agent_name: str,
) -> Callable[[RLMIteration, int], None]:
    """Return a callback that saves RLM iterations as StatusUpdates.

    Spawn data is read deterministically from
    ``REPLResult.spawn_records``.  Domain-specific parsing is handled
    by ``result_processor`` on each sub-agent config (runs inside the
    spawn function), so this hook only records status updates.
    """

    def _on_iteration(iteration: RLMIteration, iteration_num: int) -> None:
        # Cybergym escalating-reminder injection: when the root exploit
        # agent passes iter 4 without calling spawn_verifier, OR has a
        # verified/soft_verified record + iter > 8 without spawn_critic,
        # append a harness reminder to iteration.truncation_notice so
        # the next iteration's prompt nudges the model.
        if agent_name == "exploit" and os.environ.get("KAI_BENCHMARK") == "cybergym":
            notes: list[str] = []
            verifier_reminder = cybergym_gate.reminder_text(iteration_num)
            if verifier_reminder is not None:
                notes.append(verifier_reminder)
            # Critic reminder: trigger when at least one verified/soft
            # record exists and the model hasn't called spawn_critic
            # yet. Count records via the state manager.
            try:
                verified = state_manager.get_exploits(run_id, status="verified")
                soft = state_manager.get_exploits(run_id, status="soft_verified")
                v_count = len(verified) + len(soft)
            except Exception:
                v_count = 0
            critic_reminder = cybergym_gate.critic_reminder_text(
                iteration_num,
                verified_or_soft_count=v_count,
                critic_called=cybergym_gate.critic_was_called(),
            )
            if critic_reminder is not None:
                notes.append(critic_reminder)
            if notes:
                existing = iteration.truncation_notice or ""
                combined = "\n\n".join([existing] + notes if existing else notes)
                iteration.truncation_notice = combined.strip()
        # Skip only when an iteration is empty AND the harness did not
        # cap it. A wall-cap that fires before block 0 leaves
        # ``code_blocks=[]`` but ``dropped_blocks > 0``; that case
        # MUST be persisted so post-mortem can see the cap fire.
        if (
            not iteration.code_blocks
            and not iteration.dropped_blocks
            and not iteration.truncation_notice
        ):
            return
        try:
            # Collect all spawn records across code blocks
            all_records: list[SpawnRecord] = []
            for cb in iteration.code_blocks:
                all_records.extend(cb.result.spawn_records)

            has_spawn = bool(all_records)
            first = all_records[0] if all_records else None

            update = StatusUpdate(
                run_id=run_id,
                iteration_num=iteration_num,
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_name=agent_name,
                has_spawn_calls=has_spawn,
                iteration_time=iteration.iteration_time,
                spawn_agent=first.agent_name if first else None,
                spawn_kwargs=first.kwargs if first else None,
                spawn_result=first.result if first else None,
                dropped_blocks=iteration.dropped_blocks,
                truncation_notice=iteration.truncation_notice,
            )
            state_manager.add_status_update(update)
        except Exception:
            log.exception("on_iteration hook failed")

    return _on_iteration


def make_on_extend_hook(
    state_manager: StateManager,
    run_id: str,
    iters_per_candidate: int = 5,
) -> Callable[[int], int | None]:
    """Return a callback that extends iterations for unverified candidates.

    When the root agent hits its iteration limit, this hook checks
    whether any exploit candidates are still at ``status="candidate"``
    and grants extra iterations (~``iters_per_candidate`` per pending
    candidate) so the same agent can finish verification/fixing without
    losing REPL state.
    """

    def _on_extend(current_iteration: int) -> int | None:
        pending = state_manager.get_exploits(run_id, status="candidate")
        if not pending:
            log.info(
                "on_extend: no unverified candidates at iteration %d",
                current_iteration,
            )
            return None
        extra = len(pending) * iters_per_candidate
        log.info(
            "on_extend: %d unverified candidate(s) at iteration %d, "
            "requesting %d extra iterations",
            len(pending),
            current_iteration,
            extra,
        )
        return extra

    return _on_extend


def make_rollout_on_iteration_hook(
    state_manager: StateManager,
    run_id: str,
    agent_name: str,
    depth: int = 0,
    backend: str = "",
    model: str = "",
) -> Callable[[RLMIteration, int], None]:
    """Return a callback that writes per-agent rollout JSONL.

    Each time ``iteration_num == 1`` is seen, a new spawn is assumed:
    a fresh ``spawn_id`` is generated and a metadata entry is emitted.
    Every entry carries the ``spawn_id`` so multiple spawns of the
    same agent can be distinguished within a single file.

    When ``iteration.final_answer`` is not ``None`` a result entry is
    appended.

    Thread safety: ``spawn_id`` is stored in thread-local storage so
    that orphaned daemon threads from timed-out spawns cannot corrupt
    the rollout of a subsequent spawn running on a different thread.
    """
    _tls = threading.local()

    def _on_iteration(iteration: RLMIteration, iteration_num: int) -> None:
        try:
            ts = datetime.now(timezone.utc).isoformat()

            # New spawn detected — emit metadata
            current_id: str = getattr(_tls, "spawn_id", "")
            if iteration_num == 1 or not current_id:
                _tls.spawn_id = generate_id()
                state_manager.open_rollout(
                    run_id,
                    agent_name,
                    depth,
                    {
                        "spawn_id": _tls.spawn_id,
                        "timestamp": ts,
                        "backend": backend,
                        "model": model,
                    },
                )

            sid: str = _tls.spawn_id

            # Build iteration payload
            code_blocks: list[dict[str, object]] = []
            for cb in iteration.code_blocks:
                code_blocks.append({"code": cb.code, "output": cb.result.stdout})

            iter_payload: dict[str, object] = {
                "spawn_id": sid,
                "timestamp": ts,
                "response": iteration.response,
                "code_blocks": code_blocks,
            }
            # Surface the harness-cap markers added by rlm._completion_turn
            # so post-mortem rollout analysis can see which iterations
            # were truncated and why.
            if iteration.dropped_blocks:
                iter_payload["dropped_blocks"] = iteration.dropped_blocks
            if iteration.truncation_notice:
                iter_payload["truncation_notice"] = iteration.truncation_notice
            if iteration.iteration_time is not None:
                iter_payload["iteration_time"] = iteration.iteration_time
            state_manager.save_rollout_iteration(
                run_id,
                agent_name,
                iter_payload,
                iteration_num,
            )

            if iteration.final_answer is not None:
                state_manager.save_rollout_result(
                    run_id,
                    agent_name,
                    {
                        "spawn_id": sid,
                        "timestamp": ts,
                        "final_answer": iteration.final_answer,
                        "iteration": iteration_num,
                    },
                )
        except Exception:
            log.exception("rollout hook failed for %s", agent_name)

    return _on_iteration
