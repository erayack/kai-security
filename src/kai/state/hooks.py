"""Callback factories for RLM iteration interception."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable

from kai import generate_id

from ra.core.types import RLMIteration, SpawnRecord

from kai.state.base import StateManager
from kai.state.models import StatusUpdate

log = logging.getLogger(__name__)


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
        if not iteration.code_blocks:
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
            )
            state_manager.add_status_update(update)
        except Exception:
            log.exception("on_iteration hook failed")

    return _on_iteration


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
    """
    spawn_id: list[str] = []  # mutable; empty means no spawn yet

    def _on_iteration(iteration: RLMIteration, iteration_num: int) -> None:
        try:
            ts = datetime.now(timezone.utc).isoformat()

            # New spawn detected — emit metadata
            if iteration_num == 1 or not spawn_id:
                spawn_id.clear()
                spawn_id.append(generate_id())
                state_manager.open_rollout(
                    run_id,
                    agent_name,
                    depth,
                    {
                        "spawn_id": spawn_id[0],
                        "timestamp": ts,
                        "backend": backend,
                        "model": model,
                    },
                )

            sid = spawn_id[0]

            # Build iteration payload
            code_blocks: list[dict[str, object]] = []
            for cb in iteration.code_blocks:
                code_blocks.append({"code": cb.code, "output": cb.result.stdout})

            state_manager.save_rollout_iteration(
                run_id,
                agent_name,
                {
                    "spawn_id": sid,
                    "timestamp": ts,
                    "response": iteration.response,
                    "code_blocks": code_blocks,
                },
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
