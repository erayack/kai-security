"""Callback factories for RLM iteration interception."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable

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
