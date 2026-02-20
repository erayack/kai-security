"""Callback factories for RLM iteration interception."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable

from ra.core.types import RLMIteration, SpawnRecord

from kai.state.base import StateManager
from kai.state.models import StatusUpdate

log = logging.getLogger(__name__)

# Type alias for spawn-result parser functions.
SpawnParser = Callable[[StateManager, str, str], None]


def make_on_iteration_hook(
    state_manager: StateManager,
    run_id: str,
    agent_name: str,
    spawn_parsers: dict[str, SpawnParser] | None = None,
) -> Callable[[RLMIteration, int], None]:
    """Return a callback that saves RLM iterations as StatusUpdates.

    Spawn data is read deterministically from
    ``REPLResult.spawn_records``.  If *spawn_parsers* is provided,
    each spawn record whose ``agent_name`` matches a key is dispatched
    to the corresponding parser function.
    """
    parsers = spawn_parsers or {}

    def _on_iteration(
        iteration: RLMIteration, iteration_num: int
    ) -> None:
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

            # Dispatch each record to its parser
            for record in all_records:
                parser = parsers.get(record.agent_name)
                if parser is None:
                    continue
                try:
                    parser(state_manager, run_id, record.result)
                except Exception:
                    log.exception(
                        "spawn record parser failed for agent %s",
                        record.agent_name,
                    )
        except Exception:
            log.exception("on_iteration hook failed")

    return _on_iteration
