"""Callback factories for RLM/spawn interception."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from ra.core.types import RLMIteration

from kai.state.base import StateManager
from kai.state.models import ExploitRecord, FixRecord, StatusUpdate

log = logging.getLogger(__name__)


def make_on_iteration_hook(
    state_manager: StateManager,
    run_id: str,
    agent_name: str,
) -> Callable[[RLMIteration, int], None]:
    """Return a callback that saves root RLM iterations as StatusUpdates.

    Only saves iterations that contain code blocks (ignoring pure-text
    responses).
    """

    def _on_iteration(iteration: RLMIteration, iteration_num: int) -> None:
        if not iteration.code_blocks:
            return
        try:
            code_dicts = [cb.to_dict() for cb in iteration.code_blocks]
            has_spawn = any("spawn_" in cb.code for cb in iteration.code_blocks)
            update = StatusUpdate(
                run_id=run_id,
                iteration_num=iteration_num,
                timestamp=datetime.now(timezone.utc).isoformat(),
                agent_name=agent_name,
                response_text=iteration.response,
                code_blocks=code_dicts,
                has_spawn_calls=has_spawn,
                iteration_time=iteration.iteration_time,
            )
            state_manager.add_status_update(update)
        except Exception:
            log.exception("on_iteration hook failed")

    return _on_iteration


def _parse_analyzer_result(
    state_manager: StateManager,
    run_id: str,
    raw_result: str,
) -> None:
    """Parse analyzer spawn result and add exploit candidates."""
    candidates = json.loads(raw_result)
    if not isinstance(candidates, list):
        candidates = [candidates]
    for item in candidates:
        if not isinstance(item, dict):
            continue
        exploit = ExploitRecord(
            run_id=run_id,
            exploit_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_agent="analyzer",
            status="candidate",
            hypothesis=item.get("hypothesis", ""),
            file=item.get("file", ""),
            function=item.get("function", ""),
            exploit_sketch=item.get("exploit_sketch", ""),
        )
        state_manager.add_exploit(exploit)


def _parse_verifier_result(
    state_manager: StateManager,
    run_id: str,
    raw_result: str,
) -> None:
    """Parse verifier spawn result and update exploit records."""
    verdict = json.loads(raw_result)
    if not isinstance(verdict, dict):
        return
    existing = state_manager.find_exploit(
        run_id,
        hypothesis=verdict.get("hypothesis", ""),
        file=verdict.get("file", ""),
        function=verdict.get("function", ""),
    )
    if existing is None:
        return
    state_manager.update_exploit(
        run_id,
        existing.exploit_id,
        status="verified",
        confirmed=verdict.get("confirmed", False),
        poc_code=verdict.get("poc_code"),
        test_output=verdict.get("test_output"),
    )


def _parse_fixer_result(
    state_manager: StateManager,
    run_id: str,
    raw_result: str,
) -> None:
    """Parse fixer spawn result and update exploit + add fix record."""
    result = json.loads(raw_result)
    if not isinstance(result, dict):
        return
    existing = state_manager.find_exploit(
        run_id,
        hypothesis=result.get("hypothesis", ""),
        file=result.get("file", ""),
        function=result.get("function", ""),
    )
    if existing is None:
        return

    state_manager.update_exploit(
        run_id,
        existing.exploit_id,
        status="verified_and_fixed",
        severity=result.get("severity"),
        patch=result.get("patch"),
        test_results=result.get("test_results"),
    )

    fix = FixRecord(
        run_id=run_id,
        fix_id=str(uuid.uuid4()),
        exploit_id=existing.exploit_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        hypothesis=result.get("hypothesis", ""),
        file=result.get("file", ""),
        function=result.get("function", ""),
        severity=result.get("severity", ""),
        patch=result.get("patch", ""),
        test_results=result.get("test_results", ""),
        applied=False,
    )
    state_manager.add_fix(fix)


# Dispatch table: agent name -> parser
_SPAWN_PARSERS: dict[
    str,
    Callable[[StateManager, str, str], None],
] = {
    "analyzer": _parse_analyzer_result,
    "verifier": _parse_verifier_result,
    "fixer": _parse_fixer_result,
}


def make_on_spawn_result_hook(
    state_manager: StateManager,
    run_id: str,
) -> Callable[[str, str, Any], None]:
    """Return a callback that dispatches spawn results by agent name.

    Recognized agents: analyzer, verifier, fixer.
    Unknown agents are silently ignored.
    """

    def _on_spawn_result(
        agent_name: str,
        _kwargs_json: str,
        result: Any,
    ) -> None:
        parser = _SPAWN_PARSERS.get(agent_name)
        if parser is None:
            return
        raw = result if isinstance(result, str) else str(result)
        try:
            parser(state_manager, run_id, raw)
        except Exception:
            log.exception(
                "on_spawn_result hook failed for agent %s",
                agent_name,
            )

    return _on_spawn_result
