"""Cybergym cross-task path isolation guard.

When ``KAI_BENCHMARK=cybergym`` the agent runs inside a worker replica
that has prior tasks' rollout / state directories still on disk under
``output/bench/cybergym/run_<id>/<task_id>/``. The agent has filesystem
read access (its REPL can ``open`` arbitrary paths) and could in
principle grep a sibling task's ``state/exploits.jsonl`` for stale
hypotheses, which would cross-contaminate the current task.

The guard below rejects any path resolving inside a sibling task's
benchmark output directory. Activates only when both ``KAI_BENCHMARK``
and ``KAI_TASK_ID`` are set (i.e. inside an evaluation pipeline
subprocess); outside that context it is a no-op so unit tests and
local development remain unaffected.
"""

from __future__ import annotations

import os
import re

_OUTPUT_RE = re.compile(
    r"(?:^|/)output/bench/(?P<bench>[^/]+)/run_[^/]+/(?P<task>[^/]+)"
)


class SiblingTaskAccessBlocked(PermissionError):
    """Raised when the agent tries to read another task's output dir."""


def assert_task_isolation(path: str | os.PathLike[str]) -> None:
    """Reject access to sibling-task output directories.

    Safe to call unconditionally — only enforces when running inside a
    cybergym pipeline subprocess (``KAI_BENCHMARK`` and ``KAI_TASK_ID``
    both set).
    """
    benchmark = os.environ.get("KAI_BENCHMARK")
    task_id = os.environ.get("KAI_TASK_ID")
    if benchmark != "cybergym" or not task_id:
        return
    resolved = os.path.abspath(os.fspath(path))
    match = _OUTPUT_RE.search(resolved)
    if match is None:
        return
    if match.group("bench") != "cybergym":
        return
    other = match.group("task")
    if other == task_id:
        return
    raise SiblingTaskAccessBlocked(
        f"cybergym isolation: access to sibling task '{other}' is "
        f"blocked (current task: '{task_id}')."
    )
