"""Load RLM rollout traces from a run directory.

Reads the per-agent ``<agent>.jsonl`` files an RLM run writes via
:mod:`kai.state.hooks` (plus the optional ``score.json`` / ``run.json``
siblings) and folds them into a :class:`RunTrace` the HTML renderer can draw.

The view follows **causality, not wall-clock**. The root agent (``exploit``)
is an orchestrator: it reasons, then runs Python, and that Python calls
``spawn_analyzer(...)`` / ``spawn_researcher(...)`` / ``spawn_verifier(...)``
etc. to delegate a subtask. The sub-agent runs to completion *inside* that
code call and its ``final_answer`` comes back as the call's return value --
which is why a naive timestamp sort is misleading: the parent iteration is
stamped when it *finishes*, i.e. after the child it spawned has already run,
so the child appears to precede its own cause.

So we read the root top-to-bottom by iteration number -- reason -> run code
-> observe output -- and attach each spawned sub-agent's full sub-transcript
under the exact ``spawn_*()`` call that caused it (matched per agent in call
order), with the value it returned surfaced at the call site.

No external dependencies, no server, no spans -- just the rollouts on disk.
Pulled smoke dirs are flat (``*.jsonl`` next to ``score.json``); a fresh run
nests them under ``state/<hash>/rollouts/``. Both work: we glob for
``*.jsonl`` and skip any file whose lines aren't valid JSON (empty files, or
``cat: ... No such file`` stubs from a partial ``railway ssh`` pull).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT_AGENT = "exploit"
SPAWN_RE = re.compile(r"\bspawn_([a-z][a-z_]*)\s*\(")

# Per-agent tints, assigned in first-appearance order.
PALETTE = [
    "#7fdbca",
    "#c792ea",
    "#f78c6c",
    "#82aaff",
    "#ffcb6b",
    "#f07178",
    "#addb67",
    "#89ddff",
]


@dataclass
class Iteration:
    """One reason -> act -> observe step of an agent."""

    n: int
    timestamp: str
    reasoning: str
    blocks: list[dict[str, str]] = field(default_factory=list)


@dataclass
class AgentTrace:
    """A single (sub-)agent's rollout: its metadata + iterations + result."""

    name: str
    depth: int
    model: str
    backend: str
    iterations: list[Iteration]
    result: str | None
    first_ts: str
    color: str = ""

    def legend_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "depth": self.depth,
            "model": self.model,
            "iters": len(self.iterations),
            "color": self.color,
        }


@dataclass
class RunTrace:
    """A whole run: the causal root spine plus run-level header fields."""

    title: str
    benchmark: str
    task_id: str
    success: bool | None
    failure_reason: str | None
    poc_source: str | None
    models: list[str]
    agents: list[AgentTrace]
    root_name: str
    root_result: str | None
    root_steps: list[dict[str, Any]]
    unlinked: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "benchmark": self.benchmark,
            "task_id": self.task_id,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "poc_source": self.poc_source,
            "models": self.models,
            "legend": [a.legend_dict() for a in self.agents],
            "root_name": self.root_name,
            "root_result": self.root_result,
            "root_steps": self.root_steps,
            "unlinked": self.unlinked,
        }


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Parse a ``.jsonl`` file, skipping any line that isn't valid JSON.

    Pulled rollout dirs can contain empty files or a ``cat: ... No such
    file`` stub where an agent never ran; those simply yield no records.
    """

    records: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return records
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    return records


def _agent_from_records(
    fallback_name: str, records: list[dict[str, Any]]
) -> AgentTrace | None:
    """Fold a file's records into one :class:`AgentTrace` (or ``None``)."""

    meta = next((r for r in records if r.get("type") == "metadata"), {})
    iters = [
        Iteration(
            n=int(r.get("iteration", 0)),
            timestamp=str(r.get("timestamp", "")),
            reasoning=str(r.get("response", "")),
            blocks=[b for b in (r.get("code_blocks") or []) if isinstance(b, dict)],
        )
        for r in records
        if r.get("type") == "iteration"
    ]
    if not iters and not meta:
        return None
    result_rec = next((r for r in records if r.get("type") == "result"), None)
    result = str(result_rec.get("final_answer", "")) if result_rec is not None else None
    first_ts = str(meta.get("timestamp", "")) or (iters[0].timestamp if iters else "")
    return AgentTrace(
        name=str(meta.get("agent") or fallback_name),
        depth=int(meta.get("depth", 0)),
        model=str(meta.get("model", "")),
        backend=str(meta.get("backend", "")),
        iterations=iters,
        result=result,
        first_ts=first_ts,
    )


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return obj if isinstance(obj, dict) else {}


def _spawn_sessions(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Split a sub-agent's records into one entry per spawn, time-ordered.

    The root re-invokes a sub-agent many times; each invocation is a distinct
    ``spawn_id`` whose iteration counter restarts at 1. One session == one
    delegation the root can match a ``spawn_*()`` call to.
    """

    order: list[str] = []
    sess: dict[str, dict[str, Any]] = {}
    for r in records:
        sid = str(r.get("spawn_id", ""))
        kind = r.get("type")
        if kind == "iteration":
            if sid not in sess:
                sess[sid] = {
                    "first_ts": str(r.get("timestamp", "")),
                    "returned": None,
                    "iters": [],
                }
                order.append(sid)
            sess[sid]["iters"].append(
                {
                    "iter": int(r.get("iteration", 0)),
                    "ts": str(r.get("timestamp", "")),
                    "reasoning": str(r.get("response", "")),
                    "blocks": [
                        b for b in (r.get("code_blocks") or []) if isinstance(b, dict)
                    ],
                }
            )
        elif kind == "result" and sid in sess:
            sess[sid]["returned"] = str(r.get("final_answer", ""))
    out = [sess[s] for s in order]
    out.sort(key=lambda s: s["first_ts"])
    return out


def _child(name: str, color: str, session: dict[str, Any] | None) -> dict[str, Any]:
    if session is None:
        return {"agent": name, "color": color, "missing": True, "iters": []}
    return {
        "agent": name,
        "color": color,
        "returned": session.get("returned"),
        "iters": session["iters"],
    }


def _build_root_spine(
    root: AgentTrace,
    sessions_by_agent: dict[str, list[dict[str, Any]]],
    color_of: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Walk the root's iterations and hang each spawned sub-agent under the
    ``spawn_*()`` call that produced it (FIFO per agent name).

    Returns ``(root_steps, unlinked_children)``. ``unlinked`` holds sub-agent
    sessions we couldn't tie to a call (count mismatch) so nothing is lost.
    """

    cursor = {name: 0 for name in sessions_by_agent if name != root.name}
    steps: list[dict[str, Any]] = []
    for it in root.iterations:
        code = "\n".join(b.get("code", "") for b in it.blocks)
        children: list[dict[str, Any]] = []
        for name in SPAWN_RE.findall(code):
            sessions = sessions_by_agent.get(name)
            session = None
            if sessions is not None and cursor.get(name, 0) < len(sessions):
                session = sessions[cursor[name]]
                cursor[name] += 1
            children.append(_child(name, color_of.get(name, "#8a99ad"), session))
        steps.append(
            {
                "iter": it.n,
                "ts": it.timestamp,
                "reasoning": it.reasoning,
                "blocks": it.blocks,
                "delegated": [c["agent"] for c in children],
                "children": children,
            }
        )

    unlinked: list[dict[str, Any]] = []
    for name, sessions in sessions_by_agent.items():
        if name == root.name:
            continue
        for session in sessions[cursor.get(name, 0) :]:
            unlinked.append(_child(name, color_of.get(name, "#8a99ad"), session))
    return steps, unlinked


def load_rollout_dir(path: Path) -> RunTrace:
    """Build a :class:`RunTrace` (root spine + causal nesting) from a dir."""

    path = Path(path)
    if not path.is_dir():
        raise NotADirectoryError(f"{path} is not a directory")

    agents: list[AgentTrace] = []
    records_by_agent: dict[str, list[dict[str, Any]]] = {}
    for jf in sorted(path.rglob("*.jsonl")):
        if jf.name == "status_updates.jsonl":
            continue
        records = _load_jsonl(jf)
        agent = _agent_from_records(jf.stem, records)
        if agent is not None and agent.iterations:
            agents.append(agent)
            records_by_agent[agent.name] = records

    agents.sort(key=lambda a: (a.depth, a.first_ts, a.name))
    color_of = {a.name: PALETTE[i % len(PALETTE)] for i, a in enumerate(agents)}
    for a in agents:
        a.color = color_of[a.name]

    root = _pick_root(agents)
    sessions_by_agent = {
        name: _spawn_sessions(records) for name, records in records_by_agent.items()
    }
    if root is not None:
        root_steps, unlinked = _build_root_spine(root, sessions_by_agent, color_of)
    else:
        root_steps, unlinked = [], []

    score = _read_json(path / "score.json")
    details = score.get("details") or {}
    task_ref = score.get("task_ref") or {}
    run = _read_json(path / "run.json")

    benchmark = str(task_ref.get("benchmark") or _guess_benchmark(path.name))
    task_id = str(task_ref.get("task_id") or details.get("task_id") or path.name)
    models = sorted({a.model for a in agents if a.model})
    if not models and run.get("root_model"):
        models = [str(run["root_model"])]

    return RunTrace(
        title=path.name,
        benchmark=benchmark,
        task_id=task_id,
        success=score.get("success"),
        failure_reason=score.get("failure_reason"),
        poc_source=details.get("poc_source"),
        models=models,
        agents=agents,
        root_name=root.name if root else "",
        root_result=root.result if root else None,
        root_steps=root_steps,
        unlinked=unlinked,
    )


def _pick_root(agents: list[AgentTrace]) -> AgentTrace | None:
    """The depth-0 orchestrator (prefer the conventional ``exploit``)."""

    if not agents:
        return None
    named = next((a for a in agents if a.name == ROOT_AGENT and a.depth == 0), None)
    if named is not None:
        return named
    return min(agents, key=lambda a: (a.depth, a.first_ts))


def _guess_benchmark(dir_name: str) -> str:
    for known in ("cybergym", "bountybench", "evmbench", "noop"):
        if dir_name.startswith(known):
            return known
    return "rollout"
