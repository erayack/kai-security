"""Self-contained HTML viewer for RLM rollout traces.

Reads a rollout directory (the per-agent ``<agent>.jsonl`` files an RLM run
writes via :mod:`kai.state.hooks`, plus the optional ``score.json`` /
``run.json`` siblings) and renders a single offline HTML file.

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
order), with the value it returned surfaced at the call site. You can expand
a delegation to see *how* the sub-agent reached its answer.

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


def render_html(run: RunTrace) -> str:
    """Render a self-contained HTML page (inline data + CSS + JS)."""

    # ``</`` would prematurely close the <script>; escape it in the blob.
    data_json = json.dumps(run.as_dict()).replace("</", "<\\/")
    return _HTML_TEMPLATE.replace("__DATA__", data_json)


def write_html(rollout_dir: Path, out: Path | None = None) -> Path:
    """Load ``rollout_dir`` and write ``trace.html`` (or ``out``)."""

    run = load_rollout_dir(rollout_dir)
    target = out or (Path(rollout_dir) / "trace.html")
    target.write_text(render_html(run), encoding="utf-8")
    return target


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RLM rollout trace</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI",
    Roboto, sans-serif; background: #0e1116; color: #d6deeb;
  }
  code, pre, .mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  header {
    padding: 13px 18px; background: #11151c; border-bottom: 1px solid #232b36;
    position: sticky; top: 0; z-index: 5;
  }
  header h1 { margin: 0 0 6px; font-size: 15px; }
  header h1 .task { color: #7fdbca; }
  .badges { display: flex; flex-wrap: wrap; gap: 8px; font-size: 12px; }
  .badge {
    padding: 2px 9px; border-radius: 999px; background: #1c2430;
    border: 1px solid #2a3543; white-space: nowrap;
  }
  .ok { background: #10331f; border-color: #1d6b3a; color: #7ee2a8; }
  .fail { background: #3a1717; border-color: #7a2b2b; color: #ff9b9b; }
  .layout { display: flex; align-items: flex-start; }
  nav {
    width: 232px; flex: 0 0 232px; border-right: 1px solid #232b36;
    padding: 12px 10px; background: #0c1219;
    position: sticky; top: 56px; max-height: calc(100vh - 56px); overflow: auto;
  }
  nav .guide {
    font-size: 12px; color: #9fb0c3; background: #11161f;
    border: 1px solid #232b36; border-radius: 8px; padding: 10px; margin-bottom: 12px;
  }
  nav .guide b { color: #cdd9e5; }
  nav .guide .k { color: #ffcb6b; }
  nav .lt { font-size: 11px; text-transform: uppercase; letter-spacing: .05em;
    color: #6f7e92; margin: 4px 6px; }
  nav .agent {
    display: block; width: 100%; text-align: left; cursor: pointer;
    background: none; border: 0; color: inherit; padding: 5px 8px;
    border-radius: 6px; line-height: 1.35;
  }
  nav .agent:hover { background: #161d27; }
  nav .agent .swatch {
    display: inline-block; width: 9px; height: 9px; border-radius: 2px;
    margin-right: 6px; vertical-align: middle;
  }
  nav .agent .name { font-weight: 600; }
  nav .agent .meta { font-size: 11px; color: #8a99ad; }
  main { flex: 1 1 auto; padding: 16px 22px; min-width: 0; max-width: 980px; }
  .step { border-left: 3px solid #7fdbca; padding: 2px 0 2px 14px; margin: 0 0 18px; }
  .shead {
    display: flex; flex-wrap: wrap; gap: 9px; align-items: baseline;
    font-size: 12px; margin-bottom: 6px;
  }
  .shead .idx { color: #58657a; }
  .shead .agent { font-weight: 700; color: #7fdbca; }
  .shead .ts { color: #58657a; margin-left: auto; }
  .shead .deleg {
    color: #ffcb6b; border: 1px solid #5a4a1f; border-radius: 4px;
    padding: 0 6px; font-size: 11px;
  }
  .prose { white-space: pre-wrap; margin: 0 0 9px; }
  pre.code, pre.output {
    margin: 0 0 9px; padding: 9px 11px; border-radius: 6px;
    overflow: auto; font-size: 12.5px; white-space: pre-wrap; word-break: break-word;
  }
  pre.code { background: #0b1f2a; border: 1px solid #16384a; }
  pre.output {
    background: #15110b; border: 1px solid #3a2c16; color: #e8d8b0; max-height: 360px;
  }
  details.spawn {
    margin: 2px 0 11px; border-left: 2px dashed #4a5468; padding-left: 12px;
  }
  details.spawn > summary {
    cursor: pointer; font-size: 12.5px; padding: 4px 0; color: #cdd9e5;
  }
  details.spawn > summary .who { font-weight: 700; }
  details.spawn > summary .ret { color: #9fb0c3; }
  details.spawn[open] > summary .ret { display: none; }
  .childhead { font-size: 11px; color: #8a99ad; margin: 9px 0 4px; }
  .childit { padding-left: 10px; border-left: 1px solid #222a35; margin-bottom: 10px; }
  .missing { color: #a06a6a; font-size: 12px; padding: 4px 0; }
  .ret-box {
    border: 1px solid #3a4a2c; background: #14180e; border-radius: 6px;
    padding: 8px 10px; margin: 4px 0 9px; white-space: pre-wrap;
    font-size: 12.5px; color: #d6e6b8; max-height: 220px; overflow: auto;
  }
  .result {
    border: 1px solid #1d6b3a; border-radius: 8px; padding: 11px;
    background: #0f1c14; white-space: pre-wrap; margin: 2px 0 0;
  }
  .sec { font-size: 12px; color: #8a99ad; margin: 26px 0 10px; border-top: 1px solid #232b36;
    padding-top: 12px; }
  .empty { color: #7e8da1; padding: 30px; }
</style>
</head>
<body>
<header>
  <h1>Trace: <span class="task" id="title"></span></h1>
  <div class="badges" id="badges"></div>
</header>
<div class="layout">
  <nav id="nav"></nav>
  <main id="main"></main>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
// Every dynamic value is inserted via textContent / DOM nodes (never
// innerHTML), so unsanitised rollout text can't inject markup.
const RUN = JSON.parse(document.getElementById("data").textContent);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = String(text);
  return n;
}

function proseNode(text) {
  // Drop ``` fenced segments (code is rendered from blocks); keep prose.
  const parts = String(text || "").split("```");
  const prose = parts
    .filter((_, i) => i % 2 === 0)
    .join("\n")
    .replace(/<br>/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  return prose ? el("div", "prose", prose) : null;
}

function blockNodes(blocks) {
  const nodes = [];
  (blocks || []).forEach((b) => {
    if (b.code && b.code.trim()) nodes.push(el("pre", "code", b.code));
    if (b.output && b.output.trim()) nodes.push(el("pre", "output", b.output));
  });
  return nodes;
}

function head(s) {
  return (s || "").replace(/\s+/g, " ").trim().slice(0, 130);
}

function childNode(child) {
  const det = el("details", "spawn");
  det.dataset.agent = child.agent;
  det.style.borderLeftColor = child.color || "#4a5468";
  const sum = el("summary");
  const who = el("span", "who", "⤷ spawned " + child.agent);
  who.style.color = child.color || "inherit";
  sum.append(who);
  if (child.missing) {
    sum.append(el("span", "ret", " — no rollout captured in this dir"));
    det.append(sum, el("div", "missing", "(sub-agent file absent or empty)"));
    return det;
  }
  if (child.returned != null && child.returned !== "")
    sum.append(el("span", "ret", " — returned: " + head(child.returned)));
  else sum.append(el("span", "ret", " — (no return value recorded)"));
  det.append(sum);

  if (child.returned != null && child.returned !== "")
    det.append(el("div", "ret-box", child.returned));
  (child.iters || []).forEach((it) => {
    const wrap = el("div", "childit");
    wrap.append(el("div", "childhead", child.agent + " · iter " + it.iter));
    const p = proseNode(it.reasoning);
    if (p) wrap.append(p);
    blockNodes(it.blocks).forEach((n) => wrap.append(n));
    det.append(wrap);
  });
  return det;
}

function stepNode(step) {
  const wrap = el("div", "step");
  const h = el("div", "shead");
  h.append(el("span", "idx", "#" + step.iter));
  h.append(el("span", "agent", RUN.root_name));
  if (step.delegated && step.delegated.length)
    h.append(el("span", "deleg", "⤷ " + step.delegated.join(", ")));
  h.append(el("span", "ts", (step.ts || "").replace("T", " ").slice(0, 19)));
  wrap.append(h);

  const prose = proseNode(step.reasoning);
  if (prose) wrap.append(prose);
  // Causal order: the spawn call's reasoning/code, then dive into the child,
  // then the output (which contains what the child returned to the root).
  (step.blocks || []).forEach((b) => {
    if (b.code && b.code.trim()) wrap.append(el("pre", "code", b.code));
  });
  (step.children || []).forEach((c) => wrap.append(childNode(c)));
  (step.blocks || []).forEach((b) => {
    if (b.output && b.output.trim()) wrap.append(el("pre", "output", b.output));
  });
  return wrap;
}

function renderMain() {
  const main = document.getElementById("main");
  const nodes = [];
  if (!RUN.root_steps.length) nodes.push(el("div", "empty", "No root agent found."));
  RUN.root_steps.forEach((s) => nodes.push(stepNode(s)));
  if (RUN.root_result) {
    nodes.push(el("div", "sec", RUN.root_name + " — final answer"));
    nodes.push(el("div", "result", RUN.root_result));
  }
  if (RUN.unlinked && RUN.unlinked.length) {
    nodes.push(
      el("div", "sec", "Sub-agent runs not tied to a spawn call (" +
        RUN.unlinked.length + ")")
    );
    RUN.unlinked.forEach((c) => nodes.push(childNode(c)));
  }
  main.replaceChildren(...nodes);
}

function openAgent(name) {
  let first = null;
  document.querySelectorAll("details.spawn").forEach((d) => {
    if (d.dataset.agent === name) {
      d.open = true;
      if (!first) first = d;
    }
  });
  if (first) first.scrollIntoView({ block: "center" });
}

function badge(cls, text) {
  return el("span", cls ? "badge " + cls : "badge", text);
}

function buildNav() {
  const nav = document.getElementById("nav");
  const guide = el("div", "guide");
  guide.append(
    document.createTextNode("Read "),
    el("b", null, RUN.root_name),
    document.createTextNode(" top-to-bottom: each step is reason → run code "),
    document.createTextNode("→ observe output. A "),
    el("span", "k", "spawn_*()"),
    document.createTextNode(
      " call delegates a subtask; its answer is in that step's output. "
    ),
    document.createTextNode("Expand "),
    el("span", "k", "↳"),
    document.createTextNode(" to see how the sub-agent got there.")
  );
  nav.append(guide, el("div", "lt", "agents — click to expand"));
  RUN.legend.forEach((a) => {
    const btn = el("button", "agent");
    const sw = el("span", "swatch");
    sw.style.background = a.color;
    btn.append(
      sw,
      el("span", "name", a.name),
      el("span", "meta", "  d" + a.depth + " · " + a.iters + " it")
    );
    btn.addEventListener("click", () => openAgent(a.name));
    nav.append(btn);
  });
}

function init() {
  document.getElementById("title").textContent =
    RUN.benchmark + " / " + RUN.task_id;
  const badges = [];
  if (RUN.success === true) badges.push(badge("ok", "✅ success"));
  else if (RUN.success === false) badges.push(badge("fail", "❌ fail"));
  if (RUN.failure_reason) badges.push(badge("fail", RUN.failure_reason));
  if (RUN.poc_source) badges.push(badge("", "poc: " + RUN.poc_source));
  badges.push(badge("", RUN.legend.length + " agents"));
  (RUN.models || []).forEach((m) => badges.push(badge("mono", m)));
  document.getElementById("badges").replaceChildren(...badges);

  buildNav();
  renderMain();
}

init();
</script>
</body>
</html>
"""
