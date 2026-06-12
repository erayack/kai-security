"""Reusable, self-contained HTML viewer for any ``ra`` agent run.

This is framework-level: any agent built on ``ra`` writes per-agent
``*.jsonl`` rollouts, and this module renders them into a single offline HTML
page (no server, no external requests). The page is built from **panels** — a
tabbed shell plus one or more views — so a domain layer can add its own panel
(e.g. kai adds a security **Findings** panel) on top of the built-in
**Trace** panel.

Every dynamic value is written via ``textContent`` / DOM nodes, never
``innerHTML``, so unsanitised rollout text cannot inject markup. The palette
and shared primitives come from :mod:`ra.viewer.style`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from html import escape
from pathlib import Path
import re

from ra.viewer import style
from ra.viewer.trace import RunTrace, load_rollout_dir


@dataclass(frozen=True)
class Panel:
    """One tab in the viewer.

    ``js`` defines a render function over the embedded ``DATA``/``RUN`` globals
    (and the shared ``el()`` helper); ``render_call`` invokes it at init.
    """

    id: str
    label: str
    section: str  # the <section class="view" id="view-<id>"> … </section> block
    css: str
    js: str
    render_call: str


# Shell chrome only (header / tabs / theme toggle / view switching). Panel- and
# domain-specific styling lives on each Panel; shared tokens + primitives come
# from style.base_css().
_SHELL_CSS = """\
  header { display: flex; align-items: baseline; gap: 18px; flex-wrap: wrap;
    padding: 12px 22px; border-bottom: 1px solid var(--rule-2);
    position: sticky; top: 0; background: var(--paper); z-index: 5; }
  header h1 { margin: 0; font-size: 16px; font-weight: 600; }
  header h1 .sub { color: var(--muted); font-weight: 400; }
  .facts { display: flex; gap: 16px; font-size: 12px; color: var(--muted-2); }
  .facts b { color: var(--ink); font-weight: 600; }
  .facts .crit b { color: var(--accent); }
  .spacer { flex: 1 1 auto; }
  .tabs { display: flex; gap: 2px; }
  .tab { border: 0; background: none; color: var(--muted-2); cursor: pointer;
    font: inherit; font-size: 13px; padding: 4px 10px; border-bottom: 2px solid transparent; }
  .tab.active { color: var(--ink); border-bottom-color: var(--accent); }
  .toggle { border: 1px solid var(--rule-2); background: none; color: var(--muted-2);
    border-radius: 5px; cursor: pointer; font-size: 12px; padding: 3px 8px; }
  .view { display: none; }
  .view.active { display: block; }
"""

# ---------------------------------------------------------------------------
# Built-in Trace panel: the causal agent spine.
# ---------------------------------------------------------------------------
_TRACE_CSS = """\
  .trace { padding: 14px 22px; max-width: 920px; }
  .legend { display: flex; flex-wrap: wrap; gap: 12px; font-size: 12px; color: var(--muted-2);
    margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--rule); }
  .legend .a { display: inline-flex; align-items: center; gap: 6px; }
  .legend .sw { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
  .step { border-left: 2px solid var(--rule-2); padding: 0 0 2px 14px; margin: 0 0 16px; }
  .step .h { display: flex; gap: 10px; align-items: baseline; font-size: 12px; color: var(--muted-2); margin-bottom: 5px; }
  .step .h .who { color: var(--ink); font-weight: 600; }
  .step .h .deleg { color: var(--accent); }
  .step .h .ts { margin-left: auto; }
  .reason { white-space: pre-wrap; margin: 0 0 8px; }
  details.spawn { border-left: 2px dashed var(--rule-2); padding-left: 12px; margin: 4px 0 10px; }
  details.spawn > summary { cursor: pointer; font-size: 12.5px; color: var(--muted-2); padding: 3px 0; }
  details.spawn > summary .who { color: var(--ink); font-weight: 600; }
  details.spawn[open] > summary .ret { display: none; }
  .ret-box { border: 1px solid var(--rule-2); background: var(--code-bg); border-radius: 6px;
    padding: 8px 10px; margin: 4px 0 9px; white-space: pre-wrap; font-size: 12.5px; max-height: 220px; overflow: auto; }
  .childit { padding-left: 10px; border-left: 1px solid var(--rule); margin-bottom: 10px; }
  .childhead { font-size: 11px; color: var(--muted-2); margin: 9px 0 4px; }
  .missing { color: var(--del); font-size: 12px; padding: 4px 0; }
  .sec { font-size: 12px; color: var(--muted-2); margin: 26px 0 10px; border-top: 1px solid var(--rule); padding-top: 12px; }
  .result { border: 1px solid var(--rule-2); border-radius: 8px; padding: 11px; background: var(--panel); white-space: pre-wrap; margin: 2px 0 0; }
"""

_TRACE_SECTION = """\
<section class="view" id="view-trace">
  <div class="trace" id="trace"></div>
</section>"""

_TRACE_JS = r"""
function head(s) { return (s || "").replace(/\s+/g, " ").trim().slice(0, 130); }
function proseNode(text) {
  const parts = String(text || "").split("```");
  const prose = parts.filter((_, i) => i % 2 === 0).join("\n")
    .replace(/<br>/g, "").replace(/\n{3,}/g, "\n\n").trim();
  return prose ? el("div", "reason", prose) : null;
}
function childNode(child) {
  const det = el("details", "spawn");
  det.dataset.agent = child.agent;
  if (child.color) det.style.borderLeftColor = child.color;
  const sum = el("summary");
  const who = el("span", "who", "⤷ spawned " + child.agent);
  if (child.color) who.style.color = child.color;
  sum.append(who);
  if (child.missing) {
    sum.append(el("span", "ret", " — no rollout captured"));
    det.append(sum, el("div", "missing", "(sub-agent file absent or empty)"));
    return det;
  }
  sum.append(el("span", "ret", child.returned ? " — returned: " + head(child.returned) : " — (no return value recorded)"));
  det.append(sum);
  if (child.returned) det.append(el("div", "ret-box", child.returned));
  (child.iters || []).forEach(it => {
    const wrap = el("div", "childit");
    wrap.append(el("div", "childhead", child.agent + " · iter " + it.iter));
    const p = proseNode(it.reasoning); if (p) wrap.append(p);
    (it.blocks || []).forEach(b => {
      if (b.code && b.code.trim()) wrap.append(el("pre", "code", b.code));
      if (b.output && b.output.trim()) wrap.append(el("pre", "output", b.output));
    });
    det.append(wrap);
  });
  return det;
}
function stepNode(step) {
  const wrap = el("div", "step");
  const h = el("div", "h");
  h.append(el("span", "who", RUN.root_name), el("span", null, "#" + step.iter));
  if (step.delegated && step.delegated.length) h.append(el("span", "deleg", "⤷ " + step.delegated.join(", ")));
  h.append(el("span", "ts", (step.ts || "").replace("T", " ").slice(0, 19)));
  wrap.append(h);
  const p = proseNode(step.reasoning); if (p) wrap.append(p);
  (step.blocks || []).forEach(b => { if (b.code && b.code.trim()) wrap.append(el("pre", "code", b.code)); });
  (step.children || []).forEach(c => wrap.append(childNode(c)));
  (step.blocks || []).forEach(b => { if (b.output && b.output.trim()) wrap.append(el("pre", "output", b.output)); });
  return wrap;
}
function renderTrace() {
  const t = document.getElementById("trace");
  if (!RUN.root_steps || !RUN.root_steps.length) {
    t.replaceChildren(el("div", "empty", "No agent rollouts found for this run."));
    return;
  }
  const legend = el("div", "legend");
  (RUN.legend || []).forEach(a => {
    const span = el("span", "a");
    const sw = el("span", "sw"); sw.style.background = a.color; span.append(sw);
    span.append(el("span", null, a.name + " · d" + a.depth + " · " + a.iters + " it"));
    legend.append(span);
  });
  const nodes = [legend];
  RUN.root_steps.forEach(s => nodes.push(stepNode(s)));
  if (RUN.root_result) { nodes.push(el("div", "sec", RUN.root_name + " — final answer")); nodes.push(el("div", "result", RUN.root_result)); }
  (RUN.unlinked || []).forEach(c => nodes.push(childNode(c)));
  t.replaceChildren(...nodes);
}
"""


def trace_panel() -> Panel:
    """The built-in causal-trace panel, reusable by any ``ra`` agent."""

    return Panel(
        "trace", "Trace", _TRACE_SECTION, _TRACE_CSS, _TRACE_JS, "renderTrace();"
    )


_SHELL_PLACEHOLDER_RE = re.compile(r"__[A-Z_]+__")

_SHELL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
__STYLE__
</style>
</head>
<body>
<header>
  <h1 class="serif">__BRAND__ <span class="sub" id="sub"></span></h1>
  <div class="facts" id="facts"></div>
  <div class="spacer"></div>
  <div class="tabs" id="tabs"></div>
  <button class="toggle" id="themeBtn">◐ theme</button>
</header>

__SECTIONS__

<script id="data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById("data").textContent);
const RUN = DATA.run || {};
const PANELS = __PANELS_META__;

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = String(text);
  return n;
}

__PANEL_JS__

function activate(name) {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x.dataset.view === name));
  document.querySelectorAll(".view").forEach(x => x.classList.toggle("active", x.id === "view-" + name));
}
function init() {
  document.getElementById("sub").textContent = "— " + (DATA.title || DATA.task_id || "");
  const facts = document.getElementById("facts");
  (DATA.models || []).slice(0, 3).forEach(m => facts.append(el("span", "mono", m)));
  const tabs = document.getElementById("tabs");
  PANELS.forEach(p => {
    const b = el("button", "tab", p.label); b.dataset.view = p.id;
    b.addEventListener("click", () => activate(p.id)); tabs.append(b);
  });
  __RENDER_CALLS__
  activate(__DEFAULT_VIEW__);
  document.getElementById("themeBtn").addEventListener("click", () => {
    document.documentElement.dataset.theme = document.documentElement.dataset.theme === "dark" ? "" : "dark";
  });
}
init();
</script>
</body>
</html>
"""


def render_page(
    data: dict,
    panels: list[Panel],
    *,
    brand: str = "ra",
    default_view: str | None = None,
) -> str:
    """Assemble a self-contained page from ``data`` + an ordered list of panels.

    ``data`` is embedded as JSON (the panels' JS reads it via the ``DATA`` /
    ``RUN`` globals). ``default_view`` is the panel id shown first; it defaults
    to the first panel.
    """

    blob = json.dumps(data).replace("</", "<\\/")  # don't let </ close <script>
    css = style.base_css() + _SHELL_CSS + "".join(p.css for p in panels)
    sections = "\n".join(p.section for p in panels)
    panel_js = "\n".join(p.js for p in panels)
    render_calls = "\n  ".join(p.render_call for p in panels)
    panels_meta = json.dumps([{"id": p.id, "label": p.label} for p in panels])
    default = json.dumps(default_view or (panels[0].id if panels else ""))
    escaped_brand = escape(brand, quote=True)
    escaped_title = escape(f"{brand} — run view", quote=True)
    replacements = {
        "__TITLE__": escaped_title,
        "__BRAND__": escaped_brand,
        "__STYLE__": css,
        "__SECTIONS__": sections,
        "__PANELS_META__": panels_meta,
        "__PANEL_JS__": panel_js,
        "__RENDER_CALLS__": render_calls,
        "__DEFAULT_VIEW__": default,
        "__DATA__": blob,
    }
    return _SHELL_PLACEHOLDER_RE.sub(lambda match: replacements[match.group(0)], _SHELL)


def render_trace_html(run: RunTrace, *, brand: str = "ra") -> str:
    """Render a run's causal agent trace as a standalone single-page viewer."""

    data = {
        "title": run.title,
        "task_id": run.task_id,
        "models": run.models,
        "run": run.as_dict(),
    }
    return render_page(data, [trace_panel()], brand=brand, default_view="trace")


def write_trace_html(run_dir: Path, out: Path | None = None) -> Path:
    """Load ``run_dir`` and write the standalone trace viewer to ``out``."""

    run = load_rollout_dir(run_dir)
    target = out or (Path(run_dir) / "trace.html")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_trace_html(run), encoding="utf-8")
    return target
