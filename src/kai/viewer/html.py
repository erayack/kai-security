"""Render a run into a single self-contained HTML page.

One file, inline data + CSS + JS, no server and no external requests. The
page has two tabs -- **Findings** (the security report: severity, CVSS, PoC,
patch) and **Trace** (the causal agent spine) -- styled data-first (Tufte):
paper background, one accent colour, severity as a quiet dot + exact score +
a thin 0-10 bar, the patch as a +/- diff. Every dynamic value is written via
``textContent``/DOM nodes, never ``innerHTML``, so unsanitised rollout text
cannot inject markup.

The palette and shared primitives come from :mod:`kai.viewer.style`, so this
interactive viewer and the static ``kai report --format html`` document share
one design system.
"""

from __future__ import annotations

import json
from pathlib import Path

from kai.viewer import style
from kai.viewer.findings import Finding, load_findings
from kai.viewer.trace import RunTrace, load_rollout_dir

# Viewer-only layout: the chrome (header/tabs/toggle), the master-detail
# split, interactive table rows, and the trace spine. Shared primitives
# (tokens, table, severity, code blocks) live in kai.viewer.style.
_VIEWER_LAYOUT = """\
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
  .split { display: grid; grid-template-columns: minmax(360px, 1fr) minmax(420px, 1.3fr); }
  @media (max-width: 880px) { .split { grid-template-columns: 1fr; } }

  tbody tr { cursor: pointer; }
  tbody tr:hover { background: color-mix(in srgb, var(--accent) 5%, transparent); }
  tbody tr.sel { background: color-mix(in srgb, var(--accent) 9%, transparent); }

  .detail { border-left: 1px solid var(--rule-2); padding: 18px 22px; min-width: 0; }
  .detail h2 { margin: 0 0 4px; font-size: 18px; font-weight: 600; line-height: 1.3; }
  .detail .where { font-size: 12.5px; color: var(--muted); margin-bottom: 16px; }

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

_VIEWER_CSS = style.base_css() + _VIEWER_LAYOUT


def render_html(run: RunTrace, findings: list[Finding] | None = None) -> str:
    """Render the full page from a loaded trace + findings list.

    ``findings`` defaults to empty (e.g. a benchmark rollout dir has a trace
    but no ``exploits.json``); the Findings tab then shows an empty state.
    """

    findings = findings or []
    data = {
        "title": run.title,
        "benchmark": run.benchmark,
        "task_id": run.task_id,
        "models": run.models,
        "run": run.as_dict(),
        "findings": [f.as_dict() for f in findings],
    }
    # ``</`` would prematurely close the <script>; escape it in the blob.
    blob = json.dumps(data).replace("</", "<\\/")
    return _TEMPLATE.replace("__STYLE__", _VIEWER_CSS).replace("__DATA__", blob)


def write_html(run_dir: Path, out: Path | None = None) -> Path:
    """Load ``run_dir`` (trace + findings) and write a single HTML file.

    Defaults to ``<run_dir>/trace.html`` so existing callers that link to
    that name keep working.
    """

    run = load_rollout_dir(run_dir)
    findings = load_findings(run_dir)
    target = out or (Path(run_dir) / "trace.html")
    target.write_text(render_html(run, findings), encoding="utf-8")
    return target


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kai — run view</title>
<style>
__STYLE__
</style>
</head>
<body>
<header>
  <h1 class="serif">kai <span class="sub" id="sub"></span></h1>
  <div class="facts" id="facts"></div>
  <div class="spacer"></div>
  <div class="tabs" id="tabs"></div>
  <button class="toggle" id="themeBtn">◐ theme</button>
</header>

<section class="view" id="view-findings">
  <div class="split">
    <div><table><thead><tr>
      <th class="num">CVSS</th><th>Finding</th><th>Category</th><th>Location</th>
    </tr></thead><tbody id="rows"></tbody></table></div>
    <div class="detail" id="detail"></div>
  </div>
</section>

<section class="view" id="view-trace">
  <div class="trace" id="trace"></div>
</section>

<script id="data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById("data").textContent);
const FINDINGS = DATA.findings || [];
const RUN = DATA.run || {};

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = String(text);
  return n;
}
const pct = s => Math.max(0, Math.min(100, Math.round((s || 0) / 10 * 100)));
function head(s) { return (s || "").replace(/\s+/g, " ").trim().slice(0, 130); }

/* ---------------- findings ---------------- */
function fRow(f, i) {
  const tr = el("tr", "sev-" + (f.severity || "none") + (f.confirmed ? "" : " unconf"));
  tr.dataset.i = i;
  const c = el("td", "cvss");
  c.append(el("span", "dot"));
  c.append(el("span", "score", f.cvss_score != null ? Number(f.cvss_score).toFixed(1) : "—"));
  if (f.cvss_score != null) {
    const bar = el("span", "bar"), fill = el("i");
    fill.style.width = pct(f.cvss_score) + "%"; bar.append(fill); c.append(bar);
  }
  const t = el("td"); t.append(el("div", "ftitle", f.title));
  tr.append(c, t, el("td", "cat", (f.category || "").replace(/_/g, " ")),
    el("td", "loc", (f.file ? f.file.split("/").pop() : "") + (f.function ? ":" + f.function : "")));
  tr.addEventListener("click", () => fSelect(i));
  return tr;
}
function diffNode(patch) {
  const pre = el("pre", "diff");
  String(patch).split("\n").forEach(line => {
    const k = line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : null;
    pre.append(el("span", k, line + "\n"));
  });
  return pre;
}
function kvRow(dl, k, v) { if (v) { dl.append(el("dt", null, k), el("dd", null, v)); } }
function fSelect(i) {
  document.querySelectorAll("#rows tr").forEach(r => r.classList.toggle("sel", +r.dataset.i === i));
  const f = FINDINGS[i], d = document.getElementById("detail"); d.replaceChildren();
  d.append(el("h2", "serif", f.title));
  d.append(el("div", "where", f.file + (f.function ? " · " + f.function + "()" : "")));
  const kv = el("dl", "kv");
  const sevLine = (f.severity || "—") + (f.cvss_score != null ? " · CVSS " + Number(f.cvss_score).toFixed(1) : "");
  kvRow(kv, "Severity", sevLine);
  kvRow(kv, "Status", f.status + (f.confirmed ? " · confirmed" : ""));
  kvRow(kv, "Category", (f.category || "").replace(/_/g, " "));
  kvRow(kv, "Attacker", f.attacker_role);
  kvRow(kv, "Precondition", f.prerequisite);
  if (kv.children.length) d.append(kv);

  if (f.hypothesis) { d.append(el("div", "sec-label", "Why it's exploitable")); d.append(el("p", "prose", f.hypothesis)); }
  if (f.exploit_sketch) { d.append(el("div", "sec-label", "Exploit sketch")); d.append(el("p", "prose", f.exploit_sketch)); }

  if (f.cvss_rows && f.cvss_rows.length) {
    d.append(el("div", "sec-label", "CVSS 3.1 vector"));
    if (f.cvss_vector) d.append(el("div", "vector mono", f.cvss_vector));
    const g = el("div", "cvss-grid");
    f.cvss_rows.forEach(r => { g.append(el("span", "m", r.metric), el("span", "v", r.value), el("span", "why", r.why)); });
    d.append(g);
  }
  if (f.poc_code) { d.append(el("div", "sec-label", "Proof of concept")); d.append(el("pre", "code", f.poc_code)); }
  if (f.patch) { d.append(el("div", "sec-label", "Suggested patch")); d.append(diffNode(f.patch)); }
  if (f.critic_summary) { d.append(el("div", "sec-label", "Critic")); d.append(el("p", "prose", f.critic_summary)); }
}
function renderFindings() {
  const rows = document.getElementById("rows");
  if (!FINDINGS.length) {
    document.getElementById("view-findings").querySelector(".split")
      .replaceChildren(el("div", "empty", "No findings recorded for this run."));
    return;
  }
  FINDINGS.forEach((f, i) => rows.append(fRow(f, i)));
  fSelect(0);
}

/* ---------------- trace (causal spine) ---------------- */
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

/* ---------------- shell ---------------- */
function activate(name) {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x.dataset.view === name));
  document.querySelectorAll(".view").forEach(x => x.classList.toggle("active", x.id === "view-" + name));
}
function init() {
  document.getElementById("sub").textContent = "— " + (DATA.title || DATA.task_id || "");
  const crit = FINDINGS.filter(f => f.severity === "critical").length;
  const facts = document.getElementById("facts");
  const f1 = el("span"); f1.append(el("b", null, FINDINGS.length), document.createTextNode(" findings")); facts.append(f1);
  if (crit) { const c = el("span", "crit"); c.append(el("b", null, crit), document.createTextNode(" critical")); facts.append(c); }
  (DATA.models || []).slice(0, 3).forEach(m => facts.append(el("span", "mono", m)));

  const hasFindings = FINDINGS.length > 0;
  const hasTrace = (RUN.root_steps || []).length > 0;
  const tabs = document.getElementById("tabs");
  [["findings", "Findings"], ["trace", "Trace"]].forEach(([id, label]) => {
    const b = el("button", "tab", label); b.dataset.view = id;
    b.addEventListener("click", () => activate(id)); tabs.append(b);
  });

  renderFindings();
  renderTrace();
  activate(hasFindings || !hasTrace ? "findings" : "trace");
  document.getElementById("themeBtn").addEventListener("click", () => {
    document.documentElement.dataset.theme = document.documentElement.dataset.theme === "dark" ? "" : "dark";
  });
}
init();
</script>
</body>
</html>
"""
