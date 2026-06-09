"""Render a kai run as a single self-contained HTML page.

Composes kai's security **Findings** panel (severity, CVSS, PoC, patch) onto
the reusable viewer in :mod:`ra.viewer` — which supplies the tabbed shell, the
shared design system, and the built-in **Trace** panel. Findings stay here
because they're domain concepts (CVSS, exploits); the trace viewer and styling
live in ``ra`` so any ra agent can reuse them.

Every dynamic value is written via ``textContent`` / DOM nodes, so unsanitised
rollout text cannot inject markup.
"""

from __future__ import annotations

from pathlib import Path

from ra.viewer.html import Panel, render_page, trace_panel
from ra.viewer.trace import RunTrace, load_rollout_dir

from kai.viewer.findings import Finding, load_findings

# Findings-panel layout: the master-detail split + interactive table rows +
# the detail pane. Shared tokens/primitives come from ra.viewer.style.
_FINDINGS_CSS = """\
  .split { display: grid; grid-template-columns: minmax(360px, 1fr) minmax(420px, 1.3fr); }
  @media (max-width: 880px) { .split { grid-template-columns: 1fr; } }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: color-mix(in srgb, var(--accent) 5%, transparent); }
  tbody tr.sel { background: color-mix(in srgb, var(--accent) 9%, transparent); }
  .detail { border-left: 1px solid var(--rule-2); padding: 18px 22px; min-width: 0; }
  .detail h2 { margin: 0 0 4px; font-size: 18px; font-weight: 600; line-height: 1.3; }
  .detail .where { font-size: 12.5px; color: var(--muted); margin-bottom: 16px; }
"""

_FINDINGS_SECTION = """\
<section class="view" id="view-findings">
  <div class="split">
    <div><table><thead><tr>
      <th class="num">CVSS</th><th>Finding</th><th>Category</th><th>Location</th>
    </tr></thead><tbody id="rows"></tbody></table></div>
    <div class="detail" id="detail"></div>
  </div>
</section>"""

_FINDINGS_JS = r"""
const FINDINGS = DATA.findings || [];
const pct = s => Math.max(0, Math.min(100, Math.round((s || 0) / 10 * 100)));
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
  // Contribute the findings tally to the header facts (ahead of the models).
  const facts = document.getElementById("facts"), ref = facts.firstChild;
  const tally = el("span"); tally.append(el("b", null, FINDINGS.length), document.createTextNode(" findings"));
  facts.insertBefore(tally, ref);
  const crit = FINDINGS.filter(f => f.severity === "critical").length;
  if (crit) { const c = el("span", "crit"); c.append(el("b", null, crit), document.createTextNode(" critical")); facts.insertBefore(c, ref); }

  const rows = document.getElementById("rows");
  if (!FINDINGS.length) {
    document.getElementById("view-findings").querySelector(".split")
      .replaceChildren(el("div", "empty", "No findings recorded for this run."));
    return;
  }
  FINDINGS.forEach((f, i) => rows.append(fRow(f, i)));
  fSelect(0);
}
"""


def _findings_panel() -> Panel:
    return Panel(
        "findings", "Findings", _FINDINGS_SECTION, _FINDINGS_CSS, _FINDINGS_JS, "renderFindings();"
    )


def render_html(run: RunTrace, findings: list[Finding] | None = None) -> str:
    """Render the full kai page (Findings + Trace) from a trace + findings list.

    ``findings`` defaults to empty (e.g. a benchmark rollout dir has a trace but
    no ``exploits.json``); the Findings tab then shows an empty state and the
    Trace tab opens first.
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
    default_view = "findings" if findings else "trace"
    return render_page(
        data, [_findings_panel(), trace_panel()], brand="kai", default_view=default_view
    )


def write_html(run_dir: Path, out: Path | None = None) -> Path:
    """Load ``run_dir`` (trace + findings) and write a single HTML file.

    Defaults to ``<run_dir>/trace.html`` so existing callers that link to that
    name keep working.
    """

    run = load_rollout_dir(run_dir)
    findings = load_findings(run_dir)
    target = out or (Path(run_dir) / "trace.html")
    target.write_text(render_html(run, findings), encoding="utf-8")
    return target
