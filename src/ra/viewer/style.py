"""Shared design system for kai's HTML surfaces.

One palette, one set of primitives, used by both the interactive viewer
(:mod:`kai.viewer.html`) and the static report document (``kai report
--format html``). Each surface concatenates ``TOKENS + COMPONENTS`` with its
own layout CSS, so the look (colours, severity treatment, code/diff blocks)
can never drift between them.
"""

from __future__ import annotations

# Design tokens: the palette + the single accent. Dark theme overrides the
# same variables, so every component below is theme-aware for free.
TOKENS = """\
  :root {
    --paper:#fafaf7; --panel:#fff; --ink:#1a1a1a; --rule:#e3dfd6; --rule-2:#d8d4cc;
    --muted:#8a857c; --muted-2:#6b665d; --accent:#b3261e; --add:#2f6f43; --del:#9a2a22;
    --gray-bar:#c8c2b5; --code-bg:#f4f1ea;
  }
  [data-theme="dark"] {
    --paper:#14171b; --panel:#1b1f25; --ink:#e7e3da; --rule:#2a3038; --rule-2:#343b44;
    --muted:#9aa3ad; --muted-2:#7f8893; --accent:#e5675d; --add:#7ec99a; --del:#e79a92;
    --gray-bar:#3a424c; --code-bg:#11151b;
  }
"""

# Shared component primitives: base type, the findings table, the severity
# encoding (dot + score + 0-10 bar), the key/value + CVSS detail blocks, and
# code / diff / output panes.
COMPONENTS = """\
  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body { background: var(--paper); color: var(--ink);
    font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  .serif { font-family: Charter, "Iowan Old Style", Georgia, serif; }
  code, pre, .mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }

  table { border-collapse: collapse; width: 100%; }
  thead th { text-align: left; font-size: 10px; letter-spacing: .07em; text-transform: uppercase;
    color: var(--muted-2); font-weight: 600; padding: 10px 14px 8px; border-bottom: 1px solid var(--rule-2); }
  thead th.num { text-align: right; }
  tbody tr { border-bottom: 1px solid var(--rule); }
  td { padding: 11px 14px; vertical-align: top; }
  td.cvss { white-space: nowrap; }

  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; vertical-align: middle; margin-right: 7px; background: var(--gray-bar); }
  .sev-critical .dot, .sev-high .dot { background: var(--accent); }
  .sev-medium .dot { background: var(--muted-2); }
  .score { font-family: ui-monospace, monospace; font-weight: 600; font-size: 13px; }
  .bar { display:block; height: 3px; width: 64px; background: var(--gray-bar); margin-top: 6px; border-radius: 2px; }
  .bar > i { display:block; height: 100%; background: var(--muted-2); border-radius: 2px; }
  .sev-critical .bar > i, .sev-high .bar > i { background: var(--accent); }
  .ftitle { font-weight: 600; }
  .cat { font-size: 11px; color: var(--muted-2); }
  .loc { font-size: 12px; color: var(--muted); }
  .unconf { opacity: .62; }

  .kv { display: grid; grid-template-columns: 130px 1fr; gap: 5px 14px; font-size: 13px; margin: 0; }
  .kv dt { color: var(--muted-2); }
  .kv dd { margin: 0; }
  .sec-label { font-size: 11px; letter-spacing: .07em; text-transform: uppercase; color: var(--muted-2);
    margin: 18px 0 8px; border-top: 1px solid var(--rule); padding-top: 12px; }
  .prose { white-space: pre-wrap; margin: 0; }
  .cvss-grid { display: grid; grid-template-columns: max-content max-content 1fr; gap: 5px 14px;
    font-size: 12.5px; align-items: baseline; }
  .cvss-grid .m { color: var(--muted-2); font-family: ui-monospace, monospace; }
  .cvss-grid .v { font-weight: 500; }
  .cvss-grid .why { color: var(--muted); font-size: 12px; }
  .vector { font-size: 12px; color: var(--muted); margin: 0 0 10px; }

  pre.code, pre.diff, pre.output { margin: 0 0 4px; padding: 11px 13px; border: 1px solid var(--rule-2);
    border-radius: 6px; background: var(--code-bg); overflow: auto; font-size: 12.5px; line-height: 1.5; }
  pre.code, pre.diff { white-space: pre; }
  pre.output { white-space: pre-wrap; color: var(--muted-2); max-height: 320px; }
  pre.diff .add { color: var(--add); }
  pre.diff .del { color: var(--del); }
  .empty { color: var(--muted); padding: 40px 22px; }
"""


def base_css() -> str:
    """The shared stylesheet: tokens + component primitives."""

    return TOKENS + COMPONENTS
