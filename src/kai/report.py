"""Render a run's findings as a Markdown security report.

The no-browser companion to :mod:`kai.viewer`: same on-disk source
(``<run_dir>/exploits.json``), but a plain-text report you can pipe into CI,
paste into a PR, or read over SSH. Markdown renders on GitHub and stays
legible in a terminal, so one format serves both.

    python -m kai.report <run_dir> [-o OUT]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from kai.viewer.findings import Finding, load_findings

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "none")


def _cell(text: str) -> str:
    """Make a value safe for a single Markdown table cell."""

    return str(text).replace("|", r"\|").replace("\n", " ").strip()


def _score(finding: Finding) -> str:
    return f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "—"


def _location(finding: Finding) -> str:
    file = finding.file.split("/")[-1] if finding.file else ""
    return f"{file}:{finding.function}" if finding.function else file


def _summary_line(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [f"{counts[s]} {s}" for s in _SEVERITY_ORDER if counts.get(s)]
    n = len(findings)
    head = f"**{n} finding{'s' if n != 1 else ''}**"
    return f"{head} · {' · '.join(parts)}" if parts else head


def _summary_table(findings: list[Finding]) -> list[str]:
    rows = [
        "| CVSS | Severity | Finding | Category | Location | Status |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        status = f.status + (" ✓" if f.confirmed else "")
        rows.append(
            f"| {_score(f)} | {f.severity} | {_cell(f.title)} | "
            f"{_cell(f.category.replace('_', ' '))} | {_cell(_location(f))} | "
            f"{_cell(status)} |"
        )
    return rows


def _finding_section(idx: int, f: Finding) -> list[str]:
    out: list[str] = []
    sev = f" ({f.severity})" if f.severity != "none" else ""
    out.append(f"## {idx}. {f.title}  ·  CVSS {_score(f)}{sev}")
    out.append("")

    facts = [
        ("Location", f"{f.file} · `{f.function}()`" if f.function else f.file),
        ("Category", f.category.replace("_", " ")),
        ("Attacker", f.attacker_role),
        ("Precondition", f.prerequisite),
        ("Status", f.status + (" · confirmed" if f.confirmed else "")),
    ]
    for label, value in facts:
        if value:
            out.append(f"- **{label}:** {value}")
    out.append("")

    if f.hypothesis:
        out += ["**Why it's exploitable**", "", f.hypothesis, ""]
    if f.exploit_sketch:
        out += ["**Exploit sketch**", "", f.exploit_sketch, ""]

    if f.cvss_rows:
        out += ["**CVSS 3.1**" + (f" — `{f.cvss_vector}`" if f.cvss_vector else ""), ""]
        out += ["| Metric | Value | Justification |", "|---|---|---|"]
        for r in f.cvss_rows:
            out.append(f"| {r['metric']} | {r['value']} | {_cell(r['why'])} |")
        out.append("")

    if f.poc_code:
        out += ["**Proof of concept**", "", "```", f.poc_code, "```", ""]
    if f.patch:
        out += ["**Suggested patch**", "", "```diff", f.patch, "```", ""]
    if f.critic_summary:
        out += ["**Critic**", "", f.critic_summary, ""]
    return out


def render_markdown(findings: list[Finding], title: str = "") -> str:
    """Render a sorted findings list into a Markdown report."""

    lines = [f"# Security findings{f' — {title}' if title else ''}", ""]
    if not findings:
        lines += ["No findings recorded for this run.", ""]
        return "\n".join(lines)

    lines += [_summary_line(findings), ""]
    lines += _summary_table(findings)
    lines += ["", "---", ""]
    for idx, f in enumerate(findings, start=1):
        lines += _finding_section(idx, f)
    return "\n".join(lines).rstrip() + "\n"


def render_run(run_dir: Path) -> str:
    """Load ``<run_dir>/exploits.json`` and render the Markdown report."""

    run_dir = Path(run_dir)
    return render_markdown(load_findings(run_dir), title=run_dir.name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m kai.report",
        description="Render a run's findings as a Markdown security report.",
    )
    parser.add_argument("run_dir", help="run directory (a state/<run_id>/ dir)")
    parser.add_argument("-o", "--output", help="write to PATH (default: stdout)")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"error: {run_dir} is not a directory", file=sys.stderr)
        return 2

    markdown = render_run(run_dir)
    if args.output:
        Path(args.output).write_text(markdown, encoding="utf-8")
        print(args.output)
    else:
        sys.stdout.write(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
