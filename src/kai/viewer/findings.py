"""Load security findings from a run's ``exploits.json``.

A normal pipeline run persists its findings as a JSON array of
:class:`kai.state.models.ExploitRecord` dicts at
``<state_dir>/<run_id>/exploits.json``. This module folds those into the
flat :class:`Finding` view-model the HTML renderer draws, deriving display
helpers (a one-line title, a severity bucket, a human-readable CVSS vector)
without needing a live state backend.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kai import cvss

# Human-readable expansions for CVSS 3.1 vector codes, by metric.
_CVSS_LABELS: dict[str, dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}
_CVSS_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Status / category ordering: confirmed, runtime-exploitable findings first.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


@dataclass
class Finding:
    """One vulnerability finding, flattened for display."""

    exploit_id: str
    title: str
    hypothesis: str
    exploit_sketch: str
    file: str
    function: str
    category: str
    status: str
    confirmed: bool | None
    severity: str
    cvss_score: float | None
    cvss_vector: str
    cvss_rows: list[dict[str, str]] = field(default_factory=list)
    poc_code: str = ""
    patch: str = ""
    attacker_role: str = ""
    prerequisite: str = ""
    adversarial_viability: str = ""
    profit_model: str = ""
    critic_summary: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "exploit_id": self.exploit_id,
            "title": self.title,
            "hypothesis": self.hypothesis,
            "exploit_sketch": self.exploit_sketch,
            "file": self.file,
            "function": self.function,
            "category": self.category,
            "status": self.status,
            "confirmed": self.confirmed,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cvss_rows": self.cvss_rows,
            "poc_code": self.poc_code,
            "patch": self.patch,
            "attacker_role": self.attacker_role,
            "prerequisite": self.prerequisite,
            "adversarial_viability": self.adversarial_viability,
            "profit_model": self.profit_model,
            "critic_summary": self.critic_summary,
        }


def _title_of(record: dict[str, Any]) -> str:
    """A one-line headline: the first sentence of the hypothesis, else a
    ``<category> in <function>`` fallback."""

    hypothesis = str(record.get("hypothesis") or "").strip()
    if hypothesis:
        first = hypothesis.replace("\n", " ").split(". ")[0].strip().rstrip(".")
        # Cut at a word boundary so a long first sentence stays a scannable
        # headline rather than wrapping across table cells / section titles.
        if len(first) > 64:
            first = first[:64].rsplit(" ", 1)[0] + "…"
        return first
    category = str(record.get("category") or "finding").replace("_", " ")
    fn = str(record.get("function") or "").strip()
    return f"{category} in {fn}" if fn else category


def _cvss_rows(vector: str, justification: dict[str, str] | None) -> list[dict[str, str]]:
    """Expand a CVSS vector into ordered ``{metric, value, why}`` rows."""

    if not vector:
        return []
    try:
        metrics = cvss.parse_vector(vector)
    except Exception:
        return []
    justification = justification or {}
    rows: list[dict[str, str]] = []
    for code in _CVSS_ORDER:
        if code not in metrics:
            continue
        value = metrics[code]
        rows.append(
            {
                "metric": code,
                "value": _CVSS_LABELS.get(code, {}).get(value, value),
                "why": str(justification.get(code, "")),
            }
        )
    return rows


def _severity_of(record: dict[str, Any]) -> str:
    """The record's severity, lowercased; derived from the CVSS score when
    the field is absent."""

    severity = str(record.get("severity") or "").strip().lower()
    if severity in _SEVERITY_RANK:
        return severity
    score = record.get("cvss_score")
    if isinstance(score, (int, float)):
        return cvss.score_to_severity(float(score)).lower()
    return "none"


def _finding_from_record(record: dict[str, Any]) -> Finding:
    return Finding(
        exploit_id=str(record.get("exploit_id") or ""),
        title=_title_of(record),
        hypothesis=str(record.get("hypothesis") or ""),
        exploit_sketch=str(record.get("exploit_sketch") or ""),
        file=str(record.get("file") or ""),
        function=str(record.get("function") or ""),
        category=str(record.get("category") or ""),
        status=str(record.get("status") or ""),
        confirmed=record.get("confirmed"),
        severity=_severity_of(record),
        cvss_score=record.get("cvss_score"),
        cvss_vector=str(record.get("cvss_vector") or ""),
        cvss_rows=_cvss_rows(
            str(record.get("cvss_vector") or ""), record.get("cvss_justification")
        ),
        poc_code=str(record.get("poc_code") or ""),
        patch=str(record.get("patch") or ""),
        attacker_role=str(record.get("attacker_role") or ""),
        prerequisite=str(record.get("prerequisite") or record.get("required_privileges") or ""),
        adversarial_viability=str(record.get("adversarial_viability") or ""),
        profit_model=str(record.get("profit_model") or ""),
        critic_summary=str(record.get("critic_summary") or ""),
    )


def _sort_key(f: Finding) -> tuple[int, float]:
    """Confirmed findings first, then by descending CVSS score."""

    confirmed = 1 if f.confirmed else 0
    score = f.cvss_score if isinstance(f.cvss_score, (int, float)) else -1.0
    return (confirmed, score)


def load_findings(run_dir: Path) -> list[Finding]:
    """Read ``<run_dir>/exploits.json`` into sorted :class:`Finding` objects.

    Returns an empty list when the file is absent or unparseable (e.g. a
    benchmark rollout dir, which carries ``score.json`` but no findings).
    """

    path = Path(run_dir) / "exploits.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    findings = [_finding_from_record(r) for r in data if isinstance(r, dict)]
    findings.sort(key=_sort_key, reverse=True)
    return findings
