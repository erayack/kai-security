"""CVSS 3.1 base score calculator.

Pure-Python implementation of the CVSS v3.1 specification:
https://www.first.org/cvss/v3.1/specification-document

Only base metrics are supported (no temporal or environmental).
"""

from __future__ import annotations

import math

# -- Metric value weights per the CVSS 3.1 spec --

_AV_WEIGHTS: dict[str, float] = {
    "N": 0.85,
    "A": 0.62,
    "L": 0.55,
    "P": 0.20,
}

_AC_WEIGHTS: dict[str, float] = {
    "L": 0.77,
    "H": 0.44,
}

_PR_WEIGHTS_UNCHANGED: dict[str, float] = {
    "N": 0.85,
    "L": 0.62,
    "H": 0.27,
}

_PR_WEIGHTS_CHANGED: dict[str, float] = {
    "N": 0.85,
    "L": 0.68,
    "H": 0.50,
}

_UI_WEIGHTS: dict[str, float] = {
    "N": 0.85,
    "R": 0.62,
}

_CIA_WEIGHTS: dict[str, float] = {
    "H": 0.56,
    "L": 0.22,
    "N": 0.00,
}

_REQUIRED_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

_VALID_VALUES: dict[str, set[str]] = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"H", "L", "N"},
    "I": {"H", "L", "N"},
    "A": {"H", "L", "N"},
}


def _roundup(x: float) -> float:
    """CVSS 3.1 roundup: smallest y such that y = round(y, 1) and y >= x."""
    return math.ceil(x * 10) / 10


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS 3.1 vector string into a metric dict.

    Accepts vectors with or without the ``CVSS:3.1/`` prefix.

    >>> parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', ...}
    """
    s = vector.strip()
    if s.upper().startswith("CVSS:3.1/"):
        s = s[9:]
    elif s.upper().startswith("CVSS:3.0/"):
        s = s[9:]

    metrics: dict[str, str] = {}
    for part in s.split("/"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()
    return metrics


def validate_vector(vector: str) -> str | None:
    """Validate a CVSS 3.1 vector string.

    Returns an error message if invalid, or ``None`` if valid.
    """
    metrics = parse_vector(vector)
    missing = _REQUIRED_METRICS - metrics.keys()
    if missing:
        return f"Missing metrics: {', '.join(sorted(missing))}"

    for key, value in metrics.items():
        if key not in _VALID_VALUES:
            return f"Unknown metric: {key}"
        if value not in _VALID_VALUES[key]:
            return f"Invalid value '{value}' for metric {key}"

    return None


def compute_base_score(metrics: dict[str, str]) -> float:
    """Compute the CVSS 3.1 base score from parsed metrics.

    Parameters
    ----------
    metrics:
        Dict mapping metric abbreviations to their values,
        e.g. ``{"AV": "N", "AC": "L", ...}``.

    Returns
    -------
    float
        The base score (0.0 – 10.0).
    """
    scope_changed = metrics["S"] == "C"

    # Impact sub-score components
    isc_base = 1 - (
        (1 - _CIA_WEIGHTS[metrics["C"]])
        * (1 - _CIA_WEIGHTS[metrics["I"]])
        * (1 - _CIA_WEIGHTS[metrics["A"]])
    )

    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    if impact <= 0:
        return 0.0

    # Exploitability sub-score
    pr_weights = _PR_WEIGHTS_CHANGED if scope_changed else _PR_WEIGHTS_UNCHANGED
    exploitability = (
        8.22
        * _AV_WEIGHTS[metrics["AV"]]
        * _AC_WEIGHTS[metrics["AC"]]
        * pr_weights[metrics["PR"]]
        * _UI_WEIGHTS[metrics["UI"]]
    )

    if scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))

    return score


def score_to_severity(score: float) -> str:
    """Map a CVSS base score to a severity label per the 3.1 spec."""
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"
