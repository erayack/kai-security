"""Tests for kai.cvss — CVSS 3.1 base score calculator."""

from __future__ import annotations

import pytest

from kai.cvss import (
    compute_base_score,
    parse_vector,
    score_to_severity,
    validate_vector,
)


class TestParseVector:
    def test_basic(self) -> None:
        m = parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert m == {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "U",
            "C": "H",
            "I": "H",
            "A": "H",
        }

    def test_with_prefix(self) -> None:
        m = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert m["AV"] == "N"
        assert len(m) == 8

    def test_with_30_prefix(self) -> None:
        m = parse_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N")
        assert m["AV"] == "L"

    def test_case_insensitive(self) -> None:
        m = parse_vector("av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h")
        assert m["AV"] == "N"


class TestValidateVector:
    def test_valid(self) -> None:
        assert validate_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None

    def test_missing_metric(self) -> None:
        err = validate_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
        assert err is not None
        assert "A" in err

    def test_invalid_value(self) -> None:
        err = validate_vector("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert err is not None
        assert "AV" in err


class TestComputeBaseScore:
    """Known CVSS vectors from NVD entries."""

    def test_max_score(self) -> None:
        # CVE-2019-1653 etc. — maximum base score
        m = parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert compute_base_score(m) == 9.8

    def test_scope_changed_max(self) -> None:
        # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
        m = parse_vector("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert compute_base_score(m) == 10.0

    def test_log4shell(self) -> None:
        # CVE-2021-44228 (Log4Shell) = 10.0
        m = parse_vector("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert compute_base_score(m) == 10.0

    def test_medium_score(self) -> None:
        # AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N = 4.2
        m = parse_vector("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N")
        assert compute_base_score(m) == 4.2

    def test_low_score(self) -> None:
        # AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N = 1.8
        m = parse_vector("AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        assert compute_base_score(m) == 1.8

    def test_zero_impact(self) -> None:
        # C:N/I:N/A:N → impact is zero → score is 0.0
        m = parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert compute_base_score(m) == 0.0

    def test_scope_changed_medium(self) -> None:
        # AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N = 5.4
        m = parse_vector("AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N")
        assert compute_base_score(m) == 5.4

    def test_physical_high_priv(self) -> None:
        # AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 6.8
        m = parse_vector("AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert compute_base_score(m) == 6.8


class TestScoreToSeverity:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.0, "None"),
            (0.1, "Low"),
            (3.9, "Low"),
            (4.0, "Medium"),
            (6.9, "Medium"),
            (7.0, "High"),
            (8.9, "High"),
            (9.0, "Critical"),
            (10.0, "Critical"),
        ],
    )
    def test_thresholds(self, score: float, expected: str) -> None:
        assert score_to_severity(score) == expected
