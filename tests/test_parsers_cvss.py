"""Tests for CVSS integration in fixer and verifier result processors."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from kai.definitions.exploit.parsers import (
    process_fixer_result,
    process_verifier_result,
)


def _make_state_manager() -> MagicMock:
    sm = MagicMock()
    sm.get_fix_attempts.return_value = []
    sm.find_exploit.return_value = MagicMock(exploit_id="e1")
    return sm


class TestFixerCVSS:
    def test_cvss_vector_parsed_and_scored(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_justification": {"AV": "network"},
                "poc_code": "poc",
                "patch": "diff",
                "test_results": "ok",
                "strategy": "remove call",
                "fix_succeeded": True,
            }
        )
        process_fixer_result(sm, "run1", {"exploit_id": "e1"}, raw)

        # Check update_exploit was called with CVSS data
        sm.update_exploit.assert_called_once()
        kw = sm.update_exploit.call_args
        assert kw[1]["cvss_vector"] == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert kw[1]["cvss_score"] == 9.8
        assert kw[1]["severity"] == "Critical"
        assert kw[1]["cvss_justification"] == {"AV": "network"}

        # Check FixRecord was created with CVSS fields
        sm.add_fix.assert_called_once()
        fix = sm.add_fix.call_args[0][0]
        assert fix.cvss_vector == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert fix.cvss_score == 9.8
        assert fix.severity == "Critical"

    def test_missing_vector_falls_back(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "severity": "High",
                "poc_code": "poc",
                "patch": "diff",
                "test_results": "ok",
                "strategy": "s",
                "fix_succeeded": True,
            }
        )
        process_fixer_result(sm, "run1", {"exploit_id": "e1"}, raw)

        kw = sm.update_exploit.call_args
        assert kw[1]["severity"] == "High"
        assert kw[1]["cvss_vector"] == ""
        assert kw[1]["cvss_score"] is None

    def test_malformed_vector_logged(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "cvss_vector": "INVALID",
                "poc_code": "poc",
                "patch": "diff",
                "test_results": "ok",
                "strategy": "s",
                "fix_succeeded": True,
            }
        )
        # Should not raise — logs warning, falls back to empty severity
        process_fixer_result(sm, "run1", {"exploit_id": "e1"}, raw)
        sm.update_exploit.assert_called_once()

    def test_no_fix_no_exploit_update(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "poc_code": "poc",
                "patch": "",
                "test_results": "",
                "strategy": "s",
                "fix_succeeded": False,
            }
        )
        process_fixer_result(sm, "run1", {"exploit_id": "e1"}, raw)
        sm.update_exploit.assert_not_called()
        sm.add_fix.assert_not_called()
        sm.add_fix_attempt.assert_called_once()

    def test_medium_score(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "cvss_justification": {},
                "poc_code": "poc",
                "patch": "diff",
                "test_results": "ok",
                "strategy": "s",
                "fix_succeeded": True,
            }
        )
        process_fixer_result(sm, "run1", {"exploit_id": "e1"}, raw)
        kw = sm.update_exploit.call_args
        assert kw[1]["cvss_score"] == 4.2
        assert kw[1]["severity"] == "Medium"


class TestVerifierCVSS:
    """Tests for CVSS extraction in verifier result processor."""

    def test_confirmed_with_cvss_vector(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "confirmed": True,
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "poc_code": "poc",
                "test_output": "out",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_justification": {"AV": "network accessible"},
            }
        )
        process_verifier_result(sm, "run1", {"exploit_id": "e1"}, raw)

        sm.update_exploit.assert_called_once()
        kw = sm.update_exploit.call_args[1]
        assert kw["status"] == "verified"
        assert kw["cvss_vector"] == "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert kw["cvss_score"] == 9.8
        assert kw["severity"] == "Critical"
        assert kw["cvss_justification"] == {"AV": "network accessible"}

    def test_confirmed_without_cvss_no_cvss_fields(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "confirmed": True,
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "poc_code": "poc",
                "test_output": "out",
            }
        )
        process_verifier_result(sm, "run1", {"exploit_id": "e1"}, raw)

        sm.update_exploit.assert_called_once()
        kw = sm.update_exploit.call_args[1]
        assert kw["status"] == "verified"
        assert "cvss_vector" not in kw

    def test_rejected_no_cvss_fields(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "confirmed": False,
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "poc_code": "",
                "test_output": "",
                "cvss_vector": "",
            }
        )
        process_verifier_result(sm, "run1", {"exploit_id": "e1"}, raw)

        sm.update_exploit.assert_called_once()
        kw = sm.update_exploit.call_args[1]
        assert kw["status"] == "rejected"
        assert "cvss_vector" not in kw

    def test_malformed_vector_no_crash(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "confirmed": True,
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "poc_code": "poc",
                "test_output": "out",
                "cvss_vector": "GARBAGE",
            }
        )
        process_verifier_result(sm, "run1", {"exploit_id": "e1"}, raw)

        sm.update_exploit.assert_called_once()
        kw = sm.update_exploit.call_args[1]
        assert kw["status"] == "verified"
        # Malformed vector should not add CVSS fields
        assert "cvss_score" not in kw

    def test_medium_severity_vector(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "confirmed": True,
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "poc_code": "poc",
                "test_output": "out",
                "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "cvss_justification": {},
            }
        )
        process_verifier_result(sm, "run1", {"exploit_id": "e1"}, raw)

        kw = sm.update_exploit.call_args[1]
        assert kw["cvss_score"] == 4.2
        assert kw["severity"] == "Medium"


class TestVerifierCategoryReassessment:
    """Tests for verifier category reassessment and PR:H safety net."""

    def test_category_override_from_verifier(self) -> None:
        """Verifier returns a different category; parser applies it."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "confirmed": True,
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "poc_code": "poc",
                "test_output": "out",
                "category": "trust_assumption_violation",
                "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "cvss_justification": {},
            }
        )
        process_verifier_result(
            sm,
            "run1",
            {"exploit_id": "e1", "category": "active_exploit"},
            raw,
        )

        kw = sm.update_exploit.call_args[1]
        assert kw["category"] == "trust_assumption_violation"

    def test_pr_h_auto_downgrades_active_exploit(self) -> None:
        """PR:H + active_exploit → auto-downgraded."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "confirmed": True,
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "poc_code": "poc",
                "test_output": "out",
                "category": "active_exploit",
                "cvss_vector": "AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
                "cvss_justification": {},
            }
        )
        process_verifier_result(
            sm,
            "run1",
            {"exploit_id": "e1", "category": "active_exploit"},
            raw,
        )

        kw = sm.update_exploit.call_args[1]
        assert kw["category"] == "trust_assumption_violation"

    def test_pr_h_no_downgrade_if_already_trust_assumption(self) -> None:
        """PR:H with trust_assumption_violation stays unchanged."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "confirmed": True,
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "poc_code": "poc",
                "test_output": "out",
                "category": "trust_assumption_violation",
                "cvss_vector": "AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
                "cvss_justification": {},
            }
        )
        process_verifier_result(
            sm,
            "run1",
            {"exploit_id": "e1", "category": "active_exploit"},
            raw,
        )

        kw = sm.update_exploit.call_args[1]
        # Should be trust_assumption_violation from verifier,
        # NOT double-downgraded or changed
        assert kw["category"] == "trust_assumption_violation"

    def test_category_not_overridden_when_empty(self) -> None:
        """Empty category from verifier preserves original."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "confirmed": True,
                "hypothesis": "h",
                "file": "f",
                "function": "fn",
                "poc_code": "poc",
                "test_output": "out",
                "category": "",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_justification": {},
            }
        )
        process_verifier_result(
            sm,
            "run1",
            {"exploit_id": "e1", "category": "active_exploit"},
            raw,
        )

        kw = sm.update_exploit.call_args[1]
        # No category key should be set since verifier returned empty
        assert "category" not in kw
