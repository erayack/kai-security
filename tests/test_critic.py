"""Tests for the critic result processor and ExploitRecord enrichment."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from kai.definitions.exploit.parsers import process_critic_result
from kai.state.models import ExploitRecord


def _make_state_manager() -> MagicMock:
    sm = MagicMock()
    return sm


class TestCriticResultProcessor:
    """Tests for process_critic_result."""

    def test_critic_enriches_exploit_record(self) -> None:
        """Critic output updates ExploitRecord fields via state manager."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "exploit_id": "e1",
                "adversarial_viability": "exploitable",
                "profit_model": (
                    "Attacker drains victim staked ETH via "
                    "manipulated share calculation"
                ),
                "external_mitigations": "None identified",
                "platform_validity": "Valid under Sherlock rules",
                "critic_summary": (
                    "Rational adversary profits at victim expense. "
                    "No external safety net closes the attack path."
                ),
            }
        )
        process_critic_result(sm, "run1", {"exploit_id": "e1"}, raw)

        sm.update_exploit.assert_called_once()
        call_args = sm.update_exploit.call_args
        assert call_args[0] == ("run1", "e1")
        kw = call_args[1]
        assert kw["adversarial_viability"] == "exploitable"
        assert "manipulated share" in kw["profit_model"]
        assert kw["external_mitigations"] == "None identified"
        assert kw["platform_validity"] == "Valid under Sherlock rules"
        assert "Rational adversary" in kw["critic_summary"]

    def test_critic_self_harm_detection(self) -> None:
        """Finding where attacker == victim gets self_harm."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "exploit_id": "e2",
                "adversarial_viability": "self_harm",
                "profit_model": (
                    "Attacker can only damage their own deposit "
                    "by passing invalid target address"
                ),
                "external_mitigations": (
                    "Sequencer validates target addresses before inclusion"
                ),
                "platform_validity": (
                    "Invalid under Sherlock: user input "
                    "validation is not a valid finding"
                ),
                "critic_summary": (
                    "The attacker is the victim. Sending to an "
                    "invalid address only harms the sender's own "
                    "funds. This is user input validation."
                ),
            }
        )
        process_critic_result(sm, "run1", {"exploit_id": "e2"}, raw)

        sm.update_exploit.assert_called_once()
        kw = sm.update_exploit.call_args[1]
        assert kw["adversarial_viability"] == "self_harm"
        assert "own deposit" in kw["profit_model"]

    def test_critic_preserves_verifier_fields(self) -> None:
        """Critic does not touch confirmed, poc_code, cvss, or status."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "exploit_id": "e3",
                "adversarial_viability": "griefing",
                "profit_model": "Attacker spends gas to block others",
                "external_mitigations": "",
                "platform_validity": "no platform rules provided",
                "critic_summary": "Pure griefing with no profit motive.",
            }
        )
        process_critic_result(sm, "run1", {"exploit_id": "e3"}, raw)

        sm.update_exploit.assert_called_once()
        kw = sm.update_exploit.call_args[1]
        # Critic must never set verifier-owned fields
        assert "confirmed" not in kw
        assert "status" not in kw
        assert "poc_code" not in kw
        assert "cvss_vector" not in kw
        assert "cvss_score" not in kw
        assert "severity" not in kw

    def test_critic_empty_threat_context(self) -> None:
        """Works without threat context — external_mitigations is empty."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "exploit_id": "e4",
                "adversarial_viability": "exploitable",
                "profit_model": "Attacker extracts funds",
                "external_mitigations": "",
                "platform_validity": "no platform rules provided",
                "critic_summary": "Exploitable with no mitigations.",
            }
        )
        process_critic_result(sm, "run1", {"exploit_id": "e4"}, raw)

        sm.update_exploit.assert_called_once()
        kw = sm.update_exploit.call_args[1]
        assert kw["external_mitigations"] == ""
        assert kw["platform_validity"] == "no platform rules provided"

    def test_critic_exploit_id_from_kwargs(self) -> None:
        """exploit_id is taken from kwargs when not in result JSON."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "adversarial_viability": "no_profit",
                "profit_model": "No extractable value",
                "external_mitigations": "",
                "platform_validity": "",
                "critic_summary": "No profit motive.",
            }
        )
        process_critic_result(sm, "run1", {"exploit_id": "e5"}, raw)

        sm.update_exploit.assert_called_once()
        assert sm.update_exploit.call_args[0] == ("run1", "e5")

    def test_critic_malformed_json_no_crash(self) -> None:
        """Malformed JSON returns raw result without crashing."""
        sm = _make_state_manager()
        result = process_critic_result(
            sm, "run1", {"exploit_id": "e6"}, "not json at all {"
        )
        # Should not crash, returns raw result
        assert "not json" in result
        sm.update_exploit.assert_not_called()

    def test_critic_no_exploit_id_skips_update(self) -> None:
        """Missing exploit_id in both kwargs and result skips update."""
        sm = _make_state_manager()
        raw = json.dumps(
            {
                "adversarial_viability": "exploitable",
                "profit_model": "test",
                "external_mitigations": "",
                "platform_validity": "",
                "critic_summary": "test",
            }
        )
        process_critic_result(sm, "run1", {}, raw)
        sm.update_exploit.assert_not_called()


class TestExploitRecordCriticFields:
    """Tests for critic fields on ExploitRecord."""

    def test_fields_default_to_none(self) -> None:
        record = ExploitRecord(
            run_id="r1",
            exploit_id="e1",
            timestamp="t",
            source_agent="analyzer",
            status="candidate",
            hypothesis="h",
            file="f",
            function="fn",
        )
        assert record.adversarial_viability is None
        assert record.profit_model is None
        assert record.external_mitigations is None
        assert record.platform_validity is None
        assert record.critic_summary is None

    def test_to_dict_includes_critic_fields(self) -> None:
        record = ExploitRecord(
            run_id="r1",
            exploit_id="e1",
            timestamp="t",
            source_agent="analyzer",
            status="verified",
            hypothesis="h",
            file="f",
            function="fn",
            adversarial_viability="exploitable",
            profit_model="Attacker drains funds",
            external_mitigations="None",
            platform_validity="Valid",
            critic_summary="Exploitable finding.",
        )
        d = record.to_dict()
        assert d["adversarial_viability"] == "exploitable"
        assert d["profit_model"] == "Attacker drains funds"
        assert d["external_mitigations"] == "None"
        assert d["platform_validity"] == "Valid"
        assert d["critic_summary"] == "Exploitable finding."

    def test_from_dict_round_trips(self) -> None:
        original = ExploitRecord(
            run_id="r1",
            exploit_id="e1",
            timestamp="t",
            source_agent="analyzer",
            status="verified",
            hypothesis="h",
            file="f",
            function="fn",
            adversarial_viability="self_harm",
            profit_model="Attacker harms self",
            external_mitigations="Sequencer blocks",
            platform_validity="Invalid per Sherlock",
            critic_summary="Self-harm finding.",
        )
        d = original.to_dict()
        restored = ExploitRecord.from_dict(d)
        assert restored.adversarial_viability == "self_harm"
        assert restored.profit_model == "Attacker harms self"
        assert restored.external_mitigations == "Sequencer blocks"
        assert restored.platform_validity == "Invalid per Sherlock"
        assert restored.critic_summary == "Self-harm finding."

    def test_from_dict_missing_critic_fields(self) -> None:
        """Old data without critic fields deserializes with None."""
        data = {
            "run_id": "r1",
            "exploit_id": "e1",
            "timestamp": "t",
            "source_agent": "analyzer",
            "status": "candidate",
            "hypothesis": "h",
            "file": "f",
            "function": "fn",
        }
        record = ExploitRecord.from_dict(data)
        assert record.adversarial_viability is None
        assert record.profit_model is None
        assert record.external_mitigations is None
        assert record.platform_validity is None
        assert record.critic_summary is None
