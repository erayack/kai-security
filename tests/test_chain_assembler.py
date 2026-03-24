"""Tests for the chain assembler pipeline."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from kai.definitions.exploit.parsers import process_chain_result
from kai.main import _run_chain_assembler
from kai.state.models import ChainRecord


def _make_state_manager() -> MagicMock:
    sm = MagicMock()
    sm.get_chains.return_value = []
    return sm


class TestProcessChainResult:
    def test_valid_chain(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            [
                {
                    "description": "Reentrancy enables double-mint",
                    "steps": [
                        {
                            "exploit_id": "e1",
                            "role": "anchor",
                            "description": "re-enter withdraw",
                        },
                        {
                            "exploit_id": "e2",
                            "role": "amplifier",
                            "description": "mint extra tokens",
                        },
                    ],
                    "anchor_exploit_ids": ["e1"],
                    "composite_cvss_vector": ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
                }
            ]
        )
        records = process_chain_result(sm, "run1", raw)
        assert len(records) == 1
        assert records[0].description == "Reentrancy enables double-mint"
        assert records[0].anchor_exploit_ids == ["e1"]
        assert records[0].composite_cvss_score == 10.0
        assert records[0].status == "proposed"
        sm.add_chain.assert_called_once()

    def test_no_anchor_skipped(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            [
                {
                    "description": "speculative chain",
                    "steps": [],
                    "anchor_exploit_ids": [],
                }
            ]
        )
        records = process_chain_result(sm, "run1", raw)
        assert len(records) == 0
        sm.add_chain.assert_not_called()

    def test_empty_list(self) -> None:
        sm = _make_state_manager()
        records = process_chain_result(sm, "run1", "[]")
        assert records == []

    def test_malformed_json(self) -> None:
        sm = _make_state_manager()
        records = process_chain_result(sm, "run1", "not json at all")
        assert records == []

    def test_multiple_chains(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            [
                {
                    "description": "chain 1",
                    "steps": [],
                    "anchor_exploit_ids": ["e1"],
                },
                {
                    "description": "chain 2",
                    "steps": [],
                    "anchor_exploit_ids": ["e2"],
                },
            ]
        )
        records = process_chain_result(sm, "run1", raw)
        assert len(records) == 2
        assert sm.add_chain.call_count == 2

    def test_invalid_cvss_vector(self) -> None:
        sm = _make_state_manager()
        raw = json.dumps(
            [
                {
                    "description": "chain with bad cvss",
                    "steps": [],
                    "anchor_exploit_ids": ["e1"],
                    "composite_cvss_vector": "INVALID",
                }
            ]
        )
        records = process_chain_result(sm, "run1", raw)
        assert len(records) == 1
        assert records[0].composite_cvss_score is None


class TestRunChainAssembler:
    def test_returns_none_no_verified(self) -> None:
        sm = _make_state_manager()
        sm.get_exploits.return_value = []
        recipe = MagicMock()
        result = _run_chain_assembler(
            recipe,
            state_manager=sm,
            run_id="run1",
        )
        assert result is None


class TestChainRecordRoundTrip:
    def test_serialization(self) -> None:
        chain = ChainRecord(
            run_id="r1",
            chain_id="c1",
            timestamp="2025-01-01T00:00:00Z",
            status="proposed",
            description="test chain",
            steps=[{"exploit_id": "e1", "role": "anchor", "description": "d"}],
            anchor_exploit_ids=["e1"],
            composite_cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            composite_cvss_score=9.8,
        )
        d = chain.to_dict()
        restored = ChainRecord.from_dict(d)
        assert restored == chain
        assert json.dumps(d)  # JSON-safe
