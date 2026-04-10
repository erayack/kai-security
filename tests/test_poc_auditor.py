"""Tests for the PoC auditor agent integration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _FakeExploitRecord:
    exploit_id: str = "ex-001"
    status: str = "verified"
    hypothesis: str = "test hypothesis"
    file: str = "src/Token.sol"
    function: str = "transfer"
    poc_code: str = "print('poc')"
    test_output: str = "PASS"
    category: str = "active_exploit"
    attacker_role: str = "anyone"
    trusted_component_abused: str = "none (permissionless)"
    affected_files: list[str] = field(default_factory=list)


class _FakeStateManager:
    """Minimal stub implementing get_exploits and update_exploit."""

    def __init__(self, records: list[_FakeExploitRecord] | None = None) -> None:
        self._records = list(records or [])
        self.updates: list[dict[str, Any]] = []

    def get_exploits(
        self, run_id: str, status: str | None = None
    ) -> list[_FakeExploitRecord]:
        if status:
            return [r for r in self._records if r.status == status]
        return list(self._records)

    def update_exploit(self, run_id: str, exploit_id: str, **fields: object) -> None:
        self.updates.append({"exploit_id": exploit_id, **fields})
        for rec in self._records:
            if rec.exploit_id == exploit_id:
                for k, v in fields.items():
                    setattr(rec, k, v)


# ---------------------------------------------------------------------------
# 1. Config tests
# ---------------------------------------------------------------------------


class TestPocAuditorConfig:
    """Verify poc_auditor_config is separate from root agents."""

    def test_poc_auditor_config_not_in_root_agents(self) -> None:
        from kai.definitions.exploit.config import config, poc_auditor_config

        agent_names = [a.name for a in config.agents]
        assert "poc_auditor" not in agent_names
        assert poc_auditor_config.name == "poc_auditor"

    def test_poc_auditor_has_no_tools(self) -> None:
        from kai.definitions.exploit.config import poc_auditor_config

        assert poc_auditor_config.tools == {}

    def test_poc_auditor_max_iterations(self) -> None:
        # Default is 5 (KAI_POC_AUDITOR_ITERS env var can override).
        from kai.definitions.exploit.config import poc_auditor_config

        # Accept any value ≤ 15 — the env var may raise it for CI,
        # but the default (5) must be reasonable.
        assert poc_auditor_config.max_iterations <= 15


# ---------------------------------------------------------------------------
# 2. find_interface_source tests
# ---------------------------------------------------------------------------


class TestFindInterfaceSource:
    """Tests for the interface source finder utility."""

    def test_finds_solidity_interface(self, tmp_path: Any) -> None:
        from kai.definitions.exploit.spawn_hooks import find_interface_source

        # Create src/IToken.sol alongside src/Token.sol
        src = tmp_path / "src"
        src.mkdir()
        iface_content = "interface IToken { function transfer(); }"
        (src / "IToken.sol").write_text(iface_content)
        (src / "Token.sol").write_text("contract Token {}")

        result = find_interface_source("src/Token.sol", str(tmp_path))
        assert result == iface_content

    def test_finds_interface_in_parent(self, tmp_path: Any) -> None:
        from kai.definitions.exploit.spawn_hooks import find_interface_source

        # Interface one level up
        (tmp_path / "IGame.sol").write_text("interface IGame {}")
        sub = tmp_path / "impl"
        sub.mkdir()
        (sub / "Game.sol").write_text("contract Game {}")

        result = find_interface_source("impl/Game.sol", str(tmp_path))
        assert result == "interface IGame {}"

    def test_finds_interface_in_interfaces_dir(self, tmp_path: Any) -> None:
        from kai.definitions.exploit.spawn_hooks import find_interface_source

        src = tmp_path / "src"
        src.mkdir()
        ifaces = src / "interfaces"
        ifaces.mkdir()
        (ifaces / "IVault.sol").write_text("interface IVault {}")
        (src / "Vault.sol").write_text("contract Vault {}")

        result = find_interface_source("src/Vault.sol", str(tmp_path))
        assert result == "interface IVault {}"

    def test_not_found_returns_none(self, tmp_path: Any) -> None:
        from kai.definitions.exploit.spawn_hooks import find_interface_source

        result = find_interface_source("src/Missing.sol", str(tmp_path))
        assert result is None

    def test_never_raises(self) -> None:
        from kai.definitions.exploit.spawn_hooks import find_interface_source

        # Invalid paths should not raise
        result = find_interface_source("", "/nonexistent")
        assert result is None


# ---------------------------------------------------------------------------
# 3. Verifier wrapper + auditor chaining tests
# ---------------------------------------------------------------------------


def _make_fake_spawn(
    confirmed: bool = True,
    category: str = "active_exploit",
) -> MagicMock:
    """Return a mock spawn_fn that returns a verifier verdict."""
    verdict = json.dumps(
        {
            "confirmed": confirmed,
            "hypothesis": "test",
            "file": "src/Token.sol",
            "function": "transfer",
            "poc_code": "print('poc')",
            "test_output": "PASS",
            "category": category,
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    )
    mock = MagicMock(return_value=verdict)
    return mock


class TestVerifierWrapperAuditorChaining:
    """Test that the verifier wrapper chains the auditor."""

    def test_runs_auditor_on_confirmed(self) -> None:
        from kai.definitions.exploit.spawn_hooks import (
            make_verifier_spawn_wrapper,
        )

        rec = _FakeExploitRecord(status="candidate")
        sm = _FakeStateManager([rec])
        spawn = _make_fake_spawn(confirmed=True)
        auditor_cfg = MagicMock()

        # We need to mock resolve_exploit_index to do nothing
        # and _maybe_run_auditor to track calls
        with patch(
            "kai.definitions.exploit.spawn_hooks._maybe_run_auditor"
        ) as mock_auditor:
            wrapped = make_verifier_spawn_wrapper(
                spawn,
                sm,
                "run-1",
                auditor_config=auditor_cfg,  # type: ignore[arg-type]
            )
            # Must pass exploit_index through resolve_exploit_index
            # but our fake state doesn't support that, so mock it
            with patch(
                "kai.definitions.exploit.proxy.resolve_exploit_index",
                return_value=None,
            ):
                wrapped(exploit_id="ex-001")

            mock_auditor.assert_called_once_with(
                auditor_cfg, sm, "run-1", "ex-001", {"exploit_id": "ex-001"}
            )

    def test_auditor_hook_called_on_rejected_verdict(self) -> None:
        from kai.definitions.exploit.spawn_hooks import (
            make_verifier_spawn_wrapper,
        )

        rec = _FakeExploitRecord(status="candidate")
        sm = _FakeStateManager([rec])
        spawn = _make_fake_spawn(confirmed=False)
        auditor_cfg = MagicMock()

        with patch(
            "kai.definitions.exploit.spawn_hooks._maybe_run_auditor"
        ) as mock_auditor:
            wrapped = make_verifier_spawn_wrapper(
                spawn,
                sm,
                "run-1",
                auditor_config=auditor_cfg,  # type: ignore[arg-type]
            )
            with patch(
                "kai.definitions.exploit.proxy.resolve_exploit_index",
                return_value=None,
            ):
                wrapped(exploit_id="ex-001")

            mock_auditor.assert_called_once()

    def test_no_auditor_when_config_is_none(self) -> None:
        from kai.definitions.exploit.spawn_hooks import (
            make_verifier_spawn_wrapper,
        )

        rec = _FakeExploitRecord(status="candidate")
        sm = _FakeStateManager([rec])
        spawn = _make_fake_spawn(confirmed=True)

        with patch(
            "kai.definitions.exploit.spawn_hooks._maybe_run_auditor"
        ) as mock_auditor:
            wrapped = make_verifier_spawn_wrapper(
                spawn,
                sm,
                "run-1",
                auditor_config=None,  # type: ignore[arg-type]
            )
            with patch(
                "kai.definitions.exploit.proxy.resolve_exploit_index",
                return_value=None,
            ):
                wrapped(exploit_id="ex-001")

            mock_auditor.assert_not_called()


class TestMaybeRunAuditor:
    """Test _maybe_run_auditor logic."""

    def test_rejects_on_unsound(self) -> None:
        from kai.definitions.exploit.spawn_hooks import _maybe_run_auditor

        rec = _FakeExploitRecord(status="verified")
        sm = _FakeStateManager([rec])
        auditor_cfg = MagicMock()

        audit_result = {
            "sound": False,
            "issues": [
                {
                    "type": "mock_dependency",
                    "explanation": "MockVerifier used in trust path",
                    "severity": "fatal",
                }
            ],
            "recommendation": "reject",
            "summary": "PoC uses mock verifier",
        }

        with patch(
            "kai.definitions.exploit.spawn_hooks._run_poc_auditor",
            return_value=audit_result,
        ):
            _maybe_run_auditor(
                auditor_cfg,  # type: ignore[arg-type]
                sm,  # type: ignore[arg-type]
                "run-1",
                "ex-001",
                {"exploit_id": "ex-001"},
            )

        # Should have been rejected
        assert rec.status == "rejected"
        assert "PoC audit rejection" in (rec.test_output or "")

    def test_leaves_verified_on_sound(self) -> None:
        from kai.definitions.exploit.spawn_hooks import _maybe_run_auditor

        rec = _FakeExploitRecord(status="verified")
        sm = _FakeStateManager([rec])
        auditor_cfg = MagicMock()

        audit_result = {
            "sound": True,
            "issues": [],
            "recommendation": "accept",
            "summary": "PoC is legitimate",
        }

        with patch(
            "kai.definitions.exploit.spawn_hooks._run_poc_auditor",
            return_value=audit_result,
        ):
            _maybe_run_auditor(
                auditor_cfg,  # type: ignore[arg-type]
                sm,  # type: ignore[arg-type]
                "run-1",
                "ex-001",
                {"exploit_id": "ex-001"},
            )

        assert rec.status == "verified"

    def test_auditor_crash_fails_open(self) -> None:
        from kai.definitions.exploit.spawn_hooks import _maybe_run_auditor

        rec = _FakeExploitRecord(status="verified")
        sm = _FakeStateManager([rec])
        auditor_cfg = MagicMock()

        with patch(
            "kai.definitions.exploit.spawn_hooks._run_poc_auditor",
            side_effect=RuntimeError("auditor crashed"),
        ):
            _maybe_run_auditor(
                auditor_cfg,  # type: ignore[arg-type]
                sm,  # type: ignore[arg-type]
                "run-1",
                "ex-001",
                {"exploit_id": "ex-001"},
            )

        # Fail-open: stays verified
        assert rec.status == "verified"

    def test_skips_when_not_verified(self) -> None:
        from kai.definitions.exploit.spawn_hooks import _maybe_run_auditor

        rec = _FakeExploitRecord(status="rejected")
        sm = _FakeStateManager([rec])
        auditor_cfg = MagicMock()

        with patch(
            "kai.definitions.exploit.spawn_hooks._run_poc_auditor",
        ) as mock_run:
            _maybe_run_auditor(
                auditor_cfg,  # type: ignore[arg-type]
                sm,  # type: ignore[arg-type]
                "run-1",
                "ex-001",
                {"exploit_id": "ex-001"},
            )
            mock_run.assert_not_called()

    def test_auditor_returns_none_leaves_verified(self) -> None:
        from kai.definitions.exploit.spawn_hooks import _maybe_run_auditor

        rec = _FakeExploitRecord(status="verified")
        sm = _FakeStateManager([rec])
        auditor_cfg = MagicMock()

        with patch(
            "kai.definitions.exploit.spawn_hooks._run_poc_auditor",
            return_value=None,
        ):
            _maybe_run_auditor(
                auditor_cfg,  # type: ignore[arg-type]
                sm,  # type: ignore[arg-type]
                "run-1",
                "ex-001",
                {"exploit_id": "ex-001"},
            )

        assert rec.status == "verified"
