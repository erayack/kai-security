"""Unit tests for the EVMbench adapter that don't need the network."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from evaluation.adapters.evmbench.adapter import (
    EVMBenchAdapter,
    _agent_text_for_judge_evm,
    _match_vulns,
)
from evaluation.schemas import TaskRef


def _root(tmp_path: Path) -> Path:
    """Build a minimal frontier-evals layout with one audit + one split."""

    root = tmp_path / "frontier-evals" / "project" / "evmbench"
    (root / "audits" / "test-audit-001").mkdir(parents=True)
    (root / "splits").mkdir(parents=True)
    (root / "audits" / "test-audit-001" / "config.yaml").write_text(
        "id: test-audit-001\n"
        "vulnerabilities:\n"
        "  - id: H-01\n"
        "    title: Reentrancy in withdraw allows attacker to drain Vault\n"
        "  - id: H-02\n"
        "    title: Integer overflow in mint\n"
    )
    (root / "splits" / "detect-tasks.txt").write_text("test-audit-001\n")
    return root


def _adapter(tmp_path: Path, **overrides: Any) -> EVMBenchAdapter:
    cfg: dict[str, Any] = {
        "frontier_evals_root": str(_root(tmp_path)),
        "clone_audit_source": False,
        "audit_cache_dir": str(tmp_path / "cache"),
    }
    cfg.update(overrides)
    return EVMBenchAdapter(cfg)


def test_setup_mode_recipe_default(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    assert adapter.setup_mode == "recipe"


def test_setup_mode_invalid_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        _adapter(tmp_path, setup_mode="whatever")


def test_prepare_recipe_mode_writes_recipe(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    task = TaskRef(benchmark="evmbench", task_id="test-audit-001")
    prepared = adapter.prepare(task, tmp_path / "work")

    assert prepared.recipe_path is not None
    assert prepared.recipe_path.exists()
    assert prepared.oracle["setup_mode"] == "recipe"
    # Foundry hint must NOT be in the prompt extras in recipe mode.
    assert "Foundry project" not in (prepared.prompt_extras or "")


def test_prepare_auto_mode_skips_recipe_and_appends_foundry_hint(
    tmp_path: Path,
) -> None:
    adapter = _adapter(tmp_path, setup_mode="auto")
    task = TaskRef(benchmark="evmbench", task_id="test-audit-001")
    prepared = adapter.prepare(task, tmp_path / "work")

    assert prepared.recipe_path is None
    assert prepared.oracle["setup_mode"] == "auto"
    extras = prepared.prompt_extras or ""
    assert "Foundry" in extras
    assert "forge install" in extras
    assert "forge build" in extras


def test_match_vulns_substring_hit() -> None:
    vulns = [
        {"id": "H-01", "title": "Reentrancy in withdraw allows attacker to drain Vault"}
    ]
    haystack = "found reentrancy in withdraw allows attacker to drain vault!"
    matched = _match_vulns(haystack, vulns)
    assert [m["id"] for m in matched] == ["H-01"]


def test_match_vulns_token_majority_hit() -> None:
    vulns = [
        {"id": "H-02", "title": "Integer overflow in mint causes balance corruption"}
    ]
    haystack = "the mint function has an integer overflow problem on balance"
    matched = _match_vulns(haystack, vulns)
    assert [m["id"] for m in matched] == ["H-02"]


def test_match_vulns_returns_empty_on_miss() -> None:
    vulns = [{"id": "H-01", "title": "Reentrancy in withdraw"}]
    haystack = "totally unrelated cross-site scripting"
    assert _match_vulns(haystack, vulns) == []


def test_agent_text_for_judge_evm_flattens_findings() -> None:
    results: list[Any] = [
        {"hypothesis": "look at withdraw", "category": "reentrancy"},
        {"hypothesis": "mint overflows"},
        "raw string finding",
    ]
    text = _agent_text_for_judge_evm(results)
    assert "finding 1" in text
    assert "finding 2" in text
    assert "finding 3" in text
    assert "withdraw" in text
    assert "raw string finding" in text
