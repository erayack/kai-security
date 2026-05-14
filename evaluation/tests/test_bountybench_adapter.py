"""Unit tests for the BountyBench DETECT-mode adapter.

These tests build a synthetic ``bountytasks/`` tree under ``tmp_path`` so
that the adapter can be exercised without cloning the real corpus. None
of the tests invoke ``kai.main`` - the adapter scoring path is exercised
with hand-rolled pipeline-result dicts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evaluation.adapters.bountybench.adapter import (
    BountyBenchAdapter,
    extract_reported_cwes,
)
from evaluation.adapters.bountybench.task_loader import (
    BountyTask,
    _extract_cwes,
    iter_bounty_tasks,
    load_bounty_task,
)
from evaluation.schemas import PreparedTask, TaskRef


# ---------------------------------------------------------------------------
# fixtures


def _seed_bounty(
    root: Path,
    system: str,
    bounty: str,
    *,
    cwe: str | None = "CWE-89: SQL Injection",
    cve: str = "CVE-2024-0001",
    severity: str = "7.5",
    exploit_prompt: str = "",
    task_info: str = "",
    target_host: str = "",
    writeup_html: str | None = None,
    seed_codebase: bool = True,
) -> Path:
    """Build ``root/<system>/bounties/<bounty>/`` mirroring the upstream layout."""

    system_dir = root / system
    bounties_dir = system_dir / "bounties" / bounty
    bounties_dir.mkdir(parents=True, exist_ok=True)

    bounty_metadata: dict[str, Any] = {
        "CVE": cve,
        "severity": severity,
        "compatible_exploits": ["0"],
    }
    if cwe is not None:
        bounty_metadata["CWE"] = cwe
    if exploit_prompt:
        bounty_metadata["exploit_prompt"] = exploit_prompt
    (bounties_dir / "bounty_metadata.json").write_text(json.dumps(bounty_metadata))

    task_metadata: dict[str, Any] = {}
    if task_info:
        task_metadata["info"] = task_info
    if target_host:
        task_metadata["target_host"] = target_host
    (system_dir / "metadata.json").write_text(json.dumps(task_metadata))

    if writeup_html is not None:
        writeup_dir = bounties_dir / "writeup"
        writeup_dir.mkdir(exist_ok=True)
        (writeup_dir / "writeup.html").write_text(writeup_html)

    if seed_codebase:
        codebase = system_dir / "codebase"
        codebase.mkdir(exist_ok=True)
        (codebase / "vuln.py").write_text("# seeded source\n")

    return bounties_dir


def _adapter(root: Path, **overrides: Any) -> BountyBenchAdapter:
    config: dict[str, Any] = {"bountybench_root": str(root)}
    config.update(overrides)
    return BountyBenchAdapter(config)


# ---------------------------------------------------------------------------
# config validation


def test_adapter_requires_bountybench_root() -> None:
    with pytest.raises(ValueError, match="bountybench_root"):
        BountyBenchAdapter({})


def test_adapter_rejects_missing_root(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        BountyBenchAdapter({"bountybench_root": str(tmp_path / "does-not-exist")})


def test_adapter_rejects_non_detect_mode(tmp_path: Path) -> None:
    (tmp_path / "anything").mkdir()
    with pytest.raises(ValueError, match="mode='detect'"):
        BountyBenchAdapter({"bountybench_root": str(tmp_path), "mode": "exploit"})


# ---------------------------------------------------------------------------
# task enumeration


def test_list_tasks_walks_synthetic_layout(tmp_path: Path) -> None:
    root = tmp_path / "bountytasks"
    _seed_bounty(root, "myapp", "bounty_0", cwe="CWE-89: SQLi")
    _seed_bounty(root, "myapp", "bounty_1", cwe="CWE-79: XSS")
    _seed_bounty(root, "other", "bounty_0", cwe="CWE-22: Path Traversal")

    adapter = _adapter(root)
    tasks = list(adapter.list_tasks())
    task_ids = [t.task_id for t in tasks]
    assert task_ids == ["myapp/bounty_0", "myapp/bounty_1", "other/bounty_0"]

    first = tasks[0]
    assert first.benchmark == "bountybench"
    assert first.metadata["mode"] == "detect"
    assert first.metadata["system"] == "myapp"
    assert first.metadata["bounty"] == "bounty_0"
    assert first.metadata["cwes"] == ["CWE-89"]


def test_list_tasks_respects_systems_filter(tmp_path: Path) -> None:
    root = tmp_path / "bountytasks"
    _seed_bounty(root, "myapp", "bounty_0")
    _seed_bounty(root, "other", "bounty_0")

    adapter = _adapter(root, systems=["other"])
    tasks = list(adapter.list_tasks())
    assert [t.task_id for t in tasks] == ["other/bounty_0"]


def test_iter_bounty_tasks_skips_systems_without_bounties(tmp_path: Path) -> None:
    root = tmp_path / "bountytasks"
    _seed_bounty(root, "real", "bounty_0")
    (root / "empty").mkdir()  # no `bounties/` subdir
    assert [t.task_id for t in iter_bounty_tasks(root)] == ["real/bounty_0"]


def test_iter_bounty_tasks_raises_on_missing_root(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        list(iter_bounty_tasks(tmp_path / "missing"))


# ---------------------------------------------------------------------------
# task_loader internals


def test_extract_cwes_pulls_multiple_ids() -> None:
    assert _extract_cwes({"CWE": "CWE-89: SQLi; also CWE-79"}) == ["CWE-89", "CWE-79"]
    assert _extract_cwes({"cwe": "cwe-22"}) == ["CWE-22"]
    assert _extract_cwes({"CWE": ""}) == []
    assert _extract_cwes({}) == []


def test_load_bounty_task_strips_writeup_html(tmp_path: Path) -> None:
    root = tmp_path / "bountytasks"
    _seed_bounty(
        root,
        "myapp",
        "bounty_0",
        writeup_html="<html><body><p>Boom <b>SQLi</b></p><script>x</script></body></html>",
        exploit_prompt="hint: query injection",
        task_info="credentials: alice/secret",
        target_host="myapp:8000",
    )

    task = load_bounty_task(root / "myapp", root / "myapp" / "bounties" / "bounty_0")
    assert task.cwes == ["CWE-89"]
    assert task.exploit_prompt == "hint: query injection"
    assert task.task_info == "credentials: alice/secret"
    assert task.target_host == "myapp:8000"
    assert "Boom" in task.writeup_text
    assert "<b>" not in task.writeup_text


# ---------------------------------------------------------------------------
# prepare


def test_prepare_copies_codebase_into_workdir(tmp_path: Path) -> None:
    root = tmp_path / "bountytasks"
    _seed_bounty(
        root,
        "myapp",
        "bounty_0",
        exploit_prompt="look for IDOR",
        task_info="creds: alice/secret",
    )
    adapter = _adapter(root)

    task = next(iter(adapter.list_tasks()))
    prepared = adapter.prepare(task, tmp_path / "workdir")

    assert prepared.repo_path == tmp_path / "workdir" / "repo"
    assert (prepared.repo_path / "vuln.py").read_text() == "# seeded source\n"
    assert prepared.oracle["cwes"] == ["CWE-89"]
    assert prepared.oracle["system"] == "myapp"
    assert prepared.oracle["bounty"] == "bounty_0"
    assert prepared.oracle["bounty_dir"].endswith("myapp/bounties/bounty_0")
    extras = prepared.prompt_extras or ""
    assert "look for IDOR" in extras
    assert "creds: alice/secret" in extras
    assert "CWE-" in extras  # DETECT_INSTRUCTIONS mentions CWE explicitly


def test_prepare_falls_back_when_codebase_dir_empty(tmp_path: Path) -> None:
    root = tmp_path / "bountytasks"
    _seed_bounty(root, "myapp", "bounty_0", seed_codebase=False)
    # Codebase dir absent: prepare should still produce a repo dir.
    adapter = _adapter(root)
    task = next(iter(adapter.list_tasks()))
    prepared = adapter.prepare(task, tmp_path / "workdir")
    assert prepared.repo_path.is_dir()


def test_prepare_rejects_malformed_task_id(tmp_path: Path) -> None:
    root = tmp_path / "bountytasks"
    _seed_bounty(root, "myapp", "bounty_0")
    adapter = _adapter(root)
    bad_task = TaskRef(benchmark="bountybench", task_id="no_slash")
    with pytest.raises(ValueError):
        adapter.prepare(bad_task, tmp_path / "workdir")


# ---------------------------------------------------------------------------
# score


def _prepared_for_score(
    tmp_path: Path,
    *,
    cwes: list[str] | None = None,
) -> PreparedTask:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    return PreparedTask(
        task_ref=TaskRef(benchmark="bountybench", task_id="myapp/bounty_0"),
        repo_path=repo,
        workdir=tmp_path,
        oracle={
            "mode": "detect",
            "system": "myapp",
            "bounty": "bounty_0",
            "cwes": list(cwes) if cwes is not None else ["CWE-89"],
        },
    )


def test_score_success_when_reported_cwe_matches_oracle(tmp_path: Path) -> None:
    adapter = _adapter(_make_minimal_root(tmp_path))
    prepared = _prepared_for_score(tmp_path / "wd", cwes=["CWE-89"])
    pipeline_result = {
        "result": [
            {
                "hypothesis": "User-controlled input flows into a query — CWE-89.",
                "severity": "high",
            }
        ]
    }
    score = adapter.score(prepared, pipeline_result, exit_code=0)
    assert score.success is True
    assert score.details["matched_cwes"] == ["CWE-89"]
    assert score.details["reported_cwes"] == ["CWE-89"]
    assert score.failure_reason is None


def test_score_failure_when_cwes_disjoint(tmp_path: Path) -> None:
    adapter = _adapter(_make_minimal_root(tmp_path))
    prepared = _prepared_for_score(tmp_path / "wd", cwes=["CWE-89"])
    pipeline_result = {
        "result": [
            {
                "hypothesis": "XSS in template — CWE-79.",
                "exploit_sketch": "Reflected payload",
            }
        ]
    }
    score = adapter.score(prepared, pipeline_result, exit_code=0)
    assert score.success is False
    assert score.failure_reason == "cwe_mismatch"
    assert score.details["reported_cwes"] == ["CWE-79"]
    assert score.details["matched_cwes"] == []


def test_score_failure_when_no_cwe_reported(tmp_path: Path) -> None:
    adapter = _adapter(_make_minimal_root(tmp_path))
    prepared = _prepared_for_score(tmp_path / "wd", cwes=["CWE-89"])
    pipeline_result = {
        "result": [
            {
                "hypothesis": "Something is fishy with the auth flow.",
            }
        ]
    }
    score = adapter.score(prepared, pipeline_result, exit_code=0)
    assert score.success is False
    assert score.failure_reason == "no_cwe_reported"


def test_score_failure_when_pipeline_result_missing(tmp_path: Path) -> None:
    adapter = _adapter(_make_minimal_root(tmp_path))
    prepared = _prepared_for_score(tmp_path / "wd")
    score = adapter.score(prepared, pipeline_result=None, exit_code=2)
    assert score.success is False
    assert score.failure_reason == "no_pipeline_result"
    assert score.pipeline_exit_code == 2


def test_score_failure_when_oracle_has_no_cwes(tmp_path: Path) -> None:
    adapter = _adapter(_make_minimal_root(tmp_path))
    prepared = _prepared_for_score(tmp_path / "wd", cwes=[])
    score = adapter.score(prepared, {"result": []}, exit_code=0)
    assert score.success is False
    assert score.failure_reason == "oracle_missing_cwe"


def test_score_accepts_case_insensitive_match(tmp_path: Path) -> None:
    adapter = _adapter(_make_minimal_root(tmp_path))
    prepared = _prepared_for_score(tmp_path / "wd", cwes=["CWE-22"])
    pipeline_result = {
        "result": [
            {"hypothesis": "Looks like cwe-22 path traversal."},
        ]
    }
    score = adapter.score(prepared, pipeline_result, exit_code=0)
    assert score.success is True
    assert score.details["matched_cwes"] == ["CWE-22"]


# ---------------------------------------------------------------------------
# cleanup


def test_cleanup_removes_copied_repo(tmp_path: Path) -> None:
    adapter = _adapter(_make_minimal_root(tmp_path))
    workdir = tmp_path / "wd"
    repo = workdir / "repo"
    repo.mkdir(parents=True)
    (repo / "sentinel").write_text("x")
    prepared = PreparedTask(
        task_ref=TaskRef(benchmark="bountybench", task_id="myapp/bounty_0"),
        repo_path=repo,
        workdir=workdir,
    )
    adapter.cleanup(prepared)
    assert not repo.exists()
    # idempotent
    adapter.cleanup(prepared)


# ---------------------------------------------------------------------------
# scanner helpers


def test_extract_reported_cwes_scans_multiple_fields() -> None:
    pipeline_result = {
        "result": [
            {
                "hypothesis": "see CWE-89",
                "exploit_sketch": "no cwe here",
                "category": "active_exploit",
                "cvss_justification": {"AV": "N", "note": "matches cwe-352 pattern"},
            },
            {
                "hypothesis": "duplicate CWE-89",
            },
        ]
    }
    cwes = extract_reported_cwes(pipeline_result)
    assert cwes == {"CWE-89", "CWE-352"}


def test_extract_reported_cwes_handles_empty_result() -> None:
    assert extract_reported_cwes({}) == set()
    assert extract_reported_cwes({"result": None}) == set()
    assert extract_reported_cwes({"result": "bogus"}) == set()


# ---------------------------------------------------------------------------
# helper used by score tests above


def _make_minimal_root(tmp_path: Path) -> Path:
    root = tmp_path / "bountytasks"
    _seed_bounty(root, "myapp", "bounty_0")
    return root


# ---------------------------------------------------------------------------
# dataclass surface


def test_bountytask_task_id_property(tmp_path: Path) -> None:
    task = BountyTask(
        system="foo",
        bounty="bounty_3",
        task_dir=tmp_path,
        bounty_dir=tmp_path / "b",
        codebase_dir=tmp_path,
    )
    assert task.task_id == "foo/bounty_3"
