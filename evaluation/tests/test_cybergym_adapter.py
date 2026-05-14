"""Unit tests for the CyberGym adapter that do not need the upstream server."""

from __future__ import annotations

import base64
import tarfile
from pathlib import Path
from typing import Any

import pytest

from evaluation.adapters.cybergym.adapter import (
    POC_MARKER_RE,
    CyberGymAdapter,
    _decode_marker,
)
from evaluation.schemas import PreparedTask, TaskRef


def _adapter(tmp_path: Path, **overrides: Any) -> CyberGymAdapter:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    mask_map = tmp_path / "mask_map.json"
    mask_map.write_text("{}")
    config = {
        "data_dir": str(data_dir),
        "mask_map": str(mask_map),
        "server_url": "http://127.0.0.1:8666",
    }
    config.update(overrides)
    return CyberGymAdapter(config)


def test_adapter_requires_paths(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        CyberGymAdapter({})


def test_default_task_subset_lists(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    tasks = list(adapter.list_tasks())
    assert any(t.task_id == "arvo:10400" for t in tasks)
    assert all(t.metadata.get("difficulty") == "level1" for t in tasks)


def test_decode_marker_b64() -> None:
    payload = base64.b64encode(b"\x00\xff\x42").decode()
    assert (
        _decode_marker(f"prefix __POC_BYTES__b64={payload} suffix") == b"\x00\xff\x42"
    )


def test_decode_marker_hex() -> None:
    assert _decode_marker("noise __POC_BYTES__hex=deadbeef") == b"\xde\xad\xbe\xef"


def test_decode_marker_returns_none_when_absent() -> None:
    assert _decode_marker("no marker here") is None
    assert POC_MARKER_RE.search("no marker here") is None


def test_locate_poc_prefers_binary_file(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    workdir = tmp_path / "wd"
    repo = workdir / "repo"
    repo.mkdir(parents=True)
    (repo / "poc").write_bytes(b"BINARY")
    prepared = PreparedTask(
        task_ref=TaskRef(benchmark="cybergym", task_id="arvo:10400"),
        repo_path=repo,
        workdir=workdir,
    )
    poc, source = adapter._locate_poc(prepared, None)
    assert poc == b"BINARY"
    assert source.startswith("repo:")


def test_locate_poc_falls_back_to_marker(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    workdir = tmp_path / "wd"
    repo = workdir / "repo"
    repo.mkdir(parents=True)
    pipeline_result = {
        "result": [
            {
                "poc_code": "Plain text reasoning… __POC_BYTES__hex=cafebabe…",
            }
        ]
    }
    prepared = PreparedTask(
        task_ref=TaskRef(benchmark="cybergym", task_id="t"),
        repo_path=repo,
        workdir=workdir,
    )
    poc, source = adapter._locate_poc(prepared, pipeline_result)
    assert poc == b"\xca\xfe\xba\xbe"
    assert source == "marker"


def test_locate_poc_returns_none_when_nothing(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    workdir = tmp_path / "wd"
    workdir.mkdir()
    repo = workdir / "repo"
    repo.mkdir()
    prepared = PreparedTask(
        task_ref=TaskRef(benchmark="cybergym", task_id="t"),
        repo_path=repo,
        workdir=workdir,
    )
    poc, source = adapter._locate_poc(prepared, {"result": []})
    assert poc is None
    assert source == "not_found"


def test_score_without_poc_reports_no_poc_binary(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path, submit=False)
    workdir = tmp_path / "wd"
    repo = workdir / "repo"
    repo.mkdir(parents=True)
    prepared = PreparedTask(
        task_ref=TaskRef(benchmark="cybergym", task_id="arvo:10400"),
        repo_path=repo,
        workdir=workdir,
        oracle={"submit_sh": None},
    )
    score = adapter.score(prepared, pipeline_result=None, exit_code=0)
    assert score.success is False
    assert score.failure_reason == "no_poc_binary"


def test_score_with_poc_and_submit_disabled(tmp_path: Path) -> None:
    """With submit=False (verifier offline), a non-empty PoC is a soft pass."""

    adapter = _adapter(tmp_path, submit=False)
    workdir = tmp_path / "wd"
    repo = workdir / "repo"
    repo.mkdir(parents=True)
    (repo / "poc").write_bytes(b"XX")
    prepared = PreparedTask(
        task_ref=TaskRef(benchmark="cybergym", task_id="arvo:10400"),
        repo_path=repo,
        workdir=workdir,
        oracle={"submit_sh": "/tmp/fake.sh"},
    )
    score = adapter.score(prepared, pipeline_result=None, exit_code=0)
    assert score.success is True
    assert score.failure_reason is None
    assert score.details["poc_bytes"] == 2
    assert score.details["score_mode"] == "soft_unverified"
    assert score.details["verified"] is False


def test_prepare_extracts_tarball_and_reads_description(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = _adapter(tmp_path)

    task = TaskRef(benchmark="cybergym", task_id="arvo:10400")
    workdir = tmp_path / "wd"

    def fake_gen_task(self: CyberGymAdapter, task_id: str, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "description.txt").write_text("vuln: buffer overflow in foo()")
        (out_dir / "README.md").write_text("# task readme")
        repo_seed = tmp_path / "_seed"
        repo_seed.mkdir(exist_ok=True)
        (repo_seed / "vuln.c").write_text("int main() { return 0; }\n")
        with tarfile.open(out_dir / "repo-vul.tar.gz", "w:gz") as tar:
            tar.add(repo_seed / "vuln.c", arcname="vuln.c")
        submit_sh = out_dir / "submit.sh"
        submit_sh.write_text("#!/bin/bash\necho '{\"exit_code\": 0}'\n")

    monkeypatch.setattr(CyberGymAdapter, "_gen_task", fake_gen_task)

    prepared = adapter.prepare(task, workdir)

    assert (prepared.repo_path / "vuln.c").exists()
    assert "buffer overflow" in (prepared.prompt_extras or "")
    assert "task readme" in (prepared.prompt_extras or "")
    assert prepared.oracle["submit_sh"].endswith("submit.sh")
