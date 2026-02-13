"""Tests for kai.workspace.tools."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from kai.workspace.tools import list_dir, read_file, run_shell, search_files


def _make_tree(tmp: str) -> None:
    """Create a small file tree for testing."""
    Path(tmp, "a.txt").write_text("hello world\n")
    Path(tmp, "b.txt").write_text("foo bar\n")
    sub = Path(tmp, "sub")
    sub.mkdir()
    Path(sub, "c.txt").write_text("hello again\n")


class TestReadFile:
    def test_reads_content(self, tmp_path: Path) -> None:
        f = tmp_path / "x.txt"
        f.write_text("content")
        assert read_file(str(f)) == "content"

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        import pytest

        with pytest.raises(FileNotFoundError):
            read_file(str(tmp_path / "nope.txt"))


class TestListDir:
    def test_flat(self, tmp_path: Path) -> None:
        (tmp_path / "b.txt").write_text("")
        (tmp_path / "a.txt").write_text("")
        result = list_dir(str(tmp_path))
        assert result == ["a.txt", "b.txt"]

    def test_recursive(self, tmp_path: Path) -> None:
        (tmp_path / "top.txt").write_text("")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "deep.txt").write_text("")
        result = list_dir(str(tmp_path), recursive=True)
        assert "sub" in result
        assert "top.txt" in result
        assert os.path.join("sub", "deep.txt") in result

    def test_empty_dir(self, tmp_path: Path) -> None:
        assert list_dir(str(tmp_path)) == []


class TestSearchFiles:
    def test_finds_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _make_tree(tmp)
            results = search_files("hello", tmp)
            assert len(results) == 2
            assert any("a.txt:1:" in r for r in results)
            assert any("c.txt:1:" in r for r in results)

    def test_no_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _make_tree(tmp)
            results = search_files("zzzzz", tmp)
            assert results == []

    def test_regex_pattern(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "f.txt").write_text("line1\nline2_match\nline3\n")
            results = search_files(r"line\d_match", tmp)
            assert len(results) == 1
            assert "line2_match" in results[0]


class TestRunShell:
    def test_stdout(self) -> None:
        result = run_shell("echo hello")
        assert result["stdout"].strip() == "hello"
        assert result["returncode"] == 0

    def test_stderr_and_returncode(self) -> None:
        result = run_shell("echo err >&2 && exit 1")
        assert "err" in result["stderr"]
        assert result["returncode"] == 1

    def test_cwd(self, tmp_path: Path) -> None:
        result = run_shell("pwd", cwd=str(tmp_path))
        assert result["stdout"].strip() == str(tmp_path.resolve())

    def test_returns_dict_keys(self) -> None:
        result = run_shell("true")
        assert set(result.keys()) == {"stdout", "stderr", "returncode"}
