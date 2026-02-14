"""Tests for kai.workspace.tools and kai.definitions.exploit.tools."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kai.definitions.exploit.tools import (
    _jina_request,
    delete_lines,
    insert_lines,
    parallel_read_url,
    parallel_search_web,
    read_file_hashed,
    read_url,
    search_web,
    update_file,
)
from kai.workspace.tools import (
    list_dir,
    read_file,
    run_shell,
    search_files,
    write_file,
)


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


class TestWriteFile:
    def test_writes_content(self, tmp_path: Path) -> None:
        f = tmp_path / "out.txt"
        result = write_file(str(f), "hello")
        assert f.read_text() == "hello"
        assert "5 chars" in result

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        f = tmp_path / "a" / "b" / "deep.txt"
        write_file(str(f), "nested")
        assert f.read_text() == "nested"

    def test_overwrites_existing(self, tmp_path: Path) -> None:
        f = tmp_path / "x.txt"
        f.write_text("old")
        write_file(str(f), "new")
        assert f.read_text() == "new"


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


# ── Hashline editing tools ───────────────────────────────────────

SAMPLE = "function hello() {\n  return 'world';\n}\n"


def _write_sample(tmp_path: Path) -> Path:
    f = tmp_path / "test.js"
    f.write_text(SAMPLE)
    return f


class TestReadFileHashed:
    def test_tags_lines(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        out = read_file_hashed(str(f))
        lines = out.splitlines()
        assert len(lines) == 3
        # format: lineno:hash|content
        for line in lines:
            assert "|" in line
            ref, _content = line.split("|", 1)
            num, h = ref.split(":")
            assert num.isdigit()
            assert len(h) == 2

    def test_hashes_are_deterministic(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        a = read_file_hashed(str(f))
        b = read_file_hashed(str(f))
        assert a == b

    def test_content_preserved(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        out = read_file_hashed(str(f))
        contents = [ln.split("|", 1)[1] for ln in out.splitlines()]
        assert contents == SAMPLE.splitlines()


class TestUpdateFile:
    def test_single_line(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        tagged = read_file_hashed(str(f))
        ref = tagged.splitlines()[1].split("|")[0]  # line 2
        result = update_file(str(f), ref, "  return 'hello';")
        assert "Updated" in result
        assert "return 'hello'" in f.read_text()

    def test_range(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        tagged = read_file_hashed(str(f))
        refs = [ln.split("|")[0] for ln in tagged.splitlines()]
        target = f"{refs[0]}-{refs[2]}"
        result = update_file(str(f), target, "replaced")
        assert "Updated" in result
        assert f.read_text().strip() == "replaced"

    def test_stale_hash_rejected(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        result = update_file(str(f), "2:zz", "bad")
        assert "Error" in result
        assert "mismatch" in result.lower()

    def test_out_of_bounds(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        result = update_file(str(f), "99:ab", "bad")
        assert "Error" in result


class TestInsertLines:
    def test_insert_after(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        tagged = read_file_hashed(str(f))
        ref = tagged.splitlines()[0].split("|")[0]  # line 1
        result = insert_lines(str(f), ref, "  // comment")
        assert "Inserted" in result
        lines = f.read_text().splitlines()
        assert lines[1] == "  // comment"
        assert len(lines) == 4

    def test_stale_hash_rejected(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        result = insert_lines(str(f), "1:zz", "bad")
        assert "Error" in result


class TestDeleteLines:
    def test_single_line(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        tagged = read_file_hashed(str(f))
        ref = tagged.splitlines()[1].split("|")[0]  # line 2
        result = delete_lines(str(f), ref)
        assert "Deleted" in result
        assert len(f.read_text().splitlines()) == 2

    def test_range(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        tagged = read_file_hashed(str(f))
        refs = [ln.split("|")[0] for ln in tagged.splitlines()]
        target = f"{refs[1]}-{refs[2]}"
        result = delete_lines(str(f), target)
        assert "Deleted" in result
        assert len(f.read_text().splitlines()) == 1

    def test_stale_hash_rejected(self, tmp_path: Path) -> None:
        f = _write_sample(tmp_path)
        result = delete_lines(str(f), "1:zz")
        assert "Error" in result


# ── Web tools ────────────────────────────────────────────────────


def _mock_urlopen(body: str = "response body"):
    """Return a mock context manager for urllib.request.urlopen."""
    resp = MagicMock()
    resp.read.return_value = body.encode("utf-8")
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestJinaRequest:
    @patch("kai.definitions.exploit.tools.urllib.request.urlopen")
    def test_returns_response(self, mock_open: MagicMock) -> None:
        mock_open.return_value = _mock_urlopen("hello")
        result = _jina_request("https://example.com")
        assert result == "hello"
        mock_open.assert_called_once()

    @patch("kai.definitions.exploit.tools.urllib.request.urlopen")
    def test_adds_auth_header(self, mock_open: MagicMock) -> None:
        mock_open.return_value = _mock_urlopen()
        with patch.dict(os.environ, {"JINA_API_KEY": "test-key"}):
            _jina_request("https://example.com")
        req = mock_open.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer test-key"

    @patch("kai.definitions.exploit.tools.urllib.request.urlopen")
    def test_adds_extra_headers(self, mock_open: MagicMock) -> None:
        mock_open.return_value = _mock_urlopen()
        with patch.dict(os.environ, {"JINA_API_KEY": ""}):
            _jina_request("https://example.com", {"X-Custom": "val"})
        req = mock_open.call_args[0][0]
        assert req.get_header("X-custom") == "val"

    @patch("kai.definitions.exploit.tools.urllib.request.urlopen")
    def test_no_auth_without_key(self, mock_open: MagicMock) -> None:
        mock_open.return_value = _mock_urlopen()
        with patch.dict(os.environ, {"JINA_API_KEY": ""}):
            _jina_request("https://example.com")
        req = mock_open.call_args[0][0]
        assert req.get_header("Authorization") is None

    @patch("kai.definitions.exploit.tools.urllib.request.urlopen")
    def test_network_error_returns_message(self, mock_open: MagicMock) -> None:
        mock_open.side_effect = ConnectionError("refused")
        result = _jina_request("https://example.com")
        assert "[error]" in result
        assert "ConnectionError" in result


class TestSearchWeb:
    @patch("kai.definitions.exploit.tools._jina_request")
    def test_builds_url_and_headers(self, mock_req: MagicMock) -> None:
        mock_req.return_value = "results"
        result = search_web("reentrancy exploit")
        assert result == "results"
        url = mock_req.call_args[0][0]
        assert url == "https://s.jina.ai/?q=reentrancy+exploit"
        headers = mock_req.call_args[0][1]
        assert headers == {"X-Respond-With": "no-content"}

    @patch("kai.definitions.exploit.tools._jina_request")
    def test_encodes_special_chars(self, mock_req: MagicMock) -> None:
        mock_req.return_value = ""
        search_web("CVE-2024-1234 & overflow")
        url = mock_req.call_args[0][0]
        # & and spaces encoded as query params (quote_plus)
        assert url == "https://s.jina.ai/?q=CVE-2024-1234+%26+overflow"


class TestReadUrl:
    @patch("kai.definitions.exploit.tools._jina_request")
    def test_builds_reader_url(self, mock_req: MagicMock) -> None:
        mock_req.return_value = "# Page content"
        result = read_url("https://example.com/page")
        assert result == "# Page content"
        url = mock_req.call_args[0][0]
        assert "r.jina.ai" in url
        assert "https://example.com/page" in url


class TestParallelSearchWeb:
    @patch("kai.definitions.exploit.tools._jina_request")
    def test_returns_results_in_order(self, mock_req: MagicMock) -> None:
        mock_req.side_effect = lambda url, *a, **kw: f"result for {url}"
        results = parallel_search_web(["query1", "query2", "query3"])
        assert len(results) == 3
        assert "query1" in results[0]
        assert "query3" in results[2]

    @patch("kai.definitions.exploit.tools._jina_request")
    def test_single_query(self, mock_req: MagicMock) -> None:
        mock_req.return_value = "one"
        results = parallel_search_web(["single"])
        assert results == ["one"]


class TestParallelReadUrl:
    @patch("kai.definitions.exploit.tools._jina_request")
    def test_returns_results_in_order(self, mock_req: MagicMock) -> None:
        mock_req.side_effect = lambda url: f"content of {url}"
        results = parallel_read_url(["https://a.com", "https://b.com"])
        assert len(results) == 2
        assert "a.com" in results[0]
        assert "b.com" in results[1]

    @patch("kai.definitions.exploit.tools._jina_request")
    def test_single_url(self, mock_req: MagicMock) -> None:
        mock_req.return_value = "page"
        results = parallel_read_url(["https://x.com"])
        assert results == ["page"]


# ── Live web tests (require JINA_API_KEY) ────────────────────────


def _load_jina_key() -> str:
    """Load JINA_API_KEY from .env if not already set."""
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass
    return os.environ.get("JINA_API_KEY", "")


_has_jina_key = bool(_load_jina_key())


@pytest.mark.skipif(not _has_jina_key, reason="JINA_API_KEY not set")
class TestWebLive:
    def test_search_web_returns_results(self) -> None:
        result = search_web("python requests library")
        assert len(result) > 0
        assert "[error]" not in result

    def test_read_url_returns_content(self) -> None:
        result = read_url("https://httpbin.org/html")
        assert len(result) > 0
        assert "[error]" not in result
        assert "Herman Melville" in result
