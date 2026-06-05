"""Tests for the standalone CyberGym verify/recheck/bugmatch/check tooling.

Only the pure, no-network helpers are exercised here. The functions that touch
the eval server or OpenRouter (``submit``, ``_call_openrouter``, ``bugmatch``,
``recheck``) are intentionally left to manual/integration runs.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

from evaluation.cybergym_eval import (
    _decode_b64_line,
    _decode_marker,
    _parse_verdict,
    _scorecard_html,
    _scorecard_md,
    default_mask_map,
    extract_from_rollout,
)


# --- cybergym_eval._decode_marker -------------------------------------------


def test_decode_marker_b64_and_hex() -> None:
    payload = b"crash\x00payload"
    b64 = base64.b64encode(payload).decode()
    assert _decode_marker(f"noise __POC_BYTES__b64={b64} trailing") == payload

    hx = binascii.hexlify(payload).decode()
    assert _decode_marker(f"__POC_BYTES__hex={hx}") == payload


def test_decode_marker_absent_or_invalid() -> None:
    assert _decode_marker("nothing to see here") is None
    # Marker present but the payload is not decodable base64.
    assert _decode_marker("__POC_BYTES__b64=@@@@") is None


# --- cybergym_eval.extract_from_rollout -------------------------------------


def test_extract_from_rollout_written_file(tmp_path: Path) -> None:
    (tmp_path / "poc").write_bytes(b"RAW-CRASH-BYTES")
    poc, source = extract_from_rollout(tmp_path)
    assert poc == b"RAW-CRASH-BYTES"
    assert source == "file:poc"


def test_extract_from_rollout_marker(tmp_path: Path) -> None:
    payload = b"crash-from-marker"
    b64 = base64.b64encode(payload).decode()
    (tmp_path / "exploit.jsonl").write_text(
        f'{{"response": "built it: __POC_BYTES__b64={b64}"}}\n', encoding="utf-8"
    )
    poc, source = extract_from_rollout(tmp_path)
    assert poc == payload
    assert source == "marker"


def test_extract_from_rollout_literal_b64(tmp_path: Path) -> None:
    payload = b"literal-submit-call-bytes"
    b64 = base64.b64encode(payload).decode()
    (tmp_path / "verifier.jsonl").write_text(f'poc_b64 = "{b64}"\n', encoding="utf-8")
    poc, source = extract_from_rollout(tmp_path)
    assert poc == payload
    assert source == "submit_literal_b64"


def test_extract_from_rollout_not_found(tmp_path: Path) -> None:
    (tmp_path / "exploit.jsonl").write_text(
        '{"response": "no bytes"}\n', encoding="utf-8"
    )
    poc, source = extract_from_rollout(tmp_path)
    assert poc is None
    assert source == "not_found_in_rollout"


# --- cybergym_eval.default_mask_map -----------------------------------------


def test_default_mask_map_env_override(monkeypatch) -> None:
    monkeypatch.setenv("KAI_CYBERGYM_MASK_MAP", "/custom/path/mask.json")
    assert default_mask_map() == "/custom/path/mask.json"


def test_default_mask_map_home_fallback(monkeypatch) -> None:
    monkeypatch.delenv("KAI_CYBERGYM_MASK_MAP", raising=False)
    resolved = default_mask_map()
    assert resolved.endswith("cybergym/mask_map.json")
    assert "~" not in resolved  # expanduser() was applied


# --- cybergym_eval._parse_verdict -----------------------------------------


def test_parse_verdict_match() -> None:
    verdict, reason = _parse_verdict("VERDICT: MATCH\nREASON: same function and flaw")
    assert verdict == "MATCH"
    assert reason == "same function and flaw"


def test_parse_verdict_no_match() -> None:
    verdict, reason = _parse_verdict("VERDICT: NO_MATCH\nREASON: different file")
    assert verdict == "NO_MATCH"
    assert reason == "different file"


def test_parse_verdict_freeform_fallback() -> None:
    # Model ignored the format -> best-effort scan of the whole reply.
    assert _parse_verdict("On balance this is NO_MATCH.")[0] == "NO_MATCH"
    assert _parse_verdict("Yeah, a clear MATCH here.")[0] == "MATCH"


# --- cybergym_eval._decode_b64_line ----------------------------------------


def test_decode_b64_line_prefixed() -> None:
    payload = b"reconstructed-input"
    b64 = base64.b64encode(payload).decode()
    assert _decode_b64_line(f"B64={b64}") == payload
    assert _decode_b64_line(f"preamble\nB64={b64}\ntrailing line") == payload


def test_decode_b64_line_bare_blob() -> None:
    payload = b"bare-base64-blob"
    b64 = base64.b64encode(payload).decode()
    assert _decode_b64_line(b64) == payload


def test_decode_b64_line_none() -> None:
    assert _decode_b64_line("no base64 content here !!!") is None


# --- cybergym_eval scorecard renderers ---------------------------------------


def _rows() -> list[dict]:
    return [
        {
            "dir": "cybergym-arvo-1065",
            "task_id": "arvo:1065",
            "adapter": "no_poc_binary",
            "poc_source": "marker",
            "found_bug": "MATCH",
            "found_bug_reason": "same heap overflow",
            "ground_truth": "heap overflow in foo()",
            "hypothesis": "overflow reached via foo",
            "reproduced": "PASS",
            "exit_code": 134,
            "recheck_source": "llm:deepseek/deepseek-chat",
        },
        {
            "dir": "cybergym-arvo-368",
            "task_id": "arvo:368",
            "adapter": "pass",
            "poc_source": None,
            "found_bug": "NO_MATCH",
            "found_bug_reason": "wrong sink",
            "ground_truth": "<script>&ampersand",
            "hypothesis": "use-after-free in bar",
            "reproduced": "FAIL",
            "exit_code": 0,
            "recheck_source": None,
        },
    ]


def test_scorecard_md_tallies_and_links() -> None:
    md = _scorecard_md(_rows(), skip_hard=False)
    assert "# CyberGym rollout scorecard" in md
    assert "found-the-bug (soft): **1/2**" in md
    assert "reproduced (hard): **1/2**" in md
    assert "arvo:1065" in md and "arvo:368" in md
    assert "(cybergym-arvo-1065/trace.html)" in md


def test_scorecard_md_skip_hard() -> None:
    md = _scorecard_md(_rows(), skip_hard=True)
    assert "reproduced (hard): _skipped_" in md


def test_scorecard_html_is_self_contained_and_escapes() -> None:
    html = _scorecard_html(_rows(), skip_hard=False)
    assert html.startswith("<!DOCTYPE html>")
    assert 'href="cybergym-arvo-1065/trace.html"' in html
    # Ground-truth markup is HTML-escaped, never injected raw.
    assert "<script>&ampersand" not in html
    assert "&lt;script&gt;&amp;ampersand" in html
