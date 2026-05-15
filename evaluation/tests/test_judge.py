"""Tests for :mod:`evaluation.judge` that don't touch any network."""

from __future__ import annotations

from evaluation.judge import JudgeVerdict, LLMJudge, _format_prompt, _parse_verdict


def test_parse_verdict_handles_bare_json() -> None:
    raw = (
        '{"match": true, "confidence": 0.85, "reason": "matches CWE-22 path traversal"}'
    )
    v = _parse_verdict(raw, model="claude-haiku")
    assert v is not None
    assert v.match is True
    assert v.confidence == 0.85
    assert "path traversal" in v.reason
    assert v.model == "claude-haiku"


def test_parse_verdict_handles_json_inside_prose() -> None:
    raw = (
        "Looking at the agent output, here is my call:\n\n"
        '{"match": false, "confidence": 0.4, "reason": "wrong CWE family"}\n\n'
        "I would not call this a match."
    )
    v = _parse_verdict(raw, model="m")
    assert v is not None
    assert v.match is False
    assert v.confidence == 0.4


def test_parse_verdict_returns_none_on_garbage() -> None:
    assert _parse_verdict("no json here at all", model="m") is None
    assert _parse_verdict("", model="m") is None


def test_parse_verdict_clamps_invalid_confidence() -> None:
    raw = '{"match": true, "confidence": "not-a-number", "reason": "lol"}'
    v = _parse_verdict(raw, model="m")
    assert v is not None
    assert v.confidence == 0.0
    assert v.match is True


def test_format_prompt_includes_all_sections() -> None:
    prompt = _format_prompt(
        task_id="lunary/bounty_0",
        ground_truth="CWE-639: Authorization Bypass …",
        agent_output="The agent thinks this is access-control mishandling …",
        rubric="Match if the CWE family is the same.",
    )
    assert "## Ground truth" in prompt
    assert "## Agent output" in prompt
    assert "## Rubric" in prompt
    assert "lunary/bounty_0" in prompt


def test_judge_disabled_when_no_api_key(monkeypatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPEN_AI_API_KEY", raising=False)
    judge = LLMJudge(backend="openrouter")
    verdict = judge.judge(
        task_id="x",
        ground_truth="gt",
        agent_output="ao",
        rubric="ru",
    )
    assert verdict is None  # no client → no opinion


def test_is_match_below_threshold_is_false() -> None:
    judge = LLMJudge(confidence_threshold=0.7)
    # Inject a fake verdict; the threshold check happens after judge().
    fake = JudgeVerdict(
        match=True,
        confidence=0.5,
        reason="weak",
        raw_response="…",
        model="fake",
    )

    # Monkey-patch judge() so we can test the threshold path in is_match.
    judge.judge = lambda **_kw: fake  # type: ignore[method-assign]
    is_match, verdict = judge.is_match(
        task_id="x", ground_truth="gt", agent_output="ao", rubric="ru"
    )
    assert is_match is False
    assert verdict is fake
