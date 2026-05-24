"""Unit tests for the cybergym pre-verifier gate (file reads + reminders)."""

from __future__ import annotations

import pytest

from kai.state import cybergym_gate


@pytest.fixture(autouse=True)
def _reset_gate():
    cybergym_gate.reset()
    yield
    cybergym_gate.reset()


def test_file_read_cap_fires_before_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KAI_PRE_VERIFIER_FILE_READS", "3")
    cybergym_gate.init()
    # First 3 file reads pass.
    for _ in range(3):
        assert cybergym_gate.check_and_count_file_read() is None
    # 4th hits the cap.
    msg = cybergym_gate.check_and_count_file_read()
    assert msg is not None
    assert "BLOCKED" in msg
    assert "3+ file reads" in msg


def test_file_read_cap_no_op_after_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KAI_PRE_VERIFIER_FILE_READS", "2")
    cybergym_gate.init()
    cybergym_gate.check_and_count_file_read()
    cybergym_gate.check_and_count_file_read()
    cybergym_gate.mark_verifier_called()
    # Past the cap, but verifier was called — should not block.
    for _ in range(20):
        assert cybergym_gate.check_and_count_file_read() is None


def test_spawn_cap_fires_before_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KAI_PRE_VERIFIER_CAP", "2")
    cybergym_gate.init()
    assert cybergym_gate.check_and_count_spawn("analyzer") is None
    assert cybergym_gate.check_and_count_spawn("analyzer") is None
    msg = cybergym_gate.check_and_count_spawn("analyzer")
    assert msg is not None
    assert "BLOCKED" in msg
    assert "spawn_analyzer" in msg


def test_spawn_cap_no_op_after_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KAI_PRE_VERIFIER_CAP", "1")
    cybergym_gate.init()
    cybergym_gate.check_and_count_spawn("researcher")
    cybergym_gate.mark_verifier_called()
    for _ in range(10):
        assert cybergym_gate.check_and_count_spawn("researcher") is None


def test_reminder_silent_before_iter_4() -> None:
    cybergym_gate.init()
    for i in range(0, 4):
        assert cybergym_gate.reminder_text(i) is None


def test_reminder_fires_at_iter_4_5() -> None:
    cybergym_gate.init()
    msg = cybergym_gate.reminder_text(4)
    assert msg is not None
    assert "harness REMINDER" in msg
    msg5 = cybergym_gate.reminder_text(5)
    assert msg5 is not None
    assert "harness REMINDER" in msg5


def test_reminder_escalates_at_iter_6() -> None:
    cybergym_gate.init()
    msg = cybergym_gate.reminder_text(6)
    assert msg is not None
    assert "harness WARNING" in msg


def test_reminder_forces_at_iter_8() -> None:
    cybergym_gate.init()
    msg = cybergym_gate.reminder_text(8)
    assert msg is not None
    assert "harness FORCED" in msg


def test_reminder_silent_after_verifier_called() -> None:
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()
    for i in range(0, 20):
        assert cybergym_gate.reminder_text(i) is None


def test_state_returns_none_when_uninitialised() -> None:
    cybergym_gate.reset()
    assert cybergym_gate.get() is None
    assert cybergym_gate.check_and_count_file_read() is None
    assert cybergym_gate.check_and_count_spawn("analyzer") is None
    assert cybergym_gate.reminder_text(10) is None


def test_workspace_tools_count_against_file_read_cap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """``read_file``/``search_files``/``list_dir`` hit the gate under cybergym."""
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_PRE_VERIFIER_FILE_READS", "2")
    monkeypatch.delenv("KAI_TASK_ID", raising=False)
    cybergym_gate.init()

    from kai.workspace.tools import list_dir, read_file, search_files

    sample = tmp_path / "a.txt"
    sample.write_text("hello\n")

    # First two reads pass.
    assert read_file(str(sample)) == "hello\n"
    assert list_dir(str(tmp_path)) == ["a.txt"]
    # Third should be BLOCKED — list_dir returns [BLOCKED] not the listing.
    third = search_files("hello", str(tmp_path))
    assert isinstance(third, list)
    assert len(third) == 1
    assert "BLOCKED" in third[0]


def test_workspace_tools_uncapped_outside_cybergym(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.delenv("KAI_BENCHMARK", raising=False)
    monkeypatch.setenv("KAI_PRE_VERIFIER_FILE_READS", "1")
    cybergym_gate.init()

    from kai.workspace.tools import read_file

    sample = tmp_path / "a.txt"
    sample.write_text("hello\n")
    for _ in range(5):
        assert read_file(str(sample)) == "hello\n"


def test_critic_reminder_silent_before_verified() -> None:
    cybergym_gate.init()
    assert (
        cybergym_gate.critic_reminder_text(
            10, verified_or_soft_count=0, critic_called=False
        )
        is None
    )


def test_critic_reminder_silent_before_iter_8() -> None:
    cybergym_gate.init()
    assert (
        cybergym_gate.critic_reminder_text(
            7, verified_or_soft_count=1, critic_called=False
        )
        is None
    )


def test_critic_reminder_fires_at_iter_8() -> None:
    cybergym_gate.init()
    msg = cybergym_gate.critic_reminder_text(
        8, verified_or_soft_count=1, critic_called=False
    )
    assert msg is not None
    assert "harness REMINDER" in msg
    assert "spawn_critic" in msg


def test_critic_reminder_warns_at_iter_11() -> None:
    cybergym_gate.init()
    msg = cybergym_gate.critic_reminder_text(
        11, verified_or_soft_count=1, critic_called=False
    )
    assert msg is not None
    assert "harness WARNING" in msg


def test_critic_reminder_forces_at_iter_14() -> None:
    cybergym_gate.init()
    msg = cybergym_gate.critic_reminder_text(
        14, verified_or_soft_count=1, critic_called=False
    )
    assert msg is not None
    assert "harness FORCED" in msg


def test_critic_reminder_silent_after_critic_called() -> None:
    cybergym_gate.init()
    assert (
        cybergym_gate.critic_reminder_text(
            20, verified_or_soft_count=3, critic_called=True
        )
        is None
    )


def test_mark_critic_called_flips_flag() -> None:
    cybergym_gate.init()
    assert not cybergym_gate.critic_was_called()
    cybergym_gate.mark_critic_called()
    assert cybergym_gate.critic_was_called()


def test_post_verifier_stall_blocks_file_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After a verified/soft record exists and before critic, file reads
    burn the shared post-verifier stall budget."""
    monkeypatch.setenv("KAI_POST_VERIFIER_STALL_CAP", "2")
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()
    cybergym_gate.mark_has_verified_record()
    assert cybergym_gate.check_and_count_file_read() is None
    assert cybergym_gate.check_and_count_file_read() is None
    msg = cybergym_gate.check_and_count_file_read()
    assert msg is not None
    assert "BLOCKED" in msg
    assert "spawn_critic" in msg


def test_post_verifier_stall_budget_is_shared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """analyzer + researcher + file reads share the same stall budget."""
    monkeypatch.setenv("KAI_POST_VERIFIER_STALL_CAP", "2")
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()
    cybergym_gate.mark_has_verified_record()
    assert cybergym_gate.check_and_count_spawn("analyzer") is None
    assert cybergym_gate.check_and_count_spawn("researcher") is None
    # Cap exhausted: next file read AND next spawn both block.
    msg_file = cybergym_gate.check_and_count_file_read()
    assert msg_file is not None and "spawn_critic" in msg_file
    msg_spawn = cybergym_gate.check_and_count_spawn("analyzer")
    assert msg_spawn is not None and "spawn_critic" in msg_spawn


def test_post_verifier_stall_no_op_without_verified_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No post-verifier cap until a verified/soft record actually exists."""
    monkeypatch.setenv("KAI_POST_VERIFIER_STALL_CAP", "1")
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()
    # verifier called, but no verified record → free file reads.
    for _ in range(10):
        assert cybergym_gate.check_and_count_file_read() is None


def test_post_verifier_stall_no_op_after_critic_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once critic ran, the post-verifier stall budget is disabled."""
    monkeypatch.setenv("KAI_POST_VERIFIER_STALL_CAP", "1")
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()
    cybergym_gate.mark_has_verified_record()
    cybergym_gate.mark_critic_called()
    for _ in range(10):
        assert cybergym_gate.check_and_count_file_read() is None
        assert cybergym_gate.check_and_count_spawn("analyzer") is None
        assert cybergym_gate.check_and_count_spawn("researcher") is None


def test_post_verifier_stall_does_not_count_spawn_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """spawn_verifier is productive work; it must not burn the budget.

    Re-verifying with mutated bytes is the EXACT path we want the
    model to take after a soft_verified verdict.
    """
    monkeypatch.setenv("KAI_POST_VERIFIER_STALL_CAP", "1")
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()
    cybergym_gate.mark_has_verified_record()
    # check_and_count_spawn skips agents not in spawn_counts
    # ("verifier" is not tracked there) so it must always return None.
    for _ in range(10):
        assert cybergym_gate.check_and_count_spawn("verifier") is None
    # Stall budget intact: one file read passes, second blocks.
    assert cybergym_gate.check_and_count_file_read() is None
    msg = cybergym_gate.check_and_count_file_read()
    assert msg is not None and "spawn_critic" in msg


def test_pre_verifier_caps_still_fire_with_post_verifier_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: adding the new fields/order must not break the
    existing pre-verifier file-read cap.
    """
    monkeypatch.setenv("KAI_PRE_VERIFIER_FILE_READS", "2")
    cybergym_gate.init()
    assert cybergym_gate.check_and_count_file_read() is None
    assert cybergym_gate.check_and_count_file_read() is None
    msg = cybergym_gate.check_and_count_file_read()
    assert msg is not None
    assert "BLOCKED" in msg
    assert "spawn_verifier" in msg


def test_workspace_tools_post_verifier_stall(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """End-to-end: workspace file tools observe the post-verifier cap."""
    monkeypatch.setenv("KAI_BENCHMARK", "cybergym")
    monkeypatch.setenv("KAI_POST_VERIFIER_STALL_CAP", "1")
    monkeypatch.delenv("KAI_TASK_ID", raising=False)
    cybergym_gate.init()
    cybergym_gate.mark_verifier_called()
    cybergym_gate.mark_has_verified_record()

    from kai.workspace.tools import read_file

    sample = tmp_path / "a.txt"
    sample.write_text("hello\n")
    # First read passes; second hits BLOCKED.
    assert read_file(str(sample)) == "hello\n"
    second = read_file(str(sample))
    assert "BLOCKED" in second
    assert "spawn_critic" in second
