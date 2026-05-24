"""Shared state for the cybergym pre-verifier gate.

The cybergym pipeline has a single failure mode that recurs across
R18 / R19 / R20: the root agent does many iterations of `read_file`
/ `search_files` / `list_dir` exploration without ever invoking
`spawn_verifier`. Without verifier feedback the PoC bytes are a
guess and the strict harness rejects them.

The pre-existing `_apply_cybergym_spawn_gate` in
:mod:`kai.state.integration` caps `spawn_analyzer` and
`spawn_researcher` at 8 calls each before `spawn_verifier` is
invoked. But the model substitutes direct REPL file reads for
those spawns — those calls never trip the gate.

This module exposes a process-wide singleton that BOTH the spawn
wrappers AND the file-read tools mutate / consult. When file reads
exceed ``KAI_PRE_VERIFIER_FILE_READS`` (default 12) without a
verifier call, the file-tool layer raises a BLOCKED string the
same way the spawn gate does — the model sees the same
remediation instruction either way.

The singleton is per-process. Each cybergym task runs in its own
pipeline subprocess, so the state naturally resets between tasks.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CybergymGateState:
    """Shared counter + verifier-called flag for the cybergym gate.

    Constructed once per pipeline subprocess via :func:`init`. Mutated
    from both spawn wrappers (see ``kai.state.integration``) and file
    tools (see ``kai.workspace.tools``).
    """

    spawn_cap: int
    file_read_cap: int
    post_verifier_stall_cap: int
    spawn_counts: dict[str, int] = field(
        default_factory=lambda: {"analyzer": 0, "researcher": 0}
    )
    file_reads: int = 0
    post_verifier_stalls: int = 0
    verifier_called: bool = False
    has_verified_record: bool = False
    critic_called: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


_state: Optional[CybergymGateState] = None
_state_lock = threading.Lock()


def _read_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


def init() -> CybergymGateState:
    """Create the per-process gate state.

    Caps:
    * ``KAI_PRE_VERIFIER_CAP`` — per-sub-agent spawn cap (default 8).
    * ``KAI_PRE_VERIFIER_FILE_READS`` — total file-read cap (default 12).
    * ``KAI_POST_VERIFIER_STALL_CAP`` — combined analyzer/researcher/file-
      read cap once a verified or soft_verified record exists but
      ``spawn_critic`` has not been called yet (default 5).
    """
    global _state
    with _state_lock:
        _state = CybergymGateState(
            spawn_cap=_read_int_env("KAI_PRE_VERIFIER_CAP", 8),
            file_read_cap=_read_int_env("KAI_PRE_VERIFIER_FILE_READS", 12),
            post_verifier_stall_cap=_read_int_env("KAI_POST_VERIFIER_STALL_CAP", 5),
        )
    return _state


def get() -> CybergymGateState | None:
    """Return the per-process state, or ``None`` if not initialised."""
    return _state


def reset() -> None:
    """Drop the singleton (test helper)."""
    global _state
    with _state_lock:
        _state = None


def mark_verifier_called() -> None:
    """Flip the verifier-called flag.

    Called by the spawn wrapper for ``spawn_verifier`` so the gate
    becomes a no-op for the rest of the task.
    """
    state = _state
    if state is None:
        return
    with state.lock:
        state.verifier_called = True


def mark_critic_called() -> None:
    """Flip the critic-called flag so the critic reminder stops firing."""
    state = _state
    if state is None:
        return
    with state.lock:
        state.critic_called = True


def critic_was_called() -> bool:
    state = _state
    if state is None:
        return False
    return state.critic_called


def mark_has_verified_record() -> None:
    """Flip the verified-record flag.

    Called from :func:`kai.state.hooks.make_on_iteration_hook` once at
    least one verified or soft_verified ``ExploitRecord`` exists.
    Idempotent — safe to call from every iteration after the first
    record lands. Activates the post-verifier anti-stall budget in
    :func:`check_and_count_spawn` / :func:`check_and_count_file_read`.
    """
    state = _state
    if state is None:
        return
    with state.lock:
        state.has_verified_record = True


def _post_verifier_stall_block(
    state: CybergymGateState,
) -> str | None:
    """Return BLOCKED message when the post-verifier stall cap is hit.

    Caller MUST hold ``state.lock``. Returns ``None`` when the cap has
    not yet been exhausted; otherwise the explicit critic-required
    notice.
    """
    if state.post_verifier_stalls >= state.post_verifier_stall_cap:
        return (
            "BLOCKED: post-verifier cybergym stall cap reached "
            f"({state.post_verifier_stall_cap} non-critic "
            "file/analyzer/researcher actions after a "
            "verified/soft_verified exploit). You must call "
            "spawn_critic before further exploration. Required "
            "next action: spawn_critic(exploit_index=0) on your "
            "strongest verified candidate. After critic returns, "
            "you may continue exploration or re-emit "
            "FINAL_VAR(verified_exploits)."
        )
    return None


def check_and_count_spawn(agent_name: str) -> str | None:
    """Increment spawn counter for ``agent_name``; return BLOCKED message
    when either the pre-verifier per-agent cap OR the post-verifier
    stall cap is exceeded.

    Returns ``None`` if the call may proceed.

    Ordering note: the post-verifier check runs BEFORE the
    ``verifier_called`` early-return so the stall budget can fire
    even after verifier has already been called.
    """
    state = _state
    if state is None:
        return None
    if agent_name not in state.spawn_counts:
        return None
    with state.lock:
        # Post-verifier anti-stall path: once we have a verified or
        # soft_verified record AND spawn_critic has not been called,
        # analyzer/researcher spawns burn the shared stall budget.
        if state.has_verified_record and not state.critic_called:
            blocked = _post_verifier_stall_block(state)
            if blocked is not None:
                return blocked
            state.post_verifier_stalls += 1
            return None
        if state.verifier_called:
            return None
        if state.spawn_counts[agent_name] >= state.spawn_cap:
            return (
                f"BLOCKED: spawn_{agent_name} hit the "
                f"{state.spawn_cap}-call cybergym cap before "
                "spawn_verifier was called. Call "
                "spawn_verifier(payload=<your best raw PoC bytes>) "
                "now, then iterate on the bytes based on the "
                "verifier's feedback."
            )
        state.spawn_counts[agent_name] += 1
    return None


def check_and_count_file_read() -> str | None:
    """Increment file-read counter; return BLOCKED message when either
    the pre-verifier cap OR the post-verifier stall cap is exceeded.

    Called from the file-tool wrappers (``read_file``, ``search_files``,
    ``list_dir`` in :mod:`kai.workspace.tools``) so the model cannot
    substitute REPL file reads for sub-agent spawns indefinitely.

    Ordering note: the post-verifier check runs BEFORE the
    ``verifier_called`` early-return so file reads still trip the
    stall budget after verifier was called.
    """
    state = _state
    if state is None:
        return None
    with state.lock:
        # Post-verifier anti-stall path: once we have a verified or
        # soft_verified record AND spawn_critic has not been called,
        # file reads burn the shared stall budget.
        if state.has_verified_record and not state.critic_called:
            blocked = _post_verifier_stall_block(state)
            if blocked is not None:
                return blocked
            state.post_verifier_stalls += 1
            return None
        if state.verifier_called:
            return None
        if state.file_reads >= state.file_read_cap:
            return (
                f"BLOCKED: {state.file_read_cap}+ file reads without "
                "spawn_verifier. Call spawn_verifier(hypothesis=..., "
                "file=..., function=..., poc_code='__POC_BYTES__b64=...') "
                "with your strongest current hypothesis + best-guess "
                "bytes now. The harness will not let you continue "
                "exploring until the verifier has been invoked at "
                "least once."
            )
        state.file_reads += 1
    return None


def reminder_text(iter_num: int) -> str | None:
    """Return the escalating reminder for iteration ``iter_num`` if any.

    Fires when the cybergym gate state shows the agent has gone past
    iteration 4 without invoking ``spawn_verifier``. Returns ``None``
    when the verifier has already been called.
    """
    state = _state
    if state is None or state.verifier_called:
        return None
    if iter_num < 4:
        return None
    if iter_num >= 8:
        level = "FORCED"
        body = (
            "Next iteration MUST call spawn_verifier. The harness will "
            "block further file reads / sub-agent spawns until it does."
        )
    elif iter_num >= 6:
        level = "WARNING"
        body = (
            "By iteration 8 the harness will REQUIRE spawn_verifier "
            "before accepting any FINAL_VAR. Call it now."
        )
    else:
        level = "REMINDER"
        body = (
            "spawn_verifier is the strict-pass mechanism. Call it now "
            "even with a rough hypothesis + best-guess bytes; iterate "
            "on the bytes after the verifier reports the crash signal."
        )
    return (
        f"[harness {level}] Iteration {iter_num} — you have NOT called "
        f"spawn_verifier yet. {body} Recommended: "
        "spawn_verifier(hypothesis='...', file='src-vul/.../...', "
        "function='...', poc_code='__POC_BYTES__b64=<base64>')."
    )


def critic_reminder_text(
    iter_num: int,
    *,
    verified_or_soft_count: int,
    critic_called: bool,
) -> str | None:
    """Return a nudge to call ``spawn_critic`` when a verified /
    soft_verified record exists but the model hasn't critiqued it yet.

    Returns ``None`` when the critic was already invoked or when no
    verified record exists yet (i.e. nothing to critique).
    """
    if critic_called or verified_or_soft_count == 0:
        return None
    if iter_num < 8:
        return None
    if iter_num >= 14:
        level = "FORCED"
    elif iter_num >= 11:
        level = "WARNING"
    else:
        level = "REMINDER"
    return (
        f"[harness {level}] Iteration {iter_num} — you have a verified "
        f"(or soft_verified) finding but have NOT called spawn_critic. "
        "The critic does adversarial review (severity, exploitability, "
        "edge cases). Recommended: "
        "spawn_critic(exploit_index=<your verified candidate index>). "
        "This is a quality boost on top of the verifier's confirmation."
    )
