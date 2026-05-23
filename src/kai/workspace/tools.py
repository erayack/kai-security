"""Setup agent tools — thin stdlib wrappers for repo exploration."""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any

from kai.state import cybergym_gate
from kai.utils.path_isolation import assert_task_isolation


def _cybergym_file_read_gate() -> str | None:
    """Return BLOCKED message when the cybergym pre-verifier file-read cap
    is exceeded; ``None`` otherwise.

    Activates only when ``KAI_BENCHMARK=cybergym`` and the gate state
    has been initialised (i.e. inside an exploit pipeline subprocess).
    """
    if os.environ.get("KAI_BENCHMARK") != "cybergym":
        return None
    return cybergym_gate.check_and_count_file_read()


def read_file(path: str) -> str:
    """Read a file."""
    assert_task_isolation(path)
    blocked = _cybergym_file_read_gate()
    if blocked is not None:
        return blocked
    with open(path) as f:
        return f.read()


def list_dir(path: str, recursive: bool = False) -> list[str]:
    """List a directory. Use recursive=True to walk the tree."""
    assert_task_isolation(path)
    blocked = _cybergym_file_read_gate()
    if blocked is not None:
        return [blocked]
    if not recursive:
        return sorted(os.listdir(path))

    entries: list[str] = []
    for root, dirs, files in os.walk(path):
        rel = os.path.relpath(root, path)
        for d in sorted(dirs):
            entries.append(os.path.join(rel, d) if rel != "." else d)
        for f in sorted(files):
            entries.append(os.path.join(rel, f) if rel != "." else f)
    return entries


def search_files(pattern: str, path: str) -> list[str]:
    """Grep for a regex pattern under path. Returns 'file:lineno: line' strings."""
    assert_task_isolation(path)
    blocked = _cybergym_file_read_gate()
    if blocked is not None:
        return [blocked]
    compiled = re.compile(pattern)
    results: list[str] = []
    for root, _dirs, files in os.walk(path):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            try:
                assert_task_isolation(fpath)
            except PermissionError:
                continue
            try:
                with open(fpath, errors="replace") as f:
                    for lineno, line in enumerate(f, 1):
                        if compiled.search(line):
                            results.append(f"{fpath}:{lineno}: {line.rstrip()}")
            except (OSError, UnicodeDecodeError):
                continue
    return results


def write_file(path: str, content: str) -> str:
    """Write content to a file, creating parent dirs as needed."""
    assert_task_isolation(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return f"Wrote {len(content)} chars to {path}"


def run_shell(command: str, cwd: str | None = None) -> dict[str, Any]:
    """Run a shell command. Returns {stdout, stderr, returncode}."""
    if cwd is not None:
        assert_task_isolation(cwd)
    _assert_shell_isolation(command)
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=int(os.environ.get("KAI_SHELL_TIMEOUT", 300)),
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


_CYBERGYM_OUTPUT_RE = re.compile(
    r"output/bench/cybergym/run_[^/\s]+/(?P<task>[^/\s'\"\\)]+)"
)


def _assert_shell_isolation(command: str) -> None:
    """Reject shell commands that reference a sibling task's output dir.

    Best-effort textual guard — a determined agent could still
    exfiltrate via globbing, symlinks, or absolute paths constructed
    at runtime. Catches the obvious ``cat``/``find``/``grep`` cases.
    """
    if os.environ.get("KAI_BENCHMARK") != "cybergym":
        return
    task_id = os.environ.get("KAI_TASK_ID")
    if not task_id:
        return
    for match in _CYBERGYM_OUTPUT_RE.finditer(command):
        if match.group("task") != task_id:
            raise PermissionError(
                f"cybergym isolation: shell command references sibling "
                f"task '{match.group('task')}' (current task: "
                f"'{task_id}'). Blocked."
            )
