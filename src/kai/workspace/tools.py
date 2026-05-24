"""Setup agent tools — thin stdlib wrappers for repo exploration."""

from __future__ import annotations

import json
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


# ---------------------------------------------------------------------------
# Cybergym strict-harness submission (in-pipeline real-crash feedback)
# ---------------------------------------------------------------------------
#
# When the worker reaches the in-pipeline verifier sub-agent, it has no
# way today to actually run the fuzzer binary — the cybergym Docker
# harness can't ship to Railway (no Docker-in-Docker). This tool lets
# the verifier POST candidate PoC bytes to a real cybergym server
# (typically the user's laptop, tunneled via ngrok) and read back the
# crash signal.
#
# Activates only when KAI_BENCHMARK=cybergym AND
# KAI_CYBERGYM_HARNESS_URL is set. Otherwise returns a clear error so
# the verifier knows the tool is unavailable.

_CYBERGYM_DEFAULT_MASK_MAP_URL = (
    "https://raw.githubusercontent.com/sunblaze-ucb/cybergym/main/mask_map.json"
)
_CYBERGYM_DEFAULT_SALT = "CyberGym"
_CYBERGYM_SUBMIT_TIMEOUT_S = 600
_cybergym_mask_map_cache: dict[str, str] | None = None


def _load_cybergym_mask_map() -> dict[str, str] | None:
    """Lazy-fetch the mask_map.json from GitHub (or KAI_CYBERGYM_MASK_MAP_URL).

    Cached in module state for the lifetime of the process.
    """
    global _cybergym_mask_map_cache
    if _cybergym_mask_map_cache is not None:
        return _cybergym_mask_map_cache
    url = os.environ.get("KAI_CYBERGYM_MASK_MAP_URL", _CYBERGYM_DEFAULT_MASK_MAP_URL)
    try:
        import httpx

        resp = httpx.get(url, timeout=60.0)
        resp.raise_for_status()
        _cybergym_mask_map_cache = resp.json()
    except Exception:
        return None
    return _cybergym_mask_map_cache


def submit_to_cybergym_harness(poc_b64: str) -> dict[str, Any]:
    """Submit PoC bytes to the cybergym strict-harness server.

    Reads:
        ``KAI_CYBERGYM_HARNESS_URL`` (required) — base URL of the
        cybergym submission server (e.g. an ngrok tunnel to the
        user's laptop running ``python -m cybergym.server``).
        ``KAI_TASK_ID`` (required) — task id like ``arvo:1065``.
        ``KAI_CYBERGYM_SALT`` (optional, default ``CyberGym``) —
        checksum salt; must match the server's DEFAULT_SALT.

    Returns dict with keys:
        ``verified`` (bool) — True when the harness reported a crash
            (server ``exit_code != 0``). Source of truth for whether
            the bytes actually trigger the bug.
        ``exit_code`` (int) — server's exit_code field. 77 = MSan,
            134 = ASan/SIGABRT, 139 = SIGSEGV, 0 = clean run.
        ``output`` (str) — server stdout/stderr excerpt (truncated to
            4 KiB for prompt budget).
        ``http_status`` (int) — HTTP response status.
        ``error`` (str | None) — populated on tool-side failure
            (missing env vars, transport error, missing mask map).

    Tool is a no-op outside cybergym (returns an error explaining the
    KAI_BENCHMARK guard so the model knows not to retry).
    """
    if os.environ.get("KAI_BENCHMARK") != "cybergym":
        return {
            "verified": False,
            "exit_code": -1,
            "output": "",
            "http_status": 0,
            "error": (
                "submit_to_cybergym_harness only available when KAI_BENCHMARK=cybergym."
            ),
        }
    harness_url = os.environ.get("KAI_CYBERGYM_HARNESS_URL", "").rstrip("/")
    if not harness_url:
        return {
            "verified": False,
            "exit_code": -1,
            "output": "",
            "http_status": 0,
            "error": (
                "KAI_CYBERGYM_HARNESS_URL not set on this worker; the "
                "real harness is not reachable. Fall back to the "
                "in-pipeline soft-verify path."
            ),
        }
    task_id = os.environ.get("KAI_TASK_ID", "")
    if not task_id:
        return {
            "verified": False,
            "exit_code": -1,
            "output": "",
            "http_status": 0,
            "error": "KAI_TASK_ID not set on this worker.",
        }

    import base64
    from hashlib import sha256
    from uuid import uuid4

    try:
        poc_bytes = base64.b64decode(poc_b64, validate=True)
    except Exception as exc:
        return {
            "verified": False,
            "exit_code": -1,
            "output": "",
            "http_status": 0,
            "error": f"poc_b64 decode failed: {exc}",
        }

    mask_map = _load_cybergym_mask_map()
    if mask_map is None:
        return {
            "verified": False,
            "exit_code": -1,
            "output": "",
            "http_status": 0,
            "error": "failed to load cybergym mask_map.json",
        }
    if task_id not in mask_map:
        return {
            "verified": False,
            "exit_code": -1,
            "output": "",
            "http_status": 0,
            "error": f"task_id {task_id!r} not present in mask_map",
        }

    masked_id = mask_map[task_id]
    agent_id = uuid4().hex
    salt = os.environ.get("KAI_CYBERGYM_SALT", _CYBERGYM_DEFAULT_SALT)
    checksum = sha256(f"{masked_id}{agent_id}{salt}".encode()).hexdigest()
    metadata = {
        "task_id": masked_id,
        "agent_id": agent_id,
        "checksum": checksum,
        "require_flag": False,
    }
    submit_url = f"{harness_url}/submit-vul"
    try:
        import httpx
    except ImportError:
        return {
            "verified": False,
            "exit_code": -1,
            "output": "",
            "http_status": 0,
            "error": "httpx not installed on worker",
        }
    try:
        with httpx.Client(timeout=_CYBERGYM_SUBMIT_TIMEOUT_S) as client:
            resp = client.post(
                submit_url,
                data={"metadata": json.dumps(metadata)},
                files={
                    "file": (
                        f"{task_id.replace(':', '_')}.poc",
                        poc_bytes,
                        "application/octet-stream",
                    )
                },
            )
    except Exception as exc:
        return {
            "verified": False,
            "exit_code": -1,
            "output": "",
            "http_status": 0,
            "error": f"POST to {submit_url} failed: {exc}",
        }
    try:
        payload = resp.json()
    except Exception:
        payload = {"raw": resp.text[:600]}
    exit_code = int(payload.get("exit_code", -1)) if isinstance(payload, dict) else -1
    output = ""
    if isinstance(payload, dict):
        output = str(payload.get("output") or payload.get("raw") or "")[:4096]
    return {
        "verified": exit_code != 0,
        "exit_code": exit_code,
        "output": output,
        "http_status": resp.status_code,
        "error": None,
    }
