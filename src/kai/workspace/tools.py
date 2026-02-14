"""Setup agent tools — thin stdlib wrappers for repo exploration."""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any


def read_file(path: str) -> str:
    """Read a file."""
    with open(path) as f:
        return f.read()


def list_dir(path: str, recursive: bool = False) -> list[str]:
    """List a directory. Use recursive=True to walk the tree."""
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
    compiled = re.compile(pattern)
    results: list[str] = []
    for root, _dirs, files in os.walk(path):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
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
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return f"Wrote {len(content)} chars to {path}"


def run_shell(command: str, cwd: str | None = None) -> dict[str, Any]:
    """Run a shell command. Returns {stdout, stderr, returncode}."""
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=300,
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
