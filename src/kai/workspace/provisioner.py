"""Provision ephemeral workspaces from a master build."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid

from kai.workspace.recipe import WorkspaceRecipe


def provision_workspace(recipe: WorkspaceRecipe) -> str:
    """Create a ready-to-use workspace from a WorkspaceRecipe.

    - Symlinks dirs in ``symlink_dirs`` (fast, read-only).
    - Deep-copies dirs in ``copy_dirs`` (editable by agent).
    - Copies individual files in ``copy_files``.
    - Runs ``post_copy_commands`` in the new workspace.

    Returns the path to the new workspace directory.
    """
    master = recipe.master_path
    ws = tempfile.mkdtemp(prefix=f"kai_ws_{uuid.uuid4()}_")

    for d in recipe.symlink_dirs:
        src = os.path.join(master, d)
        dst = os.path.join(ws, d)
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            os.symlink(src, dst)

    for d in recipe.copy_dirs:
        src = os.path.join(master, d)
        dst = os.path.join(ws, d)
        if os.path.exists(src):
            shutil.copytree(src, dst, symlinks=True, ignore_dangling_symlinks=True)

    for f in recipe.copy_files:
        src = os.path.join(master, f)
        dst = os.path.join(ws, f)
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)

    for cmd in recipe.post_copy_commands:
        subprocess.run(cmd, shell=True, cwd=ws, capture_output=True, timeout=300)

    return ws
