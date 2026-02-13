"""WorkspaceRecipe: describes how to provision a workspace from a master build."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkspaceRecipe:
    """Recipe for provisioning agent workspaces from a master build.

    The master directory contains the fully-built repo. Each agent gets
    a fresh workspace where heavy dirs (node_modules, .git, lib) are
    symlinked (fast, read-only) and source dirs are deep-copied
    (editable).
    """

    master_path: str
    symlink_dirs: list[str] = field(default_factory=list)
    copy_dirs: list[str] = field(default_factory=list)
    copy_files: list[str] = field(default_factory=list)
    post_copy_commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "master_path": self.master_path,
            "symlink_dirs": self.symlink_dirs,
            "copy_dirs": self.copy_dirs,
            "copy_files": self.copy_files,
            "post_copy_commands": self.post_copy_commands,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkspaceRecipe:
        """Deserialize from a dict."""
        return cls(
            master_path=data["master_path"],
            symlink_dirs=data.get("symlink_dirs", []),
            copy_dirs=data.get("copy_dirs", []),
            copy_files=data.get("copy_files", []),
            post_copy_commands=data.get("post_copy_commands", []),
        )
