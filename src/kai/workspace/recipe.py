"""WorkspaceRecipe: describes how to provision a workspace from a master build."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

REQUIRED_RECIPE_FIELDS: tuple[str, ...] = ("master_path",)


class InvalidRecipeError(ValueError):
    """Raised when a recipe dict is missing required fields or has wrong shape.

    Carries the names of the missing/invalid fields and the offending raw
    payload so callers (e.g. the setup-agent retry loop) can log it and
    decide whether to retry or surface a user-visible error.
    """

    def __init__(self, message: str, *, missing: list[str], data: Any) -> None:
        super().__init__(message)
        self.missing = list(missing)
        self.data = data


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
    prerequisite_branch: str | None = None
    pending_candidates: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        d: dict[str, Any] = {
            "master_path": self.master_path,
            "symlink_dirs": self.symlink_dirs,
            "copy_dirs": self.copy_dirs,
            "copy_files": self.copy_files,
            "post_copy_commands": self.post_copy_commands,
        }
        if self.prerequisite_branch is not None:
            d["prerequisite_branch"] = self.prerequisite_branch
        if self.pending_candidates is not None:
            d["pending_candidates"] = self.pending_candidates
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkspaceRecipe:
        """Deserialize from a dict.

        Raises:
            InvalidRecipeError: if ``data`` is not a dict, or if any field
                in :data:`REQUIRED_RECIPE_FIELDS` is missing. The error
                names every missing field so callers can present a single
                actionable diagnostic.
        """

        if not isinstance(data, dict):
            raise InvalidRecipeError(
                f"recipe must be a JSON object, got {type(data).__name__}",
                missing=list(REQUIRED_RECIPE_FIELDS),
                data=data,
            )
        missing = [f for f in REQUIRED_RECIPE_FIELDS if f not in data]
        if missing:
            raise InvalidRecipeError(
                f"recipe is missing required field(s): {', '.join(missing)}",
                missing=missing,
                data=data,
            )
        return cls(
            master_path=data["master_path"],
            symlink_dirs=data.get("symlink_dirs", []),
            copy_dirs=data.get("copy_dirs", []),
            copy_files=data.get("copy_files", []),
            post_copy_commands=data.get("post_copy_commands", []),
            prerequisite_branch=data.get("prerequisite_branch"),
            pending_candidates=data.get("pending_candidates"),
        )
