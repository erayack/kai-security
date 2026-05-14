"""Tests for kai.workspace.recipe.WorkspaceRecipe."""

from __future__ import annotations

import pytest

from kai.workspace.recipe import InvalidRecipeError, WorkspaceRecipe


class TestWorkspaceRecipeConstruction:
    def test_minimal(self) -> None:
        recipe = WorkspaceRecipe(master_path="/tmp/master")
        assert recipe.master_path == "/tmp/master"
        assert recipe.symlink_dirs == []
        assert recipe.copy_dirs == []
        assert recipe.copy_files == []
        assert recipe.post_copy_commands == []

    def test_all_fields(self) -> None:
        recipe = WorkspaceRecipe(
            master_path="/m",
            symlink_dirs=["node_modules"],
            copy_dirs=["src"],
            copy_files=["foundry.toml"],
            post_copy_commands=["forge build"],
        )
        assert recipe.symlink_dirs == ["node_modules"]
        assert recipe.copy_dirs == ["src"]
        assert recipe.copy_files == ["foundry.toml"]
        assert recipe.post_copy_commands == ["forge build"]

    def test_default_lists_are_independent(self) -> None:
        a = WorkspaceRecipe(master_path="/a")
        b = WorkspaceRecipe(master_path="/b")
        a.symlink_dirs.append("x")
        assert b.symlink_dirs == []


class TestWorkspaceRecipeToDict:
    def test_round_trip(self) -> None:
        recipe = WorkspaceRecipe(
            master_path="/m",
            symlink_dirs=["node_modules", ".git"],
            copy_dirs=["src", "test"],
            copy_files=["foundry.toml", "remappings.txt"],
            post_copy_commands=["forge build"],
        )
        d = recipe.to_dict()
        restored = WorkspaceRecipe.from_dict(d)
        assert restored == recipe

    def test_to_dict_keys(self) -> None:
        recipe = WorkspaceRecipe(master_path="/m")
        d = recipe.to_dict()
        assert set(d.keys()) == {
            "master_path",
            "symlink_dirs",
            "copy_dirs",
            "copy_files",
            "post_copy_commands",
        }

    def test_from_dict_partial(self) -> None:
        d = {"master_path": "/m"}
        recipe = WorkspaceRecipe.from_dict(d)
        assert recipe.master_path == "/m"
        assert recipe.symlink_dirs == []
        assert recipe.copy_dirs == []

    def test_from_dict_ignores_extra_keys(self) -> None:
        d = {"master_path": "/m", "extra_key": "ignored"}
        recipe = WorkspaceRecipe.from_dict(d)
        assert recipe.master_path == "/m"

    def test_to_dict_is_json_safe(self) -> None:
        import json

        recipe = WorkspaceRecipe(
            master_path="/m",
            symlink_dirs=["a"],
            post_copy_commands=["echo ok"],
        )
        serialized = json.dumps(recipe.to_dict())
        restored = WorkspaceRecipe.from_dict(json.loads(serialized))
        assert restored == recipe


class TestWorkspaceRecipeValidation:
    """Regression tests for B-004 — recipe parsing must raise a typed error."""

    def test_from_dict_missing_master_path_raises_typed_error(self) -> None:
        with pytest.raises(InvalidRecipeError) as info:
            WorkspaceRecipe.from_dict({})
        assert info.value.missing == ["master_path"]
        assert "master_path" in str(info.value)
        assert info.value.data == {}

    def test_from_dict_not_a_dict_raises(self) -> None:
        with pytest.raises(InvalidRecipeError) as info:
            WorkspaceRecipe.from_dict([{"master_path": "/m"}])  # type: ignore[arg-type]
        assert "object" in str(info.value).lower()
        assert info.value.data == [{"master_path": "/m"}]

    def test_invalid_recipe_error_is_value_error(self) -> None:
        with pytest.raises(ValueError):
            WorkspaceRecipe.from_dict({})

    def test_partial_recipe_with_master_path_succeeds(self) -> None:
        recipe = WorkspaceRecipe.from_dict({"master_path": "/m"})
        assert recipe.master_path == "/m"
