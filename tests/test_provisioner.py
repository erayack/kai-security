"""Tests for kai.workspace.provisioner.provision_workspace."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from kai.workspace.provisioner import provision_workspace
from kai.workspace.recipe import WorkspaceRecipe


def _make_master(tmp_path: Path) -> Path:
    """Build a fake master directory with typical project layout."""
    master = tmp_path / "master"
    master.mkdir()
    # Heavy dir (will be symlinked)
    nm = master / "node_modules" / "dep"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("module.exports = {}")
    # Source dir (will be copied)
    src = master / "src"
    src.mkdir()
    (src / "main.sol").write_text("contract Main {}")
    # Individual file
    (master / "foundry.toml").write_text("[profile.default]")
    return master


class TestProvisionWorkspace:
    def test_symlink_dirs(self, tmp_path: Path) -> None:
        master = _make_master(tmp_path)
        recipe = WorkspaceRecipe(
            master_path=str(master),
            symlink_dirs=["node_modules"],
        )
        ws = provision_workspace(recipe)
        try:
            ws_nm = Path(ws) / "node_modules"
            assert ws_nm.is_symlink()
            assert ws_nm.resolve() == (master / "node_modules").resolve()
            # Content accessible through symlink
            assert (ws_nm / "dep" / "index.js").read_text() == ("module.exports = {}")
        finally:
            shutil.rmtree(ws)

    def test_copy_dirs(self, tmp_path: Path) -> None:
        master = _make_master(tmp_path)
        recipe = WorkspaceRecipe(
            master_path=str(master),
            copy_dirs=["src"],
        )
        ws = provision_workspace(recipe)
        try:
            ws_src = Path(ws) / "src"
            assert ws_src.is_dir()
            assert not ws_src.is_symlink()
            assert (ws_src / "main.sol").read_text() == "contract Main {}"
            # Verify it's a real copy — mutating doesn't affect master
            (ws_src / "main.sol").write_text("modified")
            assert (master / "src" / "main.sol").read_text() == ("contract Main {}")
        finally:
            shutil.rmtree(ws)

    def test_copy_files(self, tmp_path: Path) -> None:
        master = _make_master(tmp_path)
        recipe = WorkspaceRecipe(
            master_path=str(master),
            copy_files=["foundry.toml"],
        )
        ws = provision_workspace(recipe)
        try:
            assert (Path(ws) / "foundry.toml").read_text() == ("[profile.default]")
        finally:
            shutil.rmtree(ws)

    def test_post_copy_commands(self, tmp_path: Path) -> None:
        master = _make_master(tmp_path)
        recipe = WorkspaceRecipe(
            master_path=str(master),
            copy_dirs=["src"],
            post_copy_commands=["touch marker.txt"],
        )
        ws = provision_workspace(recipe)
        try:
            assert (Path(ws) / "marker.txt").exists()
        finally:
            shutil.rmtree(ws)

    def test_missing_source_dir_skipped(self, tmp_path: Path) -> None:
        master = _make_master(tmp_path)
        recipe = WorkspaceRecipe(
            master_path=str(master),
            symlink_dirs=["nonexistent"],
            copy_dirs=["also_missing"],
            copy_files=["nope.txt"],
        )
        ws = provision_workspace(recipe)
        try:
            assert not (Path(ws) / "nonexistent").exists()
            assert not (Path(ws) / "also_missing").exists()
            assert not (Path(ws) / "nope.txt").exists()
        finally:
            shutil.rmtree(ws)

    def test_full_recipe(self, tmp_path: Path) -> None:
        master = _make_master(tmp_path)
        recipe = WorkspaceRecipe(
            master_path=str(master),
            symlink_dirs=["node_modules"],
            copy_dirs=["src"],
            copy_files=["foundry.toml"],
            post_copy_commands=["echo done > status.txt"],
        )
        ws = provision_workspace(recipe)
        try:
            assert (Path(ws) / "node_modules").is_symlink()
            assert (Path(ws) / "src" / "main.sol").exists()
            assert (Path(ws) / "foundry.toml").exists()
            assert "done" in (Path(ws) / "status.txt").read_text()
        finally:
            shutil.rmtree(ws)

    def test_cleanup_preserves_master(self, tmp_path: Path) -> None:
        """rmtree on workspace should not delete master symlink targets."""
        master = _make_master(tmp_path)
        recipe = WorkspaceRecipe(
            master_path=str(master),
            symlink_dirs=["node_modules"],
            copy_dirs=["src"],
        )
        ws = provision_workspace(recipe)
        shutil.rmtree(ws)
        # Master is intact
        assert (master / "node_modules" / "dep" / "index.js").exists()
        assert (master / "src" / "main.sol").exists()

    def test_nested_copy_file(self, tmp_path: Path) -> None:
        """copy_files with subdirectory paths creates parent dirs."""
        master = tmp_path / "master"
        master.mkdir()
        sub = master / "config" / "deep"
        sub.mkdir(parents=True)
        (sub / "settings.json").write_text("{}")
        recipe = WorkspaceRecipe(
            master_path=str(master),
            copy_files=[os.path.join("config", "deep", "settings.json")],
        )
        ws = provision_workspace(recipe)
        try:
            assert (Path(ws) / "config" / "deep" / "settings.json").read_text() == "{}"
        finally:
            shutil.rmtree(ws)
