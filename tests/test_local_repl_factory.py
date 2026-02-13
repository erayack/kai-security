"""Tests for LocalREPL workspace_factory support."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from ra.environments.local_repl import LocalREPL


class TestLocalREPLDefaultTempDir:
    def test_creates_temp_dir(self) -> None:
        repl = LocalREPL()
        try:
            assert os.path.isdir(repl.temp_dir)
            assert "repl_env_" in repl.temp_dir
        finally:
            repl.cleanup()

    def test_cleanup_removes_temp_dir(self) -> None:
        repl = LocalREPL()
        path = repl.temp_dir
        repl.cleanup()
        assert not os.path.exists(path)


class TestLocalREPLWorkspaceFactory:
    def test_factory_sets_temp_dir(self) -> None:
        custom_dir = tempfile.mkdtemp(prefix="test_factory_")
        try:
            repl = LocalREPL(workspace_factory=lambda: custom_dir)
            assert repl.temp_dir == custom_dir
            repl.cleanup()
        finally:
            # cleanup may have already removed it
            shutil.rmtree(custom_dir, ignore_errors=True)

    def test_factory_dir_used_for_execution(self) -> None:
        custom_dir = tempfile.mkdtemp(prefix="test_exec_")
        try:
            repl = LocalREPL(workspace_factory=lambda: custom_dir)
            # Code execution should use the factory-provided dir
            repl.execute_code("import os; cwd = os.getcwd()")
            # Resolve both to handle macOS /var -> /private/var symlink
            assert os.path.realpath(repl.locals.get("cwd")) == (
                os.path.realpath(custom_dir)
            )
            repl.cleanup()
        finally:
            shutil.rmtree(custom_dir, ignore_errors=True)

    def test_factory_with_files(self, tmp_path: Path) -> None:
        """Factory-provided workspace with pre-existing files."""
        (tmp_path / "data.txt").write_text("hello")

        repl = LocalREPL(workspace_factory=lambda: str(tmp_path))
        repl.execute_code("with open('data.txt') as f: content = f.read()")
        assert repl.locals.get("content") == "hello"
        repl.cleanup()

    def test_none_factory_uses_default(self) -> None:
        """Passing workspace_factory=None uses default mkdtemp."""
        repl = LocalREPL(workspace_factory=None)
        try:
            assert os.path.isdir(repl.temp_dir)
            assert "repl_env_" in repl.temp_dir
        finally:
            repl.cleanup()

    def test_factory_kwarg_not_passed_to_parent(self) -> None:
        """workspace_factory should be popped, not passed to super()."""
        # If it wasn't popped, super().__init__ would get an unexpected
        # kwarg and raise TypeError. This test just verifies no error.
        repl = LocalREPL(workspace_factory=lambda: tempfile.mkdtemp())
        path = repl.temp_dir
        repl.cleanup()
        shutil.rmtree(path, ignore_errors=True)
