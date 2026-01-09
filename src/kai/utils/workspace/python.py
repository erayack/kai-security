"""
Python workspace adapter.

Handles Python-specific workspace provisioning including:
- Virtual environment creation
- Source directory symlinking
- Dependency installation
- Test directory setup
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Any, List

from kai.schemas import MasterContext, WorkspacePreset
from kai.utils.workspace.base import WorkspaceAdapter


class PythonWorkspaceAdapter(WorkspaceAdapter):
    """Workspace adapter for Python projects."""

    @property
    def framework_name(self) -> str:
        return "python"

    def provision_lightweight(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
        logger: Optional[Any] = None,
    ) -> str:
        """
        Create a lightweight Python workspace with symlinks to master.

        Creates a virtual environment and symlinks source directories.
        """
        # Create directory structure
        (workspace / "tests" / "poc").mkdir(parents=True, exist_ok=True)

        # Create virtual environment
        self._create_venv(workspace, logger)

        # Symlink source directories
        self._setup_source_symlinks(workspace, master, master_context)

        # Copy config files
        self._copy_config_files(workspace, master)

        # Install dependencies
        self._install_dependencies(workspace, logger)

        # Create conftest.py for pytest to find modules
        self._create_conftest(workspace, master, master_context)

        if logger:
            logger.debug(f"Provisioned LIGHTWEIGHT Python workspace: {workspace}")

        return str(workspace)

    def provision_full(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
        preset: WorkspacePreset,
        logger: Optional[Any] = None,
    ) -> str:
        """
        Create a full workspace by copying files from master.
        """
        # Exclude patterns for Python projects
        exclude_dirs = {
            ".venv",
            "venv",
            "__pycache__",
            ".git",
            ".pytest_cache",
            ".mypy_cache",
            ".tox",
            "dist",
            "build",
            "*.egg-info",
            "kai_workspaces",
        }

        if preset == WorkspacePreset.SANDBOX:
            # Copy everything except excluded dirs
            self._copy_with_excludes(master, workspace, exclude_dirs)
        else:
            # CLEAN/WRITEABLE - selective copy
            self._copy_with_excludes(master, workspace, exclude_dirs)

        # Create fresh venv
        self._create_venv(workspace, logger)

        # Install dependencies
        self._install_dependencies(workspace, logger)

        # Create test directories
        (workspace / "tests" / "poc").mkdir(parents=True, exist_ok=True)

        # Ensure workspace is writable
        self._make_writable(workspace)

        if logger:
            logger.debug(
                f"Provisioned {preset.value.upper()} Python workspace: {workspace}"
            )
        return str(workspace)

    def detect_remappings(self, master: Path) -> str:
        """Python doesn't use remappings - return empty string."""
        return ""

    def infer_src_path(self, master: Path) -> Path:
        """
        Infer the source directory for a Python project.

        Checks pyproject.toml and common patterns.
        """
        # Check pyproject.toml for package directory
        pyproject = master / "pyproject.toml"
        if pyproject.exists():
            try:
                import tomllib
                data = tomllib.loads(pyproject.read_text())

                # Check [tool.setuptools] packages
                setuptools = data.get("tool", {}).get("setuptools", {})
                package_dir = setuptools.get("package-dir", {})
                if "" in package_dir:
                    return master / package_dir[""]

                # Check packages list
                packages = setuptools.get("packages", [])
                if packages and isinstance(packages, list):
                    return master / packages[0].replace(".", "/")

            except Exception:
                pass

        # Common Python source patterns
        for src_dir in ["src", "lib", "app", master.name]:
            if (master / src_dir).is_dir():
                return master / src_dir

        return master

    def get_runtime_writable_paths(
        self, project_root: Path, master_context: MasterContext
    ) -> List[Path]:
        """
        Python projects need .venv, __pycache__, and build dirs writable.
        """
        writable = []
        for rel in [".venv", "__pycache__", ".pytest_cache", "build", "dist"]:
            path = project_root / rel
            writable.append(path)
        return writable

    def _create_venv(self, workspace: Path, logger: Optional[Any] = None) -> None:
        """Create a virtual environment in the workspace."""
        venv_path = workspace / ".venv"
        if venv_path.exists():
            return

        python_bin = shutil.which("python3") or shutil.which("python")
        if not python_bin:
            if logger:
                logger.warning("Python not found - skipping venv creation")
            return

        try:
            subprocess.run(
                [python_bin, "-m", "venv", str(venv_path)],
                cwd=str(workspace),
                capture_output=True,
                timeout=60,
            )
            if logger:
                logger.debug(f"Created venv at {venv_path}")
        except Exception as e:
            if logger:
                logger.warning(f"Failed to create venv: {e}")

    def _setup_source_symlinks(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
    ) -> None:
        """Symlink source directories from master to workspace."""
        # Determine source directory
        src_path = self.infer_src_path(master)

        # Common source directories to symlink
        src_dirs = ["src", "lib", "app"]

        # Add the inferred src path name
        if src_path != master:
            src_dirs.insert(0, src_path.name)

        for src_dir in src_dirs:
            master_dir = master / src_dir
            workspace_dir = workspace / src_dir

            if master_dir.exists() and master_dir.is_dir() and not workspace_dir.exists():
                try:
                    rel_path = os.path.relpath(master_dir, workspace)
                    workspace_dir.symlink_to(rel_path)
                except OSError:
                    # Symlink might fail on Windows, copy instead
                    shutil.copytree(master_dir, workspace_dir)

        # Also symlink the package directory if it's named after the project
        project_name = master.name.replace("-", "_").replace(".", "_")
        if (master / project_name).is_dir() and not (workspace / project_name).exists():
            try:
                rel_path = os.path.relpath(master / project_name, workspace)
                (workspace / project_name).symlink_to(rel_path)
            except OSError:
                pass

    def _copy_config_files(self, workspace: Path, master: Path) -> None:
        """Copy Python config files to workspace."""
        config_files = [
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements.txt",
            "requirements-dev.txt",
            "pytest.ini",
            "conftest.py",
            ".python-version",
            "tox.ini",
        ]

        for config_file in config_files:
            src = master / config_file
            if src.exists() and src.is_file():
                shutil.copy2(src, workspace / config_file)

    def _install_dependencies(self, workspace: Path, logger: Optional[Any] = None) -> None:
        """Install dependencies into the workspace venv."""
        venv_path = workspace / ".venv"
        pip_bin = venv_path / "bin" / "pip"

        if not pip_bin.exists():
            pip_bin = venv_path / "Scripts" / "pip.exe"

        if not pip_bin.exists():
            if logger:
                logger.debug("pip not found in venv - skipping dependency installation")
            return

        # Install from requirements.txt or pyproject.toml
        if (workspace / "requirements.txt").exists():
            try:
                subprocess.run(
                    [str(pip_bin), "install", "-r", "requirements.txt"],
                    cwd=str(workspace),
                    capture_output=True,
                    timeout=300,
                )
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to install requirements.txt: {e}")

        elif (workspace / "pyproject.toml").exists():
            try:
                subprocess.run(
                    [str(pip_bin), "install", "-e", "."],
                    cwd=str(workspace),
                    capture_output=True,
                    timeout=300,
                )
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to install from pyproject.toml: {e}")

        # Always try to install pytest for testing
        try:
            subprocess.run(
                [str(pip_bin), "install", "pytest"],
                cwd=str(workspace),
                capture_output=True,
                timeout=60,
            )
        except Exception:
            pass

    def _create_conftest(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
    ) -> None:
        """Create conftest.py to help pytest find modules."""
        conftest_path = workspace / "tests" / "poc" / "conftest.py"

        src_path = self.infer_src_path(master)
        rel_src = os.path.relpath(src_path, workspace / "tests" / "poc")

        conftest_content = f'''"""
Pytest configuration for PoC tests.
Auto-generated by Kai workspace provisioner.
"""
import sys
from pathlib import Path

# Add source directories to path for imports
_workspace = Path(__file__).parent.parent.parent
_master_src = _workspace / "{rel_src}"

if _master_src.exists():
    sys.path.insert(0, str(_master_src))

# Also add the workspace root
sys.path.insert(0, str(_workspace))
'''
        conftest_path.parent.mkdir(parents=True, exist_ok=True)
        conftest_path.write_text(conftest_content)

    def _copy_with_excludes(
        self, src: Path, dst: Path, excludes: set
    ) -> None:
        """Copy directory tree excluding certain patterns."""
        def should_exclude(path: Path) -> bool:
            for exc in excludes:
                if exc.startswith("*"):
                    if path.name.endswith(exc[1:]):
                        return True
                elif path.name == exc:
                    return True
            return False

        dst.mkdir(parents=True, exist_ok=True)

        for item in src.iterdir():
            if should_exclude(item):
                continue

            dest_path = dst / item.name

            if item.is_dir():
                if not item.name.startswith(".") or item.name == ".github":
                    self._copy_with_excludes(item, dest_path, excludes)
            else:
                shutil.copy2(item, dest_path)

    def _make_writable(self, root: Path) -> None:
        """Ensure workspace directories/files are writable."""
        try:
            root.chmod(root.stat().st_mode | 0o200)
        except Exception:
            pass
        for current, dirs, files in os.walk(root):
            for d in dirs:
                p = Path(current) / d
                try:
                    p.chmod(p.stat().st_mode | 0o200)
                except Exception:
                    pass
            for f in files:
                p = Path(current) / f
                try:
                    p.chmod(p.stat().st_mode | 0o200)
                except Exception:
                    pass
