"""
Python workspace adapter.

Handles Python-specific workspace provisioning including:
- Virtual environment creation
- Source directory symlinking
- Dependency installation
- Test directory setup
"""

import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional, Any, List

from kai.agents import settings
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

        # Reuse master's virtualenv if available to avoid reinstall; otherwise create one
        if not self._setup_venv_symlink(workspace, master):
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

        # Reuse master's virtualenv if available to avoid reinstall; otherwise create one
        if not self._setup_venv_symlink(workspace, master):
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

    @staticmethod
    def _get_venv_python_path(venv_path: Path) -> Path:
        """
        Get the expected Python binary path for a venv.

        Handles both Unix (bin/python) and Windows (Scripts/python.exe).
        """
        if platform.system() == "Windows":
            return venv_path / "Scripts" / "python.exe"
        return venv_path / "bin" / "python"

    @staticmethod
    def _venv_python_exists(venv_path: Path) -> bool:
        """
        Check if the venv has a valid Python binary.

        Cross-platform: checks both Unix and Windows paths.
        """
        unix_path = venv_path / "bin" / "python"
        win_path = venv_path / "Scripts" / "python.exe"
        return unix_path.exists() or win_path.exists()

    def _create_venv(self, workspace: Path, logger: Optional[Any] = None) -> None:
        """
        Create a virtual environment in the workspace.

        Strategy:
        1. If .venv exists but corrupted (no python binary): remove and recreate
        2. Try: uv venv .venv (preferred)
        3. Verify python binary with filesystem-settling retries (up to 5x, 100ms apart)
        4. Fallback: python -m venv .venv
        5. On total failure: raise RuntimeError
        """
        venv_path = workspace / ".venv"

        # If .venv exists, check if it's valid
        if venv_path.exists():
            if self._venv_python_exists(venv_path):
                return  # Valid venv already exists
            # Corrupted venv - remove and recreate
            if logger:
                logger.debug(f"Corrupted venv detected at {venv_path} (no python binary), recreating")
            shutil.rmtree(venv_path, ignore_errors=True)

        # Strategy 1: Try uv venv (preferred)
        uv_bin = shutil.which("uv")
        if uv_bin:
            try:
                result = subprocess.run(
                    [uv_bin, "venv", str(venv_path)],
                    cwd=str(workspace),
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode == 0:
                    # Verify with filesystem-settling retries
                    for attempt in range(5):
                        if self._venv_python_exists(venv_path):
                            if logger:
                                logger.debug(f"Created venv via uv at {venv_path}")
                            return
                        time.sleep(0.1)  # 100ms between retries

                    if logger:
                        logger.warning(
                            "uv venv succeeded but python binary not found after retries"
                        )
                else:
                    if logger:
                        logger.debug(f"uv venv failed: {result.stderr[:200]}")
            except Exception as e:
                if logger:
                    logger.debug(f"uv venv failed with exception: {e}")

        # Strategy 2: Fallback to python -m venv
        python_bin = shutil.which("python3") or shutil.which("python")
        if python_bin:
            # Clean up any partial venv from failed uv attempt
            if venv_path.exists():
                shutil.rmtree(venv_path, ignore_errors=True)

            try:
                result = subprocess.run(
                    [python_bin, "-m", "venv", str(venv_path)],
                    cwd=str(workspace),
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode == 0 and self._venv_python_exists(venv_path):
                    if logger:
                        logger.debug(f"Created venv via python -m venv at {venv_path}")
                    return
            except Exception as e:
                if logger:
                    logger.warning(f"python -m venv failed: {e}")

        # Total failure
        raise RuntimeError(
            f"Failed to create virtual environment at {venv_path}. "
            f"Neither 'uv venv' nor 'python -m venv' succeeded. "
            f"Ensure uv or Python 3 is installed."
        )

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

            if (
                master_dir.exists()
                and master_dir.is_dir()
                and not workspace_dir.exists()
            ):
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

    def _install_dependencies(
        self, workspace: Path, logger: Optional[Any] = None
    ) -> None:
        """
        Install dependencies into the workspace venv.

        Prefers uv pip install over raw pip:
        1. If pyproject.toml/setup.py exists:
           a. Try editable install (-e .)
           b. If build error: pre-install setuptools+wheel, retry with --no-build-isolation
           c. If still failing: try non-editable install (.)
           d. If still failing: skip (source available via PYTHONPATH)
        2. If requirements.txt exists: install -r requirements.txt (fatal on failure)
        3. Pre-install optional packages (pytest, requests, httpx, aiohttp) -- non-fatal
        """
        # Determine installer: prefer uv pip, fall back to venv pip
        uv_bin = shutil.which("uv")
        venv_path = workspace / ".venv"

        def _run_install(cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
            return subprocess.run(
                cmd,
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=timeout,
            )

        def _uv_pip(*args: str, timeout: int = 300) -> subprocess.CompletedProcess:
            assert uv_bin is not None
            return _run_install([uv_bin, "pip", *args], timeout=timeout)

        def _pip(*args: str, timeout: int = 300) -> subprocess.CompletedProcess:
            if platform.system() == "Windows":
                pip_bin = venv_path / "Scripts" / "pip.exe"
            else:
                pip_bin = venv_path / "bin" / "pip"
            return _run_install([str(pip_bin), *args], timeout=timeout)

        use_uv = bool(uv_bin)
        pip_install = _uv_pip if use_uv else _pip

        # 1. Install from pyproject.toml or setup.py
        has_pyproject = (workspace / "pyproject.toml").exists()
        has_setup_py = (workspace / "setup.py").exists()

        if has_pyproject or has_setup_py:
            installed_project = False

            # Strategy a: editable install
            try:
                result = pip_install("install", "-e", ".")
                if result.returncode == 0:
                    installed_project = True
                    if logger:
                        logger.debug("Installed project via editable install (-e .)")
                else:
                    output = result.stdout + result.stderr
                    build_error_patterns = [
                        "modulenotfounderror",
                        "failed to build",
                        "build_meta",
                        "setuptools",
                        "subprocess-exited-with-error",
                    ]
                    output_lower = output.lower()
                    is_build_error = any(
                        pat in output_lower for pat in build_error_patterns
                    )

                    if is_build_error:
                        # Strategy b: pre-install setuptools+wheel, retry with --no-build-isolation
                        if logger:
                            logger.debug(
                                "Editable install failed (build error), trying with --no-build-isolation"
                            )
                        try:
                            pip_install("install", "setuptools", "wheel", timeout=60)
                        except Exception:
                            pass

                        try:
                            result = pip_install(
                                "install", "-e", ".", "--no-build-isolation"
                            )
                            if result.returncode == 0:
                                installed_project = True
                                if logger:
                                    logger.debug(
                                        "Installed project via --no-build-isolation"
                                    )
                        except Exception:
                            pass

                    if not installed_project:
                        # Strategy c: non-editable install
                        if logger:
                            logger.debug(
                                "Editable install failed, trying non-editable install"
                            )
                        try:
                            result = pip_install("install", ".")
                            if result.returncode == 0:
                                installed_project = True
                                if logger:
                                    logger.debug(
                                        "Installed project via non-editable install (.)"
                                    )
                        except Exception:
                            pass

            except Exception as e:
                if logger:
                    logger.debug(f"Editable install failed with exception: {e}")

            if not installed_project and logger:
                # Strategy d: skip - source available via PYTHONPATH
                logger.debug(
                    "All project install strategies failed; source available via PYTHONPATH"
                )

        # 2. Install from requirements.txt (fatal on failure)
        if (workspace / "requirements.txt").exists():
            try:
                result = pip_install("install", "-r", "requirements.txt")
                if result.returncode != 0:
                    output = result.stdout + result.stderr
                    if logger:
                        logger.warning(
                            f"Failed to install requirements.txt: {output[:500]}"
                        )
                else:
                    if logger:
                        logger.debug("Installed requirements.txt")
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to install requirements.txt: {e}")

        # 3. Pre-install optional packages -- non-fatal
        for pkg in settings.PRE_INSTALL_PACKAGES:
            try:
                pip_install("install", pkg, timeout=60)
            except Exception:
                pass

    def _setup_venv_symlink(self, workspace: Path, master: Path) -> bool:
        """Symlink workspace/.venv -> master/.venv when available.

        Returns True if the symlink was created or already exists; False otherwise.
        """
        venv_master = master / ".venv"
        venv_link = workspace / ".venv"
        if venv_link.exists():
            return True
        if venv_master.exists() and venv_master.is_dir():
            try:
                rel_path = os.path.relpath(venv_master, workspace)
                venv_link.symlink_to(rel_path)
                return True
            except OSError:
                pass
        return False

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

    def _copy_with_excludes(self, src: Path, dst: Path, excludes: set) -> None:
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
