"""
C workspace adapter.

Handles C-specific workspace provisioning including:
- Build system detection (CMake, Make, Meson, Autoconf)
- Source and include directory symlinking
- Git submodule initialization
- Test directory setup
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Any, List

from kai.schemas import MasterContext, WorkspacePreset
from kai.utils.workspace.base import WorkspaceAdapter


class CWorkspaceAdapter(WorkspaceAdapter):
    """Workspace adapter for C projects."""

    @property
    def framework_name(self) -> str:
        return "c"

    def provision_lightweight(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
        logger: Optional[Any] = None,
    ) -> str:
        """
        Create a lightweight C workspace with symlinks to master.

        Copies build files and symlinks source/include directories.
        """
        # Create directory structure
        (workspace / "tests" / "poc").mkdir(parents=True, exist_ok=True)
        (workspace / "build").mkdir(exist_ok=True)

        # Copy build configuration files
        self._copy_build_files(workspace, master)

        # Symlink source and include directories
        self._setup_source_symlinks(workspace, master, master_context)

        # Initialize git submodules if present
        self._init_submodules(workspace, master, logger)

        if logger:
            logger.debug(f"Provisioned LIGHTWEIGHT C workspace: {workspace}")

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
        # Exclude patterns for C projects
        exclude_dirs = {
            ".git",
            "build",
            "cmake-build-debug",
            "cmake-build-release",
            "*.o",
            "*.a",
            "*.so",
            "*.dylib",
            "kai_workspaces",
            ".venv",
            "venv",
        }

        if preset == WorkspacePreset.SANDBOX:
            self._copy_with_excludes(master, workspace, exclude_dirs)
        else:
            # CLEAN/WRITEABLE - selective copy
            self._copy_with_excludes(master, workspace, exclude_dirs)

        # Create build and test directories
        (workspace / "build").mkdir(exist_ok=True)
        (workspace / "tests" / "poc").mkdir(parents=True, exist_ok=True)

        # Initialize git submodules
        self._init_submodules(workspace, workspace, logger)

        # Ensure workspace is writable
        self._make_writable(workspace)

        if logger:
            logger.debug(
                f"Provisioned {preset.value.upper()} C workspace: {workspace}"
            )
        return str(workspace)

    def detect_remappings(self, master: Path) -> str:
        """C doesn't use remappings - return empty string."""
        return ""

    def infer_src_path(self, master: Path) -> Path:
        """
        Infer the source directory for a C project.

        Checks CMakeLists.txt and common patterns.
        """
        cmake_file = master / "CMakeLists.txt"
        if cmake_file.exists():
            try:
                content = cmake_file.read_text()
                # Look for add_subdirectory or set(SOURCE_DIR ...)
                import re

                # Check for common source directory references
                for pattern in [
                    r'add_subdirectory\s*\(\s*(\w+)\s*\)',
                    r'set\s*\(\s*\w*SRC\w*\s+"?([^")\s]+)',
                ]:
                    match = re.search(pattern, content)
                    if match:
                        src_dir = match.group(1)
                        if (master / src_dir).is_dir():
                            return master / src_dir
            except Exception:
                pass

        # Common C source patterns
        for src_dir in ["src", "source", "lib", "sources"]:
            if (master / src_dir).is_dir():
                return master / src_dir

        return master

    def get_runtime_writable_paths(
        self, project_root: Path, master_context: MasterContext
    ) -> List[Path]:
        """
        C projects need build directories writable.
        """
        writable = []
        for rel in ["build", "cmake-build-debug", "cmake-build-release", "out"]:
            path = project_root / rel
            writable.append(path)
        return writable

    def _detect_build_system(self, path: Path) -> str:
        """Detect the build system used."""
        if (path / "CMakeLists.txt").exists():
            return "cmake"
        if (path / "Makefile").exists():
            return "make"
        if (path / "configure").exists() or (path / "configure.ac").exists():
            return "autoconf"
        if (path / "meson.build").exists():
            return "meson"
        return "direct"

    def _copy_build_files(self, workspace: Path, master: Path) -> None:
        """Copy build configuration files."""
        build_files = [
            "CMakeLists.txt",
            "Makefile",
            "configure",
            "configure.ac",
            "meson.build",
            "meson_options.txt",
            ".gitmodules",
            "conanfile.txt",
            "conanfile.py",
            "vcpkg.json",
        ]

        for build_file in build_files:
            src = master / build_file
            if src.exists() and src.is_file():
                shutil.copy2(src, workspace / build_file)

        # Also copy cmake/ directory if exists
        cmake_dir = master / "cmake"
        if cmake_dir.is_dir():
            shutil.copytree(cmake_dir, workspace / "cmake", dirs_exist_ok=True)

    def _setup_source_symlinks(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
    ) -> None:
        """Symlink source and include directories from master to workspace."""
        # Common source and include directories
        dirs_to_link = ["src", "source", "lib", "include", "inc", "headers"]

        for dir_name in dirs_to_link:
            master_dir = master / dir_name
            workspace_dir = workspace / dir_name

            if master_dir.exists() and master_dir.is_dir() and not workspace_dir.exists():
                try:
                    rel_path = os.path.relpath(master_dir, workspace)
                    workspace_dir.symlink_to(rel_path)
                except OSError:
                    # Symlink might fail on Windows, copy instead
                    shutil.copytree(master_dir, workspace_dir)

        # Also symlink deps/third_party if they exist
        for deps_dir in ["deps", "third_party", "external", "vendor"]:
            master_deps = master / deps_dir
            workspace_deps = workspace / deps_dir

            if master_deps.exists() and master_deps.is_dir() and not workspace_deps.exists():
                try:
                    rel_path = os.path.relpath(master_deps, workspace)
                    workspace_deps.symlink_to(rel_path)
                except OSError:
                    pass

    def _init_submodules(self, workspace: Path, master: Path, logger: Optional[Any] = None) -> None:
        """Initialize git submodules if present."""
        gitmodules = master / ".gitmodules"
        if not gitmodules.exists():
            return

        git_bin = shutil.which("git")
        if not git_bin:
            if logger:
                logger.debug("git not found - skipping submodule initialization")
            return

        # Copy .gitmodules if needed
        if not (workspace / ".gitmodules").exists():
            shutil.copy2(gitmodules, workspace / ".gitmodules")

        # Initialize if this is a git repo
        if (workspace / ".git").exists() or (master / ".git").exists():
            try:
                subprocess.run(
                    [git_bin, "submodule", "update", "--init", "--recursive"],
                    cwd=str(master if (master / ".git").exists() else workspace),
                    capture_output=True,
                    timeout=120,
                )
                if logger:
                    logger.debug("Initialized git submodules")
            except Exception as e:
                if logger:
                    logger.debug(f"Failed to initialize submodules: {e}")

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
                # Skip object files and libraries
                if item.suffix in {".o", ".a", ".so", ".dylib", ".obj", ".lib"}:
                    continue
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
