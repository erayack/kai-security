"""
JavaScript workspace adapter.

Handles JavaScript/Node.js-specific workspace provisioning including:
- Package manager detection (npm, yarn, pnpm)
- Node modules installation
- Source directory symlinking
- Test directory setup
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Any, List

from kai.schemas import MasterContext, WorkspacePreset
from kai.utils.workspace.base import WorkspaceAdapter


class JavaScriptWorkspaceAdapter(WorkspaceAdapter):
    """Workspace adapter for JavaScript/Node.js projects."""

    @property
    def framework_name(self) -> str:
        return "javascript"

    def provision_lightweight(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
        logger: Optional[Any] = None,
    ) -> str:
        """
        Create a lightweight JavaScript workspace with symlinks to master.

        Copies package.json and lockfiles, symlinks source directories.
        """
        # Copy package.json and lockfiles
        self._copy_package_files(workspace, master)

        # Symlink source directories and copy test directories
        # NOTE: Must happen BEFORE creating poc directories to avoid conflicts
        self._setup_source_symlinks(workspace, master, master_context)

        # Make copied dirs writable (they may have been copied from read-only master)
        self._make_writable(workspace)

        # Create PoC directory structure (inside existing test dirs if they exist)
        (workspace / "tests" / "poc").mkdir(parents=True, exist_ok=True)
        (workspace / "__tests__" / "poc").mkdir(parents=True, exist_ok=True)

        # Copy config files
        self._copy_config_files(workspace, master)

        # Install dependencies
        self._install_dependencies(workspace, logger)

        # Run build if needed (for TypeScript projects where dist/ is gitignored)
        self._run_build_if_needed(workspace, logger)

        if logger:
            logger.debug(f"Provisioned LIGHTWEIGHT JavaScript workspace: {workspace}")

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
        # Exclude patterns for JavaScript projects
        # NOTE: We do NOT exclude "dist" or "build" because:
        # 1. Some projects commit pre-built dist/ to the repo (e.g., npm packages)
        # 2. Tests often import from dist/ directly
        # 3. If dist/ doesn't exist, _run_build_if_needed() will generate it
        exclude_dirs = {
            "node_modules",
            ".git",
            "coverage",
            ".cache",
            ".next",
            ".nuxt",
            "kai_workspaces",
            ".venv",
            "venv",
        }

        if preset == WorkspacePreset.SANDBOX:
            self._copy_with_excludes(master, workspace, exclude_dirs)
        else:
            # CLEAN/WRITEABLE - selective copy
            self._copy_with_excludes(master, workspace, exclude_dirs)

        # Install dependencies with fresh node_modules
        self._install_dependencies(workspace, logger)

        # Run build if needed (for TypeScript projects where dist/ is gitignored)
        self._run_build_if_needed(workspace, logger)

        # Create test directories
        (workspace / "tests" / "poc").mkdir(parents=True, exist_ok=True)
        (workspace / "__tests__" / "poc").mkdir(parents=True, exist_ok=True)

        # Ensure workspace is writable
        self._make_writable(workspace)

        if logger:
            logger.debug(
                f"Provisioned {preset.value.upper()} JavaScript workspace: {workspace}"
            )
        return str(workspace)

    def detect_remappings(self, master: Path) -> str:
        """JavaScript doesn't use remappings - return empty string."""
        return ""

    def infer_src_path(self, master: Path) -> Path:
        """
        Infer the source directory for a JavaScript project.

        Checks package.json and common patterns.
        """
        package_json = master / "package.json"
        if package_json.exists():
            try:
                data = json.loads(package_json.read_text())

                # Check main/source fields
                main = data.get("main", "")
                if main:
                    main_path = Path(main).parent
                    if (master / main_path).exists():
                        return master / main_path

                # Check source field
                source = data.get("source", "")
                if source:
                    source_path = Path(source).parent
                    if (master / source_path).exists():
                        return master / source_path

            except Exception:
                pass

        # Common JavaScript source patterns
        for src_dir in ["src", "lib", "app", "source"]:
            if (master / src_dir).is_dir():
                return master / src_dir

        return master

    def get_runtime_writable_paths(
        self, project_root: Path, master_context: MasterContext
    ) -> List[Path]:
        """
        JavaScript projects need node_modules, dist, and cache dirs writable.
        """
        writable = []
        for rel in ["node_modules", "dist", "build", ".cache", "coverage"]:
            path = project_root / rel
            writable.append(path)
        return writable

    def _detect_package_manager(self, workspace_path: Path) -> str:
        """Detect the package manager from lockfiles."""
        if (workspace_path / "pnpm-lock.yaml").exists():
            return "pnpm"
        if (workspace_path / "yarn.lock").exists():
            return "yarn"
        return "npm"

    def _copy_package_files(self, workspace: Path, master: Path) -> None:
        """Copy package.json and lockfiles."""
        package_files = [
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            ".npmrc",
            ".yarnrc",
            ".yarnrc.yml",
        ]

        for pkg_file in package_files:
            src = master / pkg_file
            if src.exists():
                shutil.copy2(src, workspace / pkg_file)

    def _setup_source_symlinks(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
    ) -> None:
        """Symlink/copy source directories from master to workspace."""
        # Source directories can be symlinked - they're imported by other code
        symlink_dirs = [
            "src", "lib", "app", "source", "components", "utils",
        ]

        # These directories must be COPIED, not symlinked, because:
        # - Node.js module resolution follows realpath, not symlink path
        # - Symlinked files would look for node_modules in master, not workspace
        # - dist/build contain executable code that imports dependencies
        # - test directories run code that imports dependencies
        copy_dirs = [
            "dist", "build",  # Build output that may import dependencies
            "test", "tests", "__tests__",  # Test directories
        ]

        for src_dir in symlink_dirs:
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
                    # Use symlinks=True to preserve symlinks (e.g., label symlinks in test suites)
                    shutil.copytree(master_dir, workspace_dir, symlinks=True, dirs_exist_ok=True)

        # Copy directories that contain executable code (for correct module resolution)
        for copy_dir in copy_dirs:
            master_dir = master / copy_dir
            workspace_dir = workspace / copy_dir

            if master_dir.exists() and master_dir.is_dir():
                # Use symlinks=True to preserve symlinks (e.g., label symlinks in test suites)
                # Use dirs_exist_ok=True in case the directory already exists
                shutil.copytree(master_dir, workspace_dir, symlinks=True, dirs_exist_ok=True)

    def _copy_config_files(self, workspace: Path, master: Path) -> None:
        """Copy JavaScript/TypeScript config files to workspace."""
        config_files = [
            "tsconfig.json",
            "jsconfig.json",
            "jest.config.js",
            "jest.config.ts",
            "vitest.config.js",
            "vitest.config.ts",
            ".babelrc",
            "babel.config.js",
            ".eslintrc",
            ".eslintrc.js",
            ".eslintrc.json",
            ".prettierrc",
            ".prettierrc.js",
            "webpack.config.js",
            "rollup.config.js",
            "vite.config.js",
            "vite.config.ts",
        ]

        for config_file in config_files:
            src = master / config_file
            if src.exists() and src.is_file():
                shutil.copy2(src, workspace / config_file)

        # Copy TypeScript declaration files from root (needed for tsd, type imports)
        for src in master.iterdir():
            if src.is_file() and (src.name.endswith(".d.ts") or src.name.endswith(".d.mts")):
                shutil.copy2(src, workspace / src.name)

    def _install_dependencies(
        self, workspace: Path, logger: Optional[Any] = None
    ) -> None:
        """Install dependencies using detected package manager."""
        if not (workspace / "package.json").exists():
            if logger:
                logger.debug("No package.json found - skipping dependency installation")
            return

        manager = self._detect_package_manager(workspace)
        manager_bin = shutil.which(manager)

        if not manager_bin:
            if logger:
                logger.warning(
                    f"{manager} not found - skipping dependency installation"
                )
            return

        try:
            subprocess.run(
                [manager_bin, "install"],
                cwd=str(workspace),
                capture_output=True,
                timeout=300,
            )
            if logger:
                logger.debug(f"Installed dependencies with {manager}")
        except subprocess.TimeoutExpired:
            if logger:
                logger.warning(f"{manager} install timed out")
        except Exception as e:
            if logger:
                logger.warning(f"Failed to install dependencies: {e}")

    def _run_build_if_needed(
        self, workspace: Path, logger: Optional[Any] = None
    ) -> None:
        """
        Run build step if dist/ doesn't exist but package.json has a build script.

        This handles TypeScript and other projects where dist/ is gitignored
        and must be generated before tests can run.
        """
        # Skip if dist/ already exists (pre-built or symlinked from master)
        if (workspace / "dist").exists():
            if logger:
                logger.debug("dist/ exists - skipping build step")
            return

        # Check if package.json has a build script
        package_json = workspace / "package.json"
        if not package_json.exists():
            return

        try:
            data = json.loads(package_json.read_text())
            scripts = data.get("scripts", {})

            if "build" not in scripts:
                if logger:
                    logger.debug("No build script in package.json - skipping build")
                return

        except Exception as e:
            if logger:
                logger.warning(f"Failed to parse package.json: {e}")
            return

        # Run the build
        manager = self._detect_package_manager(workspace)
        manager_bin = shutil.which(manager)

        if not manager_bin:
            if logger:
                logger.warning(f"{manager} not found - skipping build step")
            return

        try:
            if logger:
                logger.debug(f"Running {manager} run build...")

            result = subprocess.run(
                [manager_bin, "run", "build"],
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                if logger:
                    logger.debug("Build completed successfully")
            else:
                if logger:
                    logger.warning(
                        f"Build failed (exit {result.returncode}): {result.stderr[:500]}"
                    )

        except subprocess.TimeoutExpired:
            if logger:
                logger.warning("Build timed out after 300 seconds")
        except Exception as e:
            if logger:
                logger.warning(f"Build failed: {e}")

    def _copy_with_excludes(self, src: Path, dst: Path, excludes: set) -> None:
        """Copy directory tree excluding certain patterns."""

        def should_exclude(path: Path) -> bool:
            for exc in excludes:
                if path.name == exc:
                    return True
            return False

        dst.mkdir(parents=True, exist_ok=True)

        for item in src.iterdir():
            if should_exclude(item):
                continue

            dest_path = dst / item.name

            # Preserve symlinks (e.g., label symlinks in test suites)
            if item.is_symlink():
                # Copy the symlink itself, not its target
                linkto = os.readlink(item)
                dest_path.symlink_to(linkto)
            elif item.is_dir():
                if not item.name.startswith(".") or item.name in {".github", ".vscode"}:
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
