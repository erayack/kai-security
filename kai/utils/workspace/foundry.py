"""
Foundry workspace adapter.

Handles Foundry-specific workspace provisioning including:
- foundry.toml generation
- Remappings detection and adjustment
- forge-std and OpenZeppelin path handling
"""

import os
import shutil
from pathlib import Path
from typing import Optional, Any

from kai.schemas import MasterContext, WorkspacePreset
from kai.utils.workspace.base import WorkspaceAdapter


class FoundryWorkspaceAdapter(WorkspaceAdapter):
    """Workspace adapter for Foundry/Forge projects."""

    @property
    def framework_name(self) -> str:
        return "foundry"

    def provision_lightweight(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
        logger: Optional[Any] = None,
    ) -> str:
        """
        Create a lightweight forge workspace with remappings to the parent repo.

        This doesn't copy files - just creates a minimal forge project that
        references the original contracts via remappings. Ideal for PoC tests.
        """
        # Create directory structure
        (workspace / "test").mkdir(exist_ok=True)
        (workspace / "src").mkdir(exist_ok=True)

        # Detect remappings from parent project
        remappings = self.detect_remappings(master)

        # Symlink to parent's lib folder for dependencies
        self._setup_lib_symlink(workspace, master)

        # Symlink to parent's contracts/src folder for source access
        self._setup_contracts_symlink(workspace, master, master_context)

        # Create foundry.toml
        self._write_foundry_config(workspace, master, master_context, remappings)

        if logger:
            logger.debug(f"Provisioned LIGHTWEIGHT Foundry workspace: {workspace}")

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
        if preset == WorkspacePreset.SANDBOX:
            shutil.copytree(master, workspace, dirs_exist_ok=True)
            if logger:
                logger.debug(f"Provisioned SANDBOX Foundry workspace: {workspace}")
            return str(workspace)

        # CLEAN/WRITEABLE - copy essential dirs
        skip_dirs = {
            "node_modules",
            "__pycache__",
            "build",
            "out",
            "cache",
            "artifacts",
        }

        for item in master.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                if item.name not in skip_dirs:
                    shutil.copytree(item, workspace / item.name)

        # Copy all root-level config files
        for item in master.iterdir():
            if item.is_file() and not item.name.startswith("."):
                shutil.copy2(item, workspace / item.name)

        if logger:
            logger.debug(
                f"Provisioned {preset.value.upper()} Foundry workspace: {workspace}"
            )
        return str(workspace)

    def detect_remappings(self, master: Path) -> str:
        """
        Detect and generate remappings for the lightweight workspace.

        Reads existing remappings from foundry.toml or remappings.txt,
        and adjusts paths to point to parent directory.
        """
        remappings = []

        # Add standard remappings using the contracts symlink we create
        remappings.append('    "contracts/=contracts/"')
        remappings.append('    "src/=contracts/"')

        # Check for existing remappings.txt
        remappings_file = master / "remappings.txt"
        if remappings_file.exists():
            for line in remappings_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    # If value is a relative path, prefix with ../
                    # EXCEPT for lib/ paths - we have a lib symlink in the workspace
                    if not value.startswith("/") and not value.startswith(".."):
                        if not value.startswith("lib/"):
                            value = f"../{value}"
                    remappings.append(f'    "{key}={value}"')

        # Common dependency patterns (use lib/ symlink, not ../lib/)
        lib_path = master / "lib"
        if (lib_path / "openzeppelin-contracts").exists():
            remappings.append('    "@openzeppelin/=lib/openzeppelin-contracts/"')
        if (lib_path / "forge-std").exists():
            remappings.append('    "forge-std/=lib/forge-std/src/"')

        return ",\n".join(remappings)

    def infer_src_path(self, master: Path) -> Path:
        """
        Infer the source directory for a Foundry project.

        Foundry projects typically use:
        - contracts/ (common in monorepos)
        - src/ (default Foundry convention)
        """
        # Check if this is a Foundry project with existing remappings
        if (master / "contracts").exists() and (master / "remappings.txt").exists():
            return master
        if (master / "contracts").exists():
            return master / "contracts"
        if (master / "src").exists():
            return master / "src"
        return master

    def _setup_lib_symlink(self, workspace: Path, master: Path) -> None:
        """Symlink to parent's lib folder for dependencies."""
        lib_link = workspace / "lib"
        parent_lib = master / "lib"

        if parent_lib.exists() and not lib_link.exists():
            try:
                rel_path = os.path.relpath(parent_lib, workspace)
                lib_link.symlink_to(rel_path)
            except OSError:
                # Symlink might fail on Windows, copy instead
                shutil.copytree(parent_lib, lib_link)

    def _setup_contracts_symlink(
        self, workspace: Path, master: Path, master_context: MasterContext
    ) -> None:
        """Symlink to parent's contracts/src folder for source access."""
        src_dir = master_context.src_path or str(master / "contracts")
        src_path = Path(src_dir) if Path(src_dir).is_absolute() else master / src_dir

        if src_path.exists():
            contracts_link = workspace / "contracts"
            if not contracts_link.exists():
                try:
                    rel_path = os.path.relpath(src_path, workspace)
                    contracts_link.symlink_to(rel_path)
                except OSError:
                    pass  # Skip symlink if it fails

    def _write_foundry_config(
        self,
        workspace: Path,
        master: Path,
        master_context: MasterContext,
        remappings: str,
    ) -> None:
        """Write foundry.toml with proper fs_permissions."""
        # Build fs_permissions for read access to master paths
        # Foundry resolves symlinks to their real paths, so we must include
        # the *resolved* master paths
        fs_perm_paths = {str((workspace / "..").resolve())}

        try:
            fs_perm_paths.add(str(master.resolve()))
        except Exception:
            fs_perm_paths.add(str(master))

        parent_lib = master / "lib"
        if parent_lib.exists():
            try:
                fs_perm_paths.add(str(parent_lib.resolve()))
            except Exception:
                fs_perm_paths.add(str(parent_lib))

        src_dir = master_context.src_path or str(master / "contracts")
        src_path = Path(src_dir) if Path(src_dir).is_absolute() else master / src_dir
        if src_path.exists():
            try:
                fs_perm_paths.add(str(src_path.resolve()))
            except Exception:
                fs_perm_paths.add(str(src_path))

        fs_permissions = ",\n".join(
            f'{{ access = "read", path = "{p}" }}' for p in sorted(fs_perm_paths)
        )

        foundry_config = f"""[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib"]

# Remappings to access master sources
remappings = [
{remappings}
]

# Read-only access to master sources (and their resolved targets)
fs_permissions = [
{fs_permissions}
]
"""
        (workspace / "foundry.toml").write_text(foundry_config)
