"""
Workspace provisioning/cleanup for Dispatcher missions.

Framework-agnostic orchestration layer that delegates to workspace adapters.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from kai.schemas import MasterContext, Mission, WorkspacePreset
from kai.utils.workspace import get_workspace_adapter, WorkspaceAdapter


class WorkspaceManager:
    """
    Manages workspace provisioning and cleanup for missions.

    Delegates framework-specific logic to WorkspaceAdapters.
    """

    def __init__(self, *, workspace_dir: str, logger=None) -> None:
        self.workspace_dir = workspace_dir
        self.logger = logger
        self._adapters: dict[str, WorkspaceAdapter] = {}

    def _get_adapter(self, framework: str) -> WorkspaceAdapter:
        """Get or create adapter for framework."""
        if framework not in self._adapters:
            self._adapters[framework] = get_workspace_adapter(framework)
        return self._adapters[framework]

    def _detect_framework(
        self, master: Path, master_context: Optional[MasterContext] = None
    ) -> str:
        """
        Detect the framework from master_context or by inspecting the repo.

        Args:
            master: Path to the master repository
            master_context: Optional MasterContext with framework info

        Returns:
            Framework name (defaults to "foundry" if not detected)
        """
        # Check MasterContext first
        if master_context and master_context.frameworks:
            # Return first framework (primary)
            return master_context.frameworks[0].lower()

        # Detect by config files
        if (master / "foundry.toml").exists():
            return "foundry"
        if (master / "hardhat.config.js").exists() or (
            master / "hardhat.config.ts"
        ).exists():
            return "hardhat"
        if (master / "truffle-config.js").exists():
            return "truffle"

        # Default to foundry for Solidity projects
        return "foundry"

    async def provision(self, mission: Mission, master_context: MasterContext) -> str:
        """
        Provision a workspace for a mission based on preset.

        Presets:
        - CLEAN: copy essential dirs + configs
        - WRITEABLE: currently same as CLEAN (workspace is writeable either way)
        - SANDBOX: full project copy
        - LIGHTWEIGHT: minimal project with remappings (no file copy)
        """
        master = Path(master_context.root_path)
        workspace_base = Path(self.workspace_dir)
        workspace = workspace_base / mission.mission_id

        if workspace.exists():
            shutil.rmtree(workspace)
        workspace.mkdir(parents=True, exist_ok=True)

        preset = mission.workspace_preset
        framework = self._detect_framework(master, master_context)
        adapter = self._get_adapter(framework)

        if preset == WorkspacePreset.LIGHTWEIGHT:
            return adapter.provision_lightweight(
                workspace, master, master_context, self.logger
            )

        return adapter.provision_full(
            workspace, master, master_context, preset, self.logger
        )

    def provision_sync(
        self,
        workspace_id: str,
        master_path: str,
        preset: WorkspacePreset = WorkspacePreset.LIGHTWEIGHT,
        master_context: Optional[MasterContext] = None,
    ) -> str:
        """
        Synchronous workspace provisioning for standalone use (e.g., playgrounds).

        Args:
            workspace_id: Unique identifier for the workspace
            master_path: Path to the master/source repository
            preset: Workspace preset to use
            master_context: Optional MasterContext (will be inferred if not provided)

        Returns:
            Path to the provisioned workspace
        """
        master = Path(master_path)
        workspace_base = Path(self.workspace_dir)
        workspace = workspace_base / workspace_id

        if workspace.exists():
            shutil.rmtree(workspace)
        workspace.mkdir(parents=True, exist_ok=True)

        # Detect framework
        framework = self._detect_framework(master, master_context)
        adapter = self._get_adapter(framework)

        # Create MasterContext if not provided
        if master_context is None:
            src_path = adapter.infer_src_path(master)
            master_context = MasterContext(
                root_path=str(master),
                compile_success=True,
                src_path=str(src_path),
                frameworks=[framework],
            )

        if preset == WorkspacePreset.LIGHTWEIGHT:
            return adapter.provision_lightweight(
                workspace, master, master_context, self.logger
            )

        return adapter.provision_full(
            workspace, master, master_context, preset, self.logger
        )

    async def cleanup(self, mission: Mission) -> None:
        """Clean up a mission's workspace."""
        workspace = Path(self.workspace_dir) / mission.mission_id
        if workspace.exists():
            try:
                shutil.rmtree(workspace)
                if self.logger:
                    self.logger.debug(f"Cleaned up workspace: {workspace}")
            except OSError as e:
                if self.logger:
                    self.logger.warning(f"Failed to cleanup workspace {workspace}: {e}")

    def cleanup_sync(self, workspace_id: str) -> None:
        """Synchronous cleanup for standalone use."""
        workspace = Path(self.workspace_dir) / workspace_id
        if workspace.exists():
            try:
                shutil.rmtree(workspace)
                if self.logger:
                    self.logger.debug(f"Cleaned up workspace: {workspace}")
            except OSError as e:
                if self.logger:
                    self.logger.warning(f"Failed to cleanup workspace {workspace}: {e}")
