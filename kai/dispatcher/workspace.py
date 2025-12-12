"""
Workspace provisioning/cleanup for Dispatcher missions.

Extracted to keep `kai/dispatcher.py` small and focused.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from kai.schemas import MasterContext, Mission, WorkspacePreset


class WorkspaceManager:
    def __init__(self, *, workspace_dir: str, logger=None) -> None:
        self.workspace_dir = workspace_dir
        self.logger = logger

    async def provision(self, mission: Mission, master_context: MasterContext) -> str:
        """
        Provision a workspace for a mission based on preset.

        Presets:
        - CLEAN: copy essential dirs + configs
        - WRITEABLE: currently same as CLEAN (workspace is writeable either way)
        - SANDBOX: full project copy
        """
        master = Path(master_context.root_path)
        workspace_base = Path(self.workspace_dir)
        workspace = workspace_base / mission.mission_id

        if workspace.exists():
            shutil.rmtree(workspace)
        workspace.mkdir(parents=True, exist_ok=True)

        preset = mission.workspace_preset

        if preset == WorkspacePreset.SANDBOX:
            shutil.copytree(master, workspace, dirs_exist_ok=True)
            if self.logger:
                self.logger.debug(f"Provisioned SANDBOX workspace: {workspace}")
            return str(workspace)

        # Copy source directories (language-agnostic common patterns)
        for item in master.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                # Skip common non-source dirs
                if item.name in {
                    "node_modules",
                    "__pycache__",
                    "build",
                    "out",
                    "cache",
                    "artifacts",
                }:
                    continue
                shutil.copytree(item, workspace / item.name)

        # Copy all root-level config files (non-directories, non-hidden)
        for item in master.iterdir():
            if item.is_file() and not item.name.startswith("."):
                shutil.copy2(item, workspace / item.name)

        if self.logger:
            self.logger.debug(
                f"Provisioned {preset.value.upper()} workspace: {workspace}"
            )
        return str(workspace)

    async def cleanup(self, mission: Mission) -> None:
        workspace = Path(self.workspace_dir) / mission.mission_id
        if workspace.exists():
            try:
                shutil.rmtree(workspace)
                if self.logger:
                    self.logger.debug(f"Cleaned up workspace: {workspace}")
            except OSError as e:
                if self.logger:
                    self.logger.warning(f"Failed to cleanup workspace {workspace}: {e}")
