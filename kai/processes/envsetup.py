import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from kai.agents.agent_types import SetupAgent
from kai.processes.base import BaseProcess
from kai.schemas import (
    AgentResponse,
    EnvironmentSetupInput,
    EnvironmentSetupOutput,
    MasterContext,
)


class EnvironmentSetupProcess(
    BaseProcess[EnvironmentSetupInput, EnvironmentSetupOutput]
):
    """
    Process to setup the target environment for Kai.

    If a local repo path is provided, uses it directly (no copy).
    If a URL is provided, clones to testbed/.
    Runs SetupAgent to detect framework and compile.
    """

    async def execute(
        self, input_data: EnvironmentSetupInput
    ) -> EnvironmentSetupOutput:
        repo_url = input_data.repo_url

        # Determine the repo path to use
        if input_data.repo_path_override:
            # Local path provided - use directly, no copy
            repo_path = Path(input_data.repo_path_override).resolve()
            if not repo_path.exists():
                raise FileNotFoundError(
                    f"Repository not found at {input_data.repo_path_override}"
                )
            repo_slug = self._repo_slug(str(repo_path))
        else:
            # URL provided - clone to testbed
            repo_slug = self._repo_slug(repo_url)
            clone_dest = self._clone_root(repo_slug)
            repo_path = self._clone_repo(repo_url, clone_dest)

        # Run SetupAgent on the repo (directly, no intermediate copy)
        agent = SetupAgent(
            repo_path=str(repo_path),
            model=input_data.model_name,
            max_tool_turns=input_data.num_turns,
            use_openai=input_data.use_openai,
            execution_id=input_data.execution_id,
        )

        response: Optional[AgentResponse] = None
        exception_occurred = False
        exception_msg = ""

        try:
            self.logger.info("Starting SetupAgent (native tool-calling)...")
            response = await agent.chat_with_tools(
                "You must start setting up the repository now."
            )

            # If the agent terminated without registering a MasterContext, nudge it.
            if response is not None and response.master_context is None:
                retry_prompt = (
                    "FORMAT REQUIREMENT: You must call register_master_context({...}) "
                    "with the final build information. Call it now to finish."
                )
                response = await agent.chat_with_tools(retry_prompt)
        except Exception as e:
            self.logger.error(f"SetupAgent failed: {e}", exc_info=True)
            exception_occurred = True
            exception_msg = str(e)
        finally:
            try:
                await agent.close()
            except Exception:
                pass

        master_context = response.master_context if response else None
        if master_context:
            master_context = self._normalize_master_context_paths(
                master_context, repo_path
            )

        setup_successful = (
            not exception_occurred
            and response is not None
            and response.master_context is not None
        )

        if not setup_successful and not exception_msg:
            exception_msg = "Setup agent did not produce a MasterContext"

        return EnvironmentSetupOutput(
            response=response,
            master_context=master_context,
            estimated_cost=agent.estimated_cost,
            total_tokens=agent.total_tokens,
            success=setup_successful,
            error_message=exception_msg if not setup_successful else None,
            master_repo_path=str(repo_path),
            repo_slug=repo_slug,
        )

    def _project_root(self) -> Path:
        return Path(__file__).resolve().parent.parent.parent

    def _clone_root(self, repo_slug: str) -> Path:
        """Directory where cloned repos are stored."""
        path = self._project_root() / "testbed" / repo_slug
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _get_repo_commit_hash(self, repo_url: str) -> Optional[str]:
        """Get short commit hash from repo URL or local path."""
        commit_hash = None
        is_local_repo = os.path.isdir(repo_url)
        command = (
            ["git", "-C", repo_url, "rev-parse", "HEAD"]
            if is_local_repo
            else ["git", "ls-remote", repo_url, "HEAD"]
        )

        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            if output:
                commit_hash = output if is_local_repo else output.split()[0]
        except Exception:
            commit_hash = None

        if commit_hash:
            commit_hash = commit_hash[:8]

        return commit_hash

    def _repo_slug(self, repo_url: str) -> str:
        """Generate a slug for the repo (name-hash)."""
        name = Path(re.sub(r"\\.git$", "", repo_url.split("/")[-1])).stem or "repo"
        short_hash = self._get_repo_commit_hash(repo_url) or "unknown"
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "-", name)
        return f"{safe_name}-{short_hash}"

    def _clone_repo(self, repo_url: str, dest: Path) -> Path:
        """Clone a repo from URL. Removes existing if present."""
        if dest.exists():
            shutil.rmtree(dest)
        subprocess.run(["git", "clone", repo_url, str(dest)], check=True)
        return dest

    def _normalize_master_context_paths(
        self, master_context: MasterContext, repo_path: Path
    ) -> MasterContext:
        """Normalize relative paths in MasterContext to absolute paths."""

        def _normalize_path(value: Optional[str]) -> str:
            if not value or value in (".", "./"):
                return str(repo_path)
            p = Path(value)
            if p.is_absolute():
                return str(p)
            return str(repo_path / p)

        master_context.root_path = _normalize_path(master_context.root_path)
        master_context.artifacts_path = _normalize_path(master_context.artifacts_path)
        master_context.src_path = _normalize_path(master_context.src_path)
        master_context.lib_path = _normalize_path(master_context.lib_path)
        master_context.test_path = _normalize_path(master_context.test_path)
        return master_context
