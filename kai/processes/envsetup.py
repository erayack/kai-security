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
    Clones the repository, builds it using SetupAgent, and prepares the MasterContext.
    """

    async def execute(
        self, input_data: EnvironmentSetupInput
    ) -> EnvironmentSetupOutput:
        # Derive the slug from the actual source we will use. If the caller
        # provides a materialized repo_path_override, prefer that for slugging
        # so we don't accidentally reuse a slug from an old URL (which can lead
        # to copying the wrong repository into the master workspace).
        repo_url = input_data.repo_url
        slug_source = input_data.repo_path_override or repo_url
        repo_slug = self._repo_slug(slug_source)
        inputs_root = self._inputs_root(repo_slug)
        master_root = self._master_root(repo_slug)

        inputs_repo_path = (
            Path(input_data.repo_path_override)
            if input_data.repo_path_override
            else inputs_root
        )
        master_repo_path = master_root

        if input_data.repo_path_override:
            if not inputs_repo_path.exists():
                raise FileNotFoundError(
                    f"Materialized repo not found at {input_data.repo_path_override}"
                )
        else:
            self._clone_repo(repo_url, inputs_repo_path)

        self._copy_to_master(inputs_repo_path, master_repo_path)

        agent = SetupAgent(
            repo_path=str(master_repo_path),
            model=input_data.model_name,
            max_tool_turns=input_data.num_turns,
            use_openai=input_data.use_openai,
            execution_id=input_data.execution_id,
        )

        response: Optional[AgentResponse] = None
        exception_occurred = False
        exception_msg = ""
        prefix = "setup"

        try:
            self.logger.info("Starting SetupAgent chat...")
            response = await agent.chat("You must start setting up the repository now")

            # If the agent terminated without emitting a MasterContext, ask it to
            # output the MasterContext JSON in a <done> block (no more tools).
            if response is not None and response.master_context is None:
                prefix = "setup_retry"
                retry_prompt = (
                    "FORMAT REQUIREMENT: You must finish by outputting a <done>{...}</done> block.\n"
                    "The JSON inside <done> must be a valid MasterContext.\n"
                    "Do NOT run any more tools. Only output <think> and a final <done>.\n"
                )
                response = await agent.chat(retry_prompt)
        except Exception as e:
            self.logger.error(f"SetupAgent failed: {e}", exc_info=True)
            exception_occurred = True
            exception_msg = str(e)
            prefix = "error_setup"
        finally:
            try:
                await agent.close()
            except Exception:
                pass

        # Save conversation under output/<repo_slug>
        save_folder = self._project_root() / "output" / repo_slug
        agent.save_conversation(save_folder=str(save_folder), prefix=prefix)

        master_context = response.master_context if response else None
        if master_context:
            master_context = self._normalize_master_context_paths(
                master_context, master_repo_path
            )

        # Mark master as read-only to enforce golden master contract
        try:
            self._make_read_only(master_repo_path)
        except Exception:
            pass

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
            master_repo_path=str(master_repo_path),
            repo_slug=repo_slug,
        )

    def _project_root(self) -> Path:
        return Path(__file__).resolve().parent.parent.parent

    def _inputs_root(self, repo_slug: str) -> Path:
        path = self._project_root() / "testbed" / repo_slug / "inputs"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _master_root(self, repo_slug: str) -> Path:
        path = self._project_root() / "testbed" / repo_slug / "master"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _get_repo_commit_hash(self, repo_url: str) -> Optional[str]:
        # Simple cache could be added as instance variable if needed, but not critical for process
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
        name = Path(re.sub(r"\\.git$", "", repo_url.split("/")[-1])).stem or "repo"
        short_hash = self._get_repo_commit_hash(repo_url) or "unknown"
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "-", name)
        return f"{safe_name}-{short_hash}"

    def _clone_repo(self, repo_url: str, dest: Path) -> Path:
        if dest.exists():
            shutil.rmtree(dest)
        subprocess.run(["git", "clone", repo_url, str(dest)], check=True)
        return dest

    def _copy_to_master(self, inputs_path: Path, master_path: Path) -> Path:
        if master_path.exists():
            shutil.rmtree(master_path)
        shutil.copytree(inputs_path, master_path)
        return master_path

    def _make_read_only(self, path: Path) -> None:
        try:
            path.chmod(path.stat().st_mode & ~0o222)
        except Exception:
            pass
        for root, dirs, files in os.walk(path):
            for d in dirs:
                dir_path = Path(root) / d
                dir_path.chmod(dir_path.stat().st_mode & ~0o222)
            for f in files:
                file_path = Path(root) / f
                try:
                    file_path.chmod(file_path.stat().st_mode & ~0o222)
                except PermissionError:
                    pass

    def _normalize_master_context_paths(
        self, master_context: MasterContext, master_repo_path: Path
    ) -> MasterContext:
        def _normalize_path(value: Optional[str]) -> str:
            if not value or value in (".", "./"):
                return str(master_repo_path)
            p = Path(value)
            if p.is_absolute():
                return str(p)
            return str(master_repo_path / p)

        master_context.root_path = _normalize_path(master_context.root_path)
        master_context.artifacts_path = _normalize_path(master_context.artifacts_path)
        master_context.src_path = _normalize_path(master_context.src_path)
        master_context.lib_path = _normalize_path(master_context.lib_path)
        master_context.test_path = _normalize_path(master_context.test_path)
        return master_context
