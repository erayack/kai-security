"""
Tools for the BlackboxAgent to run campaigns, record observations, and
record observations.
"""

import json
import os
import re
import shutil
from typing import Optional, Union, Dict, Any, List

from kai.agents.tools.tools import (
    read_file,
    list_files,
    grep,
    dependency_graph_resolve,
    dependency_graph_loc,
    dependency_graph_snippet,
    dependency_graph_neighbors,
    dependency_graph_public_entrypoints,
    dependency_graph_protocol_entrypoints,
    dependency_graph_slice,
    dependency_graph_explain,
    forge_test,
    _get_current_agent,
)
from kai.schemas import Observation


def _ensure_agent():
    agent = _get_current_agent()
    if agent is None:
        raise RuntimeError("Blackbox tools require an active agent context.")
    return agent


def write_campaign_file(file_path: str, content: str) -> str:
    """
    Write a campaign artifact under the agent's external campaign directory.

    The file is placed inside <campaigns_dir>/campaigns/ to avoid mutating the target repo.
    """
    agent = _ensure_agent()
    base_dir = getattr(agent, "campaigns_dir", None)
    if not base_dir:
        raise RuntimeError(
            "Blackbox agent campaigns_dir is not set. This should be attached by BlackboxProcess."
        )
    campaign_root = os.path.join(base_dir, "campaigns")
    os.makedirs(campaign_root, exist_ok=True)

    # Normalize path to stay under campaign_root
    relative = file_path.lstrip("/\\")
    # Be forgiving: the prompt historically told agents to include "campaigns/".
    # If the agent provides it, strip it to avoid campaigns/campaigns nesting.
    if relative == "campaigns":
        relative = ""
    else:
        relative = re.sub(r"^campaigns[\\/]+", "", relative)
    abs_path = os.path.abspath(os.path.join(campaign_root, relative))

    if not abs_path.startswith(os.path.abspath(campaign_root)):
        raise ValueError("Campaign file path must stay within campaigns/")

    with open(abs_path, "w") as f:
        f.write(content)

    return abs_path


def run_forge_campaign(
    test_file: str,
    seed: Optional[int] = None,
    match_contract: Optional[str] = None,
    match_test: Optional[str] = None,
    additional_args: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run a forge test focused on a campaign harness.

    Adds --fuzz-seed when provided and runs inside the agent's working dir.
    """
    agent = _ensure_agent()
    extra = additional_args or ""
    if seed is not None:
        seed_flag = f"--fuzz-seed {seed}"
        extra = f"{extra} {seed_flag}".strip()

    # Campaign harnesses are written to an external campaigns_dir.
    campaigns_dir = getattr(agent, "campaigns_dir", None)
    if not campaigns_dir:
        raise RuntimeError(
            "Blackbox agent campaigns_dir is not set. This should be attached by BlackboxProcess."
        )
    external_campaign_root = os.path.join(campaigns_dir, "campaigns")

    # Resolve the harness path under external_campaign_root.
    relative = test_file.lstrip("/\\")
    if relative == "campaigns":
        relative = ""
    else:
        relative = re.sub(r"^campaigns[\\/]+", "", relative)
    if relative and ("/" not in relative and "\\" not in relative):
        relative = relative  # bare filename under external campaigns root

    external_harness_path = os.path.abspath(
        os.path.join(external_campaign_root, relative)
    )
    if not external_harness_path.startswith(os.path.abspath(external_campaign_root)):
        raise ValueError(
            "Campaign test path must stay within external campaigns/ directory"
        )
    if not os.path.exists(external_harness_path):
        return {
            "error": "campaign_harness_missing",
            "path": external_harness_path,
            "returncode": -1,
        }

    # Run forge from the target repo (workspace), never from external campaigns dir.
    repo_root = getattr(agent, "repo_path", None) or getattr(agent, "working_dir", None)
    if not repo_root:
        repo_root = os.getcwd()

    # First attempt: try matching by absolute path (preferred; avoids writing to repo).
    result = forge_test(
        test_script_path=external_harness_path,
        working_dir=repo_root,
        match_contract=match_contract,
        match_test=match_test,
        additional_args=extra or None,
        output_json=True,
    )

    # If forge can't discover/compile a test from an external absolute path, fallback:
    # temporarily copy the harness into the repo's Foundry test directory and run there, then clean up.
    try:
        returncode = int(result.get("returncode", 0)) if isinstance(result, dict) else 0
    except Exception:
        returncode = 0
    if returncode == 0:
        return result

    def _detect_foundry_test_dir(repo_root_path: str) -> str:
        """
        Best-effort parse of foundry.toml to find the configured test directory.

        Defaults to 'test' if not found.
        """
        try:
            toml_path = os.path.join(repo_root_path, "foundry.toml")
            if not os.path.exists(toml_path):
                return "test"
            content = ""
            with open(toml_path, "r") as f:
                content = f.read()
            # naive parse: look for a line like: test = "campaigns" or test = 'test/foundry'
            m = re.search(
                r"^\s*test\s*=\s*['\"](.*?)['\"]\s*$",
                content,
                flags=re.MULTILINE,
            )
            if not m:
                return "test"
            val = (m.group(1) or "").strip()
            if not val:
                return "test"
            # normalize to a relative directory name
            val = val.strip("/\\")
            if os.path.isabs(val) or ".." in val.split("/"):
                return "test"
            return val
        except Exception:
            return "test"

    test_dir = _detect_foundry_test_dir(repo_root)
    repo_test_dir = os.path.join(repo_root, test_dir)
    os.makedirs(repo_test_dir, exist_ok=True)
    tmp_path = os.path.join(repo_test_dir, os.path.basename(external_harness_path))
    try:
        shutil.copyfile(external_harness_path, tmp_path)
        rel_match = os.path.join(test_dir, os.path.basename(tmp_path))
        result2 = forge_test(
            test_script_path=rel_match,
            working_dir=repo_root,
            match_contract=match_contract,
            match_test=match_test,
            additional_args=extra or None,
            output_json=True,
        )
        return result2
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def add_observation(
    description: str,
    affected_functions: List[str],
    affected_files: List[str],
    logs: List[str],
    anomaly_type: Optional[str] = None,
    repro_command: Optional[str] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Record an observation of anomalous behavior.

    Args:
        description: What you observed.
        affected_functions: Function names or IDs involved.
        affected_files: File paths involved.
        logs: Evidence such as test output or error messages.
        anomaly_type: Optional category, e.g., "always_reverts".
    """
    agent = _ensure_agent()

    mission_id = getattr(agent, "execution_id", None) or agent.agent_id

    obs = Observation(
        worker_id=agent.agent_id,
        mission_id=mission_id,
        description=description,
        affected_functions=affected_functions,
        affected_files=affected_files,
        logs=logs,
        anomaly_type=anomaly_type,
        repro_command=repro_command,
        seed=seed,
    )

    bucket = getattr(agent, "blackbox_observations", None)
    if bucket is None:
        bucket = []
        setattr(agent, "blackbox_observations", bucket)
    bucket.append(obs)

    return {
        "status": "observation_added",
        "observation_id": len(bucket),
        "total_observations": len(bucket),
    }


__all__ = [
    "read_file",
    "list_files",
    "grep",
    "dependency_graph_resolve",
    "dependency_graph_loc",
    "dependency_graph_snippet",
    "dependency_graph_neighbors",
    "dependency_graph_public_entrypoints",
    "dependency_graph_protocol_entrypoints",
    "dependency_graph_slice",
    "dependency_graph_explain",
    "write_campaign_file",
    "run_forge_campaign",
    "add_observation",
]
