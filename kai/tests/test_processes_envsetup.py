import os
import shutil
from pathlib import Path

import pytest

from kai.agents import settings
from kai.processes.envsetup import EnvironmentSetupProcess
from kai.schemas import EnvironmentSetupInput, EnvironmentSetupOutput, MasterContext


MONAD_REPO_URL = "https://github.com/code-423n4/2025-09-monad.git"


@pytest.mark.asyncio
async def test_envsetup_process_integration(monkeypatch):
    api_key = settings.OPENROUTER_API_KEY or settings.OPENAI_API_KEY
    if not api_key:
        pytest.skip("Requires OPENROUTER_API_KEY or OPENAI_API_KEY for real setup run")

    repo_url = os.getenv("MONAD_REPO_URL", MONAD_REPO_URL)
    repo_path_override = os.getenv("MONAD_REPO_PATH")
    model_name = os.getenv("SETUP_MODEL", settings.SETUP_DEFAULT_MODEL)

    # Persist outputs under the repository testbed for inspection
    repo_root = Path(__file__).resolve().parents[2]
    testbed_root = repo_root / "testbed"
    testbed_root.mkdir(exist_ok=True)
    monkeypatch.setattr(
        EnvironmentSetupProcess, "_project_root", lambda self: repo_root
    )

    process = EnvironmentSetupProcess(
        MasterContext(root_path="/tmp", compile_success=True)
    )
    slug = process._repo_slug(repo_url)
    slug_root = testbed_root / slug
    inputs_dir = slug_root / "inputs"
    master_dir = slug_root / "master"

    # Clean previous run remnants
    if slug_root.exists():
        shutil.rmtree(slug_root)

    result = await process.execute(
        EnvironmentSetupInput(
            repo_url=repo_url,
            num_turns=int(os.getenv("SETUP_TURNS", settings.DEFAULT_TURNS)),
            model_name=model_name,
            use_openai=bool(
                settings.OPENAI_API_KEY and not settings.OPENROUTER_API_KEY
            ),
            repo_path_override=repo_path_override,
        )
    )

    assert isinstance(result, EnvironmentSetupOutput)
    assert result.success is True
    mc = result.master_context
    assert isinstance(mc, MasterContext)
    assert Path(result.master_repo_path).exists()
    assert Path(mc.root_path).resolve() == Path(result.master_repo_path).resolve()
    assert inputs_dir.exists()
    assert master_dir.exists()
    # Master should include at least all files from inputs (allow extra build artifacts)
    for root, _, files in os.walk(inputs_dir):
        rel_root = Path(root).relative_to(inputs_dir)
        for f in files:
            rel_file = rel_root / f
            assert (master_dir / rel_file).exists(), f"Missing in master: {rel_file}"
    # Master copy must be read-only
    assert not os.access(result.master_repo_path, os.W_OK)
