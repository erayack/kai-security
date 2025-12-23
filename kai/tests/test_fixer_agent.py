import json
import shutil
import sys
from pathlib import Path

import pytest  # type: ignore[import-not-found]

from kai.agents import settings
from kai.agents.agent_types.fixer_agent import FixerAgent
from kai.schemas import FixerInput, WorkspacePreset
from kai.tests.test_processes_profiler import _normalize_master_context_paths
from kai.utils.dependency import DependencyGraph
from kai.utils.workspace import get_workspace_adapter
from logger import logging
from logger.mongo_adapter import MongoDBHandler


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def disable_mongo_logging():
    logger = logging.getLogger()
    for h in list(logger.handlers):
        if isinstance(h, MongoDBHandler):
            logger.removeHandler(h)
    yield


def _load_fixer_input_fixture() -> FixerInput:
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    payload = json.loads((fixtures_dir / "fixer_input_bbp.json").read_text())
    return FixerInput(**payload)


@pytest.mark.anyio
async def test_fixer_agent_runs_and_registers_fix_on_bbp(tmp_path: Path):
    """
    Real (non-mock) FixerAgent test:
    - Loads FixerInput fixture for the Ethena BBP repo
    - Provisions a writable Foundry workspace (copy of master)
    - Runs FixerAgent via chat_with_tools (LLM + tool calling)
    - Asserts register_fix was called (agent produced a fix)
    """
    fx = _load_fixer_input_fixture()
    assert fx.master_context is not None

    project_root = Path(__file__).resolve().parents[2]
    mc = _normalize_master_context_paths(fx.master_context, project_root)

    master_root = Path(mc.root_path)
    if not master_root.exists():
        pytest.skip(
            f"MasterContext root_path not found at {master_root}. "
            "Materialize the testbed (envsetup) before running this test."
        )

    api_key = settings.OPENROUTER_API_KEY or settings.OPENAI_API_KEY
    if not api_key:
        pytest.skip("Requires OPENROUTER_API_KEY or OPENAI_API_KEY to run FixerAgent")

    if shutil.which("forge") is None:
        pytest.skip("Requires Foundry forge installed to run FixerAgent validation")

    # Provision a writable workspace copy so the agent can apply diffs safely
    ws = tmp_path / "fixer_ws"
    ws.mkdir(parents=True, exist_ok=True)
    adapter = get_workspace_adapter("foundry")
    workspace_path = adapter.provision_full(
        workspace=ws,
        master=master_root,
        master_context=mc,
        preset=WorkspacePreset.WRITEABLE,
    )

    # Load dependency graph fixture (cached BBP graph used in other tests)
    graph_json = Path(__file__).resolve().parent / "fixtures" / "dependency_graph.json"
    if not graph_json.exists():
        pytest.skip(f"Dependency graph fixture missing at {graph_json}")
    graph = DependencyGraph.from_json(graph_json)

    # Decide whether to use OpenAI direct or OpenRouter (OpenAI-compatible)
    use_openai = bool(settings.OPENAI_API_KEY and not settings.OPENROUTER_API_KEY)

    agent = FixerAgent(
        exploit_candidate=fx.exploit_candidate,
        verdict=fx.verdict,
        master_context=mc,
        dependency_graph=graph,
        repo_path=workspace_path,
        scope_paths=[workspace_path],
        model=fx.model_name,
        use_openai=use_openai,
        max_tool_turns=24,
    )
    agent.workspace_path = workspace_path
    agent.framework = "foundry"
    user_prompt = "Start your work."

    try:
        await agent.chat_with_tools(user_prompt)

        fixes = getattr(agent, "_registered_fixes", []) or []
        assert fixes, "Expected FixerAgent to call register_fix at least once"

        latest = fixes[-1]
        assert "canonical_diff" in latest and latest["canonical_diff"]
        # Sanity: canonical unified diff should look like a diff.
        assert "---" in latest["canonical_diff"] or "@@" in latest["canonical_diff"]
    finally:
        # Persist conversation for debugging even when assertions fail.
        try:
            convo_path = agent.save_conversation("conversations/fixer_convo.json")
            print(
                f"[fixer_test] fixer conversation saved at: {convo_path}",
                file=sys.stderr,
            )
            print(f"[fixer_test] exists={Path(convo_path).exists()}", file=sys.stderr)
        except Exception as e:
            print(
                f"[fixer_test] failed to save fixer conversation: {e}", file=sys.stderr
            )
        await agent.close()
