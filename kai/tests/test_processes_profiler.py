import json
from pathlib import Path

import pytest  # type: ignore[import-not-found]

from kai.processes.profiler import ProfilerProcess
from kai.schemas import (
    MasterContext,
    ProfilerInput,
)
from kai.agents import settings
from logger import logging
from logger.mongo_adapter import MongoDBHandler


@pytest.fixture
def anyio_backend():
    # Restrict anyio to asyncio backend to avoid requiring trio
    return "asyncio"


@pytest.fixture(autouse=True)
def disable_mongo_logging():
    """Remove MongoDBHandler during tests to avoid connection errors."""
    logger = logging.getLogger()
    removed = []
    for h in list(logger.handlers):
        if isinstance(h, MongoDBHandler):
            logger.removeHandler(h)
            removed.append(h)
    yield
    # no re-adding handlers after tests


def _load_bbp_master_context() -> MasterContext:
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "bbp_master_context.json"
    data = json.loads(fixture_path.read_text())
    return MasterContext(**data)


@pytest.mark.anyio
async def test_profiler_process_live_with_bbp_fixture():
    """
    Runs the real ProfilerProcess + ProfilerAgent using the Ethena BBP MasterContext fixture,
    the glm model from settings.MAIN_DEFAULT_MODEL, and the actual dependency graph builder.
    """
    mc = _load_bbp_master_context()

    process = ProfilerProcess(mc)
    result = await process.execute(
        ProfilerInput(
            master_context=mc,
            num_turns=16,
            model_name=settings.MAIN_DEFAULT_MODEL,
            use_openai=bool(settings.OPENAI_API_KEY and not settings.OPENROUTER_API_KEY),
        )
    )

    assert result.success is True
    assert result.protocol_manifesto is not None
    assert result.response is not None
    assert result.total_tokens.get("prompt_tokens", 0) > 0

