
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from kai.processes.envsetup import EnvironmentSetupProcess
from kai.schemas import (
    EnvironmentSetupInput,
    EnvironmentSetupOutput,
    MasterContext,
    AgentResponse,
)

@pytest.fixture
def mock_setup_agent():
    with patch("kai.processes.envsetup.SetupAgent") as MockAgent:
        agent_instance = MockAgent.return_value
        # Mock chat method
        agent_response = AgentResponse(
            thoughts="Mock setup thoughts",
            master_context=MasterContext(
                root_path=".",
                compile_success=True,
                src_path="src",
                test_path="test"
            )
        )
        agent_instance.chat = AsyncMock(return_value=agent_response)
        agent_instance.close = AsyncMock()
        agent_instance.save_conversation = MagicMock()
        agent_instance.estimated_cost = 0.01
        agent_instance.total_tokens = {"prompt_tokens": 100, "completion_tokens": 50}
        yield MockAgent

@pytest.fixture
def process():
    # Setup a dummy MasterContext for the process init (though mostly unused by this process)
    context = MasterContext(root_path="/tmp", compile_success=True)
    return EnvironmentSetupProcess(context)

import asyncio

def test_envsetup_execution_success(process, mock_setup_agent, tmp_path):
    # Mock file system operations to avoid actual git clones
    with patch("kai.processes.envsetup.EnvironmentSetupProcess._clone_repo") as mock_clone, \
         patch("kai.processes.envsetup.EnvironmentSetupProcess._copy_to_master") as mock_copy, \
         patch("kai.processes.envsetup.EnvironmentSetupProcess._make_read_only") as mock_readonly, \
         patch("kai.processes.envsetup.EnvironmentSetupProcess._repo_slug", return_value="mock-repo-slug"), \
         patch("kai.processes.envsetup.EnvironmentSetupProcess._inputs_root", return_value=tmp_path / "inputs"), \
         patch("kai.processes.envsetup.EnvironmentSetupProcess._master_root", return_value=tmp_path / "master"), \
         patch("kai.processes.envsetup.EnvironmentSetupProcess._project_root", return_value=tmp_path):

        input_data = EnvironmentSetupInput(
            repo_url="https://github.com/example/repo",
            num_turns=5,
            model_name="mock-model",
            use_openai=False
        )
        
        async def run_test():
             return await process.execute(input_data)
        
        output = asyncio.run(run_test())
        
        assert isinstance(output, EnvironmentSetupOutput)
        assert output.success is True
        assert output.repo_slug == "mock-repo-slug"
        assert output.master_context.root_path == str(tmp_path / "master")
        
        # Verify calls
        mock_clone.assert_called_once()
        mock_copy.assert_called_once()
        mock_setup_agent.return_value.chat.assert_called_once()
