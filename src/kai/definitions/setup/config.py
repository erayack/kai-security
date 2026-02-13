"""Setup agent configuration."""

from __future__ import annotations

from ra.agents.config import RecursiveAgentConfig

from kai.definitions.setup.prompt import SYSTEM_PROMPT
from kai.workspace.tools import list_dir, read_file, run_shell, search_files

config = RecursiveAgentConfig(
    name="setup",
    system_prompt=SYSTEM_PROMPT,
    tools={
        "read_file": read_file,
        "list_dir": list_dir,
        "search_files": search_files,
        "run_shell": run_shell,
    },
    backend="openai",
    backend_kwargs={"model_name": "gpt-4o"},
    max_iterations=15,
)
