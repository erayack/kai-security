"""Setup agent configuration."""

from __future__ import annotations

import os

from ra.agents.config import RecursiveAgentConfig

from kai.definitions.setup.prompt import SYSTEM_PROMPT
from kai.definitions.setup.tools import list_dir, read_file, run_shell, search_files

config = RecursiveAgentConfig(
    name="setup",
    system_prompt=SYSTEM_PROMPT,
    tools={
        "read_file": read_file,
        "list_dir": list_dir,
        "search_files": search_files,
        "run_shell": run_shell,
    },
    backend="openrouter",
    backend_kwargs={
        "model_name": os.environ.get(
            "KAI_SETUP_MODEL", "minimax/minimax-m2.5"
        ),
    },
    max_iterations=int(os.environ.get("KAI_SETUP_ITERS", 30)),
)
