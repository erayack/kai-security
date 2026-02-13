"""Run a kai agent by name, or the full setup→exploit pipeline.

Usage::

    uv run python -m kai.main setup --repo-path /path/to/target
    uv run python -m kai.main exploit --input context.json
    uv run python -m kai.main pipeline --repo-path /path/to/target
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from typing import Any

from kai.definitions import exploit_config, setup_config
from kai.workspace.integration import inject_workspace
from kai.workspace.recipe import WorkspaceRecipe
from ra.agents import RecursiveAgent, RecursiveAgentConfig

AGENTS: dict[str, RecursiveAgentConfig] = {
    "setup": setup_config,
    "exploit": exploit_config,
}


def _parse_input(raw: str) -> str | dict[str, Any]:
    """Try JSON first, fall back to raw string."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


def run_pipeline(repo_path: str) -> str:
    """Run the full setup → exploit pipeline.

    1. Create a long-lived master_dir.
    2. Run the setup agent to build the repo and produce a recipe.
    3. Inject workspace provisioning into the exploit config tree.
    4. Run the exploit agent with workspace-injected config.
    5. Clean up master_dir.

    Returns the exploit agent's final response.
    """
    master_dir = tempfile.mkdtemp(prefix="kai_master_")
    try:
        # --- Step 1: run setup agent ---
        setup_agent = RecursiveAgent(setup_config)
        setup_result = setup_agent.completion(
            {"repo_path": repo_path, "master_dir": master_dir}
        )
        raw_response = (
            setup_result.response
            if hasattr(setup_result, "response")
            else str(setup_result)
        )

        # --- Step 2: deserialize recipe ---
        recipe = WorkspaceRecipe.from_dict(json.loads(raw_response))

        # --- Step 3: inject workspace into exploit config ---
        injected_config = inject_workspace(exploit_config, recipe)

        # --- Step 4: run exploit agent ---
        exploit_agent = RecursiveAgent(injected_config)
        exploit_result = exploit_agent.completion(
            {"repo_path": repo_path, "master_dir": master_dir}
        )
        return (
            exploit_result.response
            if hasattr(exploit_result, "response")
            else str(exploit_result)
        )
    finally:
        shutil.rmtree(master_dir, ignore_errors=True)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kai",
        description="Run a kai agent.",
    )
    sub = parser.add_subparsers(dest="command")

    # --- single-agent mode ---
    agent_parser = sub.add_parser("agent", help="Run a single agent.")
    agent_parser.add_argument(
        "name",
        choices=sorted(AGENTS),
        help="Agent to run.",
    )
    agent_parser.add_argument(
        "--input",
        required=True,
        help="Input data: JSON string, or path to a .json file.",
    )
    agent_parser.add_argument(
        "--backend",
        default=None,
        help="Override the agent's backend (e.g. anthropic).",
    )
    agent_parser.add_argument(
        "--model",
        default=None,
        help="Override the agent's model name.",
    )
    agent_parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Override max iterations.",
    )

    # --- pipeline mode ---
    pipe_parser = sub.add_parser("pipeline", help="Run setup → exploit pipeline.")
    pipe_parser.add_argument(
        "--repo-path",
        required=True,
        help="Path to the target repository.",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """Entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "pipeline":
        print(run_pipeline(args.repo_path))
        return

    if args.command == "agent":
        config = AGENTS[args.name]

        # Apply overrides without mutating the original config
        if args.backend or args.model or args.max_iterations:
            kwargs: dict[str, Any] = {
                "name": config.name,
                "system_prompt": config.system_prompt,
                "tools": config.tools,
                "agents": config.agents,
                "backend": args.backend or config.backend,
                "backend_kwargs": (
                    {**config.backend_kwargs, "model_name": args.model}
                    if args.model
                    else config.backend_kwargs
                ),
                "max_iterations": (args.max_iterations or config.max_iterations),
            }
            config = RecursiveAgentConfig(**kwargs)  # type: ignore[arg-type]

        # Resolve input
        raw = args.input
        try:
            with open(raw) as f:
                data = json.load(f)
        except (FileNotFoundError, IsADirectoryError):
            data = _parse_input(raw)

        agent = RecursiveAgent(config)
        result = agent.completion(data)
        response = result.response if hasattr(result, "response") else str(result)
        print(response)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
