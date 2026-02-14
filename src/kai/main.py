"""Run a kai agent by name, or the full setup→exploit pipeline.

Usage::

    uv run python -m kai.main pipeline --repo-path /path/to/target
    uv run python -m kai.main pipeline --recipe recipe.json
    uv run python -m kai.main agent setup --input '{"repo_path": "..."}'
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from dataclasses import replace
from typing import Any

from kai.definitions import exploit_config, setup_config
from kai.definitions.exploit.tools import make_graph_tools
from kai.dependency import TreeSitterBuilder
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


def run_exploit(recipe: WorkspaceRecipe, *, verbose: bool = False) -> str:
    """Run the exploit agent with a pre-built workspace recipe.

    Returns the exploit agent's final response.
    """
    # Build dependency graph and bind as root tools
    graph = TreeSitterBuilder().build(recipe.master_path)
    graph_tools = make_graph_tools(graph)

    injected_config = inject_workspace(exploit_config, recipe, verbose=verbose)
    injected_config = replace(
        injected_config, tools={**injected_config.tools, **graph_tools}
    )

    exploit_agent = RecursiveAgent(injected_config)
    result = exploit_agent.completion({"master_path": recipe.master_path})
    return result.response if hasattr(result, "response") else str(result)


def run_pipeline(repo_path: str, *, verbose: bool = False) -> str:
    """Run the full setup → exploit pipeline.

    1. Create a long-lived master_dir.
    2. Run the setup agent to build the repo and produce a recipe.
    3. Run exploit with the resulting recipe.
    4. Clean up master_dir.

    Returns the exploit agent's final response.
    """
    master_dir = tempfile.mkdtemp(prefix="kai_master_")
    try:
        # --- Step 1: run setup agent ---
        setup_cfg = replace(setup_config, verbose=verbose)
        setup_agent = RecursiveAgent(setup_cfg)
        setup_result = setup_agent.completion(
            {"repo_path": repo_path, "master_dir": master_dir}
        )
        raw_response = (
            setup_result.response
            if hasattr(setup_result, "response")
            else str(setup_result)
        )

        # --- Step 2: deserialize recipe and run exploit ---
        recipe = WorkspaceRecipe.from_dict(json.loads(raw_response))
        return run_exploit(recipe, verbose=verbose)
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
    agent_parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Print rich iteration output to console.",
    )

    # --- pipeline mode ---
    pipe_parser = sub.add_parser("pipeline", help="Run setup → exploit pipeline.")
    pipe_group = pipe_parser.add_mutually_exclusive_group(required=True)
    pipe_group.add_argument(
        "--repo-path",
        help="Path to the target repository (runs setup first).",
    )
    pipe_group.add_argument(
        "--recipe",
        help="Path to a recipe JSON file (skips setup).",
    )
    pipe_parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Print rich iteration output to console.",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """Entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "pipeline":
        if args.recipe:
            with open(args.recipe) as f:
                recipe = WorkspaceRecipe.from_dict(json.load(f))
            print(run_exploit(recipe, verbose=args.verbose))
        else:
            print(run_pipeline(args.repo_path, verbose=args.verbose))
        return

    if args.command == "agent":
        config = AGENTS[args.name]

        # Apply overrides without mutating the original config
        overrides: dict[str, Any] = {}
        if args.backend:
            overrides["backend"] = args.backend
        if args.model:
            overrides["backend_kwargs"] = {
                **config.backend_kwargs,
                "model_name": args.model,
            }
        if args.max_iterations:
            overrides["max_iterations"] = args.max_iterations
        overrides["verbose"] = args.verbose
        config = replace(config, **overrides)

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
