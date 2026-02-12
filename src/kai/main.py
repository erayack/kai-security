"""Run a kai agent by name.

Usage::

    uv run python -m kai.main setup --repo-path /path/to/target
    uv run python -m kai.main exploit --input context.json
    uv run python -m kai.main exploit --input "raw string context"
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from kai.definitions import exploit_config, setup_config
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kai",
        description="Run a kai agent.",
    )
    parser.add_argument(
        "agent",
        choices=sorted(AGENTS),
        help="Agent to run.",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Input data: JSON string, or path to a .json file.",
    )
    parser.add_argument(
        "--backend",
        default=None,
        help="Override the agent's backend (e.g. anthropic).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override the agent's model name.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Override max iterations.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Entry point."""
    args = _build_parser().parse_args(argv)

    config = AGENTS[args.agent]

    # Apply overrides without mutating the original config
    if args.backend or args.model or args.max_iterations:
        kwargs = {
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
            "max_iterations": args.max_iterations or config.max_iterations,
        }
        config = RecursiveAgentConfig(**kwargs)

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


if __name__ == "__main__":
    main()
