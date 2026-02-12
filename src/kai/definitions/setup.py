"""Setup agent: prepare target repo for analysis."""

from __future__ import annotations

from typing import Any

from ra.agents.config import RecursiveAgentConfig


# --- Tool stubs ---


def detect_framework(repo_path: str) -> dict[str, Any]:
    """Detect language and framework of target repository."""
    # TODO: inspect files, detect solidity/foundry/hardhat/python/c
    raise NotImplementedError


def compile_project(repo_path: str) -> str:
    """Attempt to compile the target project."""
    # TODO: run appropriate compiler based on detected framework
    raise NotImplementedError


def build_dependency_graph(repo_path: str) -> dict[str, Any]:
    """Build a static dependency graph via tree-sitter/AST."""
    # TODO: parse imports, trace calls, build graph
    raise NotImplementedError


def validate_workspace(repo_path: str) -> bool:
    """Verify testbed is ready (compiled, tests runnable)."""
    # TODO: check artifacts exist, dry-run tests
    raise NotImplementedError


# --- System prompt ---

SYSTEM_PROMPT = """\
You are a setup agent. Your job is to prepare a target repository
for security analysis.

You have access to the following tool functions in your REPL:

- detect_framework(repo_path: str) -> dict
    Detect the language and framework of the target repository.

- compile_project(repo_path: str) -> str
    Attempt to compile the target project. Returns compiler output.

- build_dependency_graph(repo_path: str) -> dict
    Build a static dependency graph via AST/tree-sitter analysis.

- validate_workspace(repo_path: str) -> bool
    Verify the testbed is ready for analysis.

- llm_query(prompt: str) -> str
    Ask an LLM a question (single-shot, for quick lookups).

Your input is in the `context` variable (a dict with "repo_path" and
optional metadata). Set up the workspace step by step, then return
a summary dict with FINAL_VAR(variable_name).
"""

# --- Config ---

config = RecursiveAgentConfig(
    name="setup",
    system_prompt=SYSTEM_PROMPT,
    tools={
        "detect_framework": detect_framework,
        "compile_project": compile_project,
        "build_dependency_graph": build_dependency_graph,
        "validate_workspace": validate_workspace,
    },
    backend="openai",
    backend_kwargs={"model_name": "gpt-4o"},
    max_iterations=15,
)
