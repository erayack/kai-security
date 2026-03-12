"""Run a kai agent by name, or the full setup→exploit pipeline.

Usage::

    uv run python -m kai.main pipeline --repo-path /path/to/target
    uv run python -m kai.main pipeline --recipe recipe.json
    uv run python -m kai.main agent setup --input '{"repo_path": "..."}'
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kai import generate_id
from kai.definitions import exploit_config, exploit_result_processors, setup_config
from kai.logging_config import configure_logging
from kai.definitions.exploit.tools import make_graph_tools
from kai.dependency import TreeSitterBuilder
from kai.state import LocalStateManager, StateManager, inject_state_manager
from kai.state.models import RunRecord
from kai.workspace.integration import inject_workspace
from kai.workspace.recipe import WorkspaceRecipe
from ra.agents import RecursiveAgent, RecursiveAgentConfig
from ra.core.types import RLMChatCompletion, UsageSummary

log = logging.getLogger(__name__)

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


def _save_result(
    result: RLMChatCompletion,
    output_path: str | None,
) -> Path:
    """Persist an agent result to a JSON file.

    If *output_path* is None a timestamped file under ``output/`` is used.
    Returns the path that was written.
    """
    if output_path is None:
        out_dir = Path("output")
        out_dir.mkdir(exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = out_dir / f"run_{ts}.json"
    else:
        dest = Path(output_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        exploits = json.loads(result.response)
    except (json.JSONDecodeError, TypeError):
        exploits = result.response

    payload = {
        "model": result.root_model,
        "execution_time": result.execution_time,
        "usage": result.usage_summary.to_dict(),
        "result": exploits,
    }
    dest.write_text(json.dumps(payload, indent=2))
    return dest


_BUILD_COMMANDS: list[tuple[str, list[str]]] = [
    ("foundry.toml", ["forge", "build"]),
    ("Cargo.toml", ["cargo", "build"]),
    ("package.json", ["npm", "run", "build"]),
]


def _detect_build_cmd(repo: str) -> list[str] | None:
    """Return the build command for *repo*, or ``None`` if unknown."""
    for marker, cmd in _BUILD_COMMANDS:
        if (Path(repo) / marker).exists():
            return cmd
    return None


def _apply_fixes(
    master_path: str,
    findings: list[dict[str, Any]],
    round_num: int,
) -> list[dict[str, Any]]:
    """Apply patches from *findings* and return the subset that succeeded.

    Creates a branch, applies each patch individually, commits, and
    runs a build check.  On build failure the commit is rolled back
    and an empty list is returned.
    """
    branch = f"fix/round-{round_num}"
    run = subprocess.run

    # Create a fix branch
    run(
        ["git", "checkout", "-b", branch],
        cwd=master_path,
        capture_output=True,
    )

    applied: list[dict[str, Any]] = []
    for finding in findings:
        patch = finding.get("patch", "")
        if not patch:
            continue
        try:
            fd, tmp_str = tempfile.mkstemp(suffix=".patch")
            tmp = Path(tmp_str)
            os.close(fd)
            tmp.write_text(patch)
            res = run(
                ["git", "apply", str(tmp)],
                cwd=master_path,
                capture_output=True,
            )
            if res.returncode == 0:
                applied.append(finding)
            else:
                log.warning(
                    "Patch for %s failed: %s",
                    finding.get("hypothesis", "?"),
                    res.stderr.decode(errors="replace").strip(),
                )
        finally:
            tmp.unlink(missing_ok=True)

    if not applied:
        run(["git", "checkout", "-"], cwd=master_path, capture_output=True)
        run(
            ["git", "branch", "-D", branch],
            cwd=master_path,
            capture_output=True,
        )
        return []

    # Commit the applied patches
    run(["git", "add", "-A"], cwd=master_path, capture_output=True)
    run(
        ["git", "commit", "-m", f"Round {round_num} fixes"],
        cwd=master_path,
        capture_output=True,
    )

    # Build check
    build_cmd = _detect_build_cmd(master_path)
    if build_cmd:
        res = run(build_cmd, cwd=master_path, capture_output=True)
        if res.returncode != 0:
            log.warning(
                "Build failed after round %d fixes, rolling back",
                round_num,
            )
            run(
                ["git", "reset", "--hard", "HEAD~1"],
                cwd=master_path,
                capture_output=True,
            )
            run(
                ["git", "checkout", "-"],
                cwd=master_path,
                capture_output=True,
            )
            run(
                ["git", "branch", "-D", branch],
                cwd=master_path,
                capture_output=True,
            )
            return []

    return applied


def run_exploit(
    recipe: WorkspaceRecipe,
    *,
    verbose: bool = False,
    log_file: str = "",
    log_structured: bool = False,
    instructions: str = "",
    prior_findings: list[dict[str, Any]] | None = None,
    pending_candidates: list[dict[str, Any]] | None = None,
    state_manager: StateManager | None = None,
    run_id: str | None = None,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
) -> RLMChatCompletion:
    """Run the exploit agent with a pre-built workspace recipe.

    Parameters
    ----------
    instructions:
        Free-text guidance passed through to the exploit agent context.
    prior_findings:
        Already-known vulnerabilities from earlier rounds.  The agent
        is told not to re-report these and to focus on new bugs.
    state_manager:
        Optional state manager for progress tracking.
    run_id:
        Run identifier (required when *state_manager* is given).

    Returns the full ``RLMChatCompletion`` from the exploit agent.
    """
    if log_file:
        log_file = str(Path(log_file).resolve())

    # Build dependency graph and bind as root tools
    graph = TreeSitterBuilder().build(recipe.master_path)
    graph_tools = make_graph_tools(graph)

    injected_config = inject_workspace(
        exploit_config,
        recipe,
        verbose=verbose,
        log_file=log_file or None,
        log_structured=log_structured or None,
    )
    injected_config = replace(
        injected_config,
        tools={**injected_config.tools, **graph_tools},
    )

    if state_manager is not None and run_id is not None:
        injected_config = inject_state_manager(
            injected_config,
            state_manager,
            run_id,
            result_processors=exploit_result_processors,
            save_rollouts=save_rollouts,
            rollout_agents=rollout_agents,
        )

    context: dict[str, Any] = {"master_path": recipe.master_path}
    if instructions:
        context["instructions"] = instructions
    if prior_findings:
        context["prior_findings"] = prior_findings
    if pending_candidates:
        context["pending_candidates"] = pending_candidates

    exploit_agent = RecursiveAgent(injected_config)
    return exploit_agent.completion(context)


def run_pipeline(
    repo_path: str,
    *,
    verbose: bool = False,
    log_file: str = "",
    log_structured: bool = False,
    instructions: str = "",
    max_rounds: int = 1,
    state_dir: str = "output/state",
    no_state: bool = False,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
    state_manager: StateManager | None = None,
    run_id: str | None = None,
) -> RLMChatCompletion:
    """Run the full setup → exploit pipeline.

    1. Create a long-lived master_dir.
    2. Run the setup agent to build the repo and produce a recipe.
    3. Loop up to *max_rounds* times: run exploit, apply fixes, repeat.
    4. Clean up master_dir on success (preserved on failure).

    Returns a merged ``RLMChatCompletion`` containing all findings.
    """
    repo_path = str(Path(repo_path).resolve())
    master_dir = tempfile.mkdtemp(prefix="kai_master_")

    # State tracking — use caller-provided manager or create one
    sm = state_manager
    rid = run_id
    if sm is None and not no_state:
        try:
            sm = LocalStateManager(state_dir=state_dir)
            rid = generate_id()
            sm.create_run(
                RunRecord(
                    run_id=rid,
                    repo_path=repo_path,
                    started_at=datetime.now(timezone.utc).isoformat(),
                    status="running",
                    root_model=exploit_config.backend_kwargs.get(
                        "model_name", "unknown"
                    ),
                )
            )
        except Exception:
            log.exception("Failed to initialize state manager")
            sm = None
            rid = None

    succeeded = False
    try:
        # --- Step 1: run setup agent (with one retry) ---
        recipe_data = None
        max_setup_attempts = 2
        for attempt in range(1, max_setup_attempts + 1):
            setup_cfg = replace(
                setup_config, verbose=verbose, log_structured=log_structured
            )
            setup_agent = RecursiveAgent(setup_cfg)
            setup_result = setup_agent.completion(
                {"repo_path": repo_path, "master_dir": master_dir}
            )
            raw_response = (
                setup_result.response
                if hasattr(setup_result, "response")
                else str(setup_result)
            )

            # --- Step 2: deserialize recipe ---
            if not raw_response or not raw_response.strip():
                log.warning(
                    "Setup agent returned empty response (attempt %d/%d)",
                    attempt,
                    max_setup_attempts,
                )
                continue
            try:
                recipe_data = json.loads(raw_response)
                break
            except json.JSONDecodeError:
                from json_repair import repair_json

                repaired = str(repair_json(raw_response))
                if repaired and repaired.strip():
                    try:
                        recipe_data = json.loads(repaired)
                        break
                    except json.JSONDecodeError:
                        pass
                log.warning(
                    "Setup agent response not valid JSON (attempt %d/%d)",
                    attempt,
                    max_setup_attempts,
                )

        if recipe_data is None:
            raise RuntimeError(
                "Setup agent failed to produce valid JSON after "
                f"{max_setup_attempts} attempts"
            )
        recipe = WorkspaceRecipe.from_dict(recipe_data)

        # --- Step 3: iterative exploit loop ---
        result = _run_exploit_loop(
            recipe,
            verbose=verbose,
            log_file=log_file,
            log_structured=log_structured,
            instructions=instructions,
            max_rounds=max_rounds,
            state_manager=sm,
            run_id=rid,
            save_rollouts=save_rollouts,
            rollout_agents=rollout_agents,
        )
        succeeded = True

        if sm is not None and rid is not None:
            exploits = sm.get_exploits(rid)
            fixes = sm.get_fixes(rid)
            sm.update_run(
                rid,
                status="completed",
                finished_at=datetime.now(timezone.utc).isoformat(),
                execution_time=result.execution_time,
                usage_summary=result.usage_summary.to_dict(),
                total_exploits=len(exploits),
                total_fixes=len(fixes),
            )

        return result
    except BaseException:
        if sm is not None and rid is not None:
            sm.update_run(
                rid,
                status="failed",
                finished_at=datetime.now(timezone.utc).isoformat(),
            )
        raise
    finally:
        if succeeded:
            shutil.rmtree(master_dir, ignore_errors=True)
        else:
            log.warning(
                "Preserving workspace for debugging: %s",
                master_dir,
            )


def _run_exploit_loop(
    recipe: WorkspaceRecipe,
    *,
    verbose: bool = False,
    log_file: str = "",
    log_structured: bool = False,
    instructions: str = "",
    max_rounds: int = 1,
    state_manager: StateManager | None = None,
    run_id: str | None = None,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
) -> RLMChatCompletion:
    """Run up to *max_rounds* of exploit → fix → re-audit."""
    all_findings: list[dict[str, Any]] = []
    fixed_findings: list[dict[str, Any]] = []
    pending_for_next: list[dict[str, Any]] | None = None
    last_result: RLMChatCompletion | None = None
    merged_usage = UsageSummary(model_usage_summaries={})
    total_time = 0.0

    for round_num in range(1, max_rounds + 1):
        # Per-round log file
        if log_file and max_rounds > 1:
            stem = Path(log_file).stem
            suffix = Path(log_file).suffix
            parent = Path(log_file).parent
            round_log = str(parent / f"{stem}_round{round_num}{suffix}")
        else:
            round_log = log_file

        result = run_exploit(
            recipe,
            verbose=verbose,
            log_file=round_log,
            log_structured=log_structured,
            instructions=instructions,
            prior_findings=fixed_findings or None,
            pending_candidates=pending_for_next,
            state_manager=state_manager,
            run_id=run_id,
            save_rollouts=save_rollouts,
            rollout_agents=rollout_agents,
        )
        last_result = result
        merged_usage = merged_usage.merge(result.usage_summary)
        total_time += result.execution_time

        # Save intermediate so no work is lost
        _save_result(result, None)

        # Parse new findings
        try:
            new_findings = json.loads(result.response)
        except (json.JSONDecodeError, TypeError):
            break

        if not isinstance(new_findings, list) or not new_findings:
            break

        all_findings.extend(new_findings)

        # Apply fixes and continue (unless last round).
        # Only successfully-applied findings go into prior context
        # so the next round doesn't skip unfixed bugs.
        if round_num < max_rounds:
            fixed = _apply_fixes(recipe.master_path, new_findings, round_num)
            fixed_findings.extend(fixed)

            # Collect leftover work for the next round: candidates
            # never verified and confirmed exploits never fixed.
            # Both need re-verification because _apply_fixes may
            # have changed the codebase.
            pending: list[dict[str, Any]] = []
            if state_manager is not None and run_id is not None:
                for e in state_manager.get_exploits(run_id, status="candidate"):
                    pending.append(
                        {
                            "hypothesis": e.hypothesis,
                            "file": e.file,
                            "function": e.function,
                            "exploit_sketch": e.exploit_sketch,
                        }
                    )
                for e in state_manager.get_exploits(run_id, status="verified"):
                    if e.confirmed:
                        item: dict[str, Any] = {
                            "hypothesis": e.hypothesis,
                            "file": e.file,
                            "function": e.function,
                            "exploit_sketch": e.exploit_sketch,
                        }
                        if e.poc_code:
                            item["poc_code"] = e.poc_code
                        pending.append(item)
            pending_for_next = pending or None

    # Return merged result when multi-round, or original for single
    if last_result is None:
        msg = "No exploit rounds completed"
        raise RuntimeError(msg)

    if max_rounds == 1:
        return last_result

    return RLMChatCompletion(
        root_model=last_result.root_model,
        prompt=last_result.prompt,
        response=json.dumps(all_findings),
        usage_summary=merged_usage,
        execution_time=total_time,
    )


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
    agent_parser.add_argument(
        "--log-file",
        default="",
        help="Save full verbose log to this file.",
    )
    agent_parser.add_argument(
        "--log-structured",
        action="store_true",
        default=False,
        help="Emit structured JSON logs (for CloudWatch / log aggregation).",
    )
    agent_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help=("Path to save result JSON (default: output/run_<timestamp>.json)."),
    )
    agent_parser.add_argument(
        "--save-rollouts",
        action="store_true",
        default=False,
        help="Save per-agent rollout histories as JSONL.",
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
    pipe_parser.add_argument(
        "--log-file",
        default="",
        help="Save full verbose log to this file.",
    )
    pipe_parser.add_argument(
        "--log-structured",
        action="store_true",
        default=False,
        help="Emit structured JSON logs (for CloudWatch / log aggregation).",
    )
    pipe_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help=("Path to save result JSON (default: output/run_<timestamp>.json)."),
    )
    pipe_parser.add_argument(
        "--instructions",
        default="",
        help="Extra instructions for the exploit agent.",
    )
    pipe_parser.add_argument(
        "--max-rounds",
        type=int,
        default=1,
        help="Max fix-and-re-audit rounds (default: 1).",
    )
    pipe_parser.add_argument(
        "--state-dir",
        default="output/state",
        help="Directory for state storage (default: output/state).",
    )
    pipe_parser.add_argument(
        "--no-state",
        action="store_true",
        default=False,
        help="Disable state tracking.",
    )
    pipe_parser.add_argument(
        "--save-rollouts",
        action="store_true",
        default=False,
        help="Save per-agent rollout histories as JSONL.",
    )

    return parser


def _resolve_rollout_flags(
    args: argparse.Namespace,
) -> tuple[bool, set[str] | None]:
    """Return ``(save_rollouts, rollout_agents)`` from CLI + env."""
    save = getattr(args, "save_rollouts", False) or os.environ.get(
        "KAI_SAVE_ROLLOUTS", ""
    ) in ("1", "true", "yes")
    raw = os.environ.get("KAI_ROLLOUT_AGENTS", "").strip()
    agents: set[str] | None = None
    if raw:
        agents = {a.strip() for a in raw.split(",") if a.strip()}
    return save, agents


def main(argv: list[str] | None = None) -> None:
    """Entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Resolve structured logging: CLI flag or env var
    structured = getattr(args, "log_structured", False) or os.environ.get(
        "KAI_LOG_STRUCTURED", ""
    ) in ("1", "true", "yes")
    configure_logging(structured=structured)

    # Resolve rollout flags
    save_rollouts, rollout_agents = _resolve_rollout_flags(args)

    if args.command == "pipeline":
        log_file = args.log_file
        instructions = args.instructions
        max_rounds = args.max_rounds
        state_dir = args.state_dir
        no_state = args.no_state
        sm: StateManager | None = None
        rid: str | None = None
        try:
            if args.recipe:
                with open(args.recipe) as f:
                    recipe = WorkspaceRecipe.from_dict(json.load(f))
                if not no_state:
                    try:
                        sm = LocalStateManager(state_dir=state_dir)
                        rid = generate_id()
                        sm.create_run(
                            RunRecord(
                                run_id=rid,
                                repo_path=args.recipe,
                                started_at=datetime.now(timezone.utc).isoformat(),
                                status="running",
                                root_model=exploit_config.backend_kwargs.get(
                                    "model_name", "unknown"
                                ),
                            )
                        )
                    except Exception:
                        log.exception("Failed to initialize state manager")
                        sm = None
                        rid = None
                result = _run_exploit_loop(
                    recipe,
                    verbose=args.verbose,
                    log_file=log_file,
                    log_structured=structured,
                    instructions=instructions,
                    max_rounds=max_rounds,
                    state_manager=sm,
                    run_id=rid,
                    save_rollouts=save_rollouts,
                    rollout_agents=rollout_agents,
                )
                if sm is not None and rid is not None:
                    sm.update_run(
                        rid,
                        status="completed",
                        finished_at=datetime.now(timezone.utc).isoformat(),
                    )
            else:
                if not no_state:
                    try:
                        sm = LocalStateManager(state_dir=state_dir)
                        rid = generate_id()
                        sm.create_run(
                            RunRecord(
                                run_id=rid,
                                repo_path=args.repo_path,
                                started_at=datetime.now(timezone.utc).isoformat(),
                                status="running",
                                root_model=exploit_config.backend_kwargs.get(
                                    "model_name", "unknown"
                                ),
                            )
                        )
                    except Exception:
                        log.exception("Failed to initialize state manager")
                        sm = None
                        rid = None
                result = run_pipeline(
                    args.repo_path,
                    verbose=args.verbose,
                    log_file=log_file,
                    log_structured=structured,
                    instructions=instructions,
                    max_rounds=max_rounds,
                    state_dir=state_dir,
                    no_state=no_state,
                    save_rollouts=save_rollouts,
                    rollout_agents=rollout_agents,
                    state_manager=sm,
                    run_id=rid,
                )
            print(result.response)
            dest = _save_result(result, args.output)
            print(f"Result saved to {dest}", file=sys.stderr)
        except Exception as exc:
            log.error("Pipeline crashed: %s — saving partial results", exc)
            # Build a minimal result so the harness can grade
            # whatever the agent found before crashing.
            partial = RLMChatCompletion(
                root_model="unknown",
                prompt="",
                response="[]",
                usage_summary=UsageSummary(model_usage_summaries={}),
                execution_time=0,
            )
            # Try to recover exploits from state manager
            if sm is not None and rid is not None:
                try:
                    exploits = sm.get_exploits(rid)
                    if exploits:
                        partial = RLMChatCompletion(
                            root_model="unknown",
                            prompt="",
                            response=json.dumps([e.to_dict() for e in exploits]),
                            usage_summary=UsageSummary(model_usage_summaries={}),
                            execution_time=0,
                        )
                        log.info(
                            "Recovered %d exploits from state",
                            len(exploits),
                        )
                except Exception:
                    log.exception("Failed to recover exploits from state")
            if args.output:
                try:
                    _save_result(partial, args.output)
                    log.info("Partial results saved to %s", args.output)
                except Exception:
                    log.exception("Failed to save partial results")
            raise
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
        overrides["log_structured"] = structured
        if args.log_file:
            overrides["log_file"] = str(Path(args.log_file).resolve())
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
        print(result.response)
        dest = _save_result(result, args.output)
        print(f"Result saved to {dest}", file=sys.stderr)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
