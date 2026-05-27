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
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from kai import generate_id
from kai.definitions import (
    exploit_config,
    exploit_result_processors,
    patch_assembler_config,
    setup_config,
)
from kai.logging_config import configure_logging
from kai.definitions.exploit.tools import make_graph_tools
from kai.dependency import TreeSitterBuilder
from kai.state import LocalStateManager, StateManager, inject_state_manager
from kai.state.models import RunRecord, ThreatContext
from kai.workspace.integration import inject_workspace
from kai.workspace.recipe import InvalidRecipeError, WorkspaceRecipe
from ra.agents import RecursiveAgent, RecursiveAgentConfig
from ra.core.types import RLMChatCompletion, UsageSummary

log = logging.getLogger(__name__)

# Resolved once at import time so _save_result always writes relative to
# the original working directory — even when LocalREPL._temp_cwd() has
# moved the process CWD into a temp workspace.
_STARTUP_CWD = Path.cwd()

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


def _load_threat_context(path: str) -> ThreatContext:
    """Load a threat context from a YAML or JSON file."""
    p = Path(path)
    raw = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        import yaml

        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    return ThreatContext.from_dict(data)


def _save_result(
    result: RLMChatCompletion,
    output_path: str | None,
) -> Path:
    """Persist an agent result to a JSON file.

    If *output_path* is None a timestamped file under ``output/`` is used.
    Returns the path that was written.
    """
    if output_path is None:
        out_dir = _STARTUP_CWD / "output"
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


# ---------------------------------------------------------------------------
# Iterative re-verification helpers
# ---------------------------------------------------------------------------

_ITERATIVE_REASONS = {"unreachable", "multi_bug_chain"}


def _collect_iterative_candidates(
    state_manager: StateManager,
    run_id: str,
) -> list[Any]:
    """Return rejected exploits eligible for iterative re-verification."""
    from kai.state.models import ExploitRecord

    rejected: list[ExploitRecord] = state_manager.get_exploits(
        run_id, status="rejected"
    )
    return [e for e in rejected if e.rejection_reason in _ITERATIVE_REASONS]


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read *key* from a dict or an object attribute."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _seed_iterative_exploits(
    state_manager: StateManager,
    iterative_run_id: str,
    parent_candidates: list[Any],
    prerequisite: str,
) -> list[dict[str, Any]]:
    """Create new candidate records for the iterative run.

    *parent_candidates* may be ``ExploitRecord`` objects (from a live
    run) or plain dicts (deserialized from a follow-up recipe).

    Returns a list of pending_candidates dicts for root context.
    """
    from kai.state.models import ExploitRecord

    pending: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for parent in parent_candidates:
        new_id = generate_id()
        rec = ExploitRecord(
            run_id=iterative_run_id,
            exploit_id=new_id,
            timestamp=now,
            source_agent="iterative_seed",
            status="candidate",
            hypothesis=_get(parent, "hypothesis", ""),
            file=_get(parent, "file", ""),
            function=_get(parent, "function", ""),
            exploit_sketch=_get(parent, "exploit_sketch", ""),
            attacker_role=_get(parent, "attacker_role", ""),
            required_privileges=_get(parent, "required_privileges", ""),
            category=_get(parent, "category", ""),
            trusted_component_abused=_get(parent, "trusted_component_abused", ""),
            affected_files=_get(parent, "affected_files", []),
            prerequisite=prerequisite,
        )
        state_manager.add_exploit(rec)
        pending.append(
            {
                "exploit_id": new_id,
                "hypothesis": _get(parent, "hypothesis", ""),
                "file": _get(parent, "file", ""),
                "function": _get(parent, "function", ""),
                "exploit_sketch": _get(parent, "exploit_sketch", ""),
            }
        )
    return pending


def _run_patch_assembler(
    recipe: WorkspaceRecipe,
    *,
    state_manager: StateManager,
    run_id: str,
    patches: list[dict[str, Any]],
    branch_name: str,
    verbose: bool = False,
    log_structured: bool = False,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
) -> str | None:
    """Run the patch assembler agent. Returns the diff or None on failure.

    The agent applies *patches* to a new branch, resolves conflicts,
    and verifies the build.  After completion the host captures
    ``git diff <before> HEAD`` and persists it as
    ``RunRecord.prerequisite_diff``.
    """
    master = recipe.master_path

    # Record HEAD before the agent mutates the worktree.
    head_before = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=master,
        text=True,
    ).strip()

    # Build hints from the recipe (if available).
    build_hints: dict[str, str] = {}
    build_cmd = getattr(recipe, "build_cmd", None)
    test_cmd = getattr(recipe, "test_cmd", None)
    if build_cmd:
        build_hints["build_cmd"] = build_cmd
    if test_cmd:
        build_hints["test_cmd"] = test_cmd

    context: dict[str, Any] = {
        "master_path": master,
        "patches": patches,
        "branch_name": branch_name,
    }
    if build_hints:
        context["build_hints"] = build_hints

    cfg = replace(
        patch_assembler_config,
        verbose=verbose,
        log_structured=log_structured,
        environment_kwargs={
            **patch_assembler_config.environment_kwargs,
            "workspace_factory": lambda: master,
            "skip_cleanup": True,
        },
    )

    # Iteration tracking only (no ExploitsProxy / spawn wrappers).
    cfg = inject_state_manager(
        cfg,
        state_manager,
        run_id,
        save_rollouts=save_rollouts,
        rollout_agents=rollout_agents,
        _depth=1,
    )

    try:
        agent = RecursiveAgent(cfg)
        agent.completion(context)

        # Capture cumulative diff and persist it.
        diff = subprocess.check_output(
            ["git", "diff", head_before, "HEAD"],
            cwd=master,
            text=True,
        )
        state_manager.update_run(run_id, prerequisite_diff=diff)
        return diff
    except Exception:
        log.exception("Patch assembler failed for run %s", run_id)
        # Attempt to restore the original branch.
        try:
            subprocess.check_call(
                ["git", "checkout", "-"],
                cwd=master,
                timeout=30,
            )
        except Exception:
            log.warning("Could not restore original branch in %s", master)
        return None


def _maybe_run_patch_assembler(
    recipe: WorkspaceRecipe,
    state_manager: StateManager,
    run_id: str,
    *,
    verbose: bool = False,
    log_structured: bool = False,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
) -> str | None:
    """Assemble patches and save a follow-up recipe for the user.

    Guards: blocked candidates + fixes with patches must exist.
    On success, saves a recipe at ``output/recipe_patched_{id}.json``
    and returns its path.  The user can launch the follow-up with
    ``--recipe``.

    Returns the saved recipe path, or ``None`` if not triggered.
    """
    candidates = _collect_iterative_candidates(state_manager, run_id)
    if not candidates:
        log.info("Iterative: no reachability-rejected candidates")
        return None

    # Need at least one fix with a patch
    fixes = state_manager.get_fixes(run_id)
    fix_dicts = [f.to_dict() for f in fixes if f.patch]
    if not fix_dicts:
        log.info("Iterative: no fixes with patches available")
        return None

    branch_name = f"patched-{run_id[:12]}"

    log.info(
        "Patch assembler: %d candidates, %d patches",
        len(candidates),
        len(fix_dicts),
    )

    diff = _run_patch_assembler(
        recipe,
        state_manager=state_manager,
        run_id=run_id,
        patches=fix_dicts,
        branch_name=branch_name,
        verbose=verbose,
        log_structured=log_structured,
        save_rollouts=save_rollouts,
        rollout_agents=rollout_agents,
    )
    if diff is None:
        return None

    # Build pending_candidates for the follow-up recipe
    pending = [
        {
            "exploit_id": c.exploit_id,
            "hypothesis": c.hypothesis,
            "file": c.file,
            "function": c.function,
            "exploit_sketch": c.exploit_sketch,
        }
        for c in candidates
    ]

    # Save follow-up recipe
    followup = replace(
        recipe,
        prerequisite_branch=branch_name,
        pending_candidates=pending,
    )
    out_dir = _STARTUP_CWD / "output"
    out_dir.mkdir(exist_ok=True)
    dest = out_dir / f"recipe_patched_{run_id[:12]}.json"
    dest.write_text(json.dumps(followup.to_dict(), indent=2))

    log.info(
        "Follow-up recipe saved to %s — run with --recipe to continue",
        dest,
    )
    return str(dest)


def run_exploit(
    recipe: WorkspaceRecipe,
    *,
    verbose: bool = False,
    log_file: str = "",
    log_structured: bool = False,
    instructions: str = "",
    pending_candidates: list[dict[str, Any]] | None = None,
    state_manager: StateManager | None = None,
    run_id: str | None = None,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
    threat_context: ThreatContext | None = None,
    skip_fixer: bool = False,
    config: RecursiveAgentConfig | None = None,
    max_iterations: int | None = None,
) -> RLMChatCompletion:
    """Run the exploit agent with a pre-built workspace recipe.

    Parameters
    ----------
    instructions:
        Free-text guidance passed through to the exploit agent context.
    state_manager:
        Optional state manager for progress tracking.
    run_id:
        Run identifier (required when *state_manager* is given).
    config:
        Override the default ``exploit_config``.
    max_iterations:
        Override the config's ``max_iterations`` budget.

    Returns the full ``RLMChatCompletion`` from the exploit agent.
    """
    base_config = config if config is not None else exploit_config

    if log_file:
        log_file = str(Path(log_file).resolve())

    # Checkout prerequisite branch if the recipe carries one
    if recipe.prerequisite_branch is not None:
        log.info(
            "Checking out prerequisite branch %s in %s",
            recipe.prerequisite_branch,
            recipe.master_path,
        )
        subprocess.check_call(
            ["git", "checkout", recipe.prerequisite_branch],
            cwd=recipe.master_path,
            timeout=60,
        )

    # Seed pending candidates from recipe when not passed explicitly
    if pending_candidates is None and recipe.pending_candidates is not None:
        pending_candidates = recipe.pending_candidates
    if (
        pending_candidates is not None
        and state_manager is not None
        and run_id is not None
    ):
        _seed_iterative_exploits(
            state_manager,
            run_id,
            pending_candidates,
            recipe.prerequisite_branch or "",
        )

    # Build dependency graph and bind as root tools
    graph = TreeSitterBuilder().build(recipe.master_path)
    graph_tools = make_graph_tools(graph)

    injected_config = inject_workspace(
        base_config,
        recipe,
        verbose=verbose,
        log_file=log_file or None,
        log_structured=log_structured or None,
    )
    if max_iterations is not None:
        injected_config = replace(injected_config, max_iterations=max_iterations)
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
            recipe=recipe,
        )

    # Auto-inject threat_context into all sub-agent spawn calls so
    # the root LLM doesn't have to forward it manually.  Applied
    # after inject_state_manager so we can compose with its wrappers.
    if threat_context is not None:
        from kai.definitions.exploit.spawn_hooks import (
            make_threat_context_spawn_wrapper,
        )

        tc_factory = make_threat_context_spawn_wrapper(
            threat_context.to_dict(),
        )
        wrappers = dict(injected_config.spawn_wrappers)
        for child in injected_config.agents:
            name = f"spawn_{child.name}"
            existing = wrappers.get(name)
            if existing is not None:
                _prev = existing

                def _chained(
                    orig: Callable[..., str],
                    *,
                    _p: Any = _prev,
                    _tc: Any = tc_factory,
                ) -> Callable[..., str]:
                    return _tc(_p(orig))

                wrappers[name] = _chained
            else:
                wrappers[name] = tc_factory
        injected_config = replace(
            injected_config,
            spawn_wrappers=wrappers,
        )

    # Skip fixer: install a no-op wrapper that short-circuits all
    # fixer spawns.  Applied last so it overrides any prior wrapper.
    if skip_fixer:
        from kai.definitions.exploit.spawn_hooks import make_skip_fixer_wrapper

        wrappers = dict(injected_config.spawn_wrappers)
        wrappers["spawn_fixer"] = make_skip_fixer_wrapper
        injected_config = replace(
            injected_config,
            spawn_wrappers=wrappers,
        )

    context: dict[str, Any] = {"master_path": recipe.master_path}
    if instructions:
        context["instructions"] = instructions
    if pending_candidates:
        context["pending_candidates"] = pending_candidates
    if threat_context is not None:
        context["threat_context"] = threat_context.to_dict()
    if skip_fixer:
        context["skip_fixer"] = True

    exploit_agent = RecursiveAgent(injected_config)
    return exploit_agent.completion(context)


def run_pipeline(
    repo_path: str,
    *,
    verbose: bool = False,
    log_file: str = "",
    log_structured: bool = False,
    instructions: str = "",
    state_dir: str = "output/state",
    no_state: bool = False,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
    state_manager: StateManager | None = None,
    run_id: str | None = None,
    threat_context: ThreatContext | None = None,
    skip_fixer: bool = False,
    no_iterative: bool = False,
) -> RLMChatCompletion:
    """Run the full setup → exploit pipeline.

    1. Create a long-lived master_dir.
    2. Run the setup agent to build the repo and produce a recipe.
    3. Run the exploit agent (with optional iterative re-verification).
    4. Clean up master_dir on success (preserved on failure).

    Returns the ``RLMChatCompletion`` from the exploit run.
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
        recipe: WorkspaceRecipe | None = None
        max_setup_attempts = 2
        last_invalid_recipe_error: InvalidRecipeError | None = None
        for attempt in range(1, max_setup_attempts + 1):
            setup_cfg = replace(
                setup_config,
                verbose=verbose,
                log_structured=log_structured,
                log_file=log_file or "",
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
            except json.JSONDecodeError:
                from json_repair import repair_json

                repaired = str(repair_json(raw_response))
                recipe_data = None
                if repaired and repaired.strip():
                    try:
                        recipe_data = json.loads(repaired)
                    except json.JSONDecodeError:
                        recipe_data = None
                if recipe_data is None:
                    log.warning(
                        "Setup agent response not valid JSON (attempt %d/%d)",
                        attempt,
                        max_setup_attempts,
                    )
                    continue
            # The setup agent occasionally wraps the recipe in a list.
            if isinstance(recipe_data, list):
                if len(recipe_data) == 1 and isinstance(recipe_data[0], dict):
                    recipe_data = recipe_data[0]
                else:
                    log.warning(
                        "Setup agent returned a JSON list instead of a recipe "
                        "dict (attempt %d/%d)",
                        attempt,
                        max_setup_attempts,
                    )
                    continue
            try:
                recipe = WorkspaceRecipe.from_dict(recipe_data)
                break
            except InvalidRecipeError as exc:
                last_invalid_recipe_error = exc
                log.warning(
                    "Setup agent recipe invalid — missing %s (attempt %d/%d)",
                    ", ".join(exc.missing),
                    attempt,
                    max_setup_attempts,
                )

        if recipe is None:
            if last_invalid_recipe_error is not None:
                raise RuntimeError(
                    "Setup agent failed to produce a valid recipe after "
                    f"{max_setup_attempts} attempts; last error: "
                    f"{last_invalid_recipe_error}"
                ) from last_invalid_recipe_error
            raise RuntimeError(
                "Setup agent failed to produce valid JSON after "
                f"{max_setup_attempts} attempts"
            )

        # Persist recipe so future runs can use --recipe.
        # Rewrite master_path to the original repo_path because the
        # temp master_dir is cleaned up after a successful run.
        saved_recipe = replace(recipe, master_path=repo_path)
        recipe_dest = _STARTUP_CWD / "output" / "recipe.json"
        recipe_dest.parent.mkdir(exist_ok=True)
        recipe_dest.write_text(json.dumps(saved_recipe.to_dict(), indent=2))
        log.info("Recipe saved to %s", recipe_dest)

        # --- Step 3: exploit run ---
        result = _run_exploit_loop(
            recipe,
            verbose=verbose,
            log_file=log_file,
            log_structured=log_structured,
            instructions=instructions,
            state_manager=sm,
            run_id=rid,
            save_rollouts=save_rollouts,
            rollout_agents=rollout_agents,
            threat_context=threat_context,
            skip_fixer=skip_fixer,
            no_iterative=no_iterative,
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
            # Roll up counts of exploits/fixes recorded so far so the
            # final run.json reflects partial progress even when the
            # pipeline raises before the success path runs. Otherwise
            # a timeout or mid-run crash leaves `total_exploits: 0`
            # despite verified findings already in exploits.json.
            try:
                partial_exploits = sm.get_exploits(rid)
                partial_fixes = sm.get_fixes(rid)
            except Exception:
                partial_exploits = []
                partial_fixes = []
            sm.update_run(
                rid,
                status="failed",
                finished_at=datetime.now(timezone.utc).isoformat(),
                total_exploits=len(partial_exploits),
                total_fixes=len(partial_fixes),
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


def _maybe_run_post_pipeline_critic(
    recipe: WorkspaceRecipe,
    *,
    state_manager: StateManager,
    run_id: str,
    verbose: bool = False,
    log_structured: bool = False,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
) -> None:
    """Force a critic run after pipeline exit when none happened in-loop.

    Cybergym-only. The in-pipeline verifier cannot reach the strict
    harness server (it runs on the user's laptop, not Railway), so
    promising PoCs land at ``status="soft_verified"`` instead of
    ``verified``. Across R19-R25 the root exploit agent has repeatedly
    failed to call ``spawn_critic`` even with escalating reminders and
    structural FINAL_VAR rejection (it loops on ``spawn_verifier``
    instead). This guarantees ``critic.jsonl`` exists in the rollouts
    whenever there is something to critique, by invoking the critic
    agent directly on the first verified or soft_verified record.

    Mirrors :func:`_run_chain_assembler`. Synchronous (~1-3 min) so it
    finishes before chain_assembler kicks off — the critic enrichment
    fields the chain assembler later reads land on the record first.
    No-op when the model already called critic, or when no critiquable
    record exists, or outside cybergym.
    """
    from kai.state import cybergym_gate

    if os.environ.get("KAI_BENCHMARK") != "cybergym":
        return
    if cybergym_gate.critic_was_called():
        return

    verified = state_manager.get_exploits(run_id, status="verified")
    soft = state_manager.get_exploits(run_id, status="soft_verified")
    candidates = verified + soft
    if not candidates:
        return

    target = candidates[0]
    log.info(
        "post-pipeline critic: invoking on exploit_id=%s status=%s "
        "(model did not call spawn_critic in-loop)",
        target.exploit_id,
        target.status,
    )

    from kai.definitions.exploit.config import critic_config
    from kai.definitions.exploit.parsers import process_critic_result

    cfg = inject_workspace(
        critic_config,
        recipe,
        verbose=verbose,
        log_structured=log_structured or None,
    )
    cfg = inject_state_manager(
        cfg,
        state_manager,
        run_id,
        save_rollouts=save_rollouts,
        rollout_agents=rollout_agents,
        _depth=1,
    )

    context = {
        "exploit_id": target.exploit_id,
        "hypothesis": target.hypothesis,
        "file": target.file,
        "function": target.function,
        "poc_code": target.poc_code or "",
    }

    prior_status = target.status
    try:
        state_manager.update_exploit(run_id, target.exploit_id, status="critiquing")
    except Exception:
        log.exception(
            "post-pipeline critic: could not mark %s critiquing",
            target.exploit_id,
        )
        return

    try:
        agent = RecursiveAgent(cfg)
        result = agent.completion(context)
        process_critic_result(
            state_manager,
            run_id,
            {"exploit_id": target.exploit_id},
            result.response,
        )
        cybergym_gate.mark_critic_called()
    except Exception:
        log.exception("post-pipeline critic failed for %s", target.exploit_id)
    finally:
        try:
            state_manager.update_exploit(run_id, target.exploit_id, status=prior_status)
        except Exception:
            log.exception(
                "post-pipeline critic: could not restore %s to %s",
                target.exploit_id,
                prior_status,
            )


def _maybe_run_post_pipeline_fixer(
    recipe: WorkspaceRecipe,
    *,
    state_manager: StateManager,
    run_id: str,
    verbose: bool = False,
    log_structured: bool = False,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
) -> None:
    """Force a fixer run after pipeline exit when none happened in-loop.

    Cybergym-only mirror of :func:`_maybe_run_post_pipeline_critic`.
    The root exploit agent currently does not call ``spawn_fixer`` on
    its soft_verified records (across R19-R26 fixer.jsonl is missing
    from every cybergym task). This stage runs the fixer agent
    synchronously after the critic stage so ``fix_attempts.json`` and
    ``fixes.json`` are produced, matching the April-2026 reference
    rollout shape.

    Picks the first verified or soft_verified record that does not yet
    have a fix attempt recorded against it. ``process_fixer_result``
    persists the attempt (and the FixRecord on success). The exploit
    status is restored to the prior verified/soft_verified marker if
    the fixer did not succeed, so downstream chain_assembler still
    sees the record.

    No-op when outside cybergym, when no eligible record exists, or
    when a fix attempt is already recorded.
    """
    if os.environ.get("KAI_BENCHMARK") != "cybergym":
        return

    verified = state_manager.get_exploits(run_id, status="verified")
    soft = state_manager.get_exploits(run_id, status="soft_verified")
    candidates = verified + soft
    if not candidates:
        return

    target = None
    for cand in candidates:
        prior = state_manager.get_fix_attempts(run_id, cand.exploit_id)
        if not prior:
            target = cand
            break
    if target is None:
        return

    log.info(
        "post-pipeline fixer: invoking on exploit_id=%s status=%s "
        "(model did not call spawn_fixer in-loop)",
        target.exploit_id,
        target.status,
    )

    from kai.definitions.exploit.config import fixer_config
    from kai.definitions.exploit.parsers import process_fixer_result

    cfg = inject_workspace(
        fixer_config,
        recipe,
        verbose=verbose,
        log_structured=log_structured or None,
    )
    cfg = inject_state_manager(
        cfg,
        state_manager,
        run_id,
        save_rollouts=save_rollouts,
        rollout_agents=rollout_agents,
        _depth=1,
    )

    context = {
        "exploit_id": target.exploit_id,
        "hypothesis": target.hypothesis,
        "file": target.file,
        "function": target.function,
        "poc_code": target.poc_code or "",
    }

    prior_status = target.status
    try:
        agent = RecursiveAgent(cfg)
        result = agent.completion(context)
        process_fixer_result(
            state_manager,
            run_id,
            {"exploit_id": target.exploit_id},
            result.response,
        )
    except Exception:
        log.exception("post-pipeline fixer failed for %s", target.exploit_id)
        try:
            state_manager.update_exploit(run_id, target.exploit_id, status=prior_status)
        except Exception:
            log.exception(
                "post-pipeline fixer: could not restore %s to %s",
                target.exploit_id,
                prior_status,
            )


def _run_chain_assembler(
    recipe: WorkspaceRecipe,
    *,
    state_manager: StateManager,
    run_id: str,
    threat_context: ThreatContext | None = None,
    verbose: bool = False,
    log_structured: bool = False,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
) -> str | None:
    """Run the chain assembler agent. Returns raw result or None."""
    from kai.definitions.exploit.config import chain_assembler_config
    from kai.definitions.exploit.parsers import process_chain_result

    verified = state_manager.get_exploits(
        run_id, status="verified"
    ) + state_manager.get_exploits(run_id, status="verified_and_fixed")
    # Cybergym: the in-pipeline verifier cannot reach the strict harness
    # server, so promising PoCs land at status="soft_verified" instead
    # of "verified". Without this branch the inner guard silently drops
    # the chain_assembler stage on every cybergym run (chain_assembler
    # rollout missing across R19-R26 even though the outer guard in
    # _run_exploit_loop did kick off the thread).
    if os.environ.get("KAI_BENCHMARK") == "cybergym":
        verified += state_manager.get_exploits(run_id, status="soft_verified")
    if not verified:
        log.info(
            "chain_assembler: no verified/soft_verified records for run %s, skipping",
            run_id,
        )
        return None
    log.info(
        "chain_assembler: starting on %d verified record(s) for run %s",
        len(verified),
        run_id,
    )

    candidates = state_manager.get_exploits(run_id, status="candidate")
    failed = state_manager.get_exploits(run_id, status="failed")
    existing_chains = state_manager.get_chains(run_id)

    context: dict[str, Any] = {
        "master_path": recipe.master_path,
        "verified_exploits": [e.to_dict() for e in verified],
        "candidates": [e.to_dict() for e in candidates],
        "failed": [e.to_dict() for e in failed],
        "existing_chains": [c.to_dict() for c in existing_chains],
    }
    if threat_context is not None:
        context["threat_context"] = threat_context.to_dict()

    # Build graph tools and inject
    graph = TreeSitterBuilder().build(recipe.master_path)
    graph_tools = make_graph_tools(graph)

    cfg = inject_workspace(
        chain_assembler_config,
        recipe,
        verbose=verbose,
        log_structured=log_structured or None,
    )
    cfg = replace(cfg, tools={**cfg.tools, **graph_tools})

    # Attach state hooks + rollout recording.
    # _depth=1 so the chain assembler gets iteration tracking but NOT
    # root-level extras (ExploitsProxy, spawn_wrappers, on_extend).
    cfg = inject_state_manager(
        cfg,
        state_manager,
        run_id,
        save_rollouts=save_rollouts,
        rollout_agents=rollout_agents,
        _depth=1,
    )

    try:
        agent = RecursiveAgent(cfg)
        result = agent.completion(context)
        process_chain_result(state_manager, run_id, result.response)
        return result.response
    except Exception:
        log.exception("Chain assembler failed for run %s", run_id)
        return None


def _run_exploit_loop(
    recipe: WorkspaceRecipe,
    *,
    verbose: bool = False,
    log_file: str = "",
    log_structured: bool = False,
    instructions: str = "",
    state_manager: StateManager | None = None,
    run_id: str | None = None,
    save_rollouts: bool = False,
    rollout_agents: set[str] | None = None,
    threat_context: ThreatContext | None = None,
    skip_fixer: bool = False,
    no_iterative: bool = False,
) -> RLMChatCompletion:
    """Run the exploit agent, optionally followed by iterative re-verification."""
    chain_thread: threading.Thread | None = None

    try:
        result = run_exploit(
            recipe,
            verbose=verbose,
            log_file=log_file,
            log_structured=log_structured,
            instructions=instructions,
            state_manager=state_manager,
            run_id=run_id,
            save_rollouts=save_rollouts,
            rollout_agents=rollout_agents,
            threat_context=threat_context,
            skip_fixer=skip_fixer,
        )

        # Save intermediate so no work is lost
        _save_result(result, None)

        # Cybergym: if the model never called spawn_critic in-loop but
        # we have a soft_verified record, force the critic stage now.
        # Synchronous so chain_assembler (below) sees the enrichment.
        if state_manager is not None and run_id is not None:
            _maybe_run_post_pipeline_critic(
                recipe,
                state_manager=state_manager,
                run_id=run_id,
                verbose=verbose,
                log_structured=log_structured,
                save_rollouts=save_rollouts,
                rollout_agents=rollout_agents,
            )

        # Cybergym: same shape — model rarely calls spawn_fixer on
        # soft_verified records, so the fixer rollout / fix_attempts /
        # fixes JSONs are missing from the run. Force a fixer pass to
        # match the healthy-reference rollout structure.
        if not skip_fixer and state_manager is not None and run_id is not None:
            _maybe_run_post_pipeline_fixer(
                recipe,
                state_manager=state_manager,
                run_id=run_id,
                verbose=verbose,
                log_structured=log_structured,
                save_rollouts=save_rollouts,
                rollout_agents=rollout_agents,
            )

        # Launch chain assembler if verified exploits exist. For
        # cybergym, also accept ``soft_verified`` candidates (the
        # in-pipeline verifier cannot reach the strict harness server,
        # so promising-looking PoCs land in soft_verified instead of
        # verified — chain_assembler should still polish them).
        if state_manager is not None and run_id is not None:
            verified = state_manager.get_exploits(run_id, status="verified")
            verified += state_manager.get_exploits(run_id, status="verified_and_fixed")
            if os.environ.get("KAI_BENCHMARK") == "cybergym":
                verified += state_manager.get_exploits(run_id, status="soft_verified")
            if verified:
                chain_thread = threading.Thread(
                    target=_run_chain_assembler,
                    kwargs={
                        "recipe": recipe,
                        "state_manager": state_manager,
                        "run_id": run_id,
                        "threat_context": threat_context,
                        "verbose": verbose,
                        "log_structured": log_structured,
                        "save_rollouts": save_rollouts,
                        "rollout_agents": rollout_agents,
                    },
                )
                chain_thread.start()
    finally:
        # Always wait for the chain assembler — it writes to the
        # state directory and needs master_dir alive.
        if chain_thread is not None and chain_thread.is_alive():
            chain_thread.join(timeout=300)

    # --- Patch assembly + follow-up recipe ---
    if not no_iterative and state_manager is not None and run_id is not None:
        recipe_path = _maybe_run_patch_assembler(
            recipe,
            state_manager,
            run_id,
            verbose=verbose,
            log_structured=log_structured,
            save_rollouts=save_rollouts,
            rollout_agents=rollout_agents,
        )
        if recipe_path is not None:
            log.info("Patched follow-up recipe: %s", recipe_path)

    return result


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
    agent_parser.add_argument(
        "--threat-context",
        default=None,
        help="Path to YAML/JSON threat model file.",
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
    pipe_parser.add_argument(
        "--threat-context",
        default=None,
        help="Path to YAML/JSON threat model file.",
    )
    pipe_parser.add_argument(
        "--skip-fixer",
        action="store_true",
        default=False,
        help="Skip fixer agent — only analyze and verify.",
    )
    pipe_parser.add_argument(
        "--no-iterative",
        action="store_true",
        default=False,
        help="Disable iterative re-verification of unreachable rejects.",
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
        state_dir = args.state_dir
        no_state = args.no_state
        no_iterative = args.no_iterative or os.environ.get("KAI_NO_ITERATIVE", "") in (
            "1",
            "true",
            "yes",
        )
        tc: ThreatContext | None = None
        if args.threat_context:
            tc = _load_threat_context(args.threat_context)
        sm: StateManager | None = None
        rid: str | None = None
        try:
            if args.recipe:
                with open(args.recipe) as f:
                    recipe_data = json.load(f)
                try:
                    recipe = WorkspaceRecipe.from_dict(recipe_data)
                except InvalidRecipeError as exc:
                    raise SystemExit(
                        f"--recipe {args.recipe} is invalid: {exc}"
                    ) from exc
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
                    state_manager=sm,
                    run_id=rid,
                    save_rollouts=save_rollouts,
                    rollout_agents=rollout_agents,
                    threat_context=tc,
                    skip_fixer=args.skip_fixer,
                    no_iterative=no_iterative,
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
                    state_dir=state_dir,
                    no_state=no_state,
                    save_rollouts=save_rollouts,
                    rollout_agents=rollout_agents,
                    state_manager=sm,
                    run_id=rid,
                    threat_context=tc,
                    skip_fixer=args.skip_fixer,
                    no_iterative=no_iterative,
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
