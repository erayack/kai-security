#!/usr/bin/env python
"""
Playground: Dispatcher E2E Demo

Full Kai v2 pipeline for security analysis:
1. Boot (preprocessing: setup → graph → profiler → actors → invariants → planning)
2. Run Loop (execute missions with STATE/QUANT agents, optionally BLACKBOX/GAMIFIED)
3. Verification (inline after each exploit found)
4. Fixing (after all missions complete, generates patches for verified exploits)

Usage:
    # Basic run (State/Quant only, no exploration)
    python scripts/playground_dispatcher.py --repo-path ./test-repos/your-contracts

    # With custom models for each agent
    python scripts/playground_dispatcher.py --repo-path ./test-repos/your-contracts \
        --model anthropic/claude-opus-4.5 \
        --setup-model openai/gpt-4.1-mini \
        --verifier-model anthropic/claude-opus-4.5 \
        --invariant-model openai/gpt-4.1-mini \
        --fixer-model openai/gpt-4.1-mini \
        --compile-timeout 900 --test-timeout 300

    # With exploration (Blackbox + Gamified phases)
    python scripts/playground_dispatcher.py --repo-path ./test-repos/your-contracts --exploration

Model Options:
    --model           Main model for State/Quant agents
    --setup-model     Model for setup/workspace validation
    --verifier-model  Model for exploit verification
    --invariant-model Model for invariant synthesis
    --fixer-model     Model for fix generation
    --dedupe-model    Model for exploit deduplication
    --gamified-model  Model for gamified exploration
    --fallback-model  Fallback when primary model fails

Timeout Options:
    --compile-timeout Compilation timeout in seconds (default: 120)
    --test-timeout    Test timeout in seconds (default: 120)

Other Options:
    --repo-path       Path to target repository (required)
    --concurrent      Max concurrent agents (default: 2)
    --max-turns       Max turns per agent (default: 32)
    --exploration     Enable Blackbox/Gamified exploration phases
    --save-rollouts   Save agent conversation rollouts to output/rollouts/
    --no-fixer        Disable fixer agent to reduce costs during debugging

Output:
    output/playground/{repo}_{timestamp}/
    ├── results.json      # Full report with campaigns, missions, verdicts
    ├── fixes.json        # Generated fixes (if any)
    ├── invariants.json   # Generated invariants (if --save-rollouts)
    ├── workspaces/       # Agent workspaces
    └── rollouts/         # Agent conversations (if --save-rollouts)
        ├── missions/     # State/Quant/Blackbox/Gamified agents
        ├── verifier/     # Verifier agent conversations
        └── fixer/        # Fixer agent conversations
"""

import asyncio
import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from kai.agents import settings  # noqa: E402
from kai.dispatcher.core import Dispatcher, DispatcherConfig  # noqa: E402
from kai.schemas import CampaignBudget  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("playground")


async def run_dispatcher_demo(
    repo_path: str,
    model: str = settings.MAIN_DEFAULT_MODEL,
    setup_model: str = settings.SETUP_DEFAULT_MODEL,
    verifier_model: str = settings.VERIFIER_DEFAULT_MODEL,
    invariant_model: str = settings.INVARIANT_DEFAULT_MODEL,
    fixer_model: str = settings.FIXER_DEFAULT_MODEL,
    dedupe_model: str = settings.DEDUPE_DEFAULT_MODEL,
    gamified_model: str = settings.GAMIFIED_DEFAULT_MODEL,
    fallback_model: str = settings.FALLBACK_MODEL,
    max_concurrent: int = 2,
    max_turns: int = settings.MAX_TOOL_TURNS,
    include_exploration: bool = False,
    save_rollouts: bool = False,
    disable_fixer: bool = False,
    compile_timeout: int = 120,
    test_timeout: int = 120,
) -> None:
    """
    Run the full dispatcher pipeline and print results.
    """
    repo_path = str(Path(repo_path).resolve())
    repo_name = Path(repo_path).name

    # Setup output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = PROJECT_ROOT / "output" / "playground" / f"{repo_name}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 70}")
    print("DISPATCHER PLAYGROUND")
    print(f"{'=' * 70}")
    print(f"Repository: {repo_path}")
    print(f"Output: {output_dir}")
    print("\nModels:")
    print(f"  Main (State/Quant): {model}")
    print(f"  Setup:              {setup_model}")
    print(f"  Verifier:           {verifier_model}")
    print(f"  Invariant:          {invariant_model}")
    print(f"  Fixer:              {fixer_model}")
    print(f"  Dedupe:             {dedupe_model}")
    print(f"  Gamified:           {gamified_model}")
    print(f"  Fallback:           {fallback_model}")
    print(f"\nTimeouts:")
    print(f"  Compile: {compile_timeout}s | Test: {test_timeout}s")
    print(f"\nExploration: {'enabled' if include_exploration else 'disabled'}")
    print(f"Fixer: {'disabled' if disable_fixer else 'enabled'}")
    print(f"Save rollouts: {'enabled' if save_rollouts else 'disabled'}")
    print(f"{'=' * 70}\n")

    # Configure dispatcher
    config = DispatcherConfig(
        max_concurrent_agents=max_concurrent,
        max_invariants_per_cluster=5,
        max_campaigns=10,
        include_exploration=include_exploration,
        default_budget=CampaignBudget(
            max_missions=10,
            max_agents=4,
            max_turns_per_agent=max_turns,
        ),
        workspace_dir=str(output_dir / "workspaces"),
        model=model,
        setup_model=setup_model,
        verifier_model=verifier_model,
        invariant_model=invariant_model,
        fixer_model=fixer_model,
        dedupe_model=dedupe_model,
        gamified_model=gamified_model,
        fallback_model=fallback_model,
        use_openai=False,
        save_rollouts=save_rollouts,
        rollouts_dir=str(output_dir / "rollouts") if save_rollouts else None,
        disable_fixer=disable_fixer,
        timeout_compile_s=compile_timeout,
        timeout_test_s=test_timeout,
    )

    # Create dispatcher (no state manager for simplicity)
    dispatcher = Dispatcher(config=config)

    # =========================================================================
    # PHASE 1: BOOT
    # =========================================================================
    print("\n[PHASE 1] BOOT - Running preprocessing pipeline...")
    start_time = datetime.now()

    success = await dispatcher.boot(
        repo_path=repo_path,
        model_name=model,
        use_openai=False,
    )

    if not success:
        print("❌ Boot failed!")
        return

    print(f"✓ Boot complete in {(datetime.now() - start_time).seconds}s")
    print(f"  - Invariants: {len(dispatcher.invariants)}")
    print(f"  - Campaigns: {len(dispatcher.campaigns)}")
    print(f"  - Missions queued: {dispatcher.mission_queue.qsize()}")

    # Show discovered invariants
    if dispatcher.invariants:
        print("\n  Invariants discovered:")
        for inv in list(dispatcher.invariants.values())[:5]:
            inv_type = inv.type.value if inv.type else "?"
            rule_preview = inv.rule[:60] + "..." if len(inv.rule) > 60 else inv.rule
            print(f"    [{inv_type}] {inv.id}")
            print(f"        {rule_preview}")
        if len(dispatcher.invariants) > 5:
            print(f"    ... and {len(dispatcher.invariants) - 5} more")

    # Save invariants if rollouts enabled
    if save_rollouts and dispatcher.invariants:
        invariants_path = output_dir / "invariants.json"
        with open(invariants_path, "w") as f:
            json.dump(
                [inv.model_dump() for inv in dispatcher.invariants.values()],
                f,
                indent=2,
                default=str,
            )
        print(f"\n  Invariants saved to: {invariants_path}")

    # =========================================================================
    # PHASE 2: RUN LOOP (includes inline verification + post-loop fixing)
    # =========================================================================
    print("\n[PHASE 2] RUN LOOP - Executing missions...")

    await dispatcher.run_loop()

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # =========================================================================
    # PHASE 3: RESULTS
    # =========================================================================
    print(f"\n{'=' * 70}")
    print("RESULTS")
    print(f"{'=' * 70}")

    print(f"\nDuration: {duration:.1f}s")
    print(f"Missions completed: {len(dispatcher.completed_missions)}")
    print(f"Exploit candidates: {len(dispatcher.exploit_candidates)}")
    print(f"Verdicts: {len(dispatcher.verdicts)}")
    print(f"Fixes generated: {len(dispatcher.fixes)}")

    # Show verified exploits
    verified = [v for v in dispatcher.verdicts if v.is_valid]
    rejected = [v for v in dispatcher.verdicts if not v.is_valid]

    if verified:
        print(f"\n{'=' * 70}")
        print(f"VERIFIED EXPLOITS ({len(verified)})")
        print(f"{'=' * 70}")
        for i, verdict in enumerate(verified):
            severity = verdict.severity.value.upper() if verdict.severity else "?"
            vuln_class = verdict.vulnerability_class or "unknown"
            print(f"\n[{i + 1}] {severity} - {vuln_class}")
            print(f"    Mission: {verdict.mission_id}")
            print(f"    Invariant: {verdict.invariant_id}")
            if verdict.reasoning:
                reasoning = (
                    verdict.reasoning[:100] + "..."
                    if len(verdict.reasoning) > 100
                    else verdict.reasoning
                )
                print(f"    Reasoning: {reasoning}")

            # Show associated fixes
            if verdict.fixes:
                print(f"    Fixes: {len(verdict.fixes)}")
                for fix in verdict.fixes:
                    summary = (
                        fix.summary[:60] + "..."
                        if len(fix.summary) > 60
                        else fix.summary
                    )
                    print(f"      - {fix.fix_id}: {summary}")
                    print(
                        f"        Compiled: {fix.compiled}, Tests passed: {fix.tests_passed}"
                    )

    if rejected:
        print(f"\n{'-' * 70}")
        print(f"REJECTED ({len(rejected)})")
        print(f"{'-' * 70}")
        for verdict in rejected[:3]:
            reason = verdict.rejection_reason or "No reason"
            reason = reason[:80] + "..." if len(reason) > 80 else reason
            print(f"  - {verdict.mission_id}: {reason}")
        if len(rejected) > 3:
            print(f"  ... and {len(rejected) - 3} more")

    # Show fixes summary
    if dispatcher.fixes:
        print(f"\n{'=' * 70}")
        print(f"FIXES GENERATED ({len(dispatcher.fixes)})")
        print(f"{'=' * 70}")
        for fix in dispatcher.fixes:
            print(f"\n[{fix.fix_id}]")
            print(f"  Mission: {fix.mission_id}")
            print(f"  Summary: {fix.summary}")
            print(
                f"  Files: {', '.join(fix.files_changed) if fix.files_changed else 'N/A'}"
            )
            print(f"  Compiled: {fix.compiled} | Tests passed: {fix.tests_passed}")
            if fix.canonical_diff:
                diff_preview = (
                    fix.canonical_diff[:200] + "..."
                    if len(fix.canonical_diff) > 200
                    else fix.canonical_diff
                )
                print(f"  Diff preview:\n{diff_preview}")

    # Export full results
    report_path = output_dir / "results.json"
    dispatcher.export_results(str(report_path))

    # Also save fixes separately
    if dispatcher.fixes:
        fixes_path = output_dir / "fixes.json"
        with open(fixes_path, "w") as f:
            json.dump(
                [fix.model_dump() for fix in dispatcher.fixes], f, indent=2, default=str
            )
        print(f"\nFixes saved to: {fixes_path}")

    print(f"\nFull report: {report_path}")
    print(f"\n{'=' * 70}")
    print("DONE")
    print(f"{'=' * 70}\n")


def main():
    parser = argparse.ArgumentParser(description="Dispatcher E2E Playground")
    parser.add_argument(
        "--repo-path",
        type=str,
        required=True,
        help="Path to target repository",
    )
    # Model configurations
    parser.add_argument(
        "--model",
        type=str,
        default=settings.MAIN_DEFAULT_MODEL,
        help=f"Main model for State/Quant agents (default: {settings.MAIN_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--setup-model",
        type=str,
        default=settings.SETUP_DEFAULT_MODEL,
        help=f"Model for setup agent (default: {settings.SETUP_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--verifier-model",
        type=str,
        default=settings.VERIFIER_DEFAULT_MODEL,
        help=f"Model for verifier agent (default: {settings.VERIFIER_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--invariant-model",
        type=str,
        default=settings.INVARIANT_DEFAULT_MODEL,
        help=f"Model for invariant synthesis (default: {settings.INVARIANT_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--fixer-model",
        type=str,
        default=settings.FIXER_DEFAULT_MODEL,
        help=f"Model for fixer agent (default: {settings.FIXER_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--dedupe-model",
        type=str,
        default=settings.DEDUPE_DEFAULT_MODEL,
        help=f"Model for deduplication (default: {settings.DEDUPE_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--gamified-model",
        type=str,
        default=settings.GAMIFIED_DEFAULT_MODEL,
        help=f"Model for gamified agent (default: {settings.GAMIFIED_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--fallback-model",
        type=str,
        default=settings.FALLBACK_MODEL,
        help=f"Fallback model for failures (default: {settings.FALLBACK_MODEL})",
    )
    # Timeout configurations
    parser.add_argument(
        "--compile-timeout",
        type=int,
        default=120,
        help="Compilation timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--test-timeout",
        type=int,
        default=120,
        help="Test timeout in seconds (default: 120)",
    )
    # Agent configurations
    parser.add_argument(
        "--concurrent",
        type=int,
        default=2,
        help="Max concurrent agents (default: 2)",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=settings.MAX_TOOL_TURNS,
        help=f"Max turns per agent (default: {settings.MAX_TOOL_TURNS})",
    )
    parser.add_argument(
        "--exploration",
        action="store_true",
        help="Enable Blackbox/Gamified exploration phases (disabled by default)",
    )
    parser.add_argument(
        "--save-rollouts",
        action="store_true",
        help="Save agent conversation rollouts for debugging (default: disabled)",
    )
    parser.add_argument(
        "--no-fixer",
        action="store_true",
        help="Disable fixer agent to reduce costs during debugging (default: enabled)",
    )

    args = parser.parse_args()

    # Resolve path
    repo_path = Path(args.repo_path)
    if not repo_path.is_absolute():
        repo_path = PROJECT_ROOT / repo_path

    if not repo_path.exists():
        print(f"Error: Repository not found: {repo_path}")
        sys.exit(1)

    asyncio.run(
        run_dispatcher_demo(
            repo_path=str(repo_path),
            model=args.model,
            setup_model=args.setup_model,
            verifier_model=args.verifier_model,
            invariant_model=args.invariant_model,
            fixer_model=args.fixer_model,
            dedupe_model=args.dedupe_model,
            gamified_model=args.gamified_model,
            fallback_model=args.fallback_model,
            max_concurrent=args.concurrent,
            max_turns=args.max_turns,
            include_exploration=args.exploration,
            save_rollouts=args.save_rollouts,
            disable_fixer=args.no_fixer,
            compile_timeout=args.compile_timeout,
            test_timeout=args.test_timeout,
        )
    )


if __name__ == "__main__":
    main()
