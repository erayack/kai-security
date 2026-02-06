#!/usr/bin/env python
"""
Batch Runner for Cantina Bug Bounty Repositories

Runs Kai security analysis on multiple repositories sequentially:
1. Clone repo from GitHub
2. Run Kai dispatcher
3. Save outputs to output/cantina_batch/{bounty}/{repo}/
4. Delete cloned repo to free disk space
5. Generate consolidated report at the end
6. Optionally save results to MongoDB for tracking

Usage:
    uv run python scripts/batch_cantina_runner.py

    # Configure all models at once
    uv run python scripts/batch_cantina_runner.py --model anthropic/claude-opus-4.5

    # Configure individual agent models
    uv run python scripts/batch_cantina_runner.py \\
        --main-model google/gemini-3-flash-preview \\
        --setup-model openai/gpt-5.2-codex \\
        --verifier-model google/gemini-3-flash-preview \\
        --fixer-model anthropic/claude-opus-4.5

    # Save results to MongoDB (requires MONGO_URI env var)
    uv run python scripts/batch_cantina_runner.py --save-to-db

    # Dry run
    uv run python scripts/batch_cantina_runner.py --dry-run

    # Resume from specific repo
    uv run python scripts/batch_cantina_runner.py --resume euler-xyz/euler-vault-kit
"""

import asyncio
import argparse
import json
import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from kai.agents import settings  # noqa: E402
from kai.dispatcher.core import Dispatcher, DispatcherConfig  # noqa: E402
from kai.schemas import CampaignBudget  # noqa: E402

# Optional DB import (for --save-to-db flag)
try:
    DEPLOY_DIR = PROJECT_ROOT / "deploy" / "aws"
    sys.path.insert(0, str(DEPLOY_DIR))
    from db import KaiBatchDB, RepoExecutionResult, VerifiedExploit
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False


@dataclass
class ModelConfig:
    """Configuration of models used for each agent type."""
    main: str = settings.MAIN_DEFAULT_MODEL          # State/Quant agents
    setup: str = settings.SETUP_DEFAULT_MODEL        # Setup agent
    verifier: str = settings.VERIFIER_DEFAULT_MODEL  # Verifier agent
    invariant: str = settings.INVARIANT_DEFAULT_MODEL  # Invariant generation
    fixer: str = settings.FIXER_DEFAULT_MODEL        # Fixer agent
    dedupe: str = settings.DEDUPE_DEFAULT_MODEL      # Deduplication
    gamified: str = settings.GAMIFIED_DEFAULT_MODEL  # Gamified agent
    fallback: str = settings.FALLBACK_MODEL          # Fallback model

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)

    @classmethod
    def from_args(cls, args) -> "ModelConfig":
        """Create ModelConfig from CLI arguments."""
        config = cls()

        # If --model is set, use it as default for main agents
        if args.model:
            config.main = args.model

        # Override with specific model args if provided
        if args.main_model:
            config.main = args.main_model
        if args.setup_model:
            config.setup = args.setup_model
        if args.verifier_model:
            config.verifier = args.verifier_model
        if args.invariant_model:
            config.invariant = args.invariant_model
        if args.fixer_model:
            config.fixer = args.fixer_model
        if args.dedupe_model:
            config.dedupe = args.dedupe_model
        if args.gamified_model:
            config.gamified = args.gamified_model
        if args.fallback_model:
            config.fallback = args.fallback_model

        return config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("batch_runner")


@dataclass
class BountyRepo:
    """A repository in a bug bounty program."""
    bounty_name: str
    bounty_amount: str
    repo: str  # e.g., "Uniswap/v4-core"

    @property
    def org(self) -> str:
        return self.repo.split("/")[0]

    @property
    def name(self) -> str:
        return self.repo.split("/")[1]

    @property
    def github_url(self) -> str:
        return f"https://github.com/{self.repo}"


# All 17 verified Solidity repositories from Cantina bounties
CANTINA_REPOS = [
    # Uniswap - $15.5M
    BountyRepo("Uniswap", "$15,500,000", "Uniswap/v4-core"),

    # Euler - $7.5M
    BountyRepo("Euler", "$7,500,000", "euler-xyz/ethereum-vault-connector"),
    BountyRepo("Euler", "$7,500,000", "euler-xyz/euler-vault-kit"),
    BountyRepo("Euler", "$7,500,000", "euler-xyz/euler-price-oracle"),
    BountyRepo("Euler", "$7,500,000", "euler-xyz/reward-streams"),
    BountyRepo("Euler", "$7,500,000", "euler-xyz/fee-flow"),
    BountyRepo("Euler", "$7,500,000", "euler-xyz/euler-earn"),
    BountyRepo("Euler", "$7,500,000", "euler-xyz/euler-swap"),

    # Morpho - $2.5M
    BountyRepo("Morpho", "$2,500,000", "morpho-org/vault-v2"),
    BountyRepo("Morpho", "$2,500,000", "morpho-org/morpho-blue"),
    BountyRepo("Morpho", "$2,500,000", "morpho-org/metamorpho"),
    BountyRepo("Morpho", "$2,500,000", "morpho-org/bundler3"),
    BountyRepo("Morpho", "$2,500,000", "morpho-org/pre-liquidation"),

    # Pendle - $2M
    BountyRepo("Pendle", "$2,000,000", "pendle-finance/pendle-core-v2-public"),
    BountyRepo("Pendle", "$2,000,000", "pendle-finance/boros-core-public"),
    BountyRepo("Pendle", "$2,000,000", "pendle-finance/Pendle-SY-Public"),

    # Ventuals - $1M
    BountyRepo("Ventuals", "$1,000,000", "ventuals/ventuals-contracts"),
]


@dataclass
class RepoResult:
    """Result of running Kai on a repository."""
    repo: BountyRepo
    success: bool
    start_time: datetime
    end_time: datetime
    output_dir: Optional[Path]
    model_config: Optional[ModelConfig] = None  # Track models used
    invariants_count: int = 0
    campaigns_count: int = 0
    missions_completed: int = 0
    exploit_candidates: int = 0
    verified_exploits: int = 0
    fixes_generated: int = 0
    error: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()


def clone_repo(repo: BountyRepo, clone_dir: Path) -> bool:
    """Clone a repository from GitHub."""
    logger.info(f"Cloning {repo.repo}...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo.github_url, str(clone_dir)],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info(f"Cloned {repo.repo} to {clone_dir}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to clone {repo.repo}: {e.stderr}")
        return False


def delete_repo(clone_dir: Path) -> bool:
    """Delete a cloned repository to free disk space."""
    try:
        if clone_dir.exists():
            shutil.rmtree(clone_dir)
            logger.info(f"Deleted {clone_dir}")
        return True
    except Exception as e:
        logger.error(f"Failed to delete {clone_dir}: {e}")
        return False


async def run_kai_on_repo(
    repo: BountyRepo,
    clone_dir: Path,
    output_dir: Path,
    model_config: ModelConfig,
    max_concurrent: int = 2,
    save_rollouts: bool = False,
    compile_timeout: int = 120,
    test_timeout: int = 120,
) -> RepoResult:
    """Run Kai dispatcher on a single repository."""
    start_time = datetime.now()

    # Save model config for this run
    model_config_path = output_dir / "model_config.json"
    with open(model_config_path, "w") as f:
        json.dump(model_config.to_dict(), f, indent=2)

    try:
        # Configure dispatcher with all model settings
        config = DispatcherConfig(
            max_concurrent_agents=max_concurrent,
            max_invariants_per_cluster=5,
            max_campaigns=10,
            include_exploration=False,  # Keep it focused
            default_budget=CampaignBudget(
                max_missions=10,
                max_agents=4,
                max_turns_per_agent=settings.MAX_TOOL_TURNS,
            ),
            workspace_dir=str(output_dir / "workspaces"),
            # Model configuration
            model=model_config.main,
            setup_model=model_config.setup,
            verifier_model=model_config.verifier,
            invariant_model=model_config.invariant,
            fixer_model=model_config.fixer,
            dedupe_model=model_config.dedupe,
            fallback_model=model_config.fallback,
            use_openai=False,
            save_rollouts=save_rollouts,
            rollouts_dir=str(output_dir / "rollouts") if save_rollouts else None,
            disable_fixer=False,
            # Timeout configuration
            timeout_compile_s=compile_timeout,
            timeout_test_s=test_timeout,
        )

        dispatcher = Dispatcher(config=config)

        # Boot phase
        logger.info(f"[{repo.name}] Running boot phase...")
        success = await dispatcher.boot(
            repo_path=str(clone_dir),
            model_name=model_config.main,
            use_openai=False,
        )

        if not success:
            return RepoResult(
                repo=repo,
                success=False,
                start_time=start_time,
                end_time=datetime.now(),
                output_dir=output_dir,
                model_config=model_config,
                error="Boot phase failed",
            )

        logger.info(f"[{repo.name}] Boot complete. Invariants: {len(dispatcher.invariants)}, Campaigns: {len(dispatcher.campaigns)}")

        # Run loop
        logger.info(f"[{repo.name}] Running missions...")
        await dispatcher.run_loop()

        end_time = datetime.now()

        # Export results
        results_path = output_dir / "results.json"
        dispatcher.export_results(str(results_path))

        # Save fixes separately
        if dispatcher.fixes:
            fixes_path = output_dir / "fixes.json"
            with open(fixes_path, "w") as f:
                json.dump(
                    [fix.model_dump() for fix in dispatcher.fixes],
                    f,
                    indent=2,
                    default=str,
                )

        # Save invariants
        if dispatcher.invariants:
            invariants_path = output_dir / "invariants.json"
            with open(invariants_path, "w") as f:
                json.dump(
                    [inv.model_dump() for inv in dispatcher.invariants.values()],
                    f,
                    indent=2,
                    default=str,
                )

        verified_count = len([v for v in dispatcher.verdicts if v.is_valid])

        return RepoResult(
            repo=repo,
            success=True,
            start_time=start_time,
            end_time=end_time,
            output_dir=output_dir,
            model_config=model_config,
            invariants_count=len(dispatcher.invariants),
            campaigns_count=len(dispatcher.campaigns),
            missions_completed=len(dispatcher.completed_missions),
            exploit_candidates=len(dispatcher.exploit_candidates),
            verified_exploits=verified_count,
            fixes_generated=len(dispatcher.fixes),
        )

    except Exception as e:
        logger.exception(f"[{repo.name}] Error running Kai")
        return RepoResult(
            repo=repo,
            success=False,
            start_time=start_time,
            end_time=datetime.now(),
            output_dir=output_dir,
            model_config=model_config,
            error=str(e),
        )


def generate_consolidated_report(results: list[RepoResult], output_dir: Path, model_config: ModelConfig) -> Path:
    """Generate a consolidated report from all results."""
    report_path = output_dir / "consolidated_report.md"

    # Collect all verified exploits
    all_verified = []
    for result in results:
        if result.success and result.output_dir:
            results_file = result.output_dir / "results.json"
            if results_file.exists():
                with open(results_file) as f:
                    data = json.load(f)
                    verdicts = data.get("verdicts", [])
                    for v in verdicts:
                        if v.get("is_valid"):
                            v["_repo"] = result.repo.repo
                            v["_bounty"] = result.repo.bounty_name
                            v["_bounty_amount"] = result.repo.bounty_amount
                            all_verified.append(v)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    all_verified.sort(key=lambda x: severity_order.get(x.get("severity", "").lower(), 5))

    # Generate report
    with open(report_path, "w") as f:
        f.write("# Cantina Bug Bounty Batch Analysis Report\n\n")
        f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")

        # Model Configuration
        f.write("## Model Configuration\n\n")
        f.write("| Agent | Model |\n")
        f.write("|-------|-------|\n")
        f.write(f"| Main (State/Quant) | `{model_config.main}` |\n")
        f.write(f"| Setup | `{model_config.setup}` |\n")
        f.write(f"| Verifier | `{model_config.verifier}` |\n")
        f.write(f"| Invariant | `{model_config.invariant}` |\n")
        f.write(f"| Fixer | `{model_config.fixer}` |\n")
        f.write(f"| Dedupe | `{model_config.dedupe}` |\n")
        f.write(f"| Gamified | `{model_config.gamified}` |\n")
        f.write(f"| Fallback | `{model_config.fallback}` |\n")
        f.write("\n")

        # Summary
        f.write("## Summary\n\n")
        total_repos = len(results)
        successful = len([r for r in results if r.success])
        failed = total_repos - successful
        total_verified = len(all_verified)

        f.write(f"- **Repositories analyzed:** {successful}/{total_repos}\n")
        f.write(f"- **Failed:** {failed}\n")
        f.write(f"- **Total verified exploits:** {total_verified}\n\n")

        # By bounty
        f.write("### By Bounty Program\n\n")
        f.write("| Bounty | Amount | Repos | Verified Exploits |\n")
        f.write("|--------|--------|-------|------------------|\n")

        bounties = {}
        for r in results:
            if r.repo.bounty_name not in bounties:
                bounties[r.repo.bounty_name] = {
                    "amount": r.repo.bounty_amount,
                    "repos": 0,
                    "verified": 0,
                }
            bounties[r.repo.bounty_name]["repos"] += 1
            bounties[r.repo.bounty_name]["verified"] += r.verified_exploits

        for name, data in bounties.items():
            f.write(f"| {name} | {data['amount']} | {data['repos']} | {data['verified']} |\n")

        f.write("\n")

        # Verified exploits detail
        if all_verified:
            f.write("## Verified Exploits\n\n")

            for i, v in enumerate(all_verified, 1):
                severity = v.get("severity", "unknown").upper()
                vuln_class = v.get("vulnerability_class", "unknown")
                repo = v.get("_repo", "unknown")
                bounty = v.get("_bounty", "unknown")

                f.write(f"### {i}. [{severity}] {vuln_class}\n\n")
                f.write(f"- **Repository:** {repo}\n")
                f.write(f"- **Bounty:** {bounty}\n")
                f.write(f"- **Mission ID:** {v.get('mission_id', 'N/A')}\n")
                f.write(f"- **Invariant ID:** {v.get('invariant_id', 'N/A')}\n\n")

                if v.get("reasoning"):
                    f.write(f"**Reasoning:**\n\n{v['reasoning']}\n\n")

                if v.get("fixes"):
                    f.write("**Fixes:**\n\n")
                    for fix in v["fixes"]:
                        f.write(f"- `{fix.get('fix_id', 'N/A')}`: {fix.get('summary', 'No summary')}\n")
                    f.write("\n")

                f.write("---\n\n")

        # Per-repo details
        f.write("## Repository Details\n\n")

        for result in results:
            status = "✅" if result.success else "❌"
            f.write(f"### {status} {result.repo.repo}\n\n")
            f.write(f"- **Bounty:** {result.repo.bounty_name} ({result.repo.bounty_amount})\n")
            f.write(f"- **Duration:** {result.duration_seconds:.1f}s\n")

            if result.success:
                f.write(f"- **Invariants:** {result.invariants_count}\n")
                f.write(f"- **Campaigns:** {result.campaigns_count}\n")
                f.write(f"- **Missions completed:** {result.missions_completed}\n")
                f.write(f"- **Exploit candidates:** {result.exploit_candidates}\n")
                f.write(f"- **Verified exploits:** {result.verified_exploits}\n")
                f.write(f"- **Fixes generated:** {result.fixes_generated}\n")
                f.write(f"- **Output:** `{result.output_dir}`\n")
            else:
                f.write(f"- **Error:** {result.error}\n")

            f.write("\n")

    logger.info(f"Consolidated report saved to {report_path}")
    return report_path


async def run_batch(
    repos: list[BountyRepo],
    model_config: ModelConfig,
    max_concurrent: int = 2,
    save_rollouts: bool = False,
    dry_run: bool = False,
    resume_from: Optional[str] = None,
    limit: Optional[int] = None,
    compile_timeout: int = 120,
    test_timeout: int = 120,
    save_to_db: bool = False,
) -> list[RepoResult]:
    """Run Kai on all repositories in sequence."""

    # Apply limit if specified
    if limit is not None and limit > 0:
        repos = repos[:limit]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_output_dir = PROJECT_ROOT / "output" / "cantina_batch" / timestamp
    clone_base_dir = PROJECT_ROOT / "temp_clones"

    batch_output_dir.mkdir(parents=True, exist_ok=True)
    clone_base_dir.mkdir(parents=True, exist_ok=True)

    # Save config for the entire batch
    batch_config_path = batch_output_dir / "batch_config.json"
    with open(batch_config_path, "w") as f:
        json.dump({
            "models": model_config.to_dict(),
            "timeouts": {
                "compile_s": compile_timeout,
                "test_s": test_timeout,
            },
            "max_concurrent": max_concurrent,
        }, f, indent=2)

    print(f"\n{'=' * 70}")
    print("CANTINA BATCH RUNNER")
    print(f"{'=' * 70}")
    print(f"Repositories: {len(repos)}" + (f" (limited from 17)" if limit else ""))
    print(f"Output: {batch_output_dir}")
    print(f"\nModel Configuration:")
    print(f"  Main (State/Quant): {model_config.main}")
    print(f"  Setup:              {model_config.setup}")
    print(f"  Verifier:           {model_config.verifier}")
    print(f"  Invariant:          {model_config.invariant}")
    print(f"  Fixer:              {model_config.fixer}")
    print(f"  Dedupe:             {model_config.dedupe}")
    print(f"  Gamified:           {model_config.gamified}")
    print(f"  Fallback:           {model_config.fallback}")
    print(f"\nTimeouts:")
    print(f"  Compile: {compile_timeout}s")
    print(f"  Test:    {test_timeout}s")
    print(f"{'=' * 70}\n")

    if dry_run:
        print("DRY RUN - would process these repos:\n")
        for i, repo in enumerate(repos, 1):
            print(f"  {i}. [{repo.bounty_name}] {repo.repo}")
        return []

    # Initialize DB if requested
    db = None
    if save_to_db:
        if not DB_AVAILABLE:
            logger.error("Database module not available. Install motor and pymongo.")
            save_to_db = False
        else:
            try:
                db = KaiBatchDB()
                await db.create_batch(
                    batch_id=timestamp,
                    repos=[r.repo for r in repos],
                    model_config=model_config.to_dict(),
                    compile_timeout_s=compile_timeout,
                    test_timeout_s=test_timeout,
                )
                logger.info(f"Created batch {timestamp} in database")
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                save_to_db = False
                db = None

    results: list[RepoResult] = []

    # Find resume point
    start_idx = 0
    if resume_from:
        for i, repo in enumerate(repos):
            if repo.repo == resume_from:
                start_idx = i
                logger.info(f"Resuming from {resume_from} (index {i})")
                break

    for i, repo in enumerate(repos[start_idx:], start_idx + 1):
        print(f"\n{'=' * 70}")
        print(f"[{i}/{len(repos)}] {repo.bounty_name}: {repo.repo}")
        print(f"Bounty: {repo.bounty_amount}")
        print(f"{'=' * 70}\n")

        clone_dir = clone_base_dir / repo.name
        output_dir = batch_output_dir / repo.bounty_name / repo.name
        output_dir.mkdir(parents=True, exist_ok=True)

        # Clean up any existing clone
        delete_repo(clone_dir)

        # Clone
        if not clone_repo(repo, clone_dir):
            results.append(RepoResult(
                repo=repo,
                success=False,
                start_time=datetime.now(),
                end_time=datetime.now(),
                output_dir=output_dir,
                error="Failed to clone repository",
            ))
            continue

        # Run Kai
        result = await run_kai_on_repo(
            repo=repo,
            clone_dir=clone_dir,
            output_dir=output_dir,
            model_config=model_config,
            max_concurrent=max_concurrent,
            save_rollouts=save_rollouts,
            compile_timeout=compile_timeout,
            test_timeout=test_timeout,
        )
        results.append(result)

        # Save to database if enabled
        if save_to_db and db:
            try:
                exec_result = RepoExecutionResult(
                    batch_id=timestamp,
                    repo=repo.repo,
                    bounty_name=repo.bounty_name,
                    bounty_amount=repo.bounty_amount,
                    success=result.success,
                    start_time=result.start_time,
                    end_time=result.end_time,
                    duration_seconds=result.duration_seconds,
                    model_config=model_config.to_dict(),
                    compile_timeout_s=compile_timeout,
                    test_timeout_s=test_timeout,
                    invariants_count=result.invariants_count,
                    campaigns_count=result.campaigns_count,
                    missions_completed=result.missions_completed,
                    exploit_candidates=result.exploit_candidates,
                    verified_exploits=result.verified_exploits,
                    fixes_generated=result.fixes_generated,
                    error=result.error,
                    results_path=str(result.output_dir / "results.json") if result.output_dir else None,
                )
                await db.save_repo_execution(exec_result)

                # Save verified exploits
                if result.success and result.output_dir:
                    results_file = result.output_dir / "results.json"
                    if results_file.exists():
                        with open(results_file) as f:
                            data = json.load(f)
                            for v in data.get("verdicts", []):
                                if v.get("is_valid"):
                                    exploit = VerifiedExploit(
                                        batch_id=timestamp,
                                        repo=repo.repo,
                                        bounty_name=repo.bounty_name,
                                        bounty_amount=repo.bounty_amount,
                                        severity=v.get("severity", "unknown"),
                                        vulnerability_class=v.get("vulnerability_class", "unknown"),
                                        mission_id=v.get("mission_id", ""),
                                        invariant_id=v.get("invariant_id", ""),
                                        reasoning=v.get("reasoning", ""),
                                        fixes=v.get("fixes", []),
                                        discovered_at=datetime.now(),
                                        model_config=model_config.to_dict(),
                                    )
                                    await db.save_verified_exploit(exploit)

                logger.info(f"Saved results to database for {repo.repo}")
            except Exception as e:
                logger.error(f"Failed to save to database: {e}")

        # Clean up clone to save disk space
        logger.info(f"Cleaning up {clone_dir}...")
        delete_repo(clone_dir)

        # Save intermediate progress
        progress_path = batch_output_dir / "progress.json"
        with open(progress_path, "w") as f:
            json.dump({
                "completed": i,
                "total": len(repos),
                "last_repo": repo.repo,
                "config": {
                    "models": model_config.to_dict(),
                    "timeouts": {
                        "compile_s": compile_timeout,
                        "test_s": test_timeout,
                    },
                },
                "results": [
                    {
                        "repo": r.repo.repo,
                        "success": r.success,
                        "verified_exploits": r.verified_exploits,
                        "duration": r.duration_seconds,
                    }
                    for r in results
                ]
            }, f, indent=2)

        # Summary so far
        verified_so_far = sum(r.verified_exploits for r in results)
        print(f"\n[Progress] {i}/{len(repos)} complete | Verified exploits so far: {verified_so_far}")

    # Clean up temp clone directory
    if clone_base_dir.exists() and not any(clone_base_dir.iterdir()):
        clone_base_dir.rmdir()

    # Complete batch in database
    if save_to_db and db:
        try:
            await db.complete_batch(timestamp)
            await db.close()
            logger.info(f"Batch {timestamp} marked complete in database")
        except Exception as e:
            logger.error(f"Failed to complete batch in database: {e}")

    # Generate consolidated report
    report_path = generate_consolidated_report(results, batch_output_dir, model_config)

    # Final summary
    print(f"\n{'=' * 70}")
    print("BATCH COMPLETE")
    print(f"{'=' * 70}")
    print(f"Total repositories: {len(results)}")
    print(f"Successful: {len([r for r in results if r.success])}")
    print(f"Failed: {len([r for r in results if not r.success])}")
    print(f"Total verified exploits: {sum(r.verified_exploits for r in results)}")
    print(f"\nConsolidated report: {report_path}")
    print(f"Output directory: {batch_output_dir}")
    print(f"{'=' * 70}\n")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Batch runner for Cantina bounty repos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test run with first 3 repos
  uv run python scripts/batch_cantina_runner.py --limit 3

  # Run with default models
  uv run python scripts/batch_cantina_runner.py

  # Set all agents to use same model
  uv run python scripts/batch_cantina_runner.py --model anthropic/claude-opus-4.5

  # Configure individual agent models
  uv run python scripts/batch_cantina_runner.py \\
      --main-model google/gemini-3-flash-preview \\
      --verifier-model google/gemini-3-flash-preview \\
      --fixer-model anthropic/claude-opus-4.5

  # Dry run to see what would be processed
  uv run python scripts/batch_cantina_runner.py --dry-run
        """,
    )

    # General model shortcut (sets main model, others use defaults)
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Main model for State/Quant agents (shortcut for --main-model)",
    )

    # Individual model configuration
    parser.add_argument(
        "--main-model",
        type=str,
        default=None,
        help=f"Model for State/Quant agents (default: {settings.MAIN_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--setup-model",
        type=str,
        default=None,
        help=f"Model for Setup agent (default: {settings.SETUP_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--verifier-model",
        type=str,
        default=None,
        help=f"Model for Verifier agent (default: {settings.VERIFIER_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--invariant-model",
        type=str,
        default=None,
        help=f"Model for Invariant generation (default: {settings.INVARIANT_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--fixer-model",
        type=str,
        default=None,
        help=f"Model for Fixer agent (default: {settings.FIXER_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--dedupe-model",
        type=str,
        default=None,
        help=f"Model for Deduplication (default: {settings.DEDUPE_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--gamified-model",
        type=str,
        default=None,
        help=f"Model for Gamified agent (default: {settings.GAMIFIED_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--fallback-model",
        type=str,
        default=None,
        help=f"Fallback model when primary fails (default: {settings.FALLBACK_MODEL})",
    )

    # Execution options
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of repos to process (for testing, e.g., --limit 3)",
    )
    parser.add_argument(
        "--concurrent",
        type=int,
        default=2,
        help="Max concurrent agents (default: 2)",
    )
    parser.add_argument(
        "--compile-timeout",
        type=int,
        default=120,
        help="Compilation timeout in seconds (default: 120, use 300-600 for large repos)",
    )
    parser.add_argument(
        "--test-timeout",
        type=int,
        default=120,
        help="Test execution timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--save-rollouts",
        action="store_true",
        help="Save agent conversation rollouts",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Just show what would run without executing",
    )
    parser.add_argument(
        "--resume",
        type=str,
        default=None,
        help="Resume from specific repo (e.g., euler-xyz/euler-vault-kit)",
    )
    parser.add_argument(
        "--save-to-db",
        action="store_true",
        help="Save results to MongoDB (requires MONGO_URI env var)",
    )

    args = parser.parse_args()

    # Build model configuration from args
    model_config = ModelConfig.from_args(args)

    asyncio.run(run_batch(
        repos=CANTINA_REPOS,
        model_config=model_config,
        max_concurrent=args.concurrent,
        save_rollouts=args.save_rollouts,
        dry_run=args.dry_run,
        resume_from=args.resume,
        limit=args.limit,
        compile_timeout=args.compile_timeout,
        test_timeout=args.test_timeout,
        save_to_db=args.save_to_db,
    ))


if __name__ == "__main__":
    main()
