#!/usr/bin/env python
"""
BountyBench Test Script

A self-contained script to run Kai on BountyBench tasks via BountyBenchRunner.

Usage:
    python test_bountybench.py <task_name>
    python test_bountybench.py <task_name> --model openai/gpt-4o --workers 8
    python test_bountybench.py <task_name> --workflow-mode detect

Examples:
    python test_bountybench.py lunary
    python test_bountybench.py django --model moonshotai/kimi-k2.5
    python test_bountybench.py fastapi --workflow-mode detect
    python test_bountybench.py --list
"""

import argparse
import asyncio
import atexit
import logging
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional

BOUNTYBENCH_REPO = "https://github.com/bountybench/bountybench.git"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
# Silence noisy loggers
for name in ("openai", "httpcore", "httpx", "urllib3"):
    logging.getLogger(name).setLevel(logging.WARNING)

logger = logging.getLogger("test_bountybench")

# Global state for cleanup
_docker_manager: Optional[object] = None
_cleanup_done = False


def get_script_dir() -> Path:
    """Get the directory containing this script."""
    return Path(__file__).parent.resolve()


def get_bountybench_dir() -> Path:
    """Get the bountybench directory path."""
    return get_script_dir() / "bountybench"


def clone_bountybench() -> bool:
    """Clone the bountybench repo if it doesn't exist.

    Returns:
        True if successful, False otherwise
    """
    bb_dir = get_bountybench_dir()

    if bb_dir.exists():
        logger.info(f"BountyBench directory already exists at {bb_dir}")
        return True

    logger.info(f"Cloning BountyBench repository to {bb_dir}...")
    try:
        result = subprocess.run(
            ["git", "clone", BOUNTYBENCH_REPO, str(bb_dir)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            logger.error(f"Failed to clone BountyBench: {result.stderr}")
            return False
        logger.info("BountyBench repository cloned successfully")
        return True
    except subprocess.TimeoutExpired:
        logger.error("Clone operation timed out")
        return False
    except Exception as e:
        logger.error(f"Error cloning BountyBench: {e}")
        return False


def init_bountytasks() -> bool:
    """Initialize bountytasks submodules if not initialized.

    Returns:
        True if successful, False otherwise
    """
    bb_dir = get_bountybench_dir()
    bountytasks_dir = bb_dir / "bountytasks"

    # Check if bountytasks is empty or doesn't exist
    if bountytasks_dir.exists():
        contents = list(bountytasks_dir.iterdir())
        # Filter out hidden files like .git
        visible_contents = [c for c in contents if not c.name.startswith(".")]
        if visible_contents:
            logger.info("BountyTasks submodules already initialized")
            return True

    logger.info("Initializing BountyBench submodules...")
    try:
        # Initialize main submodules
        result = subprocess.run(
            ["git", "submodule", "update", "--init"],
            cwd=str(bb_dir),
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            logger.warning(f"Submodule init warning: {result.stderr}")

        # Update remote
        result = subprocess.run(
            ["git", "submodule", "update", "--remote"],
            cwd=str(bb_dir),
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            logger.warning(f"Submodule update warning: {result.stderr}")

        # Initialize bountytasks submodules
        if bountytasks_dir.exists():
            result = subprocess.run(
                ["git", "submodule", "update", "--init"],
                cwd=str(bountytasks_dir),
                capture_output=True,
                text=True,
                timeout=600,  # This can take longer
            )
            if result.returncode != 0:
                logger.warning(f"BountyTasks init warning: {result.stderr}")

        logger.info("BountyBench submodules initialized successfully")
        return True
    except subprocess.TimeoutExpired:
        logger.error("Submodule initialization timed out")
        return False
    except Exception as e:
        logger.error(f"Error initializing submodules: {e}")
        return False


def get_task_dir(task_name: str) -> Optional[Path]:
    """Get the task directory for a given task name.

    Args:
        task_name: Name of the task (e.g., "lunary", "django")

    Returns:
        Path to task directory or None if not found
    """
    task_dir = get_bountybench_dir() / "bountytasks" / task_name
    if task_dir.exists():
        return task_dir
    return None


def list_available_tasks() -> list[str]:
    """List available BountyBench tasks."""
    bountytasks_dir = get_bountybench_dir() / "bountytasks"
    if not bountytasks_dir.exists():
        return []

    tasks = []
    for item in bountytasks_dir.iterdir():
        if item.is_dir() and not item.name.startswith("."):
            tasks.append(item.name)
    return sorted(tasks)


def cleanup_docker():
    """Cleanup Docker containers - called on exit."""
    global _docker_manager, _cleanup_done

    if _cleanup_done:
        return
    _cleanup_done = True

    if _docker_manager:
        logger.info("Cleaning up Docker containers...")
        try:
            _docker_manager.stop()
            logger.info("Docker containers stopped and removed")
        except Exception as e:
            logger.error(f"Error during Docker cleanup: {e}")


def signal_handler(signum: int, frame) -> None:
    """Handle termination signals."""
    signal_name = signal.Signals(signum).name
    logger.warning(f"Received {signal_name}, initiating cleanup...")
    cleanup_docker()
    sys.exit(128 + signum)


async def run_bountybench_task(
    task_name: str,
    model: str,
    workers: int,
    workflow_mode: str,
) -> int:
    """Run Kai on a BountyBench task.

    Args:
        task_name: Name of the task to run
        model: Model to use for agents
        workers: Number of concurrent agents
        workflow_mode: Workflow mode (unified, detect, exploit)

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    global _docker_manager

    script_dir = get_script_dir()

    # Add src and root to path for imports
    src_path = script_dir / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))

    try:
        from evaluation.bountybench_adapter.config import (
            BountyBenchConfig,
            WorkflowMode,
        )
        from evaluation.bountybench_adapter.runner import BountyBenchRunner
    except ImportError as e:
        logger.error(f"Failed to import modules: {e}")
        return 1

    # Get task directory
    task_dir = get_task_dir(task_name)
    if not task_dir:
        logger.error(f"Task not found: {task_name}")
        available = list_available_tasks()
        if available:
            logger.info(f"Available tasks: {', '.join(available[:10])}")
            if len(available) > 10:
                logger.info(f"  ... and {len(available) - 10} more")
        return 1

    logger.info(f"Running BountyBench task: {task_name}")
    logger.info(f"Model: {model}")
    logger.info(f"Workers: {workers}")
    logger.info(f"Workflow mode: {workflow_mode}")

    # Build configuration
    config = BountyBenchConfig(
        model=model,
        setup_model=model,
        verifier_model=model,
        fixer_model=model,
        invariant_model=model,
        dedupe_model=model,
        output_dir=str(script_dir / "output" / "bountybench"),
        workspace_dir=str(script_dir / "kai_workspaces"),
        enable_http_agent=True,
        workflow_mode=WorkflowMode(workflow_mode),
        save_rollouts=True,
        skip_workspace_validation=True,
        disable_gamified=True,
        disable_fixer=False,
        run_invariants=True,
        detect_indicator=True,
    )

    # Run through the proper pipeline
    runner = BountyBenchRunner(config)

    try:
        report = await runner.run(
            task_dir=str(task_dir),
            max_concurrent_agents=workers,
        )

        # Store docker manager reference for cleanup
        _docker_manager = runner._docker_manager

        if report is None:
            logger.error("Runner returned no report")
            return 1

        logger.info(
            f"Bounties verified: {report.bounties_verified}/{report.total_bounties}"
        )
        logger.info(f"Cost: ${report.total_cost_usd:.4f}")
        logger.info(f"Bounty claimed: ${report.total_bounty_claimed_usd:,.2f}")

        return 0 if report.bounties_verified > 0 else 1

    except Exception as e:
        logger.error(f"Error running task: {e}", exc_info=True)
        return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run Kai on a BountyBench task",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    uv run python test_bountybench.py lunary
    uv run python test_bountybench.py django --model openai/gpt-4o
    uv run python test_bountybench.py fastapi --workflow-mode detect
    uv run python test_bountybench.py --list
        """,
    )
    parser.add_argument(
        "task_name",
        nargs="?",  # Make optional
        help="Name of the BountyBench task to run (e.g., lunary, django)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available tasks and exit",
    )
    parser.add_argument(
        "--model",
        default="moonshotai/kimi-k2.5",
        help="Model to use (default: moonshotai/kimi-k2.5)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent agents (default: 4)",
    )
    parser.add_argument(
        "--workflow-mode",
        choices=["unified", "detect", "exploit"],
        default="unified",
        help="Workflow mode (default: unified)",
    )

    args = parser.parse_args()

    # Validate that task_name is provided when not using --list
    if not args.list and not args.task_name:
        parser.error("task_name is required unless using --list")

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Register cleanup on exit
    atexit.register(cleanup_docker)

    # Clone bountybench if needed
    if not clone_bountybench():
        logger.error("Failed to clone BountyBench repository")
        sys.exit(1)

    # Initialize submodules if needed
    if not init_bountytasks():
        logger.error("Failed to initialize BountyBench submodules")
        sys.exit(1)

    # List tasks if requested
    if args.list:
        tasks = list_available_tasks()
        if tasks:
            print("Available BountyBench tasks:")
            for task in tasks:
                print(f"  {task}")
        else:
            print("No tasks available. Submodules may not be initialized.")
        sys.exit(0)

    # Run the task
    exit_code = asyncio.run(
        run_bountybench_task(
            args.task_name,
            args.model,
            args.workers,
            args.workflow_mode,
        )
    )

    # Explicit cleanup before exit
    cleanup_docker()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
