"""BountyBench adapter for Kai security analysis framework.

This package provides a simplified adapter for running Kai against
BountyBench vulnerability challenges.

Example usage:
    from evaluation.bountybench_adapter import run_bountybench, BountyBenchConfig

    # Run with defaults
    report = await run_bountybench("/path/to/task")

    # Run with custom config
    config = BountyBenchConfig(
        output_dir="./my_output",
        disable_gamified=True,
    )
    report = await run_bountybench("/path/to/task", config=config)
"""

from evaluation.bountybench_adapter.config import BountyBenchConfig
from evaluation.bountybench_adapter.docker_manager import DockerManager
from evaluation.bountybench_adapter.exploit_converter import ExploitConverter
from evaluation.bountybench_adapter.report import BountyBenchReport, ReportGenerator
from evaluation.bountybench_adapter.runner import BountyBenchRunner
from evaluation.bountybench_adapter.task_loader import BountyInfo, TaskLoader
from evaluation.bountybench_adapter.verifier import BountyVerifier, VerificationResult

__all__ = [
    # Config
    "BountyBenchConfig",
    # Task loading
    "TaskLoader",
    "BountyInfo",
    # Docker
    "DockerManager",
    # Exploit conversion
    "ExploitConverter",
    # Verification
    "BountyVerifier",
    "VerificationResult",
    # Reporting
    "ReportGenerator",
    "BountyBenchReport",
    # Runner
    "BountyBenchRunner",
    # Convenience function
    "run_bountybench",
]


async def run_bountybench(
    task_dir: str,
    target_host: str | None = None,
    config: BountyBenchConfig | None = None,
) -> BountyBenchReport:
    """Run a BountyBench task through Kai.

    This is the main entry point for running BountyBench tasks.

    Args:
        task_dir: Path to BountyBench task directory
        target_host: Target host URL (auto-detected if not provided)
        config: BountyBench configuration (uses defaults if not provided)

    Returns:
        BountyBenchReport with results and metrics
    """
    runner = BountyBenchRunner(config or BountyBenchConfig())
    return await runner.run(task_dir, target_host)
