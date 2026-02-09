"""BountyBench adapter configuration."""

import os
from dataclasses import dataclass, field
from enum import Enum

from kai.agents import settings


class WorkflowMode(str, Enum):
    """Workflow modes for BountyBench benchmarking.

    Different modes control what hints are provided to Kai:
    - UNIFIED: Full functionality - all hints, all outputs (default)
    - DETECT: Zero-day discovery mode - no CVE/CWE hints
    - EXPLOIT: Targeted exploitation - full vulnerability hints
    - PATCH: Focus on generating fixes for known vulnerabilities
    """

    UNIFIED = "unified"  # Current behavior - all hints, all outputs
    DETECT = "detect"  # No CVE/CWE hints - zero-day discovery benchmarking
    EXPLOIT = "exploit"  # Full hints - targeted exploitation benchmarking
    PATCH = "patch"  # Focus on generating fixes


@dataclass
class BountyBenchConfig:
    """Configuration for BountyBench adapter.

    Model defaults are pulled from kai.agents.settings and can be overridden
    via environment variables:
    - KAI_MODEL
    - KAI_SETUP_MODEL
    - KAI_VERIFIER_MODEL
    - KAI_FIXER_MODEL
    """

    # Model configuration - use Kai's defaults from settings
    model: str = field(
        default_factory=lambda: os.getenv("KAI_MODEL", settings.MAIN_DEFAULT_MODEL)
    )
    setup_model: str = field(
        default_factory=lambda: os.getenv(
            "KAI_SETUP_MODEL", settings.SETUP_DEFAULT_MODEL
        )
    )
    verifier_model: str = field(
        default_factory=lambda: os.getenv(
            "KAI_VERIFIER_MODEL", settings.VERIFIER_DEFAULT_MODEL
        )
    )
    fixer_model: str = field(
        default_factory=lambda: os.getenv(
            "KAI_FIXER_MODEL", settings.FIXER_DEFAULT_MODEL
        )
    )
    invariant_model: str = field(
        default_factory=lambda: os.getenv(
            "KAI_INVARIANT_MODEL", settings.INVARIANT_DEFAULT_MODEL
        )
    )
    dedupe_model: str = field(
        default_factory=lambda: os.getenv(
            "KAI_DEDUPE_MODEL", settings.DEDUPE_DEFAULT_MODEL
        )
    )

    # Timeouts
    docker_startup_timeout: int = 60  # seconds to wait for containers
    exploit_timeout: int = 30  # seconds per exploit.sh execution
    verify_timeout: int = 30  # seconds per verify.sh execution

    # Agent settings
    max_tool_turns: int = settings.DEFAULT_MAX_TURNS
    blackbox_missions: int = 2

    # Output paths
    output_dir: str = "./output/bountybench"
    workspace_dir: str = "./kai_workspaces"

    # Pipeline options
    skip_workspace_validation: bool = True  # BountyBench tasks are pre-validated
    disable_gamified: bool = True  # Focus on targeted exploitation
    disable_fixer: bool = False  # Generate fixes
    save_rollouts: bool = True

    # Docker management
    disable_docker: bool = False  # Skip Docker container management

    # Exploration settings
    include_exploration: bool = True  # Run blackbox exploration phase

    # Workflow mode for benchmarking
    workflow_mode: WorkflowMode = WorkflowMode.UNIFIED

    # Invariant and Detect Indicator settings
    run_invariants: bool = True  # Run invariant checks after exploitation
    detect_indicator: bool = True  # Run Detect Indicator (vulnerable vs patched)

    # HTTP Agent settings
    enable_http_agent: bool = False  # Enable HTTP-based exploitation agent
    http_target_hosts: dict[str, str] | None = None  # Service name -> URL mapping
