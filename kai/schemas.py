from enum import Enum
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field, model_validator


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ChatMessage(BaseModel):
    role: Role
    content: str


class MasterContext(BaseModel):
    """
    Immutable view of the built repository used by downstream agents.
    """

    root_path: str
    framework: Optional[str] = None
    artifacts_path: Optional[str] = None
    src_path: Optional[str] = None
    lib_path: Optional[str] = None
    test_path: Optional[str] = None
    compile_success: bool
    build_command: Optional[str] = None
    test_command: Optional[str] = None


class AgentResponse(BaseModel):
    thoughts: str
    python_block: Optional[str] = None
    test_script: Optional[str] = None
    suggest_fix: Optional[str] = None
    master_context: Optional[MasterContext] = None

    def __str__(self):
        return (
            f"Thoughts: {self.thoughts}\n"
            f"Python block:\n {self.python_block}\n"
            f"Test script:\n {self.test_script}\n"
            f"Suggest fix:\n {self.suggest_fix}\n"
            f"Master context:\n {self.master_context}"
        )


class GrepResponse(BaseModel):
    exit_code: int
    stdout: str
    stderr: str

    def __str__(self):
        return (
            f"- Exit code: {self.exit_code}\n"
            f"- Stdout: {self.stdout}\n"
            f"- Stderr: {self.stderr}"
        )


class ExploitSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------
# Invariant Types (for InvariantAnalysis → Dispatcher)
# ---------------------------


class InvariantType(str, Enum):
    """Categories of invariants for the exploit scaffold."""

    LIVENESS = "liveness"  # Function must be callable by intended role
    SOLVENCY = "solvency"  # totalAssets >= totalLiabilities
    ACCESS_CONTROL = "access_control"  # Only X can call Y
    STATE_TRANSITION = "state_transition"  # Valid state machine transitions
    BALANCE = "balance"  # Balance/accounting invariants
    REENTRANCY = "reentrancy"  # No reentrant state corruption
    CUSTOM = "custom"  # LLM-generated or user-defined


class Invariant(BaseModel):
    """
    An invariant rule used by Dispatcher to schedule missions.

    Output of InvariantAnalysis, consumed by Dispatcher and Workers.
    """

    id: str  # e.g., "LIVENESS_addRecoveryProvider", "UNIV_SOLVENCY"
    type: InvariantType
    rule: (
        str  # Human-readable: "Function addRecoveryProvider must be callable by Admin"
    )
    target_functions: List[str] = Field(
        default_factory=list
    )  # Functions this applies to
    target_files: List[str] = Field(default_factory=list)  # Files involved
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0
    )  # How confident (1.0 = deterministic)
    source: str = "static"  # "static", "llm", "observation" - what generated this


class Observation(BaseModel):
    """
    Intermediate finding from non-invariant workers (BlackBox, Gamified).

    Gets refined by LLM into a tentative Invariant.
    """

    worker_id: str
    mission_id: str
    description: str  # "Function X always reverts when called by any actor"
    affected_functions: List[str] = Field(default_factory=list)
    affected_files: List[str] = Field(default_factory=list)
    logs: List[str] = Field(default_factory=list)  # Raw output/traces
    anomaly_type: Optional[str] = None  # "always_reverts", "unexpected_state", etc.


class ExploitCandidate(BaseModel):
    """
    A potential exploit from invariant-dependent workers.

    Sent to Verifier for confirmation.
    """

    mission_id: str
    worker_id: str
    invariant_id: str  # Which invariant this claims to violate
    mechanism: str  # "reentrancy", "access_control_bypass", etc.
    poc_code: str  # The exploit contract/test code
    target_file: str
    target_function: str
    description: str
    compiled: bool = False  # Did it compile in worker's workspace?
    logs: List[str] = Field(default_factory=list)


class ExploitLocation(BaseModel):
    file_path: str
    line_start: int
    line_end: Optional[int] = None  # None if single line
    class_name: Optional[str] = None
    function_name: Optional[str] = None


class Exploit(BaseModel):
    id: Optional[str] = None
    category: str  # e.g., "SQL Injection", "Prototype Pollution", "Regex DoS", etc.
    severity: ExploitSeverity
    location: ExploitLocation  # Single canonical location describing the exploit
    description: str  # General description of the vulnerability pattern
    suggested_fix: Optional[str] = None  # General fix approach

    @model_validator(mode="before")
    @classmethod
    def ensure_single_location(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """
        Backwards compatibility: allow legacy `locations` list/dict but normalize to `location`.
        """
        if not isinstance(values, dict):
            return values

        data = dict(values)
        location = data.get("location")

        if not location:
            locations = data.get("locations")
            if isinstance(locations, list) and locations:
                data["location"] = locations[0]
            elif isinstance(locations, dict):
                data["location"] = locations

        # Remove legacy key to avoid accidental re-serialization
        data.pop("locations", None)
        return data


# Sub-Agent Schemas for Recursive Hierarchical Exploration


class ExploitSummary(BaseModel):
    """Compact exploit representation in sub-agent report."""

    exploit_id: str
    category: str
    severity: str  # "critical", "high", "medium", "low"
    file_path: str
    line_start: int
    line_end: int
    description: str = Field(..., max_length=200)  # Truncated description


class CodeReference(BaseModel):
    """Reference to specific code location worth investigating."""

    file_path: str
    line_start: int
    line_end: int
    reason: str  # Why this location is interesting
    priority: int = Field(ge=1, le=10)  # 1-10, higher = more important


class SubAgentReport(BaseModel):
    """Structured intermediate representation from sub-agent exploration."""

    # Metadata
    agent_id: str
    parent_agent_id: Optional[str] = None
    depth: int = Field(ge=0, le=10)  # Hierarchy depth (0 = root)
    scope_path: str  # Directory or file explored
    task_description: str

    # Resource consumption
    turns_used: int
    turns_allocated: int

    # Budget tracking (this agent only)
    total_tokens: Dict[str, int] = Field(
        default_factory=dict
    )  # {"prompt_tokens": X, "completion_tokens": Y}
    estimated_cost: float = 0.0

    # Budget tracking (sub-agents only)
    sub_agent_total_tokens: Dict[str, int] = Field(default_factory=dict)
    sub_agent_total_cost: float = 0.0

    # Budget tracking (combined: this agent + all sub-agents)
    combined_total_tokens: Dict[str, int] = Field(default_factory=dict)
    combined_total_cost: float = 0.0

    # Time tracking (this agent only)
    time_spent: float = 0.0  # Time in seconds

    # Time tracking (sub-agents only)
    sub_agent_total_time: float = 0.0  # Time in seconds

    # Time tracking (combined: this agent + all sub-agents)
    combined_time_spent: float = 0.0  # Time in seconds

    # Exploration results
    files_explored: List[str] = Field(default_factory=list)
    exploits_found: List[ExploitSummary] = Field(default_factory=list)
    # For finder agents: {"critical": 2, "high": 5, ...}
    # For generator agents: {"category_name": {"verified": int, "unverified": int}, ...}
    exploit_stats: Dict[str, Any] = Field(default_factory=dict)
    code_references: List[CodeReference] = Field(default_factory=list, max_length=10)

    # Sub-reports from recursive delegation
    sub_reports: List["SubAgentReport"] = Field(default_factory=list)

    # Summary
    summary: str = Field(..., min_length=50, max_length=500)  # 2-5 sentence summary

    # Completion status
    exploration_complete: bool = False  # True if exhaustively explored
    requires_followup: bool = False  # True if parent should drill deeper

    # Nested conversation for web viewer
    conversation: Optional[List[Dict[str, Any]]] = None  # Full conversation history


# Enable forward reference for recursive schema
SubAgentReport.model_rebuild()


# Helper Functions for Report Serialization


def report_to_string(report: SubAgentReport, indent: int = 0) -> str:
    """Convert SubAgentReport to formatted string for LLM context."""
    prefix = "  " * indent
    lines = [
        f"{prefix}=== Sub-Agent Report (Depth {report.depth}): {report.scope_path} ===",
        f"{prefix}Agent ID: {report.agent_id}",
        f"{prefix}Turns Used: {report.turns_used}/{report.turns_allocated}",
        f"{prefix}Files Explored: {len(report.files_explored)}",
        f"{prefix}Cost (Combined): ${report.combined_total_cost:.4f}",
        f"{prefix}Tokens (Combined): {report.combined_total_tokens.get('prompt_tokens', 0) + report.combined_total_tokens.get('completion_tokens', 0)}",
        f"{prefix}Time (Combined): {report.combined_time_spent:.2f}s",
        "",
        f"{prefix}EXPLOITS FOUND (This Agent): {len(report.exploits_found)}",
    ]

    # Add exploit stats based on structure (finder vs generator)
    if report.exploit_stats:
        # Check if it's generator-style (category-based with verified/unverified)
        first_value = next(iter(report.exploit_stats.values()), None)
        if isinstance(first_value, dict) and "verified" in first_value:
            # Generator agent stats
            total_verified = sum(
                cat_stats.get("verified", 0)
                for cat_stats in report.exploit_stats.values()
            )
            total_unverified = sum(
                cat_stats.get("unverified", 0)
                for cat_stats in report.exploit_stats.values()
            )
            lines.append(
                f"{prefix}EXPLOIT STATS: {total_verified} verified, {total_unverified} unverified"
            )
            for category, stats in sorted(report.exploit_stats.items()):
                lines.append(
                    f"{prefix}  {category}: {stats.get('verified', 0)} verified, {stats.get('unverified', 0)} unverified"
                )
        else:
            # Finder agent stats (severity-based)
            total = sum(report.exploit_stats.values())
            stats_str = ", ".join(
                f"{count} {sev}" for sev, count in sorted(report.exploit_stats.items())
            )
            lines.append(f"{prefix}EXPLOIT STATS: {total} total - [{stats_str}]")

    lines.append("")  # Empty line before exploit details

    for exploit in report.exploits_found:
        lines.append(
            f"{prefix}- [{exploit.exploit_id}] {exploit.severity.upper()} {exploit.category} "
            f"at {exploit.file_path}:{exploit.line_start}-{exploit.line_end}"
        )
        lines.append(f"{prefix}  {exploit.description}")

    if report.code_references:
        lines.append(f"\n{prefix}KEY LOCATIONS FOR FOLLOW-UP:")
        for ref in sorted(report.code_references, key=lambda x: -x.priority)[:5]:
            lines.append(
                f"{prefix}- [{ref.priority}] {ref.file_path}:{ref.line_start}-{ref.line_end} - {ref.reason}"
            )

    lines.append(f"\n{prefix}SUMMARY:")
    lines.append(f"{prefix}{report.summary}")

    # Recursively include sub-reports
    if report.sub_reports:
        lines.append(f"\n{prefix}SUB-REPORTS ({len(report.sub_reports)}):")
        for sub_report in report.sub_reports:
            lines.append(report_to_string(sub_report, indent + 1))

    lines.append(f"{prefix}{'=' * 60}")
    return "\n".join(lines)


def report_to_json(report: SubAgentReport) -> str:
    """Serialize report to JSON string."""
    return report.model_dump_json(indent=2)


def report_from_json(json_str: str) -> SubAgentReport:
    """Deserialize report from JSON string."""
    return SubAgentReport.model_validate_json(json_str)
