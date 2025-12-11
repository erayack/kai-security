from enum import Enum
from typing import Optional, List, Dict, Any, Literal

from pydantic import BaseModel, Field, model_validator

# Adapter type literal for structured output validation
AdapterType = Literal["solidity"]


class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ChatMessage(BaseModel):
    role: Role
    content: str

class Language(str, Enum):
    SOLIDITY = "solidity"
    JAVASCRIPT = "javascript"


class Framework(str, Enum):
    FOUNDRY = "foundry"
    NODE = "node"


class AdapterSelection(BaseModel):
    """Result of selecting adapters based on detected languages."""

    languages: list[Language] = Field(default_factory=list)
    frameworks: list[Framework] = Field(default_factory=list)
    adapters: list[str | None] = Field(default_factory=list)
    reason: Optional[str] = None


class Command(BaseModel):
    command: str
    order_of_execution: int = Field(
        ge=0,
        le=100,
        description="The order of execution of the command will be executed in. 0 is the first command to be executed, 1 the second , and so on.",
    )


class MasterContext(BaseModel):
    """
    Immutable view of the built repository used by downstream agents.
    """

    root_path: str
    frameworks: Optional[list[str]] = None
    artifacts_path: Optional[str] = None
    src_path: Optional[str] = None
    lib_path: Optional[str] = None
    test_path: Optional[str] = None
    compile_success: bool
    build_commands: Optional[list[Command]] = None
    test_commands: Optional[list[Command]] = None
    adapter: AdapterType = "solidity"  # Domain adapter for dependency graph analysis


class AgentResponse(BaseModel):
    thoughts: str
    python_block: Optional[str] = None
    test_script: Optional[str] = None
    suggest_fix: Optional[str] = None
    master_context: Optional[MasterContext] = None
    # Profiler-specific optional payload
    protocol_manifesto: Optional["ProtocolManifesto"] = None

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


class EnvironmentSetupInput(BaseModel):
    repo_url: str
    num_turns: int
    model_name: str
    use_openai: bool = False
    execution_id: Optional[str] = None
    repo_path_override: Optional[str] = None


class EnvironmentSetupOutput(BaseModel):
    response: Optional[AgentResponse]
    master_context: Optional[MasterContext]
    estimated_cost: float
    total_tokens: Dict[str, int]
    success: bool
    error_message: Optional[str]
    master_repo_path: str
    repo_slug: str


# ---------------------------
# Actor Analysis Schemas
# ---------------------------


class SuspiciousFunction(BaseModel):
    """Function flagged by heuristic scan for potential access control issues."""

    function_name: str
    function_id: str
    contract_name: Optional[str] = None
    file_path: Optional[str] = None
    visibility: str
    patterns_matched: List[str] = Field(default_factory=list)
    has_modifier: bool = False
    reason: str
    writes_state: bool = False


class PrivilegeChain(BaseModel):
    """Cross-contract privilege chain (e.g., Keeper -> Vault -> Strategy)."""

    source_contract: str
    source_function: str
    source_role: Optional[str] = None
    target_contract: str
    target_function: str
    call_path: List[str] = Field(default_factory=list)
    can_send_eth: bool = False
    edge_count: int = 1


class Actor(BaseModel):
    """Actor with roles and privileges (enhanced ActorRole)."""

    role: str
    trust_level: str  # "High", "Medium", "Low", "None", "N/A"
    modifier_patterns: List[str] = Field(default_factory=list)
    direct_privileges: List[str] = Field(default_factory=list)
    indirect_privileges: List[str] = Field(default_factory=list)
    function_count: int = 0
    contracts: List[str] = Field(default_factory=list)


class LLMReviewResult(BaseModel):
    """Result from LLM review of a suspicious function."""

    function_name: str
    contract_name: Optional[str] = None
    is_vulnerability: bool
    confidence: float = Field(ge=0.0, le=1.0)
    issue_type: Optional[str] = None
    description: str
    recommendation: Optional[str] = None


class ActorAnalysisInput(BaseModel):
    """Input for ActorAnalysisProcess."""

    graph: Any  # DependencyGraph object
    slither: Optional[Any] = None
    model_name: str = "z-ai/glm-4.6"
    use_openai: bool = True
    enable_llm_review: bool = True
    max_suspicious_for_llm: int = 200


class ActorReport(BaseModel):
    """Output of ActorAnalysisProcess."""

    actors: List[Actor] = Field(default_factory=list)
    privilege_chains: List[PrivilegeChain] = Field(default_factory=list)
    guard_issues: List[Dict[str, Any]] = Field(default_factory=list)
    suspicious_functions: List[SuspiciousFunction] = Field(default_factory=list)
    llm_review_results: List[LLMReviewResult] = Field(default_factory=list)
    llm_invoked: bool = False
    llm_tokens_used: Dict[str, int] = Field(default_factory=dict)
    llm_cost_estimate: float = 0.0
    total_public_functions: int = 0
    protected_functions: int = 0
    unprotected_functions: int = 0
    suspicious_count: int = 0
    confirmed_issues: int = 0


class Feature(BaseModel):
    name: str
    description: str
    actors: list[str]


class ProtocolManifesto(BaseModel):
    name: str
    purpose: str
    description: str
    domain: str = ""
    programming_languages: list[str]

    intended_users: list[str] = Field(default_factory=list)
    # ["depositors", "borrowers", "admins"] - semantic roles, not modifier names

    # === Domain concepts ===
    key_concepts: dict[str, str] = Field(default_factory=dict)
    # {"health_factor": "ratio determining liquidation eligibility",
    #  "utilization": "borrowed / total liquidity"}

    # === Key Features ===
    key_features: list[Feature]

    @model_validator(mode="before")
    @classmethod
    def coerce_key_concepts(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        # Allow key_concepts provided as a list of strings; coerce to {k: k}
        if not isinstance(values, dict):
            return values
        kc = values.get("key_concepts")
        if isinstance(kc, list):
            coerced = {}
            for item in kc:
                if isinstance(item, str):
                    coerced[item] = item
            values["key_concepts"] = coerced
        return values


class ProfilerInput(BaseModel):
    master_context: MasterContext
    num_turns: int
    model_name: str
    use_openai: bool = False
    execution_id: Optional[str] = None


class ProfilerOutput(BaseModel):
    response: Optional[AgentResponse]
    protocol_manifesto: Optional[ProtocolManifesto]
    estimated_cost: float
    total_tokens: Dict[str, int]
    success: bool
    error_message: Optional[str]
    repo_path: str


# ---------------------------
# Actor Matrix Schemas (Grounded)
# ---------------------------


class Privilege(BaseModel):
    """A single privilege (entrypoint) with full grounding info."""

    id: str  # Node ID (e.g., "Vault.withdraw(uint256)")
    name: str  # Function name
    container: str  # Contract name
    signature: Optional[str] = None  # Full signature
    file: Optional[str] = None  # Source file path
    writes_state: bool = False  # Does it write state variables?
    write_targets: List[str] = Field(default_factory=list)  # State vars written


class RoleEvidence(BaseModel):
    """Evidence anchoring a role assignment to code."""

    function_id: str
    modifiers: List[str] = Field(
        default_factory=list
    )  # Modifier names from ACCEPTS edges
    snippet_file: Optional[str] = None
    snippet_lines: Optional[List[int]] = None  # [start, end]


class ActorMatrixRole(BaseModel):
    """A role in the ActorMatrix with grounded privileges and evidence."""

    name: str  # Role name (e.g., "Owner", "User")
    trust: str  # "high", "medium", "low", "none"
    reasoning: str = ""  # LLM's reasoning for trust assignment
    access_signature: List[str] = Field(default_factory=list)  # Normalized modifiers
    privileges: List[Privilege] = Field(default_factory=list)
    evidence: List[RoleEvidence] = Field(default_factory=list)
    risk_score: int = 0  # Aggregate of state writes


class RoleAssignment(BaseModel):
    """LLM's trust assignment for a single role cluster."""

    signature_key: (
        str  # The cluster key (e.g., "Ownable.onlyOwner" or "__unprotected__")
    )
    name: str  # Human-readable role name
    trust: Literal["high", "medium", "low", "none"]
    reasoning: str  # Brief explanation of why this trust level


class ActorMatrix(BaseModel):
    """
    Grounded ActorMatrix output.

    All privileges are anchored to node IDs, not bare names.
    Evidence links roles to actual code locations.
    """

    roles: List[ActorMatrixRole] = Field(default_factory=list)
    stats: Dict[str, int] = Field(default_factory=dict)
    # stats: {total_entrypoints, unprotected_count, review_required_count}


class ActorMatrixInput(BaseModel):
    """Input for ActorProcess."""

    master_context: "MasterContext"
    dependency_graph: Any  # DependencyGraph object
    protocol_manifesto: Optional["ProtocolManifesto"] = None
    model_name: str = "z-ai/glm-4.6"
    use_openai: bool = False


class ActorMatrixOutput(BaseModel):
    """Output of ActorProcess."""

    actor_matrix: Optional[ActorMatrix] = None
    success: bool
    error_message: Optional[str] = None
    estimated_cost: float = 0.0
    total_tokens: Dict[str, int] = Field(default_factory=dict)


# Resolve forward references for models that refer to ProtocolManifesto
AgentResponse.model_rebuild()

class AdapterChooserInput(BaseModel):
    model_name: str
    use_openai: bool = False
    available_frameworks: Optional[list[str]] = None


class AdapterChooserOutput(BaseModel):
    choice: Optional[AdapterSelection]
    raw_response: Optional[str] = None
    estimated_cost: float = 0.0
    total_tokens: Dict[str, int] = Field(default_factory=dict)
    success: bool
    error_message: Optional[str] = None
