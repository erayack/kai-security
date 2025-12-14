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
# Invariant Types (for InvariantProcess → Dispatcher)
# ---------------------------


class InvariantType(str, Enum):
    """Categories of invariants - just labels, not constraints."""

    ACCESS = "access"  # Only X can call Y
    SOLVENCY = "solvency"  # totalAssets >= totalLiabilities
    CONSERVATION = "conservation"  # Sum invariants (balances, supply)
    LIVENESS = "liveness"  # Function must be callable
    FEE_BOUND = "fee_bound"  # Fee constraints
    REENTRANCY = "reentrancy"  # No reentrant state corruption
    ORDERING = "ordering"  # State transition ordering
    OTHER = "other"  # Anything else


class Invariant(BaseModel):
    """
    A grounded invariant rule used by Dispatcher to schedule missions.

    All target fields reference node IDs from the DependencyGraph.
    Output of InvariantProcess, consumed by Dispatcher and Workers.
    """

    id: str  # e.g., "INV_SUPPLY_CONSERVATION", "INV_ADMIN_UPGRADE"
    type: InvariantType
    rule: str  # Human-readable invariant statement
    explanation: str = ""  # LLM's reasoning for this invariant

    # Grounded targets - all must be valid graph node IDs
    target_function_ids: List[str] = Field(default_factory=list)
    target_var_ids: List[str] = Field(default_factory=list)
    target_file_ids: List[str] = Field(default_factory=list)

    # Metadata
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str = "llm"  # "llm", "pattern", "docs"
    chunk_id: Optional[str] = None  # Which chunk this came from


# Vocab table entries for LLM context
class FunctionVocabEntry(BaseModel):
    """Function entry in vocab table for LLM."""

    id: str  # Node ID from graph
    name: str
    container: str  # Contract name
    file: str
    role: str = ""  # From ActorMatrix (e.g., "Admin", "User")
    trust: str = ""  # From ActorMatrix (e.g., "high", "none")
    reads: List[str] = Field(default_factory=list)  # Var names
    writes: List[str] = Field(default_factory=list)  # Var names


class VarVocabEntry(BaseModel):
    """State variable entry in vocab table for LLM."""

    id: str  # Node ID from graph
    name: str
    container: str  # Contract name
    file: str
    writers: List[str] = Field(default_factory=list)  # Function IDs that write
    readers: List[str] = Field(default_factory=list)  # Function IDs that read


class FileVocabEntry(BaseModel):
    """File entry in vocab table for LLM."""

    id: str  # File path
    contracts: List[str] = Field(default_factory=list)


class VocabChunk(BaseModel):
    """A chunk of vocabulary for one LLM call."""

    chunk_id: str
    functions: List[FunctionVocabEntry] = Field(default_factory=list)
    vars: List[VarVocabEntry] = Field(default_factory=list)
    files: List[FileVocabEntry] = Field(default_factory=list)


class InvariantProcessInput(BaseModel):
    """Input for InvariantProcess."""

    master_context: "MasterContext"
    dependency_graph: Any  # DependencyGraph object
    actor_matrix: "ActorMatrix"
    protocol_manifesto: Optional["ProtocolManifesto"] = None
    model_name: str = "openai/gpt-5.2"
    use_openai: bool = False
    max_chunk_functions: int = 25  # Max functions per chunk


class InvariantProcessOutput(BaseModel):
    """Output of InvariantProcess."""

    invariants: List[Invariant] = Field(default_factory=list)
    success: bool
    error_message: Optional[str] = None
    estimated_cost: float = 0.0
    total_tokens: Dict[str, int] = Field(default_factory=dict)
    stats: Dict[str, int] = Field(default_factory=dict)
    # stats: {total_generated, validated, dropped, merged}


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

    # --- Grounded blackbox fields (optional; backwards compatible) ---
    repro_command: Optional[str] = None
    seed: Optional[int] = None


class ExploitCandidate(BaseModel):
    """
    A potential exploit from invariant-dependent agents.

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
    compiled: bool = False  # Did it compile in agent's workspace?
    logs: List[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def coerce_legacy_shapes(cls, values: Any) -> Any:
        """
        Backwards compatibility:
        - agent_id -> worker_id
        """
        if not isinstance(values, dict):
            return values
        data = dict(values)
        if "worker_id" not in data and "agent_id" in data:
            data["worker_id"] = data.get("agent_id")
        return data


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
    write_targets: List[str] = Field(default_factory=list)  # State var names (display)
    write_target_ids: List[str] = Field(
        default_factory=list
    )  # State var node IDs (matching)


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


# Dispatcher and Campaign Schemas


class MissionAgentType(str, Enum):
    """
    Agent types for missions.

    Invariant-dependent:
    - QUANT: Break numeric invariants, equations (solvency, conservation)
    - STATE: Break state machine invariants (call sequences, access control)

    Non-dependent (exploration):
    - BLACKBOX: Anomaly detection, surfaces observations → new invariants
    - GAMIFIED: Game-theoretic exploitation (maximize attacker payoff)
    """

    QUANT = "quant"
    STATE = "state"
    BLACKBOX = "blackbox"
    GAMIFIED = "gamified"


class CampaignMode(str, Enum):
    """Campaign execution mode."""

    INVARIANT_BOUNDED = "invariant_bounded"  # Test specific invariants
    EXPLORATORY = "exploratory"  # BlackBox anomaly detection
    GAME = "game"  # Gamified payoff maximization


class WorkspacePreset(str, Enum):
    """Workspace provisioning presets."""

    CLEAN = "clean"  # src/test COPY, lib SYMLINK
    WRITEABLE = "writeable"  # src/lib/test COPY (writeable)
    SANDBOX = "sandbox"  # FULL COPY + extras (world/, mocks/, actors/)


class RewardModel(str, Enum):
    """Reward model for gamified agents."""

    NONE = "none"  # No reward model (invariant-based)
    PROFIT = "profit"  # Maximize attacker profit
    GRIEF = "grief"  # Maximize griefing effect
    COVERAGE = "coverage"  # Maximize code coverage


class EntrypointPolicy(BaseModel):
    """Policy for filtering/ordering entrypoints."""

    max_sequence_len: int = 6
    prefer: List[str] = Field(
        default_factory=list
    )  # ["writes_state", "external_calls"]
    exclude_patterns: List[str] = Field(default_factory=list)


class EntrypointSubset(BaseModel):
    """Filtered entrypoints with policy."""

    ids: List[str] = Field(default_factory=list)
    policy: EntrypointPolicy = Field(default_factory=EntrypointPolicy)


class CampaignScope(BaseModel):
    """Scope definition for a campaign."""

    entrypoints_subset: EntrypointSubset = Field(default_factory=EntrypointSubset)
    primary_var_ids: List[str] = Field(default_factory=list)
    file_ids: List[str] = Field(default_factory=list)
    actor_roles: List[str] = Field(default_factory=list)


class CampaignObjectives(BaseModel):
    """Objectives for a campaign."""

    reward_model: RewardModel = RewardModel.NONE
    notes: str = ""


class CampaignBudget(BaseModel):
    """Resource budget for a campaign."""

    max_missions: int = 6
    max_agents: int = 3
    max_turns_per_agent: int = 20


class InvariantCluster(BaseModel):
    """
    Intermediate grouping of related invariants.

    Clustering rule: invariants sharing vars OR functions
    in the same container/file → same cluster.
    """

    cluster_id: str
    invariant_ids: List[str] = Field(default_factory=list)
    primary_var_ids: List[str] = Field(default_factory=list)
    primary_function_ids: List[str] = Field(default_factory=list)
    primary_container: Optional[str] = None
    dominant_type: Optional[InvariantType] = None


class CampaignBrief(BaseModel):
    """
    A campaign brief with full execution context for agents.

    Self-contained: agents can execute with only this + workspace.
    """

    campaign_id: str
    mode: CampaignMode = CampaignMode.INVARIANT_BOUNDED
    agent_types: List[MissionAgentType] = Field(default_factory=list)
    framework: Optional[str] = None
    workspace_preset: WorkspacePreset = WorkspacePreset.CLEAN
    # Scope (derived from cluster + ActorMatrix + Graph)
    scope: CampaignScope = Field(default_factory=CampaignScope)
    # Invariants to test (full objects, not just IDs)
    invariants: List[Invariant] = Field(default_factory=list)
    # Objectives
    objectives: CampaignObjectives = Field(default_factory=CampaignObjectives)
    # Budget
    budget: CampaignBudget = Field(default_factory=CampaignBudget)
    # MasterContext for agent independence
    master_context: Optional[MasterContext] = None
    # Priority: 0=verification, 1=narrow, 2=broad
    priority: int = 1


class Mission(BaseModel):
    """
    A single mission spawned from a campaign.

    What agents actually execute.
    """

    mission_id: str
    campaign_id: str
    # Target invariant (None for exploratory/game modes)
    invariant_id: Optional[str] = None
    invariant: Optional[Invariant] = None
    # Agent assignment
    agent_type: MissionAgentType
    # Inherited from campaign
    scope: CampaignScope = Field(default_factory=CampaignScope)
    workspace_preset: WorkspacePreset = WorkspacePreset.CLEAN
    objectives: CampaignObjectives = Field(default_factory=CampaignObjectives)
    # Budget for this mission
    max_turns: int = 20
    # State
    status: str = "pending"  # pending, in_progress, completed, failed


class DispatcherProcessInput(BaseModel):
    """Input for DispatcherProcess."""

    master_context: "MasterContext"
    dependency_graph: Any  # DependencyGraph object
    actor_matrix: "ActorMatrix"
    invariants: List[Invariant]
    # Config
    max_invariants_per_cluster: int = 5
    max_campaigns: int = 10
    default_budget: CampaignBudget = Field(default_factory=CampaignBudget)
    include_exploration: bool = True  # Add exploratory/game campaigns


class DispatcherProcessOutput(BaseModel):
    """Output of DispatcherProcess."""

    clusters: List[InvariantCluster] = Field(default_factory=list)
    campaigns: List[CampaignBrief] = Field(default_factory=list)
    missions: List[Mission] = Field(default_factory=list)
    success: bool
    error_message: Optional[str] = None
    stats: Dict[str, int] = Field(default_factory=dict)


class EntrypointsPolicy(BaseModel):
    """Controls how entrypoints are sequenced/selected for a campaign."""

    max_sequence_len: int = Field(default=4, ge=1, le=50)
    prefer: List[str] = Field(default_factory=list)


class EntrypointsSubset(BaseModel):
    """Subset of allowed entrypoints for a campaign, with optional sequencing policy."""

    ids: List[str] = Field(default_factory=list)
    policy: Optional[EntrypointsPolicy] = None


class CampaignBrief(BaseModel):
    """
    Full briefing for the Blackbox worker (v2).

    Note: `master_context` is optional here and may be provided as `mastercontext`.
    """

    # --- Core campaign identity ---
    campaign_id: str
    kind: str

    # --- Targeting ---
    invariant_ids: List[str] = Field(default_factory=list)
    primary_var_ids: List[str] = Field(default_factory=list)
    actor_roles: List[str] = Field(default_factory=list)

    entrypoints_subset: EntrypointsSubset = Field(default_factory=EntrypointsSubset)

    # --- Execution controls ---
    worker_types: List[str] = Field(default_factory=list)
    workspace_preset: str = "writeable"
    priority: int = 1

    class Budget(BaseModel):
        max_missions: int = Field(default=1, ge=1, le=1000)
        max_workers: int = Field(default=1, ge=1, le=1000)
        max_turns_per_worker: int = Field(default=32, ge=1, le=1000)

    budget: Budget = Field(default_factory=Budget)

    # --- Optional attached context (backwards compatible / transitional) ---
    master_context: Optional[MasterContext] = None
    protocol_manifesto: Optional[ProtocolManifesto] = None
    actor_matrix: Optional[ActorMatrix] = None
    

class BlackboxInput(BaseModel):
    campaign_brief: CampaignBrief
    num_turns: int
    model_name: str
    use_openai: bool = False
    execution_id: Optional[str] = None


class BlackboxOutput(BaseModel):
    response: Optional[AgentResponse]
    observations: List[Observation] = Field(default_factory=list)
    estimated_cost: float
    total_tokens: Dict[str, int]
    success: bool
    error_message: Optional[str] = None
    repo_path: str