from enum import Enum
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field

class Role(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"

class ChatMessage(BaseModel):
    role: Role
    content: str

class AgentResponse(BaseModel):
    thoughts: str
    python_block: Optional[str] = None
    test_script: Optional[str] = None
    suggest_fix: Optional[str] = None

    def __str__(self):
        return f"Thoughts: {self.thoughts}\nPython block:\n {self.python_block}\nTest script:\n {self.test_script}\nSuggest fix:\n {self.suggest_fix}"

class GrepResponse(BaseModel):
    exit_code: int
    stdout: str
    stderr: str

    def __str__(self):
        return f"- Exit code: {self.exit_code}\n- Stdout: {self.stdout}\n- Stderr: {self.stderr}"

class ExploitSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

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
    locations: List[ExploitLocation]  # All locations where this exploit appears
    description: str  # General description of the vulnerability pattern
    suggested_fix: Optional[str] = None  # General fix approach

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
    total_tokens: Dict[str, int] = Field(default_factory=dict)  # {"prompt_tokens": X, "completion_tokens": Y}
    estimated_cost: float = 0.0
    
    # Budget tracking (sub-agents only)
    sub_agent_total_tokens: Dict[str, int] = Field(default_factory=dict)
    sub_agent_total_cost: float = 0.0
    
    # Budget tracking (combined: this agent + all sub-agents)
    combined_total_tokens: Dict[str, int] = Field(default_factory=dict)
    combined_total_cost: float = 0.0
    
    # Exploration results
    files_explored: List[str] = Field(default_factory=list)
    exploits_found: List[ExploitSummary] = Field(default_factory=list)
    code_references: List[CodeReference] = Field(default_factory=list, max_length=10)
    
    # Sub-reports from recursive delegation
    sub_reports: List['SubAgentReport'] = Field(default_factory=list)
    
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
        "",
        f"{prefix}EXPLOITS FOUND: {len(report.exploits_found)}",
    ]
    
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