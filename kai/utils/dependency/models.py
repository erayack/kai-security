"""Data models for the dependency graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Literal, Optional


class NodeKind(str, Enum):
    """Types of nodes in the dependency graph."""

    FILE = "file"
    CONTRACT = "contract"
    FUNCTION = "function"
    MODIFIER = "modifier"
    STATE_VAR = "state_var"
    STRUCT_FIELD = "struct_field"  # e.g., "Proof.key", "UserInfo.amount"
    EVENT = "event"
    EXTERNAL = "external"  # unresolved import/call targets


class EdgeKind(str, Enum):
    """Types of edges in the dependency graph."""

    IMPORTS = "imports"  # file -> file
    DEFINES = "defines"  # file -> contract
    INHERITS = "inherits"  # contract -> contract
    DECLARES_FUNCTION = "declares_fn"  # contract -> function
    DECLARES_MODIFIER = "declares_mod"  # contract -> modifier
    DECLARES_STATEVAR = "declares_var"  # contract -> statevar
    DECLARES_EVENT = "declares_event"  # contract -> event
    USES_MODIFIER = "uses_modifier"  # function -> modifier
    CALLS = "calls"  # function/modifier -> function/modifier
    HIGH_LEVEL_CALL = "high_level_call"  # function -> contract/external
    LOW_LEVEL_CALL = "low_level_call"  # function -> external
    LIBRARY_CALL = "library_call"  # function -> library function
    USES_LIBRARY = "uses_library"  # contract -> library (using X for Y)
    READS = "reads"  # function/modifier -> statevar
    WRITES = "writes"  # function/modifier -> statevar
    READS_FIELD = "reads_field"  # function/modifier -> struct_field
    WRITES_FIELD = "writes_field"  # function/modifier -> struct_field
    EMITS = "emits"  # function/modifier -> event


@dataclass(frozen=True)
class Node:
    """A node in the dependency graph."""

    id: str
    kind: NodeKind
    name: str
    file: Optional[str] = None  # repo-relative (posix) when applicable
    contract: Optional[str] = None  # contract node id when applicable
    signature: Optional[str] = None
    visibility: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EdgeMeta:
    """Metadata for an edge in the dependency graph."""

    kind: EdgeKind
    meta: Dict[str, Any] = field(default_factory=dict)


# Type alias for traversal direction
Direction = Literal["out", "in", "both"]

# Trust levels for actor analysis
TrustLevel = Literal["High", "Medium", "Low", "None", "N/A"]


# ---------------------------
# Analysis Result Types
# ---------------------------


@dataclass
class ActorRole:
    """A role definition from actor analysis."""

    role: str
    trust: TrustLevel
    modifier_pattern: list[str]
    privileges: list[str]
    function_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "trust": self.trust,
            "modifier_pattern": self.modifier_pattern,
            "privileges": self.privileges,
            "function_count": self.function_count,
        }


@dataclass
class WritePath:
    """A call path from public entrypoint to state variable write."""

    entrypoint: str
    path: list[str]
    writer: str
    contract: Optional[str]
    var_name: str
    var_file: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entrypoint": self.entrypoint,
            "path": self.path,
            "writer": self.writer,
            "contract": self.contract,
            "var_name": self.var_name,
            "var_file": self.var_file,
        }

    def __str__(self) -> str:
        path_str = " -> ".join(self.path)
        return (
            f"{self.entrypoint}: {path_str} (writes {self.var_name} via {self.writer})"
        )


@dataclass
class ContextSliceMeta:
    """
    Metadata for a focused slice of the codebase for a specific mission.

    This is combined with MasterContext to form the full context for workers.
    Contains graph-derived information about relevant files, symbols, and state mutations.
    """

    target_func: str
    target_node_id: Optional[str]
    invariant_seeds: list[str]
    related_files: list[str]
    symbols: list[str]
    write_paths: list[WritePath] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_func": self.target_func,
            "target_node_id": self.target_node_id,
            "invariant_seeds": self.invariant_seeds,
            "related_files": self.related_files,
            "symbols": self.symbols,
            "write_paths": [wp.to_dict() for wp in self.write_paths],
        }


@dataclass
class StateVarInfo:
    """Information about a state variable and its accessors."""

    name: str
    var_id: str
    contract: Optional[str]
    file: Optional[str]
    var_type: Optional[str]
    visibility: Optional[str]
    writers: list[str]
    readers: list[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "var_id": self.var_id,
            "contract": self.contract,
            "file": self.file,
            "type": self.var_type,
            "visibility": self.visibility,
            "writers": self.writers,
            "readers": self.readers,
        }


@dataclass
class FieldAccessInfo:
    """Information about struct field access patterns."""

    field_name: str  # e.g., "Proof.key"
    field_id: str
    struct_type: str  # e.g., "Proof"
    member: str  # e.g., "key"
    readers: list[str]  # functions that read this field
    writers: list[str]  # functions that write this field

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_name": self.field_name,
            "field_id": self.field_id,
            "struct_type": self.struct_type,
            "member": self.member,
            "readers": self.readers,
            "writers": self.writers,
        }


# ---------------------------
# Guard Detection Types
# ---------------------------


class GuardIssueType(str, Enum):
    """Types of guard/access control issues detected by static analysis."""

    TX_ORIGIN_ADDRESS_THIS = (
        "tx_origin_address_this"  # tx.origin == address(this) - impossible
    )
    TX_ORIGIN_IN_AUTH = (
        "tx_origin_in_auth"  # tx.origin used for authorization (phishing risk)
    )
    IMPOSSIBLE_OR_CONDITION = (
        "impossible_or_condition"  # if (x != A || x != B) - logic error
    )
    UNSATISFIABLE_GUARD = "unsatisfiable_guard"  # guard can never be satisfied
    ALWAYS_REVERTS = "always_reverts"  # function deterministically reverts


class Severity(str, Enum):
    """Severity levels for static analysis findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class GuardIssue:
    """
    A guard/access control issue detected by static analysis.

    Used internally by DependencyGraph analysis to surface potential bugs
    that can be converted into LIVENESS invariants.
    """

    issue_type: GuardIssueType
    severity: Severity
    function_name: str
    function_id: str
    modifier_name: Optional[str]  # If issue is in a modifier
    contract_name: Optional[str]
    file: Optional[str]
    line: Optional[int]
    description: str
    pattern: str  # The problematic code pattern found
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issue_type": self.issue_type.value,
            "severity": self.severity.value,
            "function_name": self.function_name,
            "function_id": self.function_id,
            "modifier_name": self.modifier_name,
            "contract_name": self.contract_name,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "pattern": self.pattern,
            "recommendation": self.recommendation,
        }


# ---------------------------
# Call Path Types (Graph-level)
# ---------------------------


@dataclass
class CallPath:
    """
    A typed call path through the contract system (graph-level).

    Used by workers to understand execution paths for:
    - StateWorker: Finding impossible call sequences
    - GamifiedWorker: Coordinating actor sequences
    - QuantWorker: Tracing numeric flows

    Each step contains both the node ID (for graph operations)
    and human-readable information (for analysis/display).
    """

    steps: list[str]  # Node IDs in order: ["func:1", "func:2", "func:3"]
    step_names: list[
        str
    ]  # Human readable: ["Vault.deposit", "Vault._mint", "ERC20._update"]
    contracts: list[str]  # Contracts involved: ["Vault", "Vault", "ERC20"]
    edge_types: list[str]  # Edge kinds used: ["calls", "calls"]
    entry_visibility: Optional[str] = None  # "public", "external", etc.
    terminates_at: Optional[str] = None  # "statevar", "event", "external", etc.
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def length(self) -> int:
        """Number of hops in the path."""
        return len(self.steps) - 1 if self.steps else 0

    @property
    def entrypoint(self) -> Optional[str]:
        """First step node ID."""
        return self.steps[0] if self.steps else None

    @property
    def entrypoint_name(self) -> Optional[str]:
        """First step human-readable name."""
        return self.step_names[0] if self.step_names else None

    @property
    def endpoint(self) -> Optional[str]:
        """Last step node ID."""
        return self.steps[-1] if self.steps else None

    @property
    def endpoint_name(self) -> Optional[str]:
        """Last step human-readable name."""
        return self.step_names[-1] if self.step_names else None

    @property
    def crosses_contracts(self) -> bool:
        """Whether the path crosses contract boundaries."""
        return len(set(self.contracts)) > 1

    @property
    def unique_contracts(self) -> list[str]:
        """Unique contracts in the path, in order of first appearance."""
        seen: set[str] = set()
        result: list[str] = []
        for c in self.contracts:
            if c not in seen:
                seen.add(c)
                result.append(c)
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": self.steps,
            "step_names": self.step_names,
            "contracts": self.contracts,
            "edge_types": self.edge_types,
            "entry_visibility": self.entry_visibility,
            "terminates_at": self.terminates_at,
            "length": self.length,
            "crosses_contracts": self.crosses_contracts,
            "meta": self.meta,
        }

    def __str__(self) -> str:
        return " -> ".join(self.step_names)


# ---------------------------
# Event Emission Types
# ---------------------------


@dataclass
class EventEmission:
    """Information about event emission from a function."""

    event_name: str
    event_id: str
    emitter_func: str
    emitter_func_id: str
    contract: Optional[str]
    file: Optional[str]
    indexed_params: list[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_name": self.event_name,
            "event_id": self.event_id,
            "emitter_func": self.emitter_func,
            "emitter_func_id": self.emitter_func_id,
            "contract": self.contract,
            "file": self.file,
            "indexed_params": self.indexed_params,
            "meta": self.meta,
        }


# ---------------------------
# Library Usage Types
# ---------------------------


@dataclass
class LibraryUsage:
    """Information about library usage via 'using X for Y' directive."""

    library_name: str
    library_id: str
    target_type: str  # The type Y in "using X for Y"
    consumer_contract: str
    consumer_contract_id: str
    file: Optional[str]
    functions_used: list[str] = field(
        default_factory=list
    )  # Which library funcs are called

    def to_dict(self) -> Dict[str, Any]:
        return {
            "library_name": self.library_name,
            "library_id": self.library_id,
            "target_type": self.target_type,
            "consumer_contract": self.consumer_contract,
            "consumer_contract_id": self.consumer_contract_id,
            "file": self.file,
            "functions_used": self.functions_used,
        }
