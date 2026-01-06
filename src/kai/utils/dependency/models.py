"""
Generic Data Models for Kai v2 (Language Agnostic).
"""

from __future__ import annotations
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

# Type alias for edge direction
Direction = Literal["in", "out", "both"]


class NodeKind(str, Enum):
    FILE = "file"
    # Generic container: Contract (Solidity), Module (Rust), Class (Py)
    CONTAINER = "container"
    # Executable unit: Function (Solidity), Method (Py), Instruction (Anchor)
    UNIT = "unit"
    # Interface/Guard: Modifier (Solidity), Attribute (Rust), Decorator (Py)
    INTERFACE = "interface"
    # Data: StateVar (Solidity), Account (Rust), Global (Py)
    VARIABLE = "variable"
    # Critical for Agents: Structs, Enums, Typedefs
    TYPE_DEF = "type_def"
    EVENT = "event"
    EXTERNAL = "external"


class EdgeKind(str, Enum):
    # Structural
    DEFINES = "defines"  # File -> Container
    IMPORTS = "imports"
    INHERITS = "inherits"

    # Behavioral
    CALLS = "calls"  # Unit -> Unit
    ACCEPTS = "accepts"  # Unit -> Interface (e.g. uses modifier)

    # Data Flow
    READS = "reads"
    WRITES = "writes"
    EMITS = "emits"

    # Agent Context (New)
    USES_TYPE = "uses_type"  # Unit -> TypeDef (Function sig uses Struct)


@dataclass
class EdgeMeta:
    """Metadata for an edge in the graph."""

    kind: EdgeKind
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SourceSpan:
    """Precise location for agents to reference."""

    file: str
    start_line: int
    end_line: int
    start_col: Optional[int] = None
    end_col: Optional[int] = None


@dataclass(frozen=True)
class Node:
    """A generic node in the code property graph."""

    id: str
    kind: NodeKind
    name: str
    # Spans allow agents to request specific snippets, not just full files
    span: Optional[SourceSpan] = None
    parent_id: Optional[str] = None  # ID of Container
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PathStep:
    """
    A single step in a call trace with full provenance.
    """

    node_id: str
    node_name: str
    container_name: Optional[str]
    # Where did this call happen? (Critical for diffs)
    call_site_span: Optional[SourceSpan]


@dataclass
class WritePath:
    """
    Trace from Entrypoint -> State Variable Write.
    Uses IDs for precision, Names for display.
    """

    entrypoint_id: str
    entrypoint_name: str
    steps: List[PathStep]
    var_id: str
    var_name: str

    def __str__(self) -> str:
        chain = " -> ".join([s.node_name for s in self.steps])
        return f"[{self.entrypoint_name}] {chain} -> writes {self.var_name}"
