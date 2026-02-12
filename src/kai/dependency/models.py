"""Generic data models for code dependency graphs."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Literal, Optional

Direction = Literal["in", "out", "both"]


class NodeKind(str, Enum):
    FILE = "file"
    CONTAINER = "container"  # Class, Module, Contract, Struct
    UNIT = "unit"  # Function, Method
    VARIABLE = "variable"  # State var, Global, Attribute
    TYPE_DEF = "type_def"  # Struct, Enum, Typedef
    IMPORT = "import"  # Import statement


class EdgeKind(str, Enum):
    DEFINES = "defines"  # File -> Container, Container -> Unit
    CALLS = "calls"  # Unit -> Unit
    IMPORTS = "imports"  # File -> File
    INHERITS = "inherits"  # Container -> Container


@dataclass
class EdgeMeta:
    """Metadata for an edge in the graph."""

    kind: EdgeKind
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SourceSpan:
    """Precise source location for agents to reference."""

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
    span: Optional[SourceSpan] = None
    parent_id: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)
