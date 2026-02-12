"""
Dependency graph module.

Provides a generic tree-sitter-based graph builder and a typed
DependencyGraph for structural code navigation.
"""

from .builder import LANG_CONFIGS, LangConfig, TreeSitterBuilder
from .graph import DependencyGraph
from .models import (
    Direction,
    EdgeKind,
    EdgeMeta,
    Node,
    NodeKind,
    SourceSpan,
)

__all__ = [
    "DependencyGraph",
    "Direction",
    "EdgeKind",
    "EdgeMeta",
    "LANG_CONFIGS",
    "LangConfig",
    "Node",
    "NodeKind",
    "SourceSpan",
    "TreeSitterBuilder",
]
