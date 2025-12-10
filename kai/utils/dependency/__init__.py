"""
Dependency graph module for Kai v2.

This module provides tools for building and querying dependency graphs
from projects using static analysis tools.

Features:
- DependencyGraph: Core graph data structure for code dependencies
- GraphQueryEngine: Query engine for grounded codebase exploration
- Node/Edge models: Typed representations of code elements
- Builders: Functions to construct graphs from analysis tools (e.g., Slither)
- Adapters: Domain-specific adapters for language/framework support (extensible)

GraphQueryEngine API:
    resolve          - "Where is X?" - Find code elements by name (returns List[NodeRef])
    loc              - "Where exactly?" - Get file/line location for a node
    snippet          - "Show me the code" - Pull minimal code ranges
    neighbors        - "What's connected?" - Atomic local expansion by edge type
    callers/callees  - "Who calls/is called?" - Shortcut for call graph queries
    paths            - "How to reach X?" - BFS-based bounded path enumeration
    data_paths       - "Who writes X?" - Trace entrypoints to state variable access
    slice            - "What context?" - Build justified context slice for analysis
    explain          - "Prove it!" - Generate verifiable evidence for a path
"""

# Core models
from .models import (
    EdgeKind,
    Node,
    NodeKind,
    # Legacy result types (for backwards compatibility)
    WritePath,
)

# Graph class
from .graph import DependencyGraph

# Builders
from .builders import SolidityBuilder

# Analysis wrapper class
from .analysis import GraphQueryEngine, FileSourceLoader

__all__ = [
    # Core Models
    "NodeKind",
    "EdgeKind",
    "Node",
    # Legacy Result Types (backwards compatibility)
    "WritePath",
    # 5-Tool API Types
    # Graph
    "DependencyGraph",
    # Analysis
    "GraphQueryEngine",
    "FileSourceLoader",
    # Builders
    "SolidityBuilder",
]
