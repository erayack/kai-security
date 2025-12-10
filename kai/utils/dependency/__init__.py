"""
Dependency graph module for Kai v2.

This module provides tools for building and querying dependency graphs
from projects using static analysis tools.

Features:
- DependencyGraph: Core graph data structure for code dependencies
- DependencyAnalysis: 5-Tool API for grounded codebase exploration
- Node/Edge models: Typed representations of code elements
- Builders: Functions to construct graphs from analysis tools (e.g., Slither)
- Adapters: Domain-specific adapters for language/framework support (extensible)

5-Tool API:
    search_nodes     - "Where is X?" - Find code elements by name
    inspect_container - "What's inside X?" - List contents of a contract/module
    read_context     - "Show me the code" - Get source with resolved types and guards
    get_references   - "Who uses X?" - Find callers, readers, writers
    trace_reachability - "Can I exploit X?" - Prove if function is reachable

Usage:
    from kai.utils.dependency import DependencyGraph, DependencyAnalysis

    graph = DependencyGraph.from_json("dependency_graph.json")
    analysis = DependencyAnalysis(graph)

    # Find a function
    results = analysis.search_nodes("withdraw")

    # See what's in a contract
    contents = analysis.inspect_container(contract_id)

    # Get code with types resolved
    context = analysis.read_context(func_id)

    # Find who calls this
    refs = analysis.get_references(func_id, ref_type="callers")

    # Check if exploitable
    path = analysis.trace_reachability(public_func_id, vulnerable_func_id)
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
