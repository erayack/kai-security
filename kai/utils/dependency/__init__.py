"""
Dependency graph module for Kai v2.

This module provides tools for building and querying dependency graphs
from projects using static analysis tools.

Features:
- DependencyGraph: Core graph data structure for code dependencies
- DependencyAnalysis: High-level analysis wrapper with caching
- Node/Edge models: Typed representations of code elements
- Builders: Functions to construct graphs from analysis tools (e.g., Slither)
- Adapters: Domain-specific adapters for language/framework support (extensible)

Usage:
    from kai.utils.dependency import DependencyGraph, DependencyAnalysis, build_from_slither

    # Build from a project
    graph = build_from_slither("/path/to/project")

    # Or load from cached JSON
    graph = DependencyGraph.from_json("dependency_graph.json")

    # Query the graph (basic)
    files = graph.derive_related_files("src/Vault.sol", depth=2)

    # High-level analysis via DependencyAnalysis (typed results + caching)
    analysis = DependencyAnalysis(graph)
    roles = analysis.get_actor_roles()           # -> list[ActorRole]
    paths = analysis.get_write_paths("_balances")  # -> list[WritePath]
    ctx = analysis.get_context_slice("withdraw", ["_balances"])  # -> ContextSliceMeta

    # Using adapters for different frameworks
    from kai.utils.dependency.adapters import SolidityAdapter, get_adapter_for_framework

    adapter = get_adapter_for_framework("foundry")  # Auto-detect
    analysis = DependencyAnalysis(graph, adapter=adapter)
"""

# Core models
from .models import (
    Direction,
    EdgeKind,
    EdgeMeta,
    FieldAccessInfo,
    GuardIssue,
    GuardIssueType,
    Node,
    NodeKind,
    Severity,
    TrustLevel,
    # Analysis result types
    ActorRole,
    ContextSliceMeta,
    StateVarInfo,
    WritePath,
    # New types for v2
    CallPath,
    EventEmission,
    LibraryUsage,
)

# Graph class
from .graph import DependencyGraph

# Builders
from .builders import build_from_slither

# Analysis wrapper class
from .analysis import DependencyAnalysis

__all__ = [
    # Core Models
    "NodeKind",
    "EdgeKind",
    "Node",
    "EdgeMeta",
    "Direction",
    "TrustLevel",
    # Result Types
    "ActorRole",
    "ContextSliceMeta",
    "FieldAccessInfo",
    "GuardIssue",
    "GuardIssueType",
    "Severity",
    "StateVarInfo",
    "WritePath",
    # New types for v2
    "CallPath",
    "EventEmission",
    "LibraryUsage",
    # Graph
    "DependencyGraph",
    # Analysis
    "DependencyAnalysis",
    # Builders
    "build_from_slither",
]
