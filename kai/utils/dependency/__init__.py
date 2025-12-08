"""
Dependency graph module for Kai v2.

This module provides tools for building and querying dependency graphs
from Solidity projects using Slither static analysis.

Usage:
    from kai.utils.dependency import DependencyGraph, build_from_slither

    # Build from a project
    graph = build_from_slither("/path/to/project")

    # Or load from cached JSON
    graph = DependencyGraph.from_json("dependency_graph.json")

    # Query the graph (basic)
    files = graph.derive_related_files("src/Vault.sol", depth=2)

    # High-level analysis API (typed results)
    from kai.utils.dependency import get_actor_roles, get_write_paths, get_context_slice_meta

    roles = get_actor_roles(graph)           # -> list[ActorRole]
    paths = get_write_paths(graph, "_balances")  # -> list[WritePath]
    ctx = get_context_slice_meta(graph, "withdraw", ["_balances"])  # -> ContextSliceMeta
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
)

# Graph class
from .graph import DependencyGraph

# Builders
from .builders import build_from_slither

# High-level analysis API
from .analysis import (
    detect_guard_issues,
    get_actor_roles,
    get_context_slice_meta,
    get_field_access_info,
    get_invariant_vectors,
    get_liveness_invariants,
    get_state_var_info,
    get_write_paths,
)

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
    # Graph
    "DependencyGraph",
    # Builders
    "build_from_slither",
    # Analysis API
    "detect_guard_issues",
    "get_actor_roles",
    "get_context_slice_meta",
    "get_field_access_info",
    "get_invariant_vectors",
    "get_liveness_invariants",
    "get_state_var_info",
    "get_write_paths",
]
