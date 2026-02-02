"""
Dependency graph query tools for agents.

This module exposes GraphQueryEngine methods as individual agent tools
with proper typed returns (NodeRef, ContextSlice, EvidencePack).
"""

from typing import Any, Dict, List, Literal, Optional, Union

from kai.utils.dependency.analysis import ContextSlice, EvidencePack, NodeRef

from .shared import get_query_engine


def dependency_graph_resolve(
    ref: str,
    scope: Optional[str] = None,
) -> Union[List[NodeRef], Dict[str, str]]:
    """
    Resolve a symbol reference to node IDs in the dependency graph.

    This is the entry point for finding code elements. Returns ranked candidates
    where public entrypoints are prioritized.

    Args:
        ref: Symbol name to resolve (e.g., "withdraw", "Vault.deposit", or a node ID).
        scope: Optional scope to narrow the search (e.g., contract name).

    Returns:
        List of NodeRef objects representing matching code elements, ranked by relevance.
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        # Find all functions named "withdraw"
        results = graph_resolve("withdraw")

        # Find "deposit" within the "Vault" contract
        results = graph_resolve("deposit", scope="Vault")

        # Resolve by exact node ID (fast path)
        results = graph_resolve("Vault.deposit(uint256)")
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.resolve(ref, scope)
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_loc(node_id: str) -> Union[Dict[str, Any], Dict[str, str]]:
    """
    Get the precise location (file, line span, signature) for a node.

    This is the anchor for all graph queries - every answer maps back to a location.

    Args:
        node_id: The ID of the node to locate.

    Returns:
        Dict with: id, kind, file, span (start/end lines), signature.
        Returns {"error": "..."} if the node doesn't exist or graph is unavailable.

    Examples:
        loc = graph_loc("Vault.deposit(uint256)")
        # Returns: {"id": "...", "file": "src/Vault.sol", "span": {"start": 45, "end": 60}, ...}
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.loc(node_id)
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_snippet(
    file: str, start_line: int, end_line: int
) -> Union[str, Dict[str, str]]:
    """
    Pull a minimal code snippet from a file by line range.

    Uses a secure loader to prevent path traversal attacks.

    Args:
        file: The file path (relative to repo root).
        start_line: Start line number (1-indexed).
        end_line: End line number (1-indexed, inclusive).

    Returns:
        The source code string for the specified range.
        Returns {"error": "..."} if the file doesn't exist or graph is unavailable.

    Examples:
        code = graph_snippet("src/Vault.sol", 45, 60)
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.snippet(file, {"start": start_line, "end": end_line})
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_neighbors(
    node_id: str,
    edge_kinds: List[str],
    direction: Literal["in", "out", "both"] = "out",
) -> Union[List[NodeRef], Dict[str, str]]:
    """
    Get neighbors of a node filtered by edge types and direction.

    This is the atomic local expansion primitive for graph traversal.

    Args:
        node_id: The ID of the node to expand from.
        edge_kinds: List of edge types to follow. Valid types:
            - "calls": Function call edges
            - "reads": State variable read edges
            - "writes": State variable write edges
            - "inherits": Inheritance edges
            - "imports": Import edges
            - "defines": Container definition edges
            - "accepts": Modifier/interface usage edges
            - "uses_type": Type usage edges
            - "emits": Event emission edges
        direction: "in" (incoming), "out" (outgoing), or "both".

    Returns:
        List of NodeRef objects for neighboring nodes.
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        # Find all functions that call "withdraw"
        callers = graph_neighbors("Vault.withdraw(uint256)", ["calls"], "in")

        # Find what "deposit" reads and writes
        deps = graph_neighbors("Vault.deposit(uint256)", ["reads", "writes"], "out")
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.neighbors(node_id, edge_kinds, direction)
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_callers(func_id: str) -> Union[List[NodeRef], Dict[str, str]]:
    """
    Find all functions that call a given function.

    Shortcut for graph_neighbors(func_id, ["calls"], "in").

    Args:
        func_id: The ID of the function to find callers for.

    Returns:
        List of NodeRef objects representing caller functions.
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        callers = graph_callers("Vault.withdraw(uint256)")
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.callers(func_id)
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_callees(func_id: str) -> Union[List[NodeRef], Dict[str, str]]:
    """
    Find all functions called by a given function.

    Shortcut for graph_neighbors(func_id, ["calls"], "out").

    Args:
        func_id: The ID of the function to find callees for.

    Returns:
        List of NodeRef objects representing called functions.
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        callees = graph_callees("Vault.deposit(uint256)")
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.callees(func_id)
    except Exception as e:
        return {"error": str(e)}


def _sanitize_window(
    start: int, end: Optional[int], total: int, max_window: int = 200
) -> tuple[int, int]:
    """
    Normalize pagination window to prevent unbounded output.
    """
    start = max(start, 0)
    if end is None or end <= start:
        end = start + 50
    end = min(end, start + max_window, total)
    return start, end


def dependency_graph_public_entrypoints(
    start: int = 0, end: Optional[int] = 50
) -> Union[Dict[str, Any], Dict[str, str]]:
    """
    Get all public/external function entrypoints in the dependency graph.

    Returns functions with "public" or "external" visibility (excluding constructors).
    Includes ALL public functions - both protocol code and libraries.

    For protocol-only entrypoints (excluding libraries), use dependency_graph_protocol_entrypoints().

    Pagination:
        - Results are windowed with start/end (0-based, end exclusive).
        - Maximum window size is capped to avoid huge token outputs.

    Returns:
        Dict with:
            results: List[NodeRef]
            total: int
            window: [start, end]
            truncated: bool
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        # Get all public entry points (including libraries)
        entrypoints = dependency_graph_public_entrypoints()
        for ep in entrypoints["results"]:
            print(f"{ep.container}.{ep.name} - {ep.signature}")
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        # Get public entrypoint IDs from the graph
        entrypoint_ids = engine.graph.public_entrypoints()
        total = len(entrypoint_ids)
        start, end = _sanitize_window(start, end, total)
        sliced = entrypoint_ids[start:end]
        # Convert to NodeRef using the engine's helper
        results = [engine._to_ref(engine.graph.node(nid)) for nid in sliced]
        return {
            "results": results,
            "total": total,
            "window": [start, end],
            "truncated": end < total,
        }
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_protocol_entrypoints(
    start: int = 0, end: Optional[int] = 50
) -> Union[Dict[str, Any], Dict[str, str]]:
    """
    Get public/external entrypoints that belong to the protocol (not libraries).

    This is the primary tool for identifying the attack surface. It filters out:
    - Library code (OpenZeppelin, Solmate, forge-std, etc.)
    - Test files

    Use this instead of dependency_graph_public_entrypoints() when you want
    only the protocol's own functions, not inherited library functions.

    Pagination:
        - Results are windowed with start/end (0-based, end exclusive).
        - Maximum window size is capped to avoid huge token outputs.

    Returns:
        Dict with:
            results: List[NodeRef]
            total: int
            window: [start, end]
            truncated: bool
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        # Get protocol attack surface
        entrypoints = dependency_graph_protocol_entrypoints()
        for ep in entrypoints["results"]:
            print(f"{ep.container}.{ep.name} - {ep.signature}")
            # e.g., "Vault.deposit - deposit(uint256)"
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        protocol_eps = engine.protocol_entrypoints()
        total = len(protocol_eps)
        start, end = _sanitize_window(start, end, total)
        results = protocol_eps[start:end]
        return {
            "results": results,
            "total": total,
            "window": [start, end],
            "truncated": end < total,
        }
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_paths(
    src_ids: List[str],
    dst_ids: List[str],
    edge_kinds: List[str],
    max_depth: int = 5,
) -> Union[List[List[NodeRef]], Dict[str, str]]:
    """
    Find all paths between source and destination nodes via specified edge types.

    Uses BFS to enumerate bounded paths. Useful for reachability analysis.

    Args:
        src_ids: List of source node IDs to start from.
        dst_ids: List of destination node IDs to reach.
        edge_kinds: List of edge types to traverse (e.g., ["calls"]).
        max_depth: Maximum path length (default 5).

    Returns:
        List of paths, where each path is a List[NodeRef].
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        # Find all call paths from public functions to a vulnerable sink
        paths = graph_paths(
            src_ids=["Vault.deposit(uint256)", "Vault.withdraw(uint256)"],
            dst_ids=["Vault._transfer(address,uint256)"],
            edge_kinds=["calls"],
            max_depth=5
        )
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.paths(src_ids, dst_ids, edge_kinds, max_depth)
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_data_paths(
    entrypoints: List[str],
    symbol_id: str,
    mode: Literal["read", "write"] = "write",
) -> Union[List[Dict[str, Any]], Dict[str, str]]:
    """
    Trace data flow from entrypoints to a state variable access.

    Finds paths: Entrypoint -> ... -> Function that reads/writes symbol.

    Args:
        entrypoints: List of public function IDs to trace from.
        symbol_id: The state variable node ID to trace to.
        mode: "read" to find read paths, "write" to find write paths (default).

    Returns:
        List of dicts with: entrypoint, accessor, symbol, steps, length.
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        # Find all paths where public functions can write to "balances"
        paths = graph_data_paths(
            entrypoints=["Vault.deposit(uint256)", "Vault.withdraw(uint256)"],
            symbol_id="Vault.balances",
            mode="write"
        )
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.data_paths(entrypoints, symbol_id, mode)
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_slice(
    seeds: List[str],
    policy: str = "standard",
) -> Union[ContextSlice, Dict[str, str]]:
    """
    Build a justified context slice from seed nodes.

    Expands seeds to include necessary context (type definitions, callees, parents)
    to prevent hallucination. Each included node has a justification.

    Args:
        seeds: List of node IDs to build context around.
        policy: Expansion policy. "standard" includes types, callees, and parents.

    Returns:
        ContextSlice with: nodes (List[NodeRef]), files (List[str]), justification (Dict).
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        # Get context for analyzing a function
        ctx = graph_slice(["Vault.deposit(uint256)"])
        # ctx.nodes contains the function, its callees, type definitions used
        # ctx.justification explains why each node is included
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.slice(seeds, policy)
    except Exception as e:
        return {"error": str(e)}


def dependency_graph_explain(path: List[str]) -> Union[EvidencePack, Dict[str, str]]:
    """
    Generate verifiable evidence for a path/trace.

    Takes a path and returns code snippets and
    edge metadata that prove the path exists. Used by verifiers.

    Args:
        path: List of node IDs representing a path (e.g., from graph_paths).

    Returns:
        EvidencePack with: item, trace, edges, snippets.
        Returns {"error": "..."} if the graph is unavailable.

    Examples:
        # Prove a call path exists
        paths = graph_paths(src_ids, dst_ids, ["calls"])
        if paths:
            evidence = graph_explain([ref.id for ref in paths[0]])
            # evidence.snippets contains the actual code
            # evidence.trace shows exact file:line locations
    """
    engine = get_query_engine()
    if engine is None:
        return {"error": "Dependency graph is not available to the agent"}

    try:
        return engine.explain(path)
    except Exception as e:
        return {"error": str(e)}
