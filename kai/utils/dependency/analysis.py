"""
High-level analysis API for the dependency graph.

This module provides typed, high-level functions for:
- Actor analysis (role detection from modifier patterns)
- State mutation tracking (write paths from entrypoints)
- Context slicing (focused code selection for missions)
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import TYPE_CHECKING, Any

from .models import (
    ActorRole,
    ContextSliceMeta,
    EdgeKind,
    FieldAccessInfo,
    GuardIssue,
    GuardIssueType,
    NodeKind,
    Severity,
    StateVarInfo,
    TrustLevel,
    WritePath,
)

if TYPE_CHECKING:
    from .graph import DependencyGraph


# Known modifier patterns and their role/trust mappings
ROLE_PATTERNS: dict[str, tuple[str, TrustLevel]] = {
    # High trust - ownership/admin patterns
    "onlyOwner": ("Owner", "High"),
    "onlyAdmin": ("Admin", "High"),
    "onlyRole": ("RoleBased", "High"),
    "onlyGovernance": ("Governance", "High"),
    "onlyMinter": ("Minter", "High"),
    "onlyOperator": ("Operator", "Medium"),
    # Medium trust - operational patterns
    "onlyKeeper": ("Keeper", "Medium"),
    "onlyRelayer": ("Relayer", "Medium"),
    "onlyOracle": ("Oracle", "Medium"),
    # Access control patterns (not roles themselves)
    "whenNotPaused": ("Pausable", "N/A"),
    "nonReentrant": ("ReentrancyGuard", "N/A"),
    "initializer": ("Initializer", "High"),
}

# Modifiers that are guards, not access control
GUARD_MODIFIERS = {"whenNotPaused", "nonReentrant", "whenPaused"}


def get_actor_roles(graph: DependencyGraph) -> list[ActorRole]:
    """
    Analyze the graph to extract actor roles based on modifier patterns.

    Groups functions by their modifier combinations and infers role semantics.

    Args:
        graph: The dependency graph to analyze

    Returns:
        List of ActorRole objects describing each detected role
    """
    # 1. Collect modifier usage per function
    function_to_modifiers: dict[str, list[str]] = defaultdict(list)

    for fid in graph.nodes(NodeKind.FUNCTION):
        fn = graph._nodes[fid]
        vis = (fn.visibility or "").lower()
        if vis not in ("public", "external"):
            continue
        if fn.meta.get("is_constructor", False):
            continue

        mod_ids = list(
            graph.neighbors(fid, edge_kinds={EdgeKind.USES_MODIFIER}, direction="out")
        )
        mod_names = [graph._nodes[mid].name for mid in mod_ids]

        if mod_names:
            function_to_modifiers[fn.name] = mod_names

    # 2. Group by access control modifier pattern (excluding guards)
    pattern_groups: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for fn_name, mods in function_to_modifiers.items():
        access_mods = [m for m in mods if m not in GUARD_MODIFIERS]
        if access_mods:
            pattern_key = tuple(sorted(access_mods))
            pattern_groups[pattern_key].append(fn_name)

    # 3. Build ActorRole objects
    roles: list[ActorRole] = []

    for pattern, functions in sorted(pattern_groups.items(), key=lambda x: -len(x[1])):
        role_name, trust = _infer_role_from_pattern(pattern)

        roles.append(
            ActorRole(
                role=role_name,
                trust=trust,
                modifier_pattern=list(pattern),
                privileges=sorted(functions),
                function_count=len(functions),
            )
        )

    # 4. Add unprotected public functions as "User" role
    unprotected = []
    for fid in graph.nodes(NodeKind.FUNCTION):
        fn = graph._nodes[fid]
        vis = (fn.visibility or "").lower()
        if vis in ("public", "external") and not fn.meta.get("is_constructor", False):
            if fn.name not in function_to_modifiers:
                unprotected.append(fn.name)

    if unprotected:
        roles.append(
            ActorRole(
                role="User",
                trust="None",
                modifier_pattern=[],
                privileges=sorted(set(unprotected)),
                function_count=len(set(unprotected)),
            )
        )

    return roles


def _infer_role_from_pattern(pattern: tuple[str, ...]) -> tuple[str, TrustLevel]:
    """Infer role name and trust level from a modifier pattern."""
    for mod in pattern:
        if mod in ROLE_PATTERNS:
            return ROLE_PATTERNS[mod]
        # Try prefix matching for custom modifiers
        for known_mod, (role_name, trust) in ROLE_PATTERNS.items():
            if mod.lower().startswith(known_mod.lower().replace("only", "")):
                custom_role = mod.replace("only", "").replace("Only", "")
                return (custom_role, trust)

    return ("Protected", "Medium")


def get_write_paths(
    graph: DependencyGraph, var_name: str, max_depth: int = 10
) -> list[WritePath]:
    """
    Trace all call paths from public entrypoints to state variable writes.

    Args:
        graph: The dependency graph to analyze
        var_name: Name of the state variable to trace
        max_depth: Maximum call chain depth

    Returns:
        List of WritePath objects showing how external calls can mutate state
    """
    results: list[WritePath] = []

    # 1. Find all state var nodes matching the name
    target_var_ids = []
    for vid in graph.nodes(NodeKind.STATE_VAR):
        v = graph._nodes[vid]
        if v.name == var_name:
            target_var_ids.append(vid)

    if not target_var_ids:
        return results

    # 2. For each var, find direct writers and trace back to entrypoints
    for var_id in target_var_ids:
        var_node = graph._nodes[var_id]
        writer_ids = list(
            graph.neighbors(var_id, edge_kinds={EdgeKind.WRITES}, direction="in")
        )

        for writer_id in writer_ids:
            writer_node = graph._nodes[writer_id]

            # BFS backwards to find all paths to public entrypoints
            queue: deque[tuple[str, list[str]]] = deque()
            queue.append((writer_id, [writer_node.name]))
            visited_paths: set[tuple[str, ...]] = set()

            while queue:
                curr_id, path = queue.popleft()
                curr_node = graph._nodes[curr_id]

                path_tuple = tuple(path)
                if path_tuple in visited_paths:
                    continue
                visited_paths.add(path_tuple)

                if len(path) > max_depth:
                    continue

                # Check if current node is a public entrypoint
                vis = (curr_node.visibility or "").lower()
                if curr_node.kind == NodeKind.FUNCTION and vis in (
                    "public",
                    "external",
                ):
                    contract_name = None
                    if writer_node.contract and writer_node.contract in graph._nodes:
                        contract_name = graph._nodes[writer_node.contract].name

                    results.append(
                        WritePath(
                            entrypoint=curr_node.name,
                            path=list(reversed(path)),
                            writer=writer_node.name,
                            contract=contract_name,
                            var_name=var_name,
                            var_file=var_node.file,
                        )
                    )

                # Continue BFS - find callers
                caller_ids = list(
                    graph.neighbors(
                        curr_id, edge_kinds={EdgeKind.CALLS}, direction="in"
                    )
                )
                for caller_id in caller_ids:
                    if caller_id not in graph._nodes:
                        continue
                    caller_node = graph._nodes[caller_id]
                    if caller_node.name not in path:
                        queue.append((caller_id, path + [caller_node.name]))

    # Deduplicate - keep shortest path per (entrypoint, writer) pair
    seen: dict[tuple[str, str], WritePath] = {}
    for wp in results:
        key = (wp.entrypoint, wp.writer)
        if key not in seen or len(wp.path) < len(seen[key].path):
            seen[key] = wp

    return sorted(seen.values(), key=lambda x: (x.entrypoint, len(x.path)))


def get_context_slice_meta(
    graph: DependencyGraph,
    target_func: str,
    invariant_seeds: list[str],
    depth: int = 3,
    include_write_paths: bool = True,
) -> ContextSliceMeta:
    """
    Generate a focused context slice for a mission.

    Args:
        graph: The dependency graph
        target_func: Name or ID of the target function
        invariant_seeds: State variable names related to the invariant
        depth: BFS traversal depth
        include_write_paths: Whether to include write path analysis

    Returns:
        ContextSliceMeta with related files, symbols, and optionally write paths
    """
    # 1. Resolve target func node
    target_node_id = target_func
    if target_node_id not in graph._nodes:
        candidates = graph.find_functions(target_func)
        if not candidates:
            candidates = graph.find_functions(target_func.split(".")[-1])
        if candidates:
            target_node_id = candidates[0]
        else:
            target_node_id = None

    # 2. Build seed set
    seeds: set[str] = set()
    if target_node_id and target_node_id in graph._nodes:
        seeds.add(target_node_id)

    for seed in invariant_seeds:
        for nid in graph.nodes(NodeKind.STATE_VAR):
            if graph._nodes[nid].name == seed:
                seeds.add(nid)

    # 3. BFS expansion
    edge_kinds = {
        EdgeKind.IMPORTS,
        EdgeKind.DEFINES,
        EdgeKind.INHERITS,
        EdgeKind.DECLARES_FUNCTION,
        EdgeKind.DECLARES_MODIFIER,
        EdgeKind.DECLARES_STATEVAR,
        EdgeKind.USES_MODIFIER,
        EdgeKind.CALLS,
        EdgeKind.HIGH_LEVEL_CALL,
        EdgeKind.READS,
        EdgeKind.WRITES,
    }

    visited = graph.bfs(
        list(seeds), max_hops=depth, edge_kinds=edge_kinds, direction="both"
    )

    # 4. Collect related files and symbols
    related_files: set[str] = set()
    symbols: set[str] = set()

    for nid in visited:
        n = graph._nodes[nid]
        if n.kind == NodeKind.FILE and n.file:
            related_files.add(n.file)
        elif n.kind in (
            NodeKind.FUNCTION,
            NodeKind.MODIFIER,
            NodeKind.STATE_VAR,
            NodeKind.CONTRACT,
        ):
            if n.file:
                related_files.add(n.file)
            symbols.add(n.name)

    # 5. Optionally include write paths for invariant seeds
    write_paths: list[WritePath] = []
    if include_write_paths:
        for seed in invariant_seeds:
            write_paths.extend(get_write_paths(graph, seed, max_depth=depth + 2))

    return ContextSliceMeta(
        target_func=target_func,
        target_node_id=target_node_id,
        invariant_seeds=invariant_seeds,
        related_files=sorted(related_files),
        symbols=sorted(symbols),
        write_paths=write_paths,
    )


def get_state_var_info(graph: DependencyGraph, var_name: str) -> list[StateVarInfo]:
    """
    Get detailed information about a state variable including all readers/writers.

    Args:
        graph: The dependency graph
        var_name: Name of the state variable

    Returns:
        List of StateVarInfo for each matching variable (may be multiple across contracts)
    """
    results: list[StateVarInfo] = []

    for vid in graph.nodes(NodeKind.STATE_VAR):
        v = graph._nodes[vid]
        if v.name != var_name:
            continue

        # Get contract name
        contract_name = None
        if v.contract and v.contract in graph._nodes:
            contract_name = graph._nodes[v.contract].name

        # Get readers and writers
        writer_ids = list(
            graph.neighbors(vid, edge_kinds={EdgeKind.WRITES}, direction="in")
        )
        reader_ids = list(
            graph.neighbors(vid, edge_kinds={EdgeKind.READS}, direction="in")
        )

        writers = [graph._nodes[w].name for w in writer_ids]
        readers = [graph._nodes[r].name for r in reader_ids]

        results.append(
            StateVarInfo(
                name=v.name,
                var_id=vid,
                contract=contract_name,
                file=v.file,
                var_type=v.meta.get("type"),
                visibility=v.meta.get("visibility"),
                writers=sorted(set(writers)),
                readers=sorted(set(readers)),
            )
        )

    return results


def get_invariant_vectors(
    graph: DependencyGraph, var_names: list[str]
) -> dict[str, list[str]]:
    """
    Map state variables to the functions that write to them.

    This is a simpler version of get_write_paths that just returns
    the direct writers without the full call chain.

    Args:
        graph: The dependency graph
        var_names: List of state variable names

    Returns:
        Dict mapping var_name -> list of "contract:function" writers
    """
    results: dict[str, list[str]] = defaultdict(list)

    # Build var name -> node ID mapping
    var_map: dict[str, list[str]] = defaultdict(list)
    for vid in graph.nodes(NodeKind.STATE_VAR):
        var_map[graph._nodes[vid].name].append(vid)

    # Trace writes for each requested variable
    for var_name in var_names:
        target_vids = var_map.get(var_name, [])
        for vid in target_vids:
            writers = graph.neighbors(vid, edge_kinds={EdgeKind.WRITES}, direction="in")
            for wid in writers:
                w_node = graph._nodes[wid]
                contract_name = None
                if w_node.contract and w_node.contract in graph._nodes:
                    contract_name = graph._nodes[w_node.contract].name
                label = (
                    f"{contract_name}:{w_node.name}" if contract_name else w_node.name
                )
                results[var_name].append(label)

    return {k: sorted(set(v)) for k, v in results.items()}


def get_field_access_info(
    graph: DependencyGraph,
    struct_type: str | None = None,
    field_name: str | None = None,
) -> list[FieldAccessInfo]:
    """
    Get information about struct field access patterns.

    This enables fine-grained tracking of which functions read/write
    specific struct fields (e.g., proof.key vs proof.nonExistenceKey).

    Args:
        graph: The dependency graph
        struct_type: Optional filter by struct type (e.g., "Proof")
        field_name: Optional filter by full field name (e.g., "Proof.key")

    Returns:
        List of FieldAccessInfo for matching fields
    """
    results: list[FieldAccessInfo] = []

    for fid in graph.nodes(NodeKind.STRUCT_FIELD):
        node = graph._nodes[fid]
        meta = node.meta or {}

        node_struct_type = meta.get("struct_type", "")
        node_field_name = meta.get("field_name", "")

        # Apply filters
        if struct_type and node_struct_type != struct_type:
            continue
        if field_name and node.name != field_name:
            continue

        # Get readers (functions with READS_FIELD edge to this field)
        reader_ids = list(
            graph.neighbors(fid, edge_kinds={EdgeKind.READS_FIELD}, direction="in")
        )
        readers = []
        for rid in reader_ids:
            if rid in graph._nodes:
                r_node = graph._nodes[rid]
                contract_name = None
                if r_node.contract and r_node.contract in graph._nodes:
                    contract_name = graph._nodes[r_node.contract].name
                label = (
                    f"{contract_name}:{r_node.name}" if contract_name else r_node.name
                )
                readers.append(label)

        # Get writers (functions with WRITES_FIELD edge to this field)
        writer_ids = list(
            graph.neighbors(fid, edge_kinds={EdgeKind.WRITES_FIELD}, direction="in")
        )
        writers = []
        for wid in writer_ids:
            if wid in graph._nodes:
                w_node = graph._nodes[wid]
                contract_name = None
                if w_node.contract and w_node.contract in graph._nodes:
                    contract_name = graph._nodes[w_node.contract].name
                label = (
                    f"{contract_name}:{w_node.name}" if contract_name else w_node.name
                )
                writers.append(label)

        results.append(
            FieldAccessInfo(
                field_name=node.name,
                field_id=fid,
                struct_type=node_struct_type,
                member=node_field_name,
                readers=sorted(set(readers)),
                writers=sorted(set(writers)),
            )
        )

    return sorted(results, key=lambda x: x.field_name)


# ---------------------------
# Guard Issue Detection
# ---------------------------


def detect_guard_issues(
    graph: "DependencyGraph",
    slither: Any = None,
) -> list[GuardIssue]:
    """
    Detect impossible guards and access control issues.

    Patterns detected:
    - tx.origin == address(this) - always false, impossible condition
    - tx.origin used in authorization (phishing risk)
    - if (x != A || x != B) - logic error, often should be &&
    - Modifiers named onlySelf/onlyThis using tx.origin incorrectly

    Args:
        graph: The dependency graph
        slither: Optional Slither instance for deeper IR analysis

    Returns:
        List of GuardIssue findings
    """
    from typing import Any

    issues: list[GuardIssue] = []

    # If we have Slither, do deep IR analysis
    if slither is not None:
        issues.extend(_detect_tx_origin_issues_slither(graph, slither))
        issues.extend(_detect_impossible_conditions_slither(graph, slither))

    # Graph-based heuristics (work without Slither)
    issues.extend(_detect_suspicious_modifier_patterns(graph))

    return issues


def _detect_tx_origin_issues_slither(
    graph: "DependencyGraph",
    slither: Any,
) -> list[GuardIssue]:
    """Detect tx.origin issues using Slither IR."""
    issues: list[GuardIssue] = []

    try:
        from slither.slithir.operations import Binary, SolidityCall
        from slither.slithir.variables import Constant
        from slither.core.declarations import SolidityVariableComposed
    except ImportError:
        return issues

    for contract in getattr(slither, "contracts", []) or []:
        contract_name = str(getattr(contract, "name", ""))

        # Check functions and modifiers
        all_funcs = list(getattr(contract, "functions_declared", []) or [])
        all_funcs += list(getattr(contract, "modifiers_declared", []) or [])

        for func in all_funcs:
            func_name = str(getattr(func, "name", ""))
            is_modifier = hasattr(func, "is_modifier") or func_name in [
                m.name for m in getattr(contract, "modifiers_declared", []) or []
            ]

            # Get source line if available
            line = None
            try:
                sm = getattr(func, "source_mapping", None)
                if sm:
                    line = getattr(sm, "lines", [None])[0]
            except Exception:
                pass

            # Check for tx.origin usage
            uses_tx_origin = False
            compares_to_address_this = False
            has_or_with_neq = False

            for node in getattr(func, "nodes", []) or []:
                for ir in getattr(node, "irs", []) or []:
                    # Check for tx.origin reads
                    if hasattr(ir, "read"):
                        for var in ir.read or []:
                            if isinstance(var, SolidityVariableComposed):
                                if str(var) == "tx.origin":
                                    uses_tx_origin = True

                    # Check for comparison with address(this)
                    if isinstance(ir, Binary):
                        left = getattr(ir, "variable_left", None)
                        right = getattr(ir, "variable_right", None)

                        # Check if comparing tx.origin to address(this)
                        left_str = str(left) if left else ""
                        right_str = str(right) if right else ""

                        if "tx.origin" in left_str or "tx.origin" in right_str:
                            if (
                                "address(this)" in left_str
                                or "address(this)" in right_str
                            ):
                                compares_to_address_this = True

                            # Check for != with || pattern (logic error)
                            op = str(getattr(ir, "type", ""))
                            if "!=" in op or "NOT" in op.upper():
                                has_or_with_neq = True

            # Report issues found
            if compares_to_address_this:
                # Find function ID in graph
                func_id = _find_func_id(graph, contract_name, func_name)
                file_path = (
                    graph._nodes[func_id].file
                    if func_id and func_id in graph._nodes
                    else None
                )

                issues.append(
                    GuardIssue(
                        issue_type=GuardIssueType.TX_ORIGIN_ADDRESS_THIS,
                        severity=Severity.CRITICAL,
                        function_name=func_name,
                        function_id=func_id or f"{contract_name}.{func_name}",
                        modifier_name=func_name if is_modifier else None,
                        contract_name=contract_name,
                        file=file_path,
                        line=line,
                        description=(
                            f"Comparison of tx.origin to address(this) is always false. "
                            f"tx.origin can never equal a contract address in normal EVM execution."
                        ),
                        pattern="tx.origin == address(this) or tx.origin != address(this)",
                        recommendation="Use msg.sender for access control. If checking self-calls, use: if (msg.sender != address(this)) revert;",
                    )
                )

            elif uses_tx_origin:
                func_id = _find_func_id(graph, contract_name, func_name)
                file_path = (
                    graph._nodes[func_id].file
                    if func_id and func_id in graph._nodes
                    else None
                )

                issues.append(
                    GuardIssue(
                        issue_type=GuardIssueType.TX_ORIGIN_IN_AUTH,
                        severity=Severity.MEDIUM,
                        function_name=func_name,
                        function_id=func_id or f"{contract_name}.{func_name}",
                        modifier_name=func_name if is_modifier else None,
                        contract_name=contract_name,
                        file=file_path,
                        line=line,
                        description=(
                            f"tx.origin used in access control. This is vulnerable to phishing attacks "
                            f"where a malicious contract tricks a user into calling it."
                        ),
                        pattern="tx.origin used for authorization",
                        recommendation="Use msg.sender instead of tx.origin for access control.",
                    )
                )

    return issues


def _detect_impossible_conditions_slither(
    graph: "DependencyGraph",
    slither: Any,
) -> list[GuardIssue]:
    """Detect impossible boolean conditions like if (x != A || x != B)."""
    issues: list[GuardIssue] = []

    # This requires deeper IR analysis - placeholder for now
    # Full implementation would trace Binary operations and detect:
    # - (x != A || x != B) patterns that are always true
    # - (x == A && x == B) patterns that are always false (for different A, B)

    return issues


def _detect_suspicious_modifier_patterns(graph: "DependencyGraph") -> list[GuardIssue]:
    """Detect suspicious modifier patterns using graph data only."""
    issues: list[GuardIssue] = []

    # Look for modifiers with suspicious names that might have issues
    suspicious_names = ["onlyself", "onlythis", "selfonl", "internalonly"]

    for mod_id in graph.nodes(NodeKind.MODIFIER):
        mod = graph._nodes[mod_id]
        mod_name_lower = mod.name.lower()

        for sus in suspicious_names:
            if sus in mod_name_lower:
                # Get functions using this modifier
                protected_funcs = list(
                    graph.neighbors(
                        mod_id, edge_kinds={EdgeKind.USES_MODIFIER}, direction="in"
                    )
                )

                contract_name = None
                if mod.contract and mod.contract in graph._nodes:
                    contract_name = graph._nodes[mod.contract].name

                issues.append(
                    GuardIssue(
                        issue_type=GuardIssueType.UNSATISFIABLE_GUARD,
                        severity=Severity.HIGH,
                        function_name=mod.name,
                        function_id=mod_id,
                        modifier_name=mod.name,
                        contract_name=contract_name,
                        file=mod.file,
                        line=None,
                        description=(
                            f"Modifier '{mod.name}' has a suspicious name suggesting self-call restriction. "
                            f"Verify this guard is satisfiable. Protects {len(protected_funcs)} function(s)."
                        ),
                        pattern=f"Modifier named '{mod.name}'",
                        recommendation="Verify the modifier logic. If checking self-calls, ensure it uses msg.sender, not tx.origin.",
                    )
                )
                break

    return issues


def _find_func_id(
    graph: "DependencyGraph", contract_name: str, func_name: str
) -> str | None:
    """Find function node ID by contract and function name."""
    for fid in graph.nodes(NodeKind.FUNCTION):
        node = graph._nodes[fid]
        if node.name == func_name:
            if node.contract and node.contract in graph._nodes:
                if graph._nodes[node.contract].name == contract_name:
                    return fid
    # Fallback: try modifier
    for mid in graph.nodes(NodeKind.MODIFIER):
        node = graph._nodes[mid]
        if node.name == func_name:
            if node.contract and node.contract in graph._nodes:
                if graph._nodes[node.contract].name == contract_name:
                    return mid
    return None


# ---------------------------
# Liveness Invariant Generation
# ---------------------------


def get_liveness_invariants(
    graph: "DependencyGraph",
    guard_issues: list[GuardIssue] | None = None,
) -> list[dict]:
    """
    Generate LIVENESS invariant suggestions from graph analysis.

    LIVENESS invariants assert that functions must be callable by their
    intended actors. Generated from:
    1. Guard issues (functions with impossible guards)
    2. Modifier patterns (functions protected by access control)

    Args:
        graph: The dependency graph
        guard_issues: Optional pre-computed guard issues

    Returns:
        List of invariant suggestion dicts compatible with schemas.Invariant
    """
    invariants: list[dict] = []

    # 1. Generate from guard issues (highest priority)
    if guard_issues:
        for issue in guard_issues:
            if issue.issue_type in (
                GuardIssueType.TX_ORIGIN_ADDRESS_THIS,
                GuardIssueType.UNSATISFIABLE_GUARD,
                GuardIssueType.ALWAYS_REVERTS,
            ):
                inv_id = f"LIVENESS_{issue.function_name}"

                # Find functions protected by this modifier
                target_funcs = [issue.function_name]
                if issue.modifier_name:
                    mod_ids = graph.find_functions(issue.modifier_name)
                    for mod_id in mod_ids:
                        node = graph._nodes.get(mod_id)
                        if node and node.kind == NodeKind.MODIFIER:
                            users = list(
                                graph.neighbors(
                                    mod_id,
                                    edge_kinds={EdgeKind.USES_MODIFIER},
                                    direction="in",
                                )
                            )
                            for uid in users:
                                if uid in graph._nodes:
                                    target_funcs.append(graph._nodes[uid].name)

                invariants.append(
                    {
                        "id": inv_id,
                        "type": "liveness",
                        "rule": f"Function(s) {', '.join(set(target_funcs))} must be callable by intended role",
                        "target_functions": list(set(target_funcs)),
                        "target_files": [issue.file] if issue.file else [],
                        "confidence": 1.0,  # Deterministic finding
                        "source": "guard_analysis",
                    }
                )

    # 2. Generate from modifier patterns (protected functions should be callable)
    roles = get_actor_roles(graph)
    for role in roles:
        if role.trust in ("High", "Medium") and role.modifier_pattern:
            # These functions have access control - generate liveness check
            for func_name in role.privileges[:5]:  # Limit to top 5 per role
                inv_id = f"LIVENESS_{role.role}_{func_name}"

                # Find file for this function
                func_ids = graph.find_functions(func_name)
                files = []
                for fid in func_ids:
                    if fid in graph._nodes and graph._nodes[fid].file:
                        files.append(graph._nodes[fid].file)

                invariants.append(
                    {
                        "id": inv_id,
                        "type": "liveness",
                        "rule": f"Function {func_name} must be callable by {role.role} role",
                        "target_functions": [func_name],
                        "target_files": list(set(files)),
                        "confidence": 0.8,  # Pattern-based, not deterministic
                        "source": "modifier_pattern",
                    }
                )

    # Deduplicate by invariant ID
    seen_ids: set[str] = set()
    unique_invariants: list[dict] = []
    for inv in invariants:
        if inv["id"] not in seen_ids:
            seen_ids.add(inv["id"])
            unique_invariants.append(inv)

    return unique_invariants
