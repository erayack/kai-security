"""
DependencyAnalysis - High-level analysis wrapper for DependencyGraph.

Combines a graph with a domain adapter to provide typed, cached analysis methods.

Architecture:
- Domain-specific logic (actor extraction, suspicious function scanning, privilege chains)
  is delegated to the DomainAdapter (see adapters/base.py)
- Language-agnostic graph operations (BFS, write paths, context slicing) live here
- Caching is handled at this layer

To add support for a new language, implement a new DomainAdapter - no changes needed here.
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
    StateVarInfo,
    WritePath,
)

# Import Invariant and PrivilegeChain from kai.schemas for type consistency
from kai.schemas import Invariant, InvariantType, PrivilegeChain

if TYPE_CHECKING:
    from .adapters.base import DomainAdapter
    from .graph import DependencyGraph


class DependencyAnalysis:
    """
    High-level analysis wrapper combining DependencyGraph + DomainAdapter.

    Provides cached, domain-aware analysis methods for security analysis.

    Usage:
        from kai.utils.dependency import DependencyGraph, DependencyAnalysis
        from kai.utils.dependency.adapters import SolidityAdapter

        graph = DependencyGraph.from_json("graph.json")
        analysis = DependencyAnalysis(graph)  # Uses SolidityAdapter by default

        # All methods use bound adapter + caching
        roles = analysis.get_actor_roles()
        issues = analysis.detect_guard_issues()
        chains = analysis.trace_privilege_chains()
    """

    def __init__(
        self,
        graph: "DependencyGraph",
        adapter: DomainAdapter | None = None,
        slither: Any = None,
    ):
        """
        Initialize analysis wrapper.

        Args:
            graph: The dependency graph to analyze
            adapter: Domain adapter (defaults to SolidityAdapter)
            slither: Optional Slither instance for deep IR analysis
        """
        from .adapters import SolidityAdapter

        self.graph = graph
        self.adapter = adapter or SolidityAdapter()
        self.slither = slither

        # Lazy-computed caches
        self._actor_roles: list[ActorRole] | None = None
        self._guard_issues: list[GuardIssue] | None = None
        self._privilege_chains: list[PrivilegeChain] | None = None

    @classmethod
    def from_slither(
        cls,
        slither: Any,
        adapter: "DomainAdapter | None" = None,
    ) -> "DependencyAnalysis":
        """
        Build analysis from Slither instance.

        Args:
            slither: Slither analysis instance
            adapter: Optional domain adapter

        Returns:
            DependencyAnalysis with graph built from Slither
        """
        from .builders import build_from_slither

        graph = build_from_slither(slither)
        return cls(graph, adapter, slither)

    @classmethod
    def from_json(
        cls,
        path: str,
        adapter: "DomainAdapter | None" = None,
    ) -> "DependencyAnalysis":
        """
        Load analysis from cached graph JSON.

        Args:
            path: Path to graph JSON file
            adapter: Optional domain adapter

        Returns:
            DependencyAnalysis with graph loaded from JSON
        """
        from .graph import DependencyGraph

        graph = DependencyGraph.from_json(path)
        return cls(graph, adapter)

    def invalidate_cache(self) -> None:
        """Clear all cached results. Call after graph mutation."""
        self._actor_roles = None
        self._guard_issues = None
        self._privilege_chains = None

    def get_actor_roles(self) -> list[ActorRole]:
        """
        Extract actor roles based on modifier patterns.

        Delegates to the domain adapter for language-specific logic.
        Results are cached.

        Returns:
            List of ActorRole objects describing each detected role
        """
        if self._actor_roles is not None:
            return self._actor_roles

        self._actor_roles = self.adapter.extract_actor_roles(self.graph)
        return self._actor_roles

    def detect_guard_issues(self) -> list[GuardIssue]:
        """
        Detect impossible guards and access control issues.

        Uses the adapter's domain-specific detection logic.
        Results are cached.

        Returns:
            List of GuardIssue findings
        """
        if self._guard_issues is not None:
            return self._guard_issues

        issues = self.adapter.detect_domain_issues(self.graph, self.slither)
        self._guard_issues = issues
        return issues

    def get_affected_files(self, invariant: Invariant, depth: int = 2) -> list[str]:
        """
        Get files that could violate an invariant.

        This is the critical method for the Dispatcher to map invariants to targets.

        Args:
            invariant: The invariant to analyze
            depth: BFS traversal depth from seed nodes

        Returns:
            List of file paths that could affect this invariant
        """
        graph = self.graph
        files: set[str] = set()

        # 1. Add explicitly listed target files
        for f in invariant.target_files:
            files.add(f)

        # 2. Find files containing target functions
        for func_name in invariant.target_functions:
            func_ids = graph.find_functions(func_name)
            for fid in func_ids:
                if fid in graph._nodes:
                    node = graph._nodes[fid]
                    if node.file:
                        files.add(node.file)

        # 3. Find files containing relevant state variables
        #    (Invariant from schemas.py doesn't have target_vars, so we extract
        #    variable names from the rule using common patterns)
        var_candidates = self._extract_var_names_from_rule(invariant.rule)
        for var_name in var_candidates:
            for vid in graph.nodes(NodeKind.STATE_VAR):
                v = graph._nodes[vid]
                if v.name == var_name and v.file:
                    files.add(v.file)

        # 4. BFS expansion from seed files to find related files
        seed_file_ids = [graph.file_node(f) for f in files if graph.file_node(f)]
        seed_file_ids = [f for f in seed_file_ids if f]  # Filter None

        if seed_file_ids:
            edge_kinds = {
                EdgeKind.IMPORTS,
                EdgeKind.DEFINES,
                EdgeKind.INHERITS,
                EdgeKind.CALLS,
                EdgeKind.HIGH_LEVEL_CALL,
                EdgeKind.LIBRARY_CALL,
            }
            visited = graph.bfs(
                seed_file_ids, max_hops=depth, edge_kinds=edge_kinds, direction="both"
            )

            for nid in visited:
                n = graph._nodes.get(nid)
                if n and n.kind == NodeKind.FILE and n.file:
                    files.add(n.file)

        return sorted(files)

    def _extract_var_names_from_rule(self, rule: str) -> list[str]:
        """
        Extract potential state variable names from an invariant rule string.

        Delegates to the domain adapter for language-specific patterns.
        """
        return self.adapter.extract_var_names_from_rule(rule)

    def trace_privilege_chains(self, max_depth: int = 4) -> list[PrivilegeChain]:
        """
        Trace cross-contract privilege chains via HIGH_LEVEL_CALL edges.

        Delegates to the domain adapter for language-specific logic.
        Results are cached (for default max_depth).

        Args:
            max_depth: Maximum chain length to trace

        Returns:
            List of PrivilegeChain objects (from kai.schemas)
        """
        # Only cache default depth
        if max_depth == 4 and self._privilege_chains is not None:
            return self._privilege_chains

        # Adapter returns list[dict], convert to PrivilegeChain
        raw_chains = self.adapter.trace_privilege_chains(self.graph, max_depth)
        result = [PrivilegeChain(**chain) for chain in raw_chains]

        if max_depth == 4:
            self._privilege_chains = result

        return result

    def scan_suspicious_functions(
        self,
        source_code: dict[str, str] | None = None,
    ) -> list[dict]:
        """
        Heuristic scan for functions with potential access control issues.

        Delegates to the domain adapter for language-specific logic.

        Args:
            source_code: Optional dict of file_path -> source code

        Returns:
            List of suspicious function dicts
        """
        return self.adapter.scan_suspicious_functions(self.graph, source_code)

    def get_write_paths(self, var_name: str, max_depth: int = 10) -> list[WritePath]:
        """
        Trace all call paths from public entrypoints to state variable writes.

        Args:
            var_name: Name of the state variable to trace
            max_depth: Maximum call chain depth

        Returns:
            List of WritePath objects
        """
        graph = self.graph
        results: list[WritePath] = []

        target_var_ids = []
        for vid in graph.nodes(NodeKind.STATE_VAR):
            v = graph._nodes[vid]
            if v.name == var_name:
                target_var_ids.append(vid)

        if not target_var_ids:
            return results

        for var_id in target_var_ids:
            var_node = graph._nodes[var_id]
            writer_ids = list(
                graph.neighbors(var_id, edge_kinds={EdgeKind.WRITES}, direction="in")
            )

            for writer_id in writer_ids:
                writer_node = graph._nodes[writer_id]

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

                    vis = (curr_node.visibility or "").lower()
                    if curr_node.kind == NodeKind.FUNCTION and vis in (
                        "public",
                        "external",
                    ):
                        contract_name = None
                        if (
                            writer_node.contract
                            and writer_node.contract in graph._nodes
                        ):
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

        # Deduplicate
        seen: dict[tuple[str, str], WritePath] = {}
        for wp in results:
            key = (wp.entrypoint, wp.writer)
            if key not in seen or len(wp.path) < len(seen[key].path):
                seen[key] = wp

        return sorted(seen.values(), key=lambda x: (x.entrypoint, len(x.path)))

    def get_context_slice(
        self,
        target_func: str,
        invariant_seeds: list[str],
        depth: int = 3,
        include_write_paths: bool = True,
    ) -> ContextSliceMeta:
        """
        Generate a focused context slice for a mission.

        Args:
            target_func: Name or ID of the target function
            invariant_seeds: State variable names related to the invariant
            depth: BFS traversal depth
            include_write_paths: Whether to include write path analysis

        Returns:
            ContextSliceMeta with related files, symbols, and write paths
        """
        graph = self.graph

        # Resolve target func node
        target_node_id = target_func
        if target_node_id not in graph._nodes:
            candidates = graph.find_functions(target_func)
            if not candidates:
                candidates = graph.find_functions(target_func.split(".")[-1])
            if candidates:
                target_node_id = candidates[0]
            else:
                target_node_id = None

        # Build seed set
        seeds: set[str] = set()
        if target_node_id and target_node_id in graph._nodes:
            seeds.add(target_node_id)

        for seed in invariant_seeds:
            for nid in graph.nodes(NodeKind.STATE_VAR):
                if graph._nodes[nid].name == seed:
                    seeds.add(nid)

        # BFS expansion
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

        # Collect related files and symbols
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

        # Write paths
        write_paths: list[WritePath] = []
        if include_write_paths:
            for seed in invariant_seeds:
                write_paths.extend(self.get_write_paths(seed, max_depth=depth + 2))

        return ContextSliceMeta(
            target_func=target_func,
            target_node_id=target_node_id,
            invariant_seeds=invariant_seeds,
            related_files=sorted(related_files),
            symbols=sorted(symbols),
            write_paths=write_paths,
        )

    def get_state_var_info(self, var_name: str) -> list[StateVarInfo]:
        """
        Get detailed information about a state variable.

        Args:
            var_name: Name of the state variable

        Returns:
            List of StateVarInfo (may be multiple across contracts)
        """
        graph = self.graph
        results: list[StateVarInfo] = []

        for vid in graph.nodes(NodeKind.STATE_VAR):
            v = graph._nodes[vid]
            if v.name != var_name:
                continue

            contract_name = None
            if v.contract and v.contract in graph._nodes:
                contract_name = graph._nodes[v.contract].name

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

    # ---------------------------
    # Field Access Info
    # ---------------------------

    def get_field_access_info(
        self,
        struct_type: str | None = None,
        field_name: str | None = None,
    ) -> list[FieldAccessInfo]:
        """
        Get information about struct field access patterns.

        Args:
            struct_type: Optional filter by struct type
            field_name: Optional filter by full field name

        Returns:
            List of FieldAccessInfo for matching fields
        """
        graph = self.graph
        results: list[FieldAccessInfo] = []

        for fid in graph.nodes(NodeKind.STRUCT_FIELD):
            node = graph._nodes[fid]
            meta = node.meta or {}

            node_struct_type = meta.get("struct_type", "")
            node_field_name = meta.get("field_name", "")

            if struct_type and node_struct_type != struct_type:
                continue
            if field_name and node.name != field_name:
                continue

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
                        f"{contract_name}:{r_node.name}"
                        if contract_name
                        else r_node.name
                    )
                    readers.append(label)

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
                        f"{contract_name}:{w_node.name}"
                        if contract_name
                        else w_node.name
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

    def get_invariant_vectors(self, var_names: list[str]) -> dict[str, list[str]]:
        """
        Map state variables to functions that write to them.

        Args:
            var_names: List of state variable names

        Returns:
            Dict mapping var_name -> list of "contract:function" writers
        """
        graph = self.graph
        results: dict[str, list[str]] = defaultdict(list)

        var_map: dict[str, list[str]] = defaultdict(list)
        for vid in graph.nodes(NodeKind.STATE_VAR):
            var_map[graph._nodes[vid].name].append(vid)

        for var_name in var_names:
            target_vids = var_map.get(var_name, [])
            for vid in target_vids:
                writers = graph.neighbors(
                    vid, edge_kinds={EdgeKind.WRITES}, direction="in"
                )
                for wid in writers:
                    w_node = graph._nodes[wid]
                    contract_name = None
                    if w_node.contract and w_node.contract in graph._nodes:
                        contract_name = graph._nodes[w_node.contract].name
                    label = (
                        f"{contract_name}:{w_node.name}"
                        if contract_name
                        else w_node.name
                    )
                    results[var_name].append(label)

        return {k: sorted(set(v)) for k, v in results.items()}

    def get_liveness_invariants(self) -> list[Invariant]:
        """
        Generate LIVENESS invariant suggestions from analysis.

        LIVENESS invariants assert that functions must be callable by their
        intended actors.

        Returns:
            List of Invariant objects (from kai.schemas)
        """
        graph = self.graph
        invariants: list[Invariant] = []

        # From guard issues
        guard_issues = self.detect_guard_issues()
        for issue in guard_issues:
            if issue.issue_type in (
                GuardIssueType.TX_ORIGIN_ADDRESS_THIS,
                GuardIssueType.UNSATISFIABLE_GUARD,
                GuardIssueType.ALWAYS_REVERTS,
            ):
                inv_id = f"LIVENESS_{issue.function_name}"

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
                    Invariant(
                        id=inv_id,
                        type=InvariantType.LIVENESS,
                        rule=f"Function(s) {', '.join(set(target_funcs))} must be callable by intended role",
                        target_functions=list(set(target_funcs)),
                        target_files=[issue.file] if issue.file else [],
                        confidence=1.0,
                        source="guard_analysis",
                    )
                )

        # From modifier patterns
        roles = self.get_actor_roles()
        for role in roles:
            if role.trust in ("High", "Medium") and role.modifier_pattern:
                for func_name in role.privileges[:5]:
                    inv_id = f"LIVENESS_{role.role}_{func_name}"

                    func_ids = graph.find_functions(func_name)
                    files = []
                    for fid in func_ids:
                        if fid in graph._nodes and graph._nodes[fid].file:
                            files.append(graph._nodes[fid].file)

                    invariants.append(
                        Invariant(
                            id=inv_id,
                            type=InvariantType.LIVENESS,
                            rule=f"Function {func_name} must be callable by {role.role} role",
                            target_functions=[func_name],
                            target_files=list(set(files)),
                            confidence=0.8,
                            source="modifier_pattern",
                        )
                    )

        # Deduplicate
        seen_ids: set[str] = set()
        unique_invariants: list[Invariant] = []
        for inv in invariants:
            if inv.id not in seen_ids:
                seen_ids.add(inv.id)
                unique_invariants.append(inv)

        return unique_invariants
