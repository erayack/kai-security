"""
kai/analysis/engine.py
"""

from collections import deque
from typing import List, Dict, Any, Optional, Literal
from .models import NodeRef, ContextSlice, EvidencePack
from ..models import EdgeKind
from ..adapters.base import DomainAdapter
from ..graph import DependencyGraph


class GraphQueryEngine:
    def __init__(
        self, graph: DependencyGraph, adapter: DomainAdapter, source_loader: Any
    ):
        """
        args:
            source_loader: Abstract object with .read_span(file, start, end) -> str
        """
        self.graph = graph
        self.adapter = adapter
        self.source_loader = source_loader

    def resolve(self, ref: str, scope: Optional[str] = None) -> List[NodeRef]:
        """
        Deterministic symbol resolution.
        Returns RANKED candidates. Agent must pick one ID.
        """
        # 1. Fast path: Input is already a valid Node ID
        if ref in self.graph._nodes:
            return [self._to_ref(self.graph.node(ref))]

        # 2. Adapter resolution (Handles fuzzy matching, language rules)
        candidate_ids = self.adapter.resolve_symbol(ref, self.graph, scope)

        # 3. Convert to Refs
        results = [self._to_ref(self.graph.node(nid)) for nid in candidate_ids]

        # 4. Rank: Public Entrypoints first, then alphabetical
        results.sort(
            key=lambda x: (
                0 if self.adapter.is_public_entrypoint(self.graph.node(x.id)) else 1,
                x.name,
            )
        )
        return results

    def loc(self, node_id: str) -> Dict[str, Any]:
        """
        The anchor. Every answer maps back to this.
        """
        node = self._get(node_id)
        return {
            "id": node.id,
            "kind": node.kind,
            "file": node.span.file if node.span else None,
            "span": {"start": node.span.start_line, "end": node.span.end_line}
            if node.span
            else None,
            "signature": node.meta.get("signature"),
        }

    def snippet(self, file: str, span: Dict[str, int]) -> str:
        """
        Pull minimal code ranges.
        Delegates to a secure loader to prevent path traversal.
        """
        return self.source_loader.read_span(file, span["start"], span["end"])

    def neighbors(
        self,
        node_id: str,
        edge_kinds: List[str],
        direction: Literal["in", "out", "both"] = "out",
    ) -> List[NodeRef]:
        """Atomic local expansion with explicit edge types."""
        kinds = {EdgeKind(k) for k in edge_kinds}
        # Generic neighbor lookup
        nids = self.graph.neighbors(node_id, edge_kinds=kinds, direction=direction)
        return [self._to_ref(self.graph.node(nid)) for nid in nids]

    def callers(self, func_id: str) -> List[NodeRef]:
        """Who calls this?"""
        return self.neighbors(func_id, [EdgeKind.CALLS], "in")

    def callees(self, func_id: str) -> List[NodeRef]:
        """Who does this call?"""
        return self.neighbors(func_id, [EdgeKind.CALLS], "out")

    def paths(
        self,
        src_ids: List[str],
        dst_ids: List[str],
        edge_kinds: List[str],
        max_depth: int = 5,
    ) -> List[List[NodeRef]]:
        """
        Enumerate bounded paths (BFS).
        Returns: List of [NodeRef, NodeRef, ...]
        """
        results = []
        dst_set = set(dst_ids)
        kinds = {EdgeKind(k) for k in edge_kinds}

        # Queue: (current_id, path_list_of_ids)
        queue = deque([(sid, [sid]) for sid in src_ids])

        while queue:
            curr_id, path = queue.popleft()

            if curr_id in dst_set:
                results.append([self._to_ref(self.graph.node(nid)) for nid in path])
                continue

            if len(path) >= max_depth:
                continue

            for nb in self.graph.neighbors(curr_id, edge_kinds=kinds, direction="out"):
                if nb not in path:  # Cycle prevention
                    queue.append((nb, path + [nb]))
        return results

    def data_paths(
        self,
        entrypoints: List[str],
        symbol_id: str,
        mode: Literal["read", "write"] = "write",
    ) -> List[Dict[str, Any]]:
        """
        Trace dependency: Entrypoints -> ... -> Symbol Access.
        """
        target_edge = EdgeKind.WRITES if mode == "write" else EdgeKind.READS

        # 1. Find the immediate accessors (the "sinks")
        accessors = self.graph.neighbors(
            symbol_id, edge_kinds={target_edge}, direction="in"
        )
        accessor_ids = list(accessors)

        if not accessor_ids:
            return []

        # 2. Find paths from entrypoints to these accessors
        # Reuse 'paths' primitive for consistent logic
        call_chains = self.paths(
            src_ids=entrypoints,
            dst_ids=accessor_ids,
            edge_kinds=[EdgeKind.CALLS],
            max_depth=10,
        )

        # 3. Format the result for the agent
        results = []
        symbol_ref = self._to_ref(self.graph.node(symbol_id))

        for chain in call_chains:
            # chain is [Entry, ..., Accessor]
            results.append(
                {
                    "entrypoint": chain[0],
                    "accessor": chain[-1],
                    "symbol": symbol_ref,
                    "steps": chain,
                    "length": len(chain),
                }
            )
        return results

    def slice(self, seeds: List[str], policy: str = "standard") -> ContextSlice:
        """
        Justified context slicing.
        'standard' policy includes: Definitions, Type Deps, and 1-hop Calls.
        """
        nodes = set(seeds)
        justification = {s: "Seed" for s in seeds}

        def add(nid, reason):
            if nid not in nodes:
                nodes.add(nid)
                justification[nid] = reason

        # 1. Anti-Hallucination: Always include Type Definitions
        #    Agents cannot hallucinate struct fields if we provide the struct def.
        for seed in list(nodes):
            for tid in self.graph.neighbors(
                seed, edge_kinds={EdgeKind.USES_TYPE}, direction="out"
            ):
                add(tid, f"Type used by {self.graph.node(seed).name}")

        # 2. Policy Expansion
        if policy == "standard":
            for seed in list(nodes):
                # Include Callees (Downstream)
                for nid in self.graph.neighbors(
                    seed, edge_kinds={EdgeKind.CALLS}, direction="out"
                ):
                    add(nid, f"Called by {self.graph.node(seed).name}")
                # Include Parent Container
                parent = self.graph.node(seed).parent_id
                if parent:
                    add(parent, "Parent container")

        # 3. Collect Files (Filtering Tests)
        node_refs = []
        files = set()
        for nid in nodes:
            n = self.graph.node(nid)
            node_refs.append(self._to_ref(n))
            if n.span and n.span.file:
                if not self.adapter.is_test_file(n.span.file):
                    files.add(n.span.file)

        return ContextSlice(
            nodes=node_refs, files=sorted(list(files)), justification=justification
        )

    def explain(self, item: Any) -> EvidencePack:
        """
        The Hallucination Killer.
        Takes a path/trace and returns verifiable evidence.
        """
        # 1. Normalize input to list of IDs
        path_ids = []
        if isinstance(item, list):
            path_ids = [x.id if isinstance(x, NodeRef) else x for x in item]

        trace = []
        edges = []
        snippets = {}

        for i, nid in enumerate(path_ids):
            node = self.graph.node(nid)

            # Evidence: Code Snippet
            if node.span:
                code = self.snippet(
                    node.span.file,
                    {"start": node.span.start_line, "end": node.span.end_line},
                )
                snippets[node.id] = code
                trace.append(
                    {
                        "node": node.name,
                        "file": node.span.file,
                        "lines": [node.span.start_line, node.span.end_line],
                    }
                )

            # Evidence: Edge Metadata (Call Site)
            if i < len(path_ids) - 1:
                next_id = path_ids[i + 1]
                # Hypothetical method to get specific edge object
                edge_meta = self.graph.get_edge_meta(nid, next_id)
                if edge_meta:
                    edges.append(
                        {
                            "src": nid,
                            "dst": next_id,
                            "kind": edge_meta.kind,
                            "meta": edge_meta.meta,
                        }
                    )

        return EvidencePack(
            item="Execution Trace", trace=trace, edges=edges, snippets=snippets
        )

    # --- Internals ---

    def _get(self, nid: str):
        if nid not in self.graph._nodes:
            raise ValueError(f"Unknown Node {nid}")
        return self.graph.node(nid)

    def _to_ref(self, node) -> NodeRef:
        container = self.graph.node(node.parent_id).name if node.parent_id else None
        return NodeRef(
            id=node.id,
            kind=node.kind,
            name=node.name,
            container=container,
            signature=node.meta.get("signature"),
            file=node.span.file if node.span else None,
        )
