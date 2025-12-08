"""Core DependencyGraph class for building ContextSlice inputs."""

from __future__ import annotations

import json
import os
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from .models import Direction, EdgeKind, EdgeMeta, Node, NodeKind


class DependencyGraph:
    """
    A directed, typed multigraph for building ContextSlice inputs.

    Core invariant for slicing:
      - Everything ultimately reduces to FILE nodes.
      - FILE is reachable via:
          function/modifier -> contract -> file
          statevar -> contract -> file
          imports -> file
    """

    def __init__(self, root_dir: str | Path) -> None:
        path = Path(root_dir).resolve()
        if path.is_file():
            self.root_dir = path.parent
        else:
            self.root_dir = path

        self._nodes: Dict[str, Node] = {}
        # edges[(src, kind, dst)] = EdgeMeta
        self._edges: Dict[Tuple[str, EdgeKind, str], EdgeMeta] = {}
        self._out: Dict[str, Dict[EdgeKind, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self._in: Dict[str, Dict[EdgeKind, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )

        # simple indices
        self._by_kind: Dict[NodeKind, Set[str]] = defaultdict(set)
        self._fn_by_name: Dict[str, Set[str]] = defaultdict(set)
        self._contract_by_name: Dict[str, Set[str]] = defaultdict(set)
        self._file_by_path: Dict[str, str] = {}  # relpath -> node_id

    # ---------------------------
    # IDs / path normalization
    # ---------------------------

    def norm_path(self, path: str | Path) -> str:
        """Normalize a path to a repo-relative posix string."""
        p = Path(path)
        if p.is_absolute():
            try:
                rel = p.resolve().relative_to(self.root_dir)
            except Exception:
                rel = p.name
        else:
            rel = p

        s = str(rel).replace(os.sep, "/")
        s = s.lstrip("./")
        return s

    def file_id(self, file_path: str | Path) -> str:
        """Generate a node ID for a file."""
        rel = self.norm_path(file_path)
        return f"file:{rel}"

    # ---------------------------
    # Mutation
    # ---------------------------

    def add_node(self, node: Node) -> None:
        """Add a node to the graph."""
        if node.id in self._nodes:
            return
        self._nodes[node.id] = node
        self._by_kind[node.kind].add(node.id)

        if node.kind == NodeKind.FILE and node.file:
            self._file_by_path[node.file] = node.id
        elif node.kind == NodeKind.CONTRACT:
            self._contract_by_name[node.name].add(node.id)
        elif node.kind in (NodeKind.FUNCTION, NodeKind.MODIFIER):
            self._fn_by_name[node.name].add(node.id)

    def add_edge(self, src: str, dst: str, kind: EdgeKind, **meta: Any) -> None:
        """Add an edge to the graph."""
        key = (src, kind, dst)
        if key in self._edges:
            # merge metadata (last write wins)
            merged = dict(self._edges[key].meta)
            merged.update(meta)
            self._edges[key] = EdgeMeta(kind=kind, meta=merged)
            return

        self._edges[key] = EdgeMeta(kind=kind, meta=dict(meta))
        self._out[src][kind].add(dst)
        self._in[dst][kind].add(src)

    # ---------------------------
    # Accessors / queries
    # ---------------------------

    def node(self, node_id: str) -> Node:
        """Get a node by ID."""
        return self._nodes[node_id]

    def nodes(self, kind: Optional[NodeKind] = None) -> Set[str]:
        """Get all node IDs, optionally filtered by kind."""
        return set(self._by_kind[kind]) if kind else set(self._nodes.keys())

    def edges(self) -> Iterator[Tuple[str, EdgeKind, str, Dict[str, Any]]]:
        """Iterate over all edges as (src, kind, dst, meta) tuples."""
        for (s, k, d), em in self._edges.items():
            yield s, k, d, dict(em.meta)

    def neighbors(
        self,
        node_id: str,
        *,
        edge_kinds: Optional[Set[EdgeKind]] = None,
        direction: Direction = "out",
    ) -> Iterator[str]:
        """Get neighboring node IDs."""
        if direction in ("out", "both"):
            for k, dsts in self._out.get(node_id, {}).items():
                if edge_kinds is not None and k not in edge_kinds:
                    continue
                for d in dsts:
                    yield d
        if direction in ("in", "both"):
            for k, srcs in self._in.get(node_id, {}).items():
                if edge_kinds is not None and k not in edge_kinds:
                    continue
                for s in srcs:
                    yield s

    def find_contracts(self, name: str) -> List[str]:
        """Find contract node IDs by name."""
        return sorted(self._contract_by_name.get(name, set()))

    def find_functions(self, name: str) -> List[str]:
        """Find function/modifier node IDs by name."""
        return sorted(self._fn_by_name.get(name, set()))

    def file_node(self, file_path: str | Path) -> Optional[str]:
        """Get the node ID for a file path."""
        rel = self.norm_path(file_path)
        nid = self._file_by_path.get(rel)
        if nid:
            return nid
        # allow passing "file:..." directly
        candidate = f"file:{rel}"
        return candidate if candidate in self._nodes else None

    def contracts_in_file(self, file_path: str | Path) -> List[str]:
        """Get contract node IDs defined in a file."""
        fid = self.file_node(file_path)
        if not fid:
            return []
        return sorted(self._out.get(fid, {}).get(EdgeKind.DEFINES, set()))

    def functions_in_contract(self, contract_id: str) -> List[str]:
        """Get function/modifier node IDs declared in a contract."""
        out = self._out.get(contract_id, {})
        fns = set(out.get(EdgeKind.DECLARES_FUNCTION, set()))
        mods = set(out.get(EdgeKind.DECLARES_MODIFIER, set()))
        return sorted(fns | mods)

    def functions_in_file(self, file_path: str | Path) -> List[str]:
        """Get all function/modifier node IDs in a file."""
        fns: Set[str] = set()
        for cid in self.contracts_in_file(file_path):
            fns |= set(self.functions_in_contract(cid))
        return sorted(fns)

    def public_entrypoints(self) -> List[str]:
        """Get all public/external function node IDs."""
        out: List[str] = []
        for fid in self.nodes(NodeKind.FUNCTION):
            n = self._nodes[fid]
            vis = (n.visibility or "").lower()
            if vis in ("public", "external") and not n.meta.get(
                "is_constructor", False
            ):
                out.append(fid)
        return sorted(out)

    # ---------------------------
    # Slicing
    # ---------------------------

    def bfs(
        self,
        start: Iterable[str],
        *,
        max_hops: int,
        edge_kinds: Optional[Set[EdgeKind]] = None,
        direction: Direction = "both",
        expand_kinds: Optional[Set[NodeKind]] = None,
    ) -> Set[str]:
        """
        Breadth-first search from start nodes.

        expand_kinds: if provided, ONLY expand nodes whose kind is in expand_kinds.
                     nodes outside expand_kinds are still included, but not expanded further.
        """
        start = [s for s in start if s in self._nodes]
        seen: Set[str] = set(start)
        q = deque((s, 0) for s in start)

        while q:
            cur, depth = q.popleft()
            if depth >= max_hops:
                continue

            if expand_kinds is not None and self._nodes[cur].kind not in expand_kinds:
                continue

            for nb in self.neighbors(cur, edge_kinds=edge_kinds, direction=direction):
                if nb not in seen:
                    seen.add(nb)
                    q.append((nb, depth + 1))
        return seen

    def derive_related_files(
        self,
        target_file: str | Path,
        *,
        depth: int = 2,
        mode: str = "REAL_SOURCE",
        include_tests: bool = False,
        direction: Direction = "both",
    ) -> List[str]:
        """
        Derive related files for a target file.

        Modes:
          - MINIMAL: Just the target file
          - REAL_SOURCE: imports + inheritance + calls + statevar deps + modifiers
          - BROAD: All edge types
        """
        fid = self.file_node(target_file)
        if not fid:
            return []

        if mode == "MINIMAL":
            rel = self._nodes[fid].file or self.norm_path(target_file)
            return [rel]

        if mode == "BROAD":
            kinds = set(EdgeKind)  # everything
        else:
            # "REAL_SOURCE": imports + inheritance + calls + statevar deps + modifiers
            kinds = {
                EdgeKind.IMPORTS,
                EdgeKind.DEFINES,
                EdgeKind.INHERITS,
                EdgeKind.DECLARES_FUNCTION,
                EdgeKind.DECLARES_MODIFIER,
                EdgeKind.DECLARES_STATEVAR,
                EdgeKind.USES_MODIFIER,
                EdgeKind.CALLS,
                EdgeKind.HIGH_LEVEL_CALL,
                EdgeKind.LOW_LEVEL_CALL,
                EdgeKind.READS,
                EdgeKind.WRITES,
            }

        visited = self.bfs(
            [fid],
            max_hops=depth,
            edge_kinds=kinds,
            direction=direction,
            expand_kinds=None,  # expand everything
        )

        files: Set[str] = set()
        for nid in visited:
            n = self._nodes[nid]
            if n.kind == NodeKind.FILE and n.file:
                if include_tests or not self._looks_like_test(n.file):
                    files.add(n.file)

        # Always include the target even if heuristics flag it as test.
        files.add(self._nodes[fid].file or self.norm_path(target_file))
        return sorted(files)

    @staticmethod
    def _looks_like_test(relpath: str) -> bool:
        """Check if a file path looks like a test file."""
        p = relpath.lower()
        return (
            "/test/" in p
            or "/tests/" in p
            or p.endswith(".t.sol")
            or p.endswith("_test.sol")
            or p.endswith(".spec.sol")
        )

    # ---------------------------
    # JSON (cacheable artifact)
    # ---------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the graph to a dictionary."""
        return {
            "root_dir": str(self.root_dir),
            "nodes": [
                {
                    "id": n.id,
                    "kind": n.kind.value,
                    "name": n.name,
                    "file": n.file,
                    "contract": n.contract,
                    "signature": n.signature,
                    "visibility": n.visibility,
                    "meta": n.meta,
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {"src": s, "kind": k.value, "dst": d, "meta": m}
                for (s, k, d), em in self._edges.items()
                for m in [em.meta]
            ],
        }

    def to_json(self, path: str | Path) -> None:
        """Save the graph to a JSON file."""
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DependencyGraph":
        """Load a graph from a dictionary."""
        g = cls(data["root_dir"])
        for nd in data["nodes"]:
            g.add_node(
                Node(
                    id=nd["id"],
                    kind=NodeKind(nd["kind"]),
                    name=nd["name"],
                    file=nd.get("file"),
                    contract=nd.get("contract"),
                    signature=nd.get("signature"),
                    visibility=nd.get("visibility"),
                    meta=nd.get("meta") or {},
                )
            )
        for e in data["edges"]:
            g.add_edge(e["src"], e["dst"], EdgeKind(e["kind"]), **(e.get("meta") or {}))
        return g

    @classmethod
    def from_json(cls, path: str | Path) -> "DependencyGraph":
        """Load a graph from a JSON file."""
        return cls.from_dict(json.loads(Path(path).read_text()))
