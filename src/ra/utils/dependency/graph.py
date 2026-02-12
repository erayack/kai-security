"""Core DependencyGraph class for building ContextSlice inputs."""

from __future__ import annotations

import json
import os
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from .models import Direction, EdgeKind, EdgeMeta, Node, NodeKind, SourceSpan


class DependencyGraph:
    """
    A directed, typed multigraph for code analysis.

    Language-agnostic structure:
      - FILE nodes are the root anchors
      - CONTAINER nodes (contracts/modules/classes) are defined by files
      - UNIT nodes (functions/methods) are defined by containers
      - All nodes have optional SourceSpan for grounding
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

    def add_node(self, node: Node) -> None:
        """Add a node to the graph."""
        if node.id in self._nodes:
            return
        self._nodes[node.id] = node
        self._by_kind[node.kind].add(node.id)

        # Index by file path
        file_path = node.span.file if node.span else None
        if node.kind == NodeKind.FILE and file_path:
            self._file_by_path[self.norm_path(file_path)] = node.id
        # Index by name for containers and units
        elif node.kind == NodeKind.CONTAINER:
            self._contract_by_name[node.name].add(node.id)
        elif node.kind in (NodeKind.UNIT, NodeKind.INTERFACE):
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

    def find_containers(self, name: str) -> List[str]:
        """Find container node IDs by name."""
        return sorted(self._contract_by_name.get(name, set()))

    def find_units(self, name: str) -> List[str]:
        """Find unit/interface node IDs by name."""
        return sorted(self._fn_by_name.get(name, set()))

    # Legacy aliases
    find_contracts = find_containers
    find_functions = find_units

    def file_node(self, file_path: str | Path) -> Optional[str]:
        """Get the node ID for a file path."""
        rel = self.norm_path(file_path)
        nid = self._file_by_path.get(rel)
        if nid:
            return nid
        # allow passing "file:..." directly
        candidate = f"file:{rel}"
        return candidate if candidate in self._nodes else None

    def containers_in_file(self, file_path: str | Path) -> List[str]:
        """Get container node IDs defined in a file."""
        fid = self.file_node(file_path)
        if not fid:
            return []
        return sorted(self._out.get(fid, {}).get(EdgeKind.DEFINES, set()))

    def units_in_container(self, container_id: str) -> List[str]:
        """Get unit/interface node IDs defined in a container."""
        return sorted(self._out.get(container_id, {}).get(EdgeKind.DEFINES, set()))

    def units_in_file(self, file_path: str | Path) -> List[str]:
        """Get all unit/interface node IDs in a file."""
        units: Set[str] = set()
        for cid in self.containers_in_file(file_path):
            units |= set(self.units_in_container(cid))
        return sorted(units)

    def public_entrypoints(self) -> List[str]:
        """Get all public/external unit node IDs."""
        out: List[str] = []
        for uid in self.nodes(NodeKind.UNIT):
            n = self._nodes[uid]
            vis = (n.meta.get("visibility") or "").lower()
            if vis in ("public", "external") and not n.meta.get(
                "is_constructor", False
            ):
                out.append(uid)
        return sorted(out)

    # Legacy aliases
    contracts_in_file = containers_in_file
    functions_in_contract = units_in_container
    functions_in_file = units_in_file

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
          - REAL_SOURCE: imports + inheritance + calls + reads/writes
          - BROAD: All edge types
        """
        fid = self.file_node(target_file)
        if not fid:
            return []

        target_n = self._nodes[fid]
        target_path = (
            target_n.span.file if target_n.span else self.norm_path(target_file)
        )

        if mode == "MINIMAL":
            return [target_path]

        if mode == "BROAD":
            kinds = set(EdgeKind)  # everything
        else:
            # "REAL_SOURCE": imports + defines + inheritance + calls + reads/writes
            kinds = {
                EdgeKind.IMPORTS,
                EdgeKind.DEFINES,
                EdgeKind.INHERITS,
                EdgeKind.CALLS,
                EdgeKind.ACCEPTS,
                EdgeKind.READS,
                EdgeKind.WRITES,
                EdgeKind.USES_TYPE,
            }

        visited = self.bfs(
            [fid],
            max_hops=depth,
            edge_kinds=kinds,
            direction=direction,
            expand_kinds=None,
        )

        files: Set[str] = set()
        for nid in visited:
            n = self._nodes[nid]
            file_path = n.span.file if n.span else None
            if n.kind == NodeKind.FILE and file_path:
                if include_tests or not self._looks_like_test(file_path):
                    files.add(file_path)

        # Always include the target
        files.add(target_path)
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

    def content_hash(self) -> str:
        """Deterministic hash of sorted node IDs + edge tuples."""
        import hashlib

        nodes = sorted(self._nodes.keys())
        edges = sorted((s, k.value, d) for (s, k, d) in self._edges.keys())
        payload = json.dumps([nodes, edges], sort_keys=True).encode()
        return hashlib.sha256(payload).hexdigest()[:24]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the graph to a dictionary."""
        nodes = []
        for n in self._nodes.values():
            node_dict: Dict[str, Any] = {
                "id": n.id,
                "kind": n.kind.value,
                "name": n.name,
                "meta": dict(n.meta) if n.meta else {},
            }
            if n.span:
                node_dict["span"] = {
                    "file": n.span.file,
                    "start_line": n.span.start_line,
                    "end_line": n.span.end_line,
                    "start_col": n.span.start_col,
                    "end_col": n.span.end_col,
                }
            if n.parent_id:
                node_dict["parent_id"] = n.parent_id
            nodes.append(node_dict)

        return {
            "root_dir": str(self.root_dir),
            "nodes": nodes,
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
            # Parse span if present
            span = None
            if "span" in nd and nd["span"]:
                sp = nd["span"]
                span = SourceSpan(
                    # Normalize fixture-built absolute paths to repo-relative paths.
                    # Many cached fixtures were generated on another machine and embed
                    # absolute file paths (e.g. /Users/...); keep the graph portable.
                    file=g.norm_path(sp["file"]),
                    start_line=sp["start_line"],
                    end_line=sp["end_line"],
                    start_col=sp.get("start_col"),
                    end_col=sp.get("end_col"),
                )

            g.add_node(
                Node(
                    id=nd["id"],
                    kind=NodeKind(nd["kind"]),
                    name=nd["name"],
                    span=span,
                    parent_id=nd.get("parent_id"),
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

    def get_edge_meta(
        self, src: str, dst: str, kind: Optional[EdgeKind] = None
    ) -> Optional[EdgeMeta]:
        """Get edge metadata between two nodes."""
        if kind:
            key = (src, kind, dst)
            return self._edges.get(key)
        # Find any edge between src and dst
        for (s, k, d), em in self._edges.items():
            if s == src and d == dst:
                return em
        return None
