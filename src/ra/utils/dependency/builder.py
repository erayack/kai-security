"""
Generic tree-sitter builder for dependency graphs.

One class, config-driven. Works with any language tree-sitter supports.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .graph import DependencyGraph
from .models import EdgeKind, Node, NodeKind, SourceSpan

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LangConfig:
    """Tree-sitter node-type mappings for one language."""

    extensions: List[str]
    container_types: List[str]
    unit_types: List[str]
    variable_types: List[str]
    call_node_type: str
    import_types: List[str]
    name_field: str  # child type holding the name
    body_field: str  # child type holding the body block
    # For inheritance: child type holding base class list
    superclass_list_type: Optional[str] = None
    # Type definition node types (struct, enum, typedef)
    type_def_types: List[str] = field(default_factory=list)


LANG_CONFIGS: Dict[str, LangConfig] = {
    "python": LangConfig(
        extensions=[".py"],
        container_types=["class_definition"],
        unit_types=[
            "function_definition",
            "async_function_definition",
        ],
        variable_types=["assignment"],
        call_node_type="call",
        import_types=[
            "import_statement",
            "import_from_statement",
        ],
        name_field="identifier",
        body_field="block",
        superclass_list_type="argument_list",
    ),
    "javascript": LangConfig(
        extensions=[".js", ".jsx", ".mjs", ".cjs"],
        container_types=["class_declaration"],
        unit_types=[
            "function_declaration",
            "method_definition",
            "arrow_function",
        ],
        variable_types=["variable_declarator"],
        call_node_type="call_expression",
        import_types=["import_statement"],
        name_field="identifier",
        body_field="class_body",
        superclass_list_type="class_heritage",
    ),
    "typescript": LangConfig(
        extensions=[".ts", ".tsx", ".mts", ".cts"],
        container_types=[
            "class_declaration",
            "interface_declaration",
        ],
        unit_types=[
            "function_declaration",
            "method_definition",
            "arrow_function",
        ],
        variable_types=["variable_declarator"],
        call_node_type="call_expression",
        import_types=["import_statement"],
        name_field="identifier",
        body_field="class_body",
        superclass_list_type="class_heritage",
        type_def_types=["type_alias_declaration", "enum_declaration"],
    ),
    "solidity": LangConfig(
        extensions=[".sol"],
        container_types=["contract_declaration"],
        unit_types=["function_definition"],
        variable_types=["state_variable_declaration"],
        call_node_type="call_expression",
        import_types=["import_directive"],
        name_field="identifier",
        body_field="contract_body",
        superclass_list_type="inheritance_specifier",
        type_def_types=[
            "struct_declaration",
            "enum_declaration",
            "event_definition",
        ],
    ),
    "c": LangConfig(
        extensions=[".c", ".h"],
        container_types=["struct_specifier", "union_specifier"],
        unit_types=["function_definition"],
        variable_types=["declaration"],
        call_node_type="call_expression",
        import_types=["preproc_include"],
        name_field="identifier",
        body_field="compound_statement",
        type_def_types=[
            "enum_specifier",
            "type_definition",
        ],
    ),
    "go": LangConfig(
        extensions=[".go"],
        container_types=["type_declaration"],
        unit_types=[
            "function_declaration",
            "method_declaration",
        ],
        variable_types=["var_declaration", "short_var_declaration"],
        call_node_type="call_expression",
        import_types=["import_declaration"],
        name_field="identifier",
        body_field="block",
        type_def_types=["type_declaration"],
    ),
    "rust": LangConfig(
        extensions=[".rs"],
        container_types=["struct_item", "impl_item", "trait_item"],
        unit_types=["function_item"],
        variable_types=["let_declaration", "static_item"],
        call_node_type="call_expression",
        import_types=["use_declaration"],
        name_field="identifier",
        body_field="block",
        type_def_types=["enum_item", "type_item"],
    ),
}

_SKIP_DIRS: Set[str] = {
    "test",
    "tests",
    "__test__",
    "__tests__",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".git",
    "dist",
    "build",
    "vendor",
    "third_party",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
    "target",
}


class TreeSitterBuilder:
    """
    Generic tree-sitter graph builder.

    Supports any language in LANG_CONFIGS. Language is auto-detected
    from file extensions, or can be pinned explicitly.
    """

    def __init__(
        self,
        *,
        languages: Optional[List[str]] = None,
        skip_patterns: Optional[Set[str]] = None,
    ) -> None:
        self._languages = languages
        self._skip = skip_patterns or _SKIP_DIRS
        self._parsers: Dict[str, Any] = {}
        self._configs: Dict[str, LangConfig] = {}
        # Extension -> language lookup
        self._ext_map: Dict[str, str] = {}

        self._init_configs()

    def _init_configs(self) -> None:
        """Set up configs and extension map."""
        langs = self._languages or list(LANG_CONFIGS.keys())
        for lang in langs:
            cfg = LANG_CONFIGS.get(lang)
            if cfg is None:
                logger.warning("No config for language %r", lang)
                continue
            self._configs[lang] = cfg
            for ext in cfg.extensions:
                self._ext_map[ext] = lang

    # ------------------------------------------------------------------
    # Parser loading
    # ------------------------------------------------------------------

    def _get_parser(self, lang: str) -> Any:
        """Lazy-load the tree-sitter parser for a language."""
        if lang in self._parsers:
            return self._parsers[lang]
        parser = self._create_parser(lang)
        self._parsers[lang] = parser
        return parser

    @staticmethod
    def _create_parser(lang: str) -> Any:
        """Create a tree-sitter parser, language-pack first."""
        try:
            from tree_sitter_language_pack import get_parser  # type: ignore[import-not-found]

            return get_parser(lang)
        except ImportError:
            pass

        import tree_sitter  # type: ignore[import-untyped]

        parser = tree_sitter.Parser()
        lang_module = _import_lang_module(lang)
        if lang_module is None:
            raise ImportError(
                f"No tree-sitter parser for {lang!r}. "
                f"Install tree-sitter-language-pack "
                f"or tree-sitter-{lang}"
            )
        parser.language = tree_sitter.Language(lang_module.language())
        return parser

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, source_path: str | Path) -> DependencyGraph:
        """
        Build a dependency graph from a directory or single file.

        Args:
            source_path: Path to project root or single source file.

        Returns:
            Populated DependencyGraph.
        """
        root = Path(source_path).resolve()
        graph = DependencyGraph(root)
        files = self._find_source_files(root)

        for fpath in files:
            try:
                self._process_file(fpath, graph)
            except Exception:
                logger.debug("Failed to parse %s", fpath, exc_info=True)

        self._resolve_call_edges(graph)
        return graph

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    def _find_source_files(self, root: Path) -> List[Path]:
        """Walk root for files matching any configured extension."""
        if root.is_file():
            return [root] if root.suffix in self._ext_map else []

        files: List[Path] = []
        for ext in self._ext_map:
            for fpath in root.rglob(f"*{ext}"):
                if not self._should_skip(fpath):
                    files.append(fpath)
        return sorted(files)

    def _should_skip(self, fpath: Path) -> bool:
        parts = set(fpath.parts)
        return bool(parts & self._skip)

    # ------------------------------------------------------------------
    # Per-file processing
    # ------------------------------------------------------------------

    def _process_file(self, fpath: Path, graph: DependencyGraph) -> None:
        """Parse one file and add its nodes/edges to the graph."""
        lang = self._ext_map.get(fpath.suffix)
        if lang is None:
            return
        cfg = self._configs[lang]

        source_bytes = fpath.read_bytes()
        parser = self._get_parser(lang)
        tree = parser.parse(source_bytes)

        rel = graph.norm_path(fpath)
        file_id = f"file:{rel}"

        # File node
        graph.add_node(
            Node(
                id=file_id,
                kind=NodeKind.FILE,
                name=fpath.name,
                span=SourceSpan(file=rel, start_line=1, end_line=1),
            )
        )

        root_node = tree.root_node
        self._walk_top_level(root_node, cfg, graph, file_id, rel, source_bytes)

    # ------------------------------------------------------------------
    # AST walking — generic, driven by LangConfig
    # ------------------------------------------------------------------

    def _walk_top_level(
        self,
        root: Any,
        cfg: LangConfig,
        graph: DependencyGraph,
        file_id: str,
        rel: str,
        src: bytes,
    ) -> None:
        """Walk top-level children for containers, units, vars, imports."""
        for child in root.children:
            if child.type in cfg.container_types:
                self._extract_container(child, cfg, graph, file_id, rel, src, None)
            elif child.type in cfg.unit_types:
                self._extract_unit(child, cfg, graph, file_id, rel, src, None)
            elif child.type in cfg.variable_types:
                self._extract_variable(child, cfg, graph, file_id, rel, src, None)
            elif child.type in cfg.import_types:
                self._extract_import(child, cfg, graph, file_id, rel, src)
            elif child.type in cfg.type_def_types:
                self._extract_type_def(child, cfg, graph, file_id, rel, src)
            # Handle decorated definitions (Python)
            elif child.type == "decorated_definition":
                self._walk_top_level(child, cfg, graph, file_id, rel, src)
            # Handle expression_statement wrapping assignments (Python)
            elif child.type == "expression_statement":
                for sub in child.children:
                    if sub.type in cfg.variable_types:
                        self._extract_variable(sub, cfg, graph, file_id, rel, src, None)
            # Handle export wrappers (JS/TS)
            elif child.type in (
                "export_statement",
                "lexical_declaration",
                "variable_declaration",
            ):
                self._walk_top_level(child, cfg, graph, file_id, rel, src)

    def _extract_container(
        self,
        node: Any,
        cfg: LangConfig,
        graph: DependencyGraph,
        file_id: str,
        rel: str,
        src: bytes,
        parent_id: Optional[str],
    ) -> None:
        """Extract a container (class/struct/contract) node."""
        name = self._get_name(node, cfg, src)
        if not name:
            return

        if parent_id:
            cid = f"{parent_id}.{name}"
        else:
            cid = f"{file_id}:{name}"

        span = _make_span(node, rel)
        graph.add_node(
            Node(
                id=cid,
                kind=NodeKind.CONTAINER,
                name=name,
                span=span,
                parent_id=parent_id,
            )
        )

        # DEFINES edge
        owner = parent_id or file_id
        graph.add_edge(owner, cid, EdgeKind.DEFINES)

        # Inheritance
        self._extract_inheritance(node, cfg, graph, cid, src)

        # Walk body for nested members
        body = _find_child_by_type(node, cfg.body_field)
        if body:
            self._walk_container_body(body, cfg, graph, file_id, cid, rel, src)

    def _walk_container_body(
        self,
        body: Any,
        cfg: LangConfig,
        graph: DependencyGraph,
        file_id: str,
        container_id: str,
        rel: str,
        src: bytes,
    ) -> None:
        """Walk body of a container for nested units/vars/containers."""
        for child in body.children:
            if child.type in cfg.unit_types:
                self._extract_unit(child, cfg, graph, file_id, rel, src, container_id)
            elif child.type in cfg.container_types:
                # Nested class/struct
                self._extract_container(
                    child, cfg, graph, file_id, rel, src, container_id
                )
            elif child.type in cfg.variable_types:
                self._extract_variable(
                    child, cfg, graph, file_id, rel, src, container_id
                )
            elif child.type in cfg.type_def_types:
                self._extract_type_def(child, cfg, graph, file_id, rel, src)
            elif child.type == "decorated_definition":
                self._walk_container_body(
                    child, cfg, graph, file_id, container_id, rel, src
                )
            elif child.type == "expression_statement":
                for sub in child.children:
                    if sub.type in cfg.variable_types:
                        self._extract_variable(
                            sub,
                            cfg,
                            graph,
                            file_id,
                            rel,
                            src,
                            container_id,
                        )
            # Handle field definitions (JS/TS class properties)
            elif child.type in (
                "field_definition",
                "public_field_definition",
            ):
                self._extract_variable(
                    child, cfg, graph, file_id, rel, src, container_id
                )

    def _extract_unit(
        self,
        node: Any,
        cfg: LangConfig,
        graph: DependencyGraph,
        file_id: str,
        rel: str,
        src: bytes,
        parent_id: Optional[str],
    ) -> None:
        """Extract a unit (function/method) node."""
        name = self._get_name(node, cfg, src)

        # Arrow functions: get name from parent variable_declarator
        if not name and node.type == "arrow_function":
            if node.parent and node.parent.type == "variable_declarator":
                name = self._get_name(node.parent, cfg, src)

        if not name:
            return

        if parent_id:
            uid = f"{parent_id}.{name}"
        else:
            uid = f"{file_id}:{name}"

        span = _make_span(node, rel)
        graph.add_node(
            Node(
                id=uid,
                kind=NodeKind.UNIT,
                name=name,
                span=span,
                parent_id=parent_id,
            )
        )

        # DEFINES edge
        if parent_id:
            graph.add_edge(parent_id, uid, EdgeKind.DEFINES)
        else:
            graph.add_edge(file_id, uid, EdgeKind.DEFINES)

        # Extract calls inside the function body
        self._collect_calls(node, cfg, uid, src, graph)

    def _extract_variable(
        self,
        node: Any,
        cfg: LangConfig,
        graph: DependencyGraph,
        file_id: str,
        rel: str,
        src: bytes,
        parent_id: Optional[str],
    ) -> None:
        """Extract a variable/attribute node."""
        name = self._get_name(node, cfg, src)
        if not name:
            # Try left-hand side of assignment
            if node.children:
                first = node.children[0]
                if first.type == cfg.name_field:
                    name = _text(first, src)
        if not name:
            return

        if parent_id:
            vid = f"{parent_id}.{name}"
        else:
            vid = f"{file_id}:{name}"

        span = _make_span(node, rel)
        graph.add_node(
            Node(
                id=vid,
                kind=NodeKind.VARIABLE,
                name=name,
                span=span,
                parent_id=parent_id,
            )
        )

        owner = parent_id or file_id
        graph.add_edge(owner, vid, EdgeKind.DEFINES)

    def _extract_import(
        self,
        node: Any,
        cfg: LangConfig,
        graph: DependencyGraph,
        file_id: str,
        rel: str,
        src: bytes,
    ) -> None:
        """Extract an import statement node."""
        text = _text(node, src).strip()
        if not text:
            return

        import_id = f"{file_id}:import:{text[:80]}"
        span = _make_span(node, rel)
        graph.add_node(
            Node(
                id=import_id,
                kind=NodeKind.IMPORT,
                name=text,
                span=span,
                parent_id=file_id,
            )
        )

    def _extract_type_def(
        self,
        node: Any,
        cfg: LangConfig,
        graph: DependencyGraph,
        file_id: str,
        rel: str,
        src: bytes,
    ) -> None:
        """Extract a type definition (struct, enum, typedef)."""
        name = self._get_name(node, cfg, src)
        # For C type_identifier
        if not name:
            tid_node = _find_child_by_type(node, "type_identifier")
            if tid_node:
                name = _text(tid_node, src)
        if not name:
            return

        td_id = f"{file_id}:{name}"
        span = _make_span(node, rel)
        graph.add_node(
            Node(
                id=td_id,
                kind=NodeKind.TYPE_DEF,
                name=name,
                span=span,
            )
        )
        graph.add_edge(file_id, td_id, EdgeKind.DEFINES)

    def _extract_inheritance(
        self,
        node: Any,
        cfg: LangConfig,
        graph: DependencyGraph,
        container_id: str,
        src: bytes,
    ) -> None:
        """Extract INHERITS edges from a container node."""
        if cfg.superclass_list_type is None:
            return

        heritage = _find_child_by_type(node, cfg.superclass_list_type)
        if heritage is None:
            return

        for child in heritage.children:
            if child.type == "identifier":
                base_name = _text(child, src)
                if base_name:
                    # Store as callee-style for later resolution
                    graph.add_edge(
                        container_id,
                        base_name,
                        EdgeKind.INHERITS,
                    )

    # ------------------------------------------------------------------
    # Call extraction
    # ------------------------------------------------------------------

    def _collect_calls(
        self,
        node: Any,
        cfg: LangConfig,
        caller_id: str,
        src: bytes,
        graph: DependencyGraph,
    ) -> None:
        """Recursively collect call expressions in a subtree.

        Calls are stored as (caller_id -> callee_name) with
        EdgeKind.CALLS. The callee_name is resolved to real node IDs
        in a second pass (_resolve_call_edges).
        """
        for child in node.children:
            if child.type == cfg.call_node_type:
                callee = self._call_target_name(child, src)
                if callee:
                    graph.add_edge(caller_id, callee, EdgeKind.CALLS)
            self._collect_calls(child, cfg, caller_id, src, graph)

    @staticmethod
    def _call_target_name(call_node: Any, src: bytes) -> str:
        """Extract the callee name from a call expression node."""
        if not call_node.children:
            return ""
        func = call_node.children[0]
        if func.type == "identifier":
            return _text(func, src)
        if func.type in ("attribute", "member_expression"):
            return _text(func, src)
        # Nested call: foo()()
        if func.type in ("call", "call_expression"):
            return ""
        return _text(func, src)

    def _resolve_call_edges(self, graph: DependencyGraph) -> None:
        """Second pass: resolve callee names to real node IDs.

        CALLS edges whose dst is not a real node are rewritten if we
        can find a matching UNIT by name. Unresolved edges are kept
        as-is (dangling name reference — still useful for agents).
        """
        rewrites: List[Tuple[str, EdgeKind, str, str, Dict[str, Any]]] = []
        for src, kind, dst, meta in graph.edges():
            if kind != EdgeKind.CALLS:
                continue
            if dst in graph._nodes:
                continue
            # Try to find the callee by simple name (last segment)
            simple = dst.rsplit(".", 1)[-1]
            candidates = graph.find_units(simple)
            if len(candidates) == 1:
                rewrites.append((src, kind, dst, candidates[0], meta))

        for src, kind, old_dst, new_dst, meta in rewrites:
            old_key = (src, kind, old_dst)
            if old_key in graph._edges:
                del graph._edges[old_key]
                graph._out[src][kind].discard(old_dst)
                graph._in[old_dst][kind].discard(src)
            graph.add_edge(src, new_dst, kind, **meta)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_name(node: Any, cfg: LangConfig, src: bytes) -> str:
        """Get the name of a node using the config's name_field."""
        # Try named child first (field-based)
        name_node = _find_child_by_type(node, cfg.name_field)
        if name_node:
            return _text(name_node, src)
        # C: function names hide inside function_declarator
        decl = _find_child_by_type(node, "function_declarator")
        if decl:
            name_node = _find_child_by_type(decl, cfg.name_field)
            if name_node:
                return _text(name_node, src)
        # Try property_identifier (JS methods)
        name_node = _find_child_by_type(node, "property_identifier")
        if name_node:
            return _text(name_node, src)
        # C types use type_identifier
        name_node = _find_child_by_type(node, "type_identifier")
        if name_node:
            return _text(name_node, src)
        return ""


# ======================================================================
# Module-level helpers (no self needed)
# ======================================================================


def _text(node: Any, src: bytes) -> str:
    """Get text of a tree-sitter node."""
    try:
        return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _make_span(node: Any, rel: str) -> SourceSpan:
    """Build a SourceSpan from a tree-sitter node."""
    start = node.start_point
    end = node.end_point
    return SourceSpan(
        file=rel,
        start_line=start[0] + 1,
        end_line=end[0] + 1,
        start_col=start[1],
        end_col=end[1],
    )


def _find_child_by_type(node: Any, type_name: str) -> Optional[Any]:
    """Find first direct child with a given type."""
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def _import_lang_module(lang: str) -> Optional[Any]:
    """Try to import an individual tree-sitter-<lang> package."""
    import importlib

    names = [
        f"tree_sitter_{lang}",
        f"tree_sitter_{lang.replace('-', '_')}",
    ]
    for mod_name in names:
        try:
            return importlib.import_module(mod_name)
        except ImportError:
            continue
    return None
