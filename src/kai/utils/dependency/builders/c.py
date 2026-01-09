"""
C dependency graph builder using tree-sitter.

Extracts:
- Functions (UNIT)
- Structs, unions, enums (TYPE_DEF / CONTAINER)
- Global variables (VARIABLE)
- Macros (tracked in metadata)
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, List, Optional, Tuple

from .treesitter_base import TreeSitterBuilder
from ..models import Node, SourceSpan, NodeKind, EdgeKind


class CBuilder(TreeSitterBuilder):
    """
    Tree-sitter based builder for C projects.

    Maps C constructs to NodeKind:
    - struct_specifier, union_specifier -> CONTAINER/TYPE_DEF
    - function_definition -> UNIT
    - declaration (global) -> VARIABLE
    - enum_specifier -> TYPE_DEF
    """

    @property
    def language(self) -> str:
        return "c"

    @property
    def file_extensions(self) -> List[str]:
        return [".c", ".h"]

    def _extract_from_tree(
        self, tree: Any, file_path: Path, source_bytes: bytes
    ) -> Tuple[List[Node], List[Tuple[str, str, EdgeKind]]]:
        """
        Extract C nodes and edges from the AST.
        """
        nodes: List[Node] = []
        edges: List[Tuple[str, str, EdgeKind]] = []

        file_id = str(file_path)
        root = tree.root_node

        self._extract_translation_unit(
            root, file_path, file_id, source_bytes, nodes, edges
        )

        return nodes, edges

    def _extract_translation_unit(
        self,
        root: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract translation unit (file) level constructs."""
        for child in root.children:
            if child.type == "function_definition":
                self._extract_function(
                    child, file_path, file_id, source_bytes, nodes, edges
                )
            elif child.type == "declaration":
                self._extract_declaration(
                    child, file_path, file_id, source_bytes, nodes, edges
                )
            elif child.type == "struct_specifier":
                self._extract_struct(
                    child, file_path, file_id, source_bytes, nodes, edges
                )
            elif child.type == "union_specifier":
                self._extract_union(
                    child, file_path, file_id, source_bytes, nodes, edges
                )
            elif child.type == "enum_specifier":
                self._extract_enum(
                    child, file_path, file_id, source_bytes, nodes, edges
                )
            elif child.type == "preproc_function_def":
                self._extract_macro(
                    child, file_path, file_id, source_bytes, nodes
                )
            elif child.type == "type_definition":
                self._extract_typedef(
                    child, file_path, file_id, source_bytes, nodes, edges
                )

    def _extract_function(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract a function definition."""
        # Get declarator
        declarator = self._find_child_by_type(node, "function_declarator")
        if not declarator:
            # Try pointer_declarator for functions returning pointers
            pointer_decl = self._find_child_by_type(node, "pointer_declarator")
            if pointer_decl:
                declarator = self._find_child_by_type(pointer_decl, "function_declarator")

        if not declarator:
            return

        # Get function name
        name_node = self._find_child_by_type(declarator, "identifier")
        if not name_node:
            return

        func_name = self._get_node_text(name_node, source_bytes)
        func_id = f"{file_id}:{func_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Extract return type
        return_type = ""
        for child in node.children:
            if child.type in ("primitive_type", "type_identifier", "sized_type_specifier"):
                return_type = self._get_node_text(child, source_bytes)
                break

        # Extract parameters
        params = []
        param_list = self._find_child_by_type(declarator, "parameter_list")
        if param_list:
            for param in param_list.children:
                if param.type == "parameter_declaration":
                    param_name = self._find_child_by_type(param, "identifier")
                    if param_name:
                        params.append(self._get_node_text(param_name, source_bytes))

        # Check if static (file-local)
        is_static = any(
            c.type == "storage_class_specifier" and self._get_node_text(c, source_bytes) == "static"
            for c in node.children
        )

        visibility = "private" if is_static else "public"

        func_node = Node(
            id=func_id,
            kind=NodeKind.UNIT,
            name=func_name,
            span=span,
            parent_id=None,
            meta={
                "type": "function",
                "visibility": visibility,
                "return_type": return_type,
                "parameters": params,
                "is_static": is_static,
            },
        )
        nodes.append(func_node)

        # Extract function calls within body
        body = self._find_child_by_type(node, "compound_statement")
        if body:
            self._extract_calls(body, func_id, source_bytes, edges)
            self._extract_variable_accesses(body, func_id, source_bytes, edges)

    def _extract_declaration(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract a declaration (global variable or function prototype)."""
        # Check if it's a function declaration (prototype)
        declarator = self._find_child_by_type(node, "function_declarator")
        if declarator:
            # Function prototype - could add as UNIT with "prototype" type
            return

        # Check for struct/union/enum definitions within declaration
        for child in node.children:
            if child.type == "struct_specifier":
                self._extract_struct(child, file_path, file_id, source_bytes, nodes, edges)
                return
            elif child.type == "union_specifier":
                self._extract_union(child, file_path, file_id, source_bytes, nodes, edges)
                return
            elif child.type == "enum_specifier":
                self._extract_enum(child, file_path, file_id, source_bytes, nodes, edges)
                return

        # Regular variable declaration
        init_declarator = self._find_child_by_type(node, "init_declarator")
        if init_declarator:
            name_node = self._find_child_by_type(init_declarator, "identifier")
        else:
            name_node = self._find_child_by_type(node, "identifier")

        if not name_node:
            return

        var_name = self._get_node_text(name_node, source_bytes)
        var_id = f"{file_id}:{var_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Get type
        var_type = ""
        for child in node.children:
            if child.type in ("primitive_type", "type_identifier", "sized_type_specifier"):
                var_type = self._get_node_text(child, source_bytes)
                break

        # Check if static or extern
        is_static = any(
            c.type == "storage_class_specifier" and self._get_node_text(c, source_bytes) == "static"
            for c in node.children
        )
        is_extern = any(
            c.type == "storage_class_specifier" and self._get_node_text(c, source_bytes) == "extern"
            for c in node.children
        )

        var_node = Node(
            id=var_id,
            kind=NodeKind.VARIABLE,
            name=var_name,
            span=span,
            parent_id=None,
            meta={
                "type": "global",
                "var_type": var_type,
                "visibility": "private" if is_static else "public",
                "is_static": is_static,
                "is_extern": is_extern,
            },
        )
        nodes.append(var_node)

    def _extract_struct(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract a struct definition."""
        name_node = self._find_child_by_type(node, "type_identifier")
        if not name_node:
            return

        struct_name = self._get_node_text(name_node, source_bytes)
        struct_id = f"{file_id}:struct_{struct_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Extract fields
        fields = []
        field_list = self._find_child_by_type(node, "field_declaration_list")
        if field_list:
            for field in field_list.children:
                if field.type == "field_declaration":
                    field_name = self._find_child_by_type(field, "field_identifier")
                    if field_name:
                        fields.append(self._get_node_text(field_name, source_bytes))

        struct_node = Node(
            id=struct_id,
            kind=NodeKind.CONTAINER,
            name=struct_name,
            span=span,
            parent_id=None,
            meta={
                "type": "struct",
                "fields": fields,
            },
        )
        nodes.append(struct_node)

    def _extract_union(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract a union definition."""
        name_node = self._find_child_by_type(node, "type_identifier")
        if not name_node:
            return

        union_name = self._get_node_text(name_node, source_bytes)
        union_id = f"{file_id}:union_{union_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Extract members
        members = []
        field_list = self._find_child_by_type(node, "field_declaration_list")
        if field_list:
            for field in field_list.children:
                if field.type == "field_declaration":
                    field_name = self._find_child_by_type(field, "field_identifier")
                    if field_name:
                        members.append(self._get_node_text(field_name, source_bytes))

        union_node = Node(
            id=union_id,
            kind=NodeKind.CONTAINER,
            name=union_name,
            span=span,
            parent_id=None,
            meta={
                "type": "union",
                "members": members,
            },
        )
        nodes.append(union_node)

    def _extract_enum(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract an enum definition."""
        name_node = self._find_child_by_type(node, "type_identifier")
        if not name_node:
            return

        enum_name = self._get_node_text(name_node, source_bytes)
        enum_id = f"{file_id}:enum_{enum_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Extract enumerators
        enumerators = []
        enumerator_list = self._find_child_by_type(node, "enumerator_list")
        if enumerator_list:
            for enum_val in enumerator_list.children:
                if enum_val.type == "enumerator":
                    name = self._find_child_by_type(enum_val, "identifier")
                    if name:
                        enumerators.append(self._get_node_text(name, source_bytes))

        enum_node = Node(
            id=enum_id,
            kind=NodeKind.TYPE_DEF,
            name=enum_name,
            span=span,
            parent_id=None,
            meta={
                "type": "enum",
                "values": enumerators,
            },
        )
        nodes.append(enum_node)

    def _extract_macro(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
    ) -> None:
        """Extract a function-like macro definition."""
        name_node = self._find_child_by_type(node, "identifier")
        if not name_node:
            return

        macro_name = self._get_node_text(name_node, source_bytes)
        macro_id = f"{file_id}:macro_{macro_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Extract parameters
        params = []
        param_node = self._find_child_by_type(node, "preproc_params")
        if param_node:
            for param in param_node.children:
                if param.type == "identifier":
                    params.append(self._get_node_text(param, source_bytes))

        macro_node = Node(
            id=macro_id,
            kind=NodeKind.INTERFACE,  # Macros act like modifiers/decorators
            name=macro_name,
            span=span,
            parent_id=None,
            meta={
                "type": "macro",
                "parameters": params,
            },
        )
        nodes.append(macro_node)

    def _extract_typedef(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract a typedef."""
        # Check for struct/union inside typedef
        for child in node.children:
            if child.type == "struct_specifier":
                self._extract_struct(child, file_path, file_id, source_bytes, nodes, edges)
            elif child.type == "union_specifier":
                self._extract_union(child, file_path, file_id, source_bytes, nodes, edges)
            elif child.type == "enum_specifier":
                self._extract_enum(child, file_path, file_id, source_bytes, nodes, edges)

        # Get typedef name
        declarator = self._find_child_by_type(node, "type_identifier")
        if not declarator:
            return

        typedef_name = self._get_node_text(declarator, source_bytes)
        typedef_id = f"{file_id}:typedef_{typedef_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        typedef_node = Node(
            id=typedef_id,
            kind=NodeKind.TYPE_DEF,
            name=typedef_name,
            span=span,
            parent_id=None,
            meta={
                "type": "typedef",
            },
        )
        nodes.append(typedef_node)

    def _extract_calls(
        self,
        node: Any,
        caller_id: str,
        source_bytes: bytes,
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract function calls from a node."""
        for child in node.children:
            if child.type == "call_expression":
                func = child.children[0] if child.children else None
                if func and func.type == "identifier":
                    callee = self._get_node_text(func, source_bytes)
                    edges.append((caller_id, callee, EdgeKind.CALLS))

            # Recurse into children
            self._extract_calls(child, caller_id, source_bytes, edges)

    def _extract_variable_accesses(
        self,
        node: Any,
        func_id: str,
        source_bytes: bytes,
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract variable reads and writes."""
        for child in node.children:
            if child.type == "assignment_expression":
                # Left side is written
                left = child.children[0] if child.children else None
                if left and left.type == "identifier":
                    var_name = self._get_node_text(left, source_bytes)
                    edges.append((func_id, var_name, EdgeKind.WRITES))

            elif child.type == "identifier":
                # Could be a read - would need context to know for sure
                pass

            # Recurse
            self._extract_variable_accesses(child, func_id, source_bytes, edges)
