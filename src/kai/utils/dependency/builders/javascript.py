"""
JavaScript dependency graph builder using tree-sitter.

Extracts:
- Classes (CONTAINER)
- Functions, arrow functions, and methods (UNIT)
- Exports (tracked in metadata)
- Variables and class properties (VARIABLE)
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, List, Optional, Tuple

from .treesitter_base import TreeSitterBuilder
from ..models import Node, SourceSpan, NodeKind, EdgeKind


class JavaScriptBuilder(TreeSitterBuilder):
    """
    Tree-sitter based builder for JavaScript projects.

    Maps JavaScript constructs to NodeKind:
    - class_declaration -> CONTAINER
    - function_declaration, arrow_function, method_definition -> UNIT
    - variable_declaration (module-level) -> VARIABLE
    """

    @property
    def language(self) -> str:
        return "javascript"

    @property
    def file_extensions(self) -> List[str]:
        return [".js", ".mjs", ".cjs"]

    def _extract_from_tree(
        self, tree: Any, file_path: Path, source_bytes: bytes
    ) -> Tuple[List[Node], List[Tuple[str, str, EdgeKind]]]:
        """
        Extract JavaScript nodes and edges from the AST.
        """
        nodes: List[Node] = []
        edges: List[Tuple[str, str, EdgeKind]] = []

        file_id = str(file_path)
        root = tree.root_node

        self._extract_program(root, file_path, file_id, source_bytes, nodes, edges)

        return nodes, edges

    def _extract_program(
        self,
        root: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract program-level constructs."""
        for child in root.children:
            self._extract_statement(
                child, file_path, file_id, source_bytes, nodes, edges, None
            )

    def _extract_statement(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
        parent_id: Optional[str],
    ) -> None:
        """Extract a statement (class, function, variable, etc.)."""
        if node.type == "class_declaration":
            self._extract_class(
                node, file_path, file_id, source_bytes, nodes, edges, parent_id
            )
        elif node.type == "function_declaration":
            self._extract_function(
                node, file_path, file_id, source_bytes, nodes, edges, parent_id
            )
        elif node.type in ("lexical_declaration", "variable_declaration"):
            self._extract_variable_declaration(
                node, file_path, file_id, source_bytes, nodes, edges, parent_id
            )
        elif node.type == "export_statement":
            self._extract_export(node, file_path, file_id, source_bytes, nodes, edges)
        elif node.type == "expression_statement":
            # Check for assignments or function expressions
            expr = node.children[0] if node.children else None
            if expr and expr.type == "assignment_expression":
                self._extract_assignment_expression(
                    expr, file_path, file_id, source_bytes, nodes, edges, parent_id
                )

    def _extract_class(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
        parent_id: Optional[str],
        is_exported: bool = False,
    ) -> None:
        """Extract a class declaration."""
        name_node = self._find_child_by_type(node, "identifier")
        if not name_node:
            return

        class_name = self._get_node_text(name_node, source_bytes)
        class_id = f"{file_id}:{class_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Check for extends clause
        bases = []
        heritage = self._find_child_by_type(node, "class_heritage")
        if heritage:
            extends = self._find_child_by_type(heritage, "identifier")
            if extends:
                bases.append(self._get_node_text(extends, source_bytes))

        class_node = Node(
            id=class_id,
            kind=NodeKind.CONTAINER,
            name=class_name,
            span=span,
            parent_id=parent_id,
            meta={
                "type": "class",
                "bases": bases,
                "exported": is_exported,
            },
        )
        nodes.append(class_node)

        # Add INHERITS edges
        for base in bases:
            edges.append((class_id, base, EdgeKind.INHERITS))

        # Extract class body
        body = self._find_child_by_type(node, "class_body")
        if body:
            self._extract_class_body(
                body, file_path, file_id, source_bytes, nodes, edges, class_id
            )

    def _extract_class_body(
        self,
        body: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
        class_id: str,
    ) -> None:
        """Extract members from a class body."""
        for child in body.children:
            if child.type == "method_definition":
                self._extract_method(
                    child, file_path, file_id, source_bytes, nodes, edges, class_id
                )
            elif child.type == "field_definition":
                self._extract_field(
                    child, file_path, file_id, source_bytes, nodes, class_id
                )

    def _extract_function(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
        parent_id: Optional[str],
        is_exported: bool = False,
        is_async: bool = False,
    ) -> None:
        """Extract a function declaration."""
        name_node = self._find_child_by_type(node, "identifier")
        if not name_node:
            return

        func_name = self._get_node_text(name_node, source_bytes)

        if parent_id:
            func_id = f"{parent_id}.{func_name}"
        else:
            func_id = f"{file_id}:{func_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Extract parameters
        params = []
        param_node = self._find_child_by_type(node, "formal_parameters")
        if param_node:
            for param in param_node.children:
                if param.type == "identifier":
                    params.append(self._get_node_text(param, source_bytes))
                elif param.type == "required_parameter":
                    name = self._find_child_by_type(param, "identifier")
                    if name:
                        params.append(self._get_node_text(name, source_bytes))

        # Check if async
        is_async = is_async or any(c.type == "async" for c in node.children)

        func_node = Node(
            id=func_id,
            kind=NodeKind.UNIT,
            name=func_name,
            span=span,
            parent_id=parent_id,
            meta={
                "type": "function",
                "visibility": "public",
                "is_async": is_async,
                "parameters": params,
                "exported": is_exported,
            },
        )
        nodes.append(func_node)

        # Add DEFINES edge
        if parent_id:
            edges.append((parent_id, func_id, EdgeKind.DEFINES))

        # Extract calls within body
        body = self._find_child_by_type(node, "statement_block")
        if body:
            self._extract_calls(body, func_id, source_bytes, edges)

    def _extract_method(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
        class_id: str,
    ) -> None:
        """Extract a method definition."""
        name_node = self._find_child_by_type(node, "property_identifier")
        if not name_node:
            return

        method_name = self._get_node_text(name_node, source_bytes)
        method_id = f"{class_id}.{method_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Extract parameters
        params = []
        param_node = self._find_child_by_type(node, "formal_parameters")
        if param_node:
            for param in param_node.children:
                if param.type == "identifier":
                    params.append(self._get_node_text(param, source_bytes))

        # Check for static/async/getter/setter
        is_static = any(c.type == "static" for c in node.children)
        is_async = any(c.type == "async" for c in node.children)
        is_getter = any(c.type == "get" for c in node.children)
        is_setter = any(c.type == "set" for c in node.children)

        visibility = "private" if method_name.startswith("_") else "public"

        method_node = Node(
            id=method_id,
            kind=NodeKind.UNIT,
            name=method_name,
            span=span,
            parent_id=class_id,
            meta={
                "type": "method",
                "visibility": visibility,
                "is_async": is_async,
                "is_static": is_static,
                "is_getter": is_getter,
                "is_setter": is_setter,
                "parameters": params,
            },
        )
        nodes.append(method_node)
        edges.append((class_id, method_id, EdgeKind.DEFINES))

        # Extract calls within body
        body = self._find_child_by_type(node, "statement_block")
        if body:
            self._extract_calls(body, method_id, source_bytes, edges)

    def _extract_field(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        class_id: str,
    ) -> None:
        """Extract a class field."""
        name_node = self._find_child_by_type(node, "property_identifier")
        if not name_node:
            return

        field_name = self._get_node_text(name_node, source_bytes)
        field_id = f"{class_id}.{field_name}"

        span = self.extract_span(node)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        is_static = any(c.type == "static" for c in node.children)
        is_private = field_name.startswith("#") or field_name.startswith("_")

        field_node = Node(
            id=field_id,
            kind=NodeKind.VARIABLE,
            name=field_name,
            span=span,
            parent_id=class_id,
            meta={
                "type": "field",
                "visibility": "private" if is_private else "public",
                "is_static": is_static,
            },
        )
        nodes.append(field_node)

    def _extract_variable_declaration(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
        parent_id: Optional[str],
        is_exported: bool = False,
    ) -> None:
        """Extract variable declarations (const, let, var)."""
        for child in node.children:
            if child.type == "variable_declarator":
                name_node = self._find_child_by_type(child, "identifier")
                if not name_node:
                    continue

                var_name = self._get_node_text(name_node, source_bytes)

                if parent_id:
                    var_id = f"{parent_id}.{var_name}"
                else:
                    var_id = f"{file_id}:{var_name}"

                span = self.extract_span(child)
                if span:
                    span = SourceSpan(
                        file=file_id,
                        start_line=span.start_line,
                        end_line=span.end_line,
                    )

                # Check if it's a function expression or arrow function
                value = self._find_child_by_type(child, "arrow_function")
                if not value:
                    value = self._find_child_by_type(child, "function")

                if value:
                    # It's a function - create UNIT instead of VARIABLE
                    self._extract_function_expression(
                        child,
                        var_name,
                        file_path,
                        file_id,
                        source_bytes,
                        nodes,
                        edges,
                        parent_id,
                        is_exported,
                    )
                else:
                    # Regular variable
                    var_node = Node(
                        id=var_id,
                        kind=NodeKind.VARIABLE,
                        name=var_name,
                        span=span,
                        parent_id=parent_id,
                        meta={
                            "type": "variable",
                            "visibility": "public",
                            "exported": is_exported,
                        },
                    )
                    nodes.append(var_node)

    def _extract_function_expression(
        self,
        declarator: Any,
        func_name: str,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
        parent_id: Optional[str],
        is_exported: bool = False,
    ) -> None:
        """Extract a function expression or arrow function."""
        if parent_id:
            func_id = f"{parent_id}.{func_name}"
        else:
            func_id = f"{file_id}:{func_name}"

        span = self.extract_span(declarator)
        if span:
            span = SourceSpan(
                file=file_id,
                start_line=span.start_line,
                end_line=span.end_line,
            )

        # Check for arrow function or regular function
        arrow = self._find_child_by_type(declarator, "arrow_function")
        func = self._find_child_by_type(declarator, "function")
        func_node_ast = arrow or func

        is_async = False
        params = []

        if func_node_ast:
            is_async = any(c.type == "async" for c in func_node_ast.children)
            param_node = self._find_child_by_type(func_node_ast, "formal_parameters")
            if param_node:
                for param in param_node.children:
                    if param.type == "identifier":
                        params.append(self._get_node_text(param, source_bytes))

        func_node = Node(
            id=func_id,
            kind=NodeKind.UNIT,
            name=func_name,
            span=span,
            parent_id=parent_id,
            meta={
                "type": "arrow_function" if arrow else "function",
                "visibility": "public",
                "is_async": is_async,
                "parameters": params,
                "exported": is_exported,
            },
        )
        nodes.append(func_node)

        # Extract calls within body
        if func_node_ast:
            body = self._find_child_by_type(func_node_ast, "statement_block")
            if body:
                self._extract_calls(body, func_id, source_bytes, edges)

    def _extract_export(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
    ) -> None:
        """Extract an export statement."""
        for child in node.children:
            if child.type == "class_declaration":
                self._extract_class(
                    child, file_path, file_id, source_bytes, nodes, edges, None, True
                )
            elif child.type == "function_declaration":
                self._extract_function(
                    child, file_path, file_id, source_bytes, nodes, edges, None, True
                )
            elif child.type in ("lexical_declaration", "variable_declaration"):
                self._extract_variable_declaration(
                    child, file_path, file_id, source_bytes, nodes, edges, None, True
                )

    def _extract_assignment_expression(
        self,
        node: Any,
        file_path: Path,
        file_id: str,
        source_bytes: bytes,
        nodes: List[Node],
        edges: List[Tuple[str, str, EdgeKind]],
        parent_id: Optional[str],
    ) -> None:
        """Extract assignment expressions (e.g., module.exports = ...)."""
        left = node.children[0] if node.children else None
        if not left:
            return

        # Handle module.exports patterns
        if left.type == "member_expression":
            text = self._get_node_text(left, source_bytes)
            if "exports" in text:
                # Check if right side is a function or class
                right = node.children[-1] if len(node.children) > 1 else None
                if right and right.type == "class":
                    self._extract_class(
                        right,
                        file_path,
                        file_id,
                        source_bytes,
                        nodes,
                        edges,
                        None,
                        True,
                    )

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
                if func:
                    if func.type == "identifier":
                        callee = self._get_node_text(func, source_bytes)
                        edges.append((caller_id, callee, EdgeKind.CALLS))
                    elif func.type == "member_expression":
                        callee = self._get_node_text(func, source_bytes)
                        edges.append((caller_id, callee, EdgeKind.CALLS))

            # Recurse into children
            self._extract_calls(child, caller_id, source_bytes, edges)
