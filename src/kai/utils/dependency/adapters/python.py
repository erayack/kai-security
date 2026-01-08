"""
Python-specific domain adapter for the GraphQueryEngine.

Provides domain knowledge for Python security analysis:
- Entrypoint detection (Flask/Django routes, CLI decorators, public functions)
- Library file identification
- Trust level patterns (decorators)
"""

from typing import TYPE_CHECKING, Dict, List, Optional

from .base import DomainAdapter
from ..models import Node, NodeKind

if TYPE_CHECKING:
    from ..graph import DependencyGraph


class PythonAdapter(DomainAdapter):
    """
    Python-specific implementation of DomainAdapter.

    Provides domain knowledge for:
    - Symbol resolution (modules, classes, functions)
    - Entrypoint detection (routes, CLI handlers, public functions)
    - Test file identification
    - Library detection
    """

    @property
    def name(self) -> str:
        return "python"

    def get_domain_mapping(self) -> Dict[str, str]:
        """Return Python-specific NodeKind mappings."""
        return {
            "class": "CONTAINER",
            "module": "CONTAINER",
            "function": "UNIT",
            "method": "UNIT",
            "async_function": "UNIT",
            "decorator": "INTERFACE",
            "global_variable": "VARIABLE",
            "class_attribute": "VARIABLE",
        }

    def is_public_entrypoint(self, node: Node) -> bool:
        """
        Check if a node is a public entrypoint.

        Entrypoints in Python include:
        - Flask/Django/FastAPI route handlers (decorated)
        - CLI entry points (click, argparse decorators)
        - Public functions not starting with _
        """
        if node.kind != NodeKind.UNIT:
            return False

        # Check visibility
        name = node.name
        if name.startswith("_") and not name.startswith("__"):
            return False  # Private by convention

        # Skip dunder methods except __init__ and __call__
        if name.startswith("__") and name.endswith("__"):
            if name not in ("__init__", "__call__"):
                return False

        # Check for route decorators
        decorators = node.meta.get("decorators", [])
        route_decorators = {
            # Flask
            "route", "get", "post", "put", "delete", "patch",
            "app.route", "blueprint.route",
            # FastAPI
            "api_route", "router.get", "router.post",
            # Django
            "api_view", "action",
            # Click/CLI
            "command", "group", "click.command",
        }
        for dec in decorators:
            dec_lower = dec.lower()
            if any(rd in dec_lower for rd in route_decorators):
                return True

        # Public function without _ prefix is considered entrypoint
        visibility = node.meta.get("visibility", "")
        if visibility == "public":
            return True

        return not name.startswith("_")

    def is_state_variable(self, node: Node) -> bool:
        """Check if a node is a state variable."""
        if node.kind != NodeKind.VARIABLE:
            return False

        var_type = node.meta.get("type", "")
        return var_type in ("global", "class_attribute")

    def is_test_file(self, file_path: str) -> bool:
        """Check if a file path looks like a test file."""
        p = file_path.lower()
        return (
            "/test/" in p
            or "/tests/" in p
            or p.endswith("_test.py")
            or p.endswith("test_.py")
            or "test_" in p.split("/")[-1]
            or "/conftest.py" in p
            or "_test.py" in p
        )

    def is_library_file(self, file_path: str) -> bool:
        """
        Check if a file path is from an external library.

        Identifies common Python dependency patterns.
        """
        p = file_path.lower()
        library_indicators = [
            # Virtual environments
            "/site-packages/",
            "/dist-packages/",
            "/.venv/",
            "/venv/",
            "/virtualenv/",
            # Common package prefixes
            "/lib/python",
            # Standard library paths
            "/usr/lib/python",
            "/usr/local/lib/python",
            # Package managers
            "/.local/lib/",
        ]
        return any(indicator in p for indicator in library_indicators)

    def resolve_symbol(
        self,
        name: str,
        context_graph: "DependencyGraph",
        scope: Optional[str] = None,
    ) -> List[str]:
        """
        Resolve a symbol name to node IDs in the dependency graph.

        Args:
            name: Symbol name to resolve (e.g., "process_data", "UserModel")
            context_graph: The dependency graph to search
            scope: Optional container ID to limit search scope

        Returns:
            List of matching node IDs
        """
        candidate_ids: List[str] = []

        # Check if symbol is already a node ID
        if name in context_graph._nodes:
            return [name]

        # If scope specified, include methods of the class
        valid_parents: Optional[set] = None
        if scope:
            valid_parents = {scope}
            # Could expand to include parent classes if inheritance edges exist

        # Search by name across all nodes
        for nid, node in context_graph._nodes.items():
            if node.name == name:
                if valid_parents is not None:
                    if node.parent_id not in valid_parents:
                        continue
                candidate_ids.append(nid)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for cid in candidate_ids:
            if cid not in seen:
                seen.add(cid)
                unique.append(cid)

        return unique

    def is_non_auth_guard(self, modifier_name: str) -> bool:
        """Check if a decorator is a non-auth guard."""
        non_auth_decorators = {
            # Rate limiting
            "ratelimit",
            "rate_limit",
            "throttle",
            # Caching
            "cache",
            "cached",
            "memoize",
            "lru_cache",
            # Validation
            "validate",
            "validator",
            # Logging/monitoring
            "log",
            "trace",
            "profile",
            # Async
            "async_to_sync",
            "sync_to_async",
            # Other non-auth
            "deprecated",
            "staticmethod",
            "classmethod",
            "property",
            "abstractmethod",
        }
        return modifier_name.lower() in non_auth_decorators

    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        """
        Determine trust level based on decorator patterns.

        Returns: "high", "medium", "low", "none", "review_required"
        """
        if not modifier_names:
            return "none"

        # High trust patterns (admin/auth required)
        high_trust = {
            "admin_required",
            "superuser_required",
            "staff_required",
            "permission_required",
            "login_required",
            "authenticated",
        }

        # Medium trust patterns (some auth)
        medium_trust = {
            "permission_classes",
            "has_permission",
            "is_authenticated",
            "jwt_required",
            "token_required",
        }

        # Low trust patterns (basic checks)
        low_trust = {
            "csrf_protect",
            "require_http_methods",
        }

        for mod in modifier_names:
            mod_lower = mod.lower()
            if any(ht in mod_lower for ht in high_trust):
                return "high"

        for mod in modifier_names:
            mod_lower = mod.lower()
            if any(mt in mod_lower for mt in medium_trust):
                return "medium"

        for mod in modifier_names:
            mod_lower = mod.lower()
            if any(lt in mod_lower for lt in low_trust):
                return "low"

        # Unknown decorator pattern
        return "review_required"

    def get_entrypoint_visibility(self) -> List[str]:
        """Return visibility levels that indicate public entrypoints."""
        return ["public"]

    def get_role_patterns(self) -> Dict[str, List[str]]:
        """Return decorator patterns that indicate roles."""
        return {
            "Admin": ["admin_required", "superuser_required", "staff_required"],
            "Authenticated": ["login_required", "authenticated", "jwt_required"],
            "Permission": ["permission_required", "has_permission"],
        }

    def get_guard_patterns(self) -> List[str]:
        """Return common guard/decorator patterns."""
        return [
            "login_required",
            "permission_required",
            "admin_required",
            "authenticated",
            "rate_limit",
            "cache",
        ]
