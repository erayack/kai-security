"""
JavaScript-specific domain adapter for the GraphQueryEngine.

Provides domain knowledge for JavaScript/Node.js security analysis:
- Entrypoint detection (Express/Koa routes, exports, event handlers)
- Library file identification (node_modules)
- Trust level patterns
"""

from typing import TYPE_CHECKING, Dict, List, Optional

from .base import DomainAdapter
from ..models import Node, NodeKind

if TYPE_CHECKING:
    from ..graph import DependencyGraph


class JavaScriptAdapter(DomainAdapter):
    """
    JavaScript-specific implementation of DomainAdapter.

    Provides domain knowledge for:
    - Symbol resolution (modules, classes, functions)
    - Entrypoint detection (routes, exports, event handlers)
    - Test file identification
    - Library detection
    """

    @property
    def name(self) -> str:
        return "javascript"

    def get_domain_mapping(self) -> Dict[str, str]:
        """Return JavaScript-specific NodeKind mappings."""
        return {
            "class": "CONTAINER",
            "module": "CONTAINER",
            "function": "UNIT",
            "method": "UNIT",
            "arrow_function": "UNIT",
            "async_function": "UNIT",
            "variable": "VARIABLE",
            "field": "VARIABLE",
        }

    def is_public_entrypoint(self, node: Node) -> bool:
        """
        Check if a node is a public entrypoint.

        Entrypoints in JavaScript include:
        - Express/Koa/Fastify route handlers
        - Exported functions
        - Event handlers (on*, handle*)
        """
        if node.kind != NodeKind.UNIT:
            return False

        name = node.name
        meta = node.meta

        # Check if exported
        if meta.get("exported", False):
            return True

        # Check for route handler patterns
        route_patterns = {
            "get", "post", "put", "delete", "patch",
            "use", "all", "route",
        }
        if name.lower() in route_patterns:
            return True

        # Check for event handler patterns
        if name.startswith("on") or name.startswith("handle"):
            return True

        # Check visibility - private methods start with _ or #
        visibility = meta.get("visibility", "")
        if visibility == "private":
            return False

        if name.startswith("_") or name.startswith("#"):
            return False

        # Public methods/functions are entrypoints
        return True

    def is_state_variable(self, node: Node) -> bool:
        """Check if a node is a state variable."""
        if node.kind != NodeKind.VARIABLE:
            return False

        var_type = node.meta.get("type", "")
        return var_type in ("variable", "field")

    def is_test_file(self, file_path: str) -> bool:
        """Check if a file path looks like a test file."""
        p = file_path.lower()
        return (
            "/test/" in p
            or "/tests/" in p
            or "/__tests__/" in p
            or ".test." in p
            or ".spec." in p
            or "_test." in p
            or "_spec." in p
            or "/test-" in p
        )

    def is_library_file(self, file_path: str) -> bool:
        """
        Check if a file path is from an external library.

        Identifies common JavaScript dependency patterns.
        """
        p = file_path.lower()
        library_indicators = [
            # npm modules
            "node_modules/",
            "/node_modules/",
            # TypeScript definitions
            "@types/",
            "/@types/",
            # Common library directories
            "/vendor/",
            "/bower_components/",
            # Build output
            "/dist/",
            "/build/",
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
            name: Symbol name to resolve
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
        """Check if this is a non-auth guard pattern."""
        non_auth_patterns = {
            # Rate limiting
            "ratelimit",
            "ratelimiter",
            "throttle",
            # Caching
            "cache",
            "memoize",
            # Validation
            "validate",
            "sanitize",
            # Logging
            "log",
            "logger",
            "morgan",
            # Error handling
            "errorhandler",
            "asynchandler",
            # Cors
            "cors",
            # Compression
            "compression",
            # Body parsing
            "bodyparser",
            "json",
            "urlencoded",
        }
        return modifier_name.lower() in non_auth_patterns

    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        """
        Determine trust level based on middleware/decorator patterns.

        Returns: "high", "medium", "low", "none", "review_required"
        """
        if not modifier_names:
            return "none"

        # High trust patterns (admin/auth)
        high_trust = {
            "isadmin",
            "requireadmin",
            "adminonly",
            "superuser",
        }

        # Medium trust patterns (authenticated)
        medium_trust = {
            "isauthenticated",
            "requireauth",
            "passport",
            "jwt",
            "jwtauth",
            "authenticate",
            "ensureloggedin",
        }

        # Low trust patterns (basic)
        low_trust = {
            "csrf",
            "helmet",
            "xss",
        }

        for mod in modifier_names:
            mod_lower = mod.lower().replace("-", "").replace("_", "")
            if mod_lower in high_trust:
                return "high"

        for mod in modifier_names:
            mod_lower = mod.lower().replace("-", "").replace("_", "")
            if mod_lower in medium_trust:
                return "medium"

        for mod in modifier_names:
            mod_lower = mod.lower().replace("-", "").replace("_", "")
            if mod_lower in low_trust:
                return "low"

        return "review_required"

    def get_entrypoint_visibility(self) -> List[str]:
        """Return visibility levels that indicate public entrypoints."""
        return ["public", "exported"]

    def get_role_patterns(self) -> Dict[str, List[str]]:
        """Return patterns that indicate roles."""
        return {
            "Admin": ["isAdmin", "requireAdmin", "adminOnly"],
            "Authenticated": ["isAuthenticated", "requireAuth", "ensureLoggedIn"],
            "Permission": ["hasPermission", "checkPermission", "authorize"],
        }

    def get_guard_patterns(self) -> List[str]:
        """Return common guard/middleware patterns."""
        return [
            "authenticate",
            "authorize",
            "requireAuth",
            "isAuthenticated",
            "passport",
            "jwt",
            "rateLimit",
        ]
