"""
Solidity-specific domain adapter for the GraphQueryEngine.
"""

from typing import TYPE_CHECKING, Dict, List, Optional

from .base import DomainAdapter
from ..models import Node, NodeKind

if TYPE_CHECKING:
    from ..graph import DependencyGraph


class SolidityAdapter(DomainAdapter):
    """
    Solidity-specific implementation of DomainAdapter.

    Provides domain knowledge for:
    - Symbol resolution (contracts, functions, variables)
    - Entrypoint detection (public/external)
    - Test file identification
    """

    @property
    def name(self) -> str:
        return "solidity"

    def get_domain_mapping(self) -> Dict[str, str]:
        """Return Solidity-specific NodeKind mappings."""
        return {
            "contract": "CONTAINER",
            "interface": "CONTAINER",
            "library": "CONTAINER",
            "function": "UNIT",
            "modifier": "INTERFACE",
            "state_variable": "VARIABLE",
            "struct": "TYPE_DEF",
            "enum": "TYPE_DEF",
            "event": "EVENT",
        }

    def is_public_entrypoint(self, node: Node) -> bool:
        """Check if a node is a public entrypoint."""
        if node.kind != NodeKind.UNIT:
            return False

        visibility = (node.meta.get("visibility") or "").lower()
        if visibility not in ("public", "external"):
            return False

        # Exclude constructors, fallback, receive
        if node.meta.get("is_constructor"):
            return False
        if node.meta.get("is_fallback"):
            return False
        if node.meta.get("is_receive"):
            return False

        return True

    def is_state_variable(self, node: Node) -> bool:
        """Check if a node is a state variable."""
        return node.kind == NodeKind.VARIABLE

    def is_test_file(self, file_path: str) -> bool:
        """Check if a file path looks like a test file."""
        p = file_path.lower()
        return (
            "/test/" in p
            or "/tests/" in p
            or p.endswith(".t.sol")
            or p.endswith("_test.sol")
            or p.endswith(".spec.sol")
        )

    def is_library_file(self, file_path: str) -> bool:
        """
        Check if a file path is from an external library.

        Identifies common Solidity dependency patterns:
        - node_modules/ (npm packages)
        - lib/ (forge dependencies)
        - @openzeppelin, @solmate, etc. (namespaced packages)
        - forge-std (foundry standard library)
        """
        p = file_path.lower()
        library_indicators = [
            # Dependency directories
            "node_modules/",
            "/lib/",
            # Common namespaced packages
            "@openzeppelin",
            "@solmate",
            "@rari-capital",
            "@uniswap",
            "@aave",
            "@chainlink",
            "@compound",
            # Foundry/forge
            "forge-std/",
            "ds-test/",
            # Other common libs
            "solady/",
            "solmate/",
            "openzeppelin-contracts/",
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
            symbol: The symbol name to resolve (e.g., "withdraw", "Vault")
            graph: The dependency graph to search
            scope: Optional container ID to limit search scope

        Returns:
            List of matching node IDs, ordered by relevance
        """
        candidate_ids: List[str] = []

        # Check if symbol is already a node ID
        if name in context_graph._nodes:
            return [name]

        # If scope specified, also include inherited contracts
        valid_parents: Optional[set] = None
        if scope:  # Treat empty string same as None
            valid_parents = self._get_scope_with_inheritance(context_graph, scope)

        # Search by name across all nodes
        for nid in context_graph._nodes:
            node = context_graph._nodes[nid]

            # Special handling for "constructor" - Slither stores it with empty name
            if name == "constructor" and node.kind == NodeKind.UNIT:
                if node.meta.get("is_constructor"):
                    if valid_parents is None or node.parent_id in valid_parents:
                        candidate_ids.append(nid)
                    continue

            # Match by name
            if node.name == name:
                # If scope specified, check parent (including inherited)
                if valid_parents is not None:
                    if node.parent_id not in valid_parents:
                        continue
                candidate_ids.append(nid)

            # Also check signature for functions
            if node.kind == NodeKind.UNIT:
                sig = node.meta.get("signature", "")
                if sig and sig.startswith(f"{name}("):
                    if valid_parents is None or node.parent_id in valid_parents:
                        candidate_ids.append(nid)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for cid in candidate_ids:
            if cid not in seen:
                seen.add(cid)
                unique.append(cid)

        return unique

    def _get_scope_with_inheritance(
        self, context_graph: "DependencyGraph", scope: str
    ) -> set:
        """
        Get a set containing the scope and all contracts it inherits from.

        Recursively follows INHERITS edges to find all ancestor contracts.
        """
        from kai.utils.dependency.models import EdgeKind

        # First, resolve scope name to actual node ID if it's not already one
        scope_node_id = scope
        if scope not in context_graph._nodes:
            # Search for a container node with matching name
            for nid, node in context_graph._nodes.items():
                if node.kind == NodeKind.CONTAINER and node.name == scope:
                    scope_node_id = nid
                    break

        valid_parents = {scope_node_id}
        to_visit = [scope_node_id]

        while to_visit:
            current = to_visit.pop()
            # Get contracts that 'current' inherits from (outgoing INHERITS edges)
            try:
                inherited = context_graph.neighbors(
                    current, edge_kinds={EdgeKind.INHERITS}, direction="out"
                )
                for parent_id in inherited:
                    if parent_id not in valid_parents:
                        valid_parents.add(parent_id)
                        to_visit.append(parent_id)
            except Exception:
                # Node doesn't exist or no edges - continue
                pass

        return valid_parents

    def get_entrypoint_visibility(self) -> List[str]:
        """Return visibility levels that indicate public entrypoints."""
        return ["public", "external"]

    def get_role_patterns(self) -> Dict[str, List[str]]:
        """Return modifier patterns that indicate roles."""
        return {
            "Owner": ["onlyOwner", "onlyAdmin"],
            "Admin": ["onlyAdmin", "onlyRole"],
            "Operator": ["onlyOperator", "onlyKeeper"],
            "Minter": ["onlyMinter"],
            "Pauser": ["whenNotPaused", "onlyPauser"],
            "Guardian": ["onlyGuardian"],
        }

    def get_guard_patterns(self) -> List[str]:
        """Return common guard/modifier patterns (both auth and non-auth)."""
        return [
            "onlyOwner",
            "onlyAdmin",
            "onlyRole",
            "whenNotPaused",
            "nonReentrant",
            "initializer",
            "onlyProxy",
        ]

    def get_non_auth_guards(self) -> List[str]:
        """
        Return guard patterns that are NOT access control (don't indicate a role).

        These protect against reentrancy, pausing, initialization, etc.
        but don't restrict WHO can call the function.
        """
        return [
            "nonReentrant",
            "noReentrancy",
            "whenNotPaused",
            "whenPaused",
            "initializer",
            "reinitializer",
            "onlyInitializing",
            "onlyProxy",
            "onlyDelegateCall",
            "noDelegateCall",
        ]

    def is_non_auth_guard(self, modifier_name: str) -> bool:
        """Check if a modifier is a non-auth guard (reentrancy, pause, etc.)."""
        non_auth = self.get_non_auth_guards()
        return modifier_name in non_auth

    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        """
        Deterministically assign trust level based on modifier patterns.

        Returns: "high", "medium", "low", "none", "review_required"
        """
        if not modifier_names:
            return "none"

        # High trust patterns (full admin control)
        high_trust = {"onlyOwner", "onlyAdmin", "requiresAuth", "auth"}
        # Medium trust patterns (operational roles)
        medium_trust = {
            "onlyRole",
            "onlyKeeper",
            "onlyOperator",
            "onlyMinter",
            "onlyGuardian",
        }
        # Low trust patterns
        low_trust = {"onlyWhitelisted", "onlyAllowed"}

        for mod in modifier_names:
            if mod in high_trust:
                return "high"

        for mod in modifier_names:
            if mod in medium_trust:
                return "medium"

        for mod in modifier_names:
            if mod in low_trust:
                return "low"

        # Unknown modifier pattern - needs review
        return "review_required"
