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

        # Search by name across all nodes
        for nid in context_graph._nodes:
            node = context_graph._nodes[nid]

            # Match by name
            if node.name == name:
                # If scope specified, check parent
                if scope is not None:
                    if node.parent_id != scope:
                        continue
                candidate_ids.append(nid)

            # Also check signature for functions
            if node.kind == NodeKind.UNIT:
                sig = node.meta.get("signature", "")
                if sig and sig.startswith(f"{name}("):
                    if scope is None or node.parent_id == scope:
                        candidate_ids.append(nid)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for cid in candidate_ids:
            if cid not in seen:
                seen.add(cid)
                unique.append(cid)

        return unique

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
        """Return common guard/modifier patterns."""
        return [
            "onlyOwner",
            "onlyAdmin",
            "onlyRole",
            "whenNotPaused",
            "nonReentrant",
            "initializer",
            "onlyProxy",
        ]
