from abc import ABC, abstractmethod
from typing import List, Dict, Optional, TYPE_CHECKING
from ..models import Node

if TYPE_CHECKING:
    from ..graph import DependencyGraph


class DomainAdapter(ABC):
    """
    Defines how generic graph nodes map to language-specific security concepts.
    """

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def get_domain_mapping(self) -> Dict[str, str]:
        """Map generic NodeKinds to domain terms (e.g. CONTAINER -> 'Contract')."""
        pass

    @abstractmethod
    def is_public_entrypoint(self, node: Node) -> bool:
        """
        Is this node callable by an external attacker?
        Solidity: public/external visibility.
        Rust: pub fn in generic module / instruction handler.
        """
        pass

    @abstractmethod
    def is_state_variable(self, node: Node) -> bool:
        """Does this node represent persistent state?"""
        pass

    @abstractmethod
    def is_test_file(self, file_path: str) -> bool:
        """Is this a test/mock file?"""
        pass

    @abstractmethod
    def is_library_file(self, file_path: str) -> bool:
        """
        Is this file from an external library (not protocol code)?
        E.g., OpenZeppelin, Solmate, forge-std, node_modules, lib/
        """
        pass

    @abstractmethod
    def resolve_symbol(
        self, name: str, context_graph: "DependencyGraph", scope: Optional[str] = None
    ) -> List[str]:
        """
        Resolve a user-provided string (e.g. "deposit") to Node IDs.
        Handles fuzzy matching or language-specific overloading.

        Args:
            name: Symbol name to resolve
            context_graph: The dependency graph to search
            scope: Optional container ID to limit search scope
        """
        pass

    @abstractmethod
    def is_non_auth_guard(self, modifier_name: str) -> bool:
        """
        Is this modifier a non-auth guard (e.g., reentrancy, pause)?
        These should be filtered out when clustering by access control.
        """
        pass

    @abstractmethod
    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        """
        Determine trust level based on modifier patterns.
        Returns: "high", "medium", "low", "none", or "review_required"
        """
        pass
