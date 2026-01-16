from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, TYPE_CHECKING

from ..models import Node

if TYPE_CHECKING:
    from ..graph import DependencyGraph


@dataclass
class LensDefinition:
    """
    Domain-agnostic lens definition for invariant generation.

    Each lens focuses on a specific security concern. The LLM uses
    the description and prompt_template to categorize functions and
    generate focused invariants.
    """

    name: str
    description: str
    invariant_types: List[str]

    # Lens-specific prompt template for LLM invariant generation
    prompt_template: str = ""

    # Mandatory checklist items - used for coverage verification
    checklist: List[str] = field(default_factory=list)


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

    # =========================================================================
    # Lens-based invariant generation methods
    # =========================================================================

    @abstractmethod
    def get_lens_definitions(self) -> List[LensDefinition]:
        """
        Return lens definitions for this domain.

        Each lens defines a focused security concern with:
        - name: Identifier for the lens
        - description: What security concerns this lens covers
        - invariant_types: Which InvariantType values this lens generates
        - prompt_template: Lens-specific LLM prompt
        - checklist: Mandatory coverage items

        The LLM uses these definitions to:
        1. Categorize functions into lens buckets
        2. Generate focused invariants per lens

        Returns:
            List of LensDefinition for this domain
        """
        pass

    @abstractmethod
    def get_function_metadata_extractors(self) -> Dict[str, Callable]:
        """
        Return extractors for function metadata.

        Each extractor populates domain-specific metadata on functions.
        This metadata is passed to the LLM to help with bucketing and
        invariant generation.

        Returns:
            Dict mapping field_name -> callable(node, graph) -> value

        Example for Solidity:
            {
                "is_payable": lambda node, graph: node.meta.get("is_payable", False),
                "visibility": lambda node, graph: node.meta.get("visibility", ""),
            }
        """
        pass
