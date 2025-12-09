"""
Base builder interface for language-agnostic graph construction.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Optional

from ..graph import DependencyGraph


class BaseBuilder(ABC):
    """
    Abstract base for language-specific graph builders.

    Each builder maps language constructs to generic NodeKind/EdgeKind:
        - CONTAINER: Contract (Sol), Module (Rust), Class (Py)
        - UNIT: Function (Sol), Method (Py), Instruction (Anchor)
        - INTERFACE: Modifier (Sol), Attribute (Rust), Decorator (Py)
        - VARIABLE: StateVar (Sol), Account (Rust), Global (Py)
        - TYPE_DEF: Struct, Enum, Typedef
    """

    @abstractmethod
    def build(self, source: Any, **kwargs) -> DependencyGraph:
        """
        Build a DependencyGraph from the source.

        Args:
            source: Path to project, analysis object, or other source
            **kwargs: Builder-specific options

        Returns:
            Populated DependencyGraph with nodes and edges
        """
        pass

    @abstractmethod
    def extract_span(self, obj: Any) -> Optional[dict]:
        """
        Extract source span from a language-specific object.

        Returns:
            Dict with {file, start_line, end_line, start_col, end_col} or None
        """
        pass

    @property
    @abstractmethod
    def language(self) -> str:
        """Return the language this builder handles (e.g., 'solidity', 'rust')."""
        pass
