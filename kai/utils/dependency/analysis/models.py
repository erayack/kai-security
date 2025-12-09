"""
kai/analysis/models.py
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Literal

# Re-use existing NodeKind/EdgeKind from your graph.py
from ..models import NodeKind, EdgeKind, SourceSpan


@dataclass(frozen=True)
class NodeRef:
    """
    A deterministic handle for a code element.
    Agents must hold these IDs, never raw strings.
    """

    id: str
    kind: NodeKind
    name: str
    container: Optional[str]  # e.g., "Vault" (context)
    signature: Optional[str]  # e.g., "deposit(uint256)"
    file: Optional[str]  # For quick filtering


@dataclass
class ContextSlice:
    """A justified subgraph for the agent's working memory."""

    nodes: List[NodeRef]
    files: List[str]
    # "Why is this node here?" (e.g. "Called by seed", "Type Definition")
    justification: Dict[str, str]


@dataclass
class EvidencePack:
    """
    The 'Receipt'.
    The Verifier uses this to reproduce the agent's finding without searching.
    """

    item: str  # Description of the finding
    trace: List[Dict[str, Any]]  # The exact sequence of nodes
    edges: List[Dict[str, Any]]  # Metadata proving the connections (call sites)
    snippets: Dict[str, str]  # The exact code backing the trace
