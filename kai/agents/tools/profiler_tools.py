"""
Read-only tools for the ProfilerAgent.
"""

from typing import Dict, Any
from kai.agents.tools.tools import (
    read_file,
    list_files,
    dependency_graph_resolve,
    dependency_graph_loc,
    dependency_graph_snippet,
    dependency_graph_neighbors,
    dependency_graph_public_entrypoints,
    dependency_graph_protocol_entrypoints,
    dependency_graph_slice,
    dependency_graph_explain,
    _get_current_agent,
)
from kai.schemas import ProtocolManifesto

__all__ = [
    "read_file",
    "list_files",
    "dependency_graph_resolve",
    "dependency_graph_loc",
    "dependency_graph_snippet",
    "dependency_graph_neighbors",
    "dependency_graph_public_entrypoints",
    "dependency_graph_protocol_entrypoints",
    "dependency_graph_slice",
    "dependency_graph_explain",
    "register_protocol_manifesto",
]


def register_protocol_manifesto(manifesto: Dict[str, Any]) -> Dict[str, Any]:
    """
    Register the final ProtocolManifesto for the repository.
    Call this tool once you have analyzed the protocol and are ready to submit your findings.

    The manifesto dict must follow the ProtocolManifesto schema:
    - name (str): Protocol name.
    - purpose (str): High-level purpose.
    - description (str): Detailed description.
    - domain (str): Protocol domain (e.g. "Lending", "DEX").
    - programming_languages (List[str]): Languages used.
    - intended_users (List[str]): Types of users.
    - key_concepts (Dict[str, str]): Domain concepts and their definitions.
    - key_features (List[dict]): List of features. Each feature dict:
        - name (str): Feature name.
        - description (str): Feature description.
        - actors (List[str]): Roles involved in this feature.

    Example:
        register_protocol_manifesto({
            "name": "MyProtocol",
            "purpose": "Decentralized lending",
            "description": "...",
            "domain": "Lending",
            "programming_languages": ["Solidity"],
            "intended_users": ["Liquidity Providers", "Borrowers"],
            "key_concepts": {"LTV": "Loan to Value ratio"},
            "key_features": [
                {"name": "Borrowing", "description": "...", "actors": ["Borrower"]}
            ]
        })
    """
    agent = _get_current_agent()
    if agent is None:
        return {"registered": False, "error": "No active agent context found."}

    try:
        # Validate using Pydantic model
        pm = ProtocolManifesto(**manifesto)
        # Store on agent instance
        agent._registered_protocol_manifesto = pm
        return {
            "registered": True,
            "message": "ProtocolManifesto registered successfully. You may now stop.",
        }
    except Exception as e:
        return {"registered": False, "error": f"Validation failed: {str(e)}"}
