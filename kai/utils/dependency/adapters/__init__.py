"""
Domain adapters for language/framework-specific security analysis.

This module provides pluggable adapters that encapsulate domain-specific
knowledge, enabling Kai to support multiple languages and frameworks.

Currently supported:
- Solidity (Foundry, Hardhat, Truffle, Brownie)

To add support for a new language:
1. Create a new adapter inheriting from DomainAdapter
2. Implement all abstract methods with language-specific patterns
3. Add the adapter to get_adapter_for_framework() registry

Usage:
    from kai.utils.dependency.adapters import DomainAdapter, SolidityAdapter, get_adapter_for_framework

    # Explicit adapter
    adapter = SolidityAdapter()

    # Auto-detect from framework
    adapter = get_adapter_for_framework("foundry")  # Returns SolidityAdapter

    # Use in analysis
    roles = get_actor_roles(graph, adapter=adapter)
"""

from .base import DomainAdapter
from .solidity import SolidityAdapter

__all__ = [
    # Abstract base
    "DomainAdapter",
    # Factory
    # Concrete adapters
    "SolidityAdapter",
]
