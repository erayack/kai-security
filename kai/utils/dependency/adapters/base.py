"""
Abstract base class for domain-specific security analysis adapters.

This enables Kai to support multiple languages/platforms (Solidity, Rust, Go, etc.)
by isolating domain-specific knowledge into pluggable adapters.

Adapters encapsulate:
- Pattern recognition (modifiers, guards, access checks)
- Actor role extraction and trust inference
- Suspicious function detection
- Privilege chain tracing
- Invariant generation

To add support for a new language, implement all abstract methods.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from ..graph import DependencyGraph
    from ..models import ActorRole, GuardIssue, WritePath

# Trust levels for actor roles
TrustLevel = Literal["High", "Medium", "Low", "None", "N/A"]


class DomainAdapter(ABC):
    """
    Abstract interface for domain-specific security knowledge.

    Each adapter encapsulates:
    - Role/permission patterns specific to the language/framework
    - Guard patterns (non-access-control modifiers/attributes)
    - Inline access check patterns for source code scanning
    - Entrypoint visibility keywords
    - Domain-specific vulnerability detection logic

    To add support for a new language:
    1. Create a new adapter class inheriting from DomainAdapter
    2. Implement all abstract methods with language-specific patterns
    3. Register the adapter in the factory or use dependency injection
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique identifier for this domain.

        Examples: "solidity", "rust", "go", "python"
        """
        ...

    @property
    @abstractmethod
    def frameworks(self) -> list[str]:
        """
        List of framework names this adapter handles.

        Used for auto-detection from MasterContext.framework.

        Examples:
            Solidity: ["foundry", "hardhat", "truffle", "brownie"]
            Rust: ["anchor", "cargo", "near"]
        """
        ...

    @abstractmethod
    def get_role_patterns(self) -> dict[str, tuple[str, TrustLevel]]:
        """
        Return mapping of modifier/attribute names to (role_name, trust_level).

        These patterns identify access control constructs in the code.

        Returns:
            Dict mapping pattern name -> (inferred role name, trust level)

        Examples:
            Solidity: {"onlyOwner": ("Owner", "High"), "onlyKeeper": ("Keeper", "Medium")}
            Rust: {"#[only_owner]": ("Owner", "High")}
        """
        ...

    @abstractmethod
    def get_guard_patterns(self) -> set[str]:
        """
        Return set of modifier/attribute names that are guards, NOT access control.

        These are filtered out when determining actor roles.

        Returns:
            Set of pattern names to exclude from role analysis

        Examples:
            Solidity: {"nonReentrant", "whenNotPaused", "whenPaused"}
            Rust: {"#[non_reentrant]"}
        """
        ...

    @abstractmethod
    def get_access_check_patterns(self) -> list[str]:
        """
        Return regex patterns for inline access control checks in source code.

        Used by heuristic scanning to find functions with inline guards
        (as opposed to modifier/attribute-based guards).

        Returns:
            List of regex patterns (raw strings recommended)

        Examples:
            Solidity: [r"\\bmsg\\.sender\\b", r"\\brequire\\s*\\(\\s*msg\\.sender"]
            Rust: [r"ctx\\.accounts\\.", r"require!\\s*\\("]
        """
        ...

    @abstractmethod
    def get_entrypoint_visibility(self) -> set[str]:
        """
        Return visibility keywords that indicate public entrypoints.

        Used to identify functions callable by external actors.

        Returns:
            Set of visibility keywords (lowercase)

        Examples:
            Solidity: {"public", "external"}
            Rust: {"pub"}
            Go: {""}  # Capitalized names are public
        """
        ...

    @abstractmethod
    def detect_domain_issues(
        self,
        graph: "DependencyGraph",
        analyzer: Any = None,
    ) -> list["GuardIssue"]:
        """
        Detect domain-specific security issues.

        This is where language-specific vulnerability patterns are checked.

        Args:
            graph: The dependency graph to analyze
            analyzer: Optional domain-specific analyzer (e.g., Slither for Solidity)

        Returns:
            List of GuardIssue findings

        Examples:
            Solidity: tx.origin checks, impossible guards, reentrancy patterns
            Rust: unsafe blocks in critical paths, unchecked arithmetic
        """
        ...

    # ---------------------------
    # Analysis Methods (Domain-Specific Logic)
    # ---------------------------

    @abstractmethod
    def extract_actor_roles(
        self,
        graph: "DependencyGraph",
    ) -> list["ActorRole"]:
        """
        Extract actor roles from the dependency graph.

        Analyzes access control patterns (modifiers, attributes, guards) to
        identify distinct actor roles and their trust levels.

        Args:
            graph: The dependency graph to analyze

        Returns:
            List of ActorRole objects describing each detected role

        Examples:
            Solidity: Groups functions by onlyOwner, onlyAdmin modifiers
            Rust: Groups by #[access_control] attributes
        """
        ...

    @abstractmethod
    def scan_suspicious_functions(
        self,
        graph: "DependencyGraph",
        source_code: dict[str, str] | None = None,
    ) -> list[dict]:
        """
        Scan for functions with potential access control issues.

        Flags public/external functions that either:
        - Have inline access checks (suggests missing modifier)
        - Write to state without protection

        Args:
            graph: The dependency graph to analyze
            source_code: Optional dict of file_path -> source code

        Returns:
            List of suspicious function dicts with keys:
            - function_name, function_id, contract_name, file_path
            - visibility, patterns_matched, has_modifier, reason, writes_state
        """
        ...

    @abstractmethod
    def trace_privilege_chains(
        self,
        graph: "DependencyGraph",
        max_depth: int = 4,
    ) -> list[dict]:
        """
        Trace cross-contract privilege chains.

        Finds call paths where privileged functions invoke functions
        in other contracts, potentially propagating trust.

        Args:
            graph: The dependency graph to analyze
            max_depth: Maximum chain length to trace

        Returns:
            List of privilege chain dicts with keys:
            - source_contract, source_function, source_role
            - target_contract, target_function
            - call_path, can_send_eth, edge_count
        """
        ...

    @abstractmethod
    def extract_var_names_from_rule(self, rule: str) -> list[str]:
        """
        Extract potential state variable names from an invariant rule string.

        Uses language-specific heuristics to identify variable references.

        Args:
            rule: Natural language or semi-formal invariant rule

        Returns:
            List of potential variable names

        Examples:
            Solidity: Extracts camelCase, snake_case, _prefixed identifiers
            Rust: Extracts snake_case identifiers
        """
        ...

    def infer_role_from_pattern(
        self, pattern: tuple[str, ...]
    ) -> tuple[str, TrustLevel]:
        """
        Infer role name and trust level from a modifier/attribute pattern.

        Default implementation uses get_role_patterns() for exact matching
        and prefix matching. Override for custom logic.

        Args:
            pattern: Tuple of modifier/attribute names

        Returns:
            (role_name, trust_level) tuple
        """
        role_patterns = self.get_role_patterns()

        for mod in pattern:
            if mod in role_patterns:
                return role_patterns[mod]
            # Try prefix matching for custom modifiers
            for known_mod, (role_name, trust) in role_patterns.items():
                # Handle "onlyX" style patterns
                if mod.lower().startswith(known_mod.lower().replace("only", "")):
                    custom_role = mod.replace("only", "").replace("Only", "")
                    return (custom_role, trust)

        # Default: unknown protected role
        return ("Protected", "Medium")


def get_adapter_for_framework(framework: str | None) -> DomainAdapter:
    """
    Factory function to get the appropriate adapter for a framework.

    Args:
        framework: Framework name from MasterContext (e.g., "foundry", "anchor")

    Returns:
        Appropriate DomainAdapter instance

    Raises:
        ValueError: If no adapter supports the framework
    """
    # Import here to avoid circular imports
    from .solidity import SolidityAdapter

    # Registry of adapters
    adapters: list[type[DomainAdapter]] = [
        SolidityAdapter,
        # Add more adapters here as they're implemented:
        # RustAdapter,
        # GoAdapter,
    ]

    if framework is None:
        # Default to Solidity for backwards compatibility
        return SolidityAdapter()

    framework_lower = framework.lower()
    for adapter_cls in adapters:
        adapter = adapter_cls()
        if framework_lower in [f.lower() for f in adapter.frameworks]:
            return adapter

    # Fallback to Solidity (most common case)
    return SolidityAdapter()
