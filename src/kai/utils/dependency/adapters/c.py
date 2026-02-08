"""
C-specific domain adapter for the GraphQueryEngine.

Provides domain knowledge for C security analysis:
- Entrypoint detection (main, non-static functions, header declarations)
- Library file identification (system headers, third-party)
- Trust level patterns
"""

from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from .base import DomainAdapter, LensDefinition
from ..models import Node, NodeKind

if TYPE_CHECKING:
    from ..graph import DependencyGraph


class CAdapter(DomainAdapter):
    """
    C-specific implementation of DomainAdapter.

    Provides domain knowledge for:
    - Symbol resolution (functions, structs, globals)
    - Entrypoint detection (main, exported functions)
    - Test file identification
    - Library detection
    """

    @property
    def name(self) -> str:
        return "c"

    def get_domain_mapping(self) -> Dict[str, str]:
        """Return C-specific NodeKind mappings."""
        return {
            "struct": "CONTAINER",
            "union": "CONTAINER",
            "function": "UNIT",
            "macro": "INTERFACE",
            "global": "VARIABLE",
            "enum": "TYPE_DEF",
            "typedef": "TYPE_DEF",
        }

    def is_public_entrypoint(self, node: Node) -> bool:
        """
        Check if a node is a public entrypoint.

        Entrypoints in C include:
        - main() function
        - Non-static functions (visible to other translation units)
        - Functions declared in header files
        """
        if node.kind != NodeKind.UNIT:
            return False

        name = node.name
        meta = node.meta

        # main() is always an entrypoint
        if name == "main":
            return True

        # Static functions are not public
        if meta.get("is_static", False):
            return False

        # Functions starting with _ are typically internal
        if name.startswith("_"):
            return False

        # Check visibility from meta
        visibility = meta.get("visibility", "public")
        if visibility == "private":
            return False

        # Non-static functions are public entrypoints
        return True

    def is_state_variable(self, node: Node) -> bool:
        """Check if a node is a state variable."""
        if node.kind != NodeKind.VARIABLE:
            return False

        var_type = node.meta.get("type", "")
        # Global and static variables are state
        return var_type == "global" or node.meta.get("is_static", False)

    def is_test_file(self, file_path: str) -> bool:
        """Check if a file path looks like a test file."""
        p = file_path.lower()
        return (
            "/test/" in p
            or "/tests/" in p
            or "test_" in p.split("/")[-1]
            or "_test." in p
            or "/t/" in p  # Common in some projects
            or "/check_" in p
            or "check_" in p.split("/")[-1]
        )

    def is_library_file(self, file_path: str) -> bool:
        """
        Check if a file path is from an external library.

        Identifies common C library/dependency patterns.
        """
        p = file_path.lower()
        library_indicators = [
            # System headers
            "/usr/include/",
            "/usr/local/include/",
            # Common library directories
            "/lib/",
            "/libs/",
            "/third_party/",
            "/third-party/",
            "/vendor/",
            "/external/",
            "/deps/",
            # Build directories
            "/build/",
            "/cmake-build",
            # Package managers
            "/vcpkg/",
            "/conan/",
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
            scope: Optional scope to limit search

        Returns:
            List of matching node IDs
        """
        candidate_ids: List[str] = []

        # Check if symbol is already a node ID
        if name in context_graph._nodes:
            return [name]

        # Search by name across all nodes
        for nid, node in context_graph._nodes.items():
            if node.name == name:
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
        """
        Check if this is a non-auth guard pattern.

        In C, this would be checking for non-auth macros/attributes.
        """
        non_auth_patterns = {
            # Compiler attributes
            "unused",
            "deprecated",
            "warn_unused_result",
            "nonnull",
            "noreturn",
            # Common macros
            "likely",
            "unlikely",
            "inline",
            "always_inline",
            "noinline",
            # Assert-like
            "assert",
            "static_assert",
            # Annotations
            "const",
            "restrict",
            "volatile",
        }
        return modifier_name.lower() in non_auth_patterns

    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        """
        Determine trust level based on patterns.

        In C, this is less applicable but can check for things like
        static (file-local) or specific naming conventions.

        Returns: "high", "medium", "low", "none", "review_required"
        """
        if not modifier_names:
            return "none"

        # High trust patterns
        high_trust = {
            "root_only",
            "privileged",
            "secure",
        }

        # Medium trust patterns
        medium_trust = {
            "authenticated",
            "checked",
        }

        for mod in modifier_names:
            mod_lower = mod.lower()
            if mod_lower in high_trust:
                return "high"

        for mod in modifier_names:
            mod_lower = mod.lower()
            if mod_lower in medium_trust:
                return "medium"

        return "review_required"

    def get_lens_definitions(self) -> List[LensDefinition]:
        """C-specific lens definitions for security analysis."""
        return [
            LensDefinition(
                name="memory_safety",
                description="Buffer overflows, use-after-free, double-free, out-of-bounds access",
                invariant_types=["OTHER"],
                prompt_template="""
## MEMORY SAFETY LENS - C

Focus on memory corruption vulnerabilities.

### Buffer Overflows (CRITICAL)
For EACH function that handles buffers:
- Check for unbounded copies (strcpy, strcat, sprintf, gets)
- Verify size parameters match destination buffer size
- Check loop bounds against allocation sizes

### Use-After-Free / Double-Free
For EACH function that frees memory:
- Verify pointer is not used after free
- Check for double-free patterns
- Verify freed pointers are set to NULL

### Integer Overflows in Allocation
For EACH allocation using computed sizes:
- Check for integer overflow in size calculations
- Verify multiplication doesn't wrap
""",
                checklist=[
                    "buffer_overflow_checks",
                    "use_after_free_checks",
                    "allocation_overflow_checks",
                ],
            ),
            LensDefinition(
                name="security",
                description="Command injection, format strings, race conditions",
                invariant_types=["ACCESS", "OTHER"],
                prompt_template="""
## SECURITY LENS - C

Focus on injection and access control vulnerabilities.

### Command Injection
For EACH function calling system/popen/exec:
- Check if user input reaches command string
- Verify input sanitization before shell execution

### Format String Vulnerabilities
For EACH printf-family call:
- Check for user-controlled format strings
  - BAD: printf(user_input)
  - GOOD: printf("%s", user_input)

### Race Conditions (TOCTOU)
For EACH check-then-use pattern:
- Check for time-of-check-to-time-of-use gaps
- Verify file operations use safe patterns
""",
                checklist=[
                    "command_injection_checks",
                    "format_string_checks",
                    "race_condition_checks",
                ],
            ),
        ]

    def get_function_metadata_extractors(self) -> Dict[str, Callable]:
        """C-specific metadata extractors for function analysis."""

        def extract_is_static(node: Node, graph: "DependencyGraph") -> bool:
            return node.meta.get("is_static", False)

        def extract_returns_pointer(node: Node, graph: "DependencyGraph") -> bool:
            return_type = node.meta.get("return_type", "")
            return "*" in return_type

        def extract_has_malloc(node: Node, graph: "DependencyGraph") -> bool:
            calls = node.meta.get("calls", [])
            alloc_funcs = {"malloc", "calloc", "realloc", "free"}
            return any(
                c in alloc_funcs for c in calls if isinstance(c, str)
            )

        return {
            "is_static": extract_is_static,
            "returns_pointer": extract_returns_pointer,
            "has_malloc": extract_has_malloc,
        }

    def get_entrypoint_visibility(self) -> List[str]:
        """Return visibility levels that indicate public entrypoints."""
        return ["public"]

    def get_role_patterns(self) -> Dict[str, List[str]]:
        """Return patterns that indicate roles (limited in C)."""
        return {
            "Root": ["root_only", "privileged"],
            "User": ["user_check", "authenticated"],
        }

    def get_guard_patterns(self) -> List[str]:
        """Return common guard patterns."""
        return [
            "check_permissions",
            "validate_input",
            "sanitize",
            "verify",
        ]

    def get_dangerous_functions(self) -> List[str]:
        """Return list of dangerous C functions (security-relevant)."""
        return [
            # Memory
            "strcpy",
            "strcat",
            "sprintf",
            "gets",
            "scanf",
            # Format string
            "printf",
            "fprintf",
            "snprintf",  # can still be dangerous
            # Memory allocation
            "malloc",
            "calloc",
            "realloc",
            "free",
            # File operations
            "fopen",
            "fread",
            "fwrite",
            # System
            "system",
            "popen",
            "exec",
            "execve",
            "fork",
        ]

    def get_safe_alternatives(self) -> Dict[str, str]:
        """Return safer alternatives to dangerous functions."""
        return {
            "strcpy": "strncpy or strlcpy",
            "strcat": "strncat or strlcat",
            "sprintf": "snprintf",
            "gets": "fgets",
            "scanf": "fgets + sscanf with limits",
        }
