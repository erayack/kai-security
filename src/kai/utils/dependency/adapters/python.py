"""
Python-specific domain adapter for the GraphQueryEngine.

Provides domain knowledge for Python security analysis:
- Entrypoint detection (Flask/Django routes, CLI decorators, public functions)
- Library file identification
- Trust level patterns (decorators)
"""

from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from .base import DomainAdapter, LensDefinition
from ..models import Node, NodeKind

if TYPE_CHECKING:
    from ..graph import DependencyGraph


class PythonAdapter(DomainAdapter):
    """
    Python-specific implementation of DomainAdapter.

    Provides domain knowledge for:
    - Symbol resolution (modules, classes, functions)
    - Entrypoint detection (routes, CLI handlers, public functions)
    - Test file identification
    - Library detection
    """

    @property
    def name(self) -> str:
        return "python"

    def get_domain_mapping(self) -> Dict[str, str]:
        """Return Python-specific NodeKind mappings."""
        return {
            "class": "CONTAINER",
            "module": "CONTAINER",
            "function": "UNIT",
            "method": "UNIT",
            "async_function": "UNIT",
            "decorator": "INTERFACE",
            "global_variable": "VARIABLE",
            "class_attribute": "VARIABLE",
        }

    def is_public_entrypoint(self, node: Node) -> bool:
        """
        Check if a node is a public entrypoint.

        Entrypoints in Python include:
        - Flask/Django/FastAPI route handlers (decorated)
        - CLI entry points (click, argparse decorators)
        - Public functions not starting with _
        """
        if node.kind != NodeKind.UNIT:
            return False

        # Check visibility
        name = node.name
        if name.startswith("_") and not name.startswith("__"):
            return False  # Private by convention

        # Skip dunder methods except __init__ and __call__
        if name.startswith("__") and name.endswith("__"):
            if name not in ("__init__", "__call__"):
                return False

        # Check for route decorators
        decorators = node.meta.get("decorators", [])
        route_decorators = {
            # Flask
            "route",
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "app.route",
            "blueprint.route",
            # FastAPI
            "api_route",
            "router.get",
            "router.post",
            # Django
            "api_view",
            "action",
            # Click/CLI
            "command",
            "group",
            "click.command",
        }
        for dec in decorators:
            dec_lower = dec.lower()
            if any(rd in dec_lower for rd in route_decorators):
                return True

        # Public function without _ prefix is considered entrypoint
        visibility = node.meta.get("visibility", "")
        if visibility == "public":
            return True

        return not name.startswith("_")

    def is_state_variable(self, node: Node) -> bool:
        """Check if a node is a state variable."""
        if node.kind != NodeKind.VARIABLE:
            return False

        var_type = node.meta.get("type", "")
        return var_type in ("global", "class_attribute")

    def is_test_file(self, file_path: str) -> bool:
        """Check if a file path looks like a test file."""
        p = file_path.lower()
        return (
            "/test/" in p
            or "/tests/" in p
            or p.endswith("_test.py")
            or p.endswith("test_.py")
            or "test_" in p.split("/")[-1]
            or "/conftest.py" in p
            or "_test.py" in p
        )

    def is_library_file(self, file_path: str) -> bool:
        """
        Check if a file path is from an external library.

        Identifies common Python dependency patterns.
        """
        p = file_path.lower()
        library_indicators = [
            # Virtual environments
            "/site-packages/",
            "/dist-packages/",
            "/.venv/",
            "/venv/",
            "/virtualenv/",
            # Common package prefixes
            "/lib/python",
            # Standard library paths
            "/usr/lib/python",
            "/usr/local/lib/python",
            # Package managers
            "/.local/lib/",
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
            name: Symbol name to resolve (e.g., "process_data", "UserModel")
            context_graph: The dependency graph to search
            scope: Optional container ID to limit search scope

        Returns:
            List of matching node IDs
        """
        candidate_ids: List[str] = []

        # Check if symbol is already a node ID
        if name in context_graph._nodes:
            return [name]

        # If scope specified, include methods of the class
        valid_parents: Optional[set] = None
        if scope:
            valid_parents = {scope}
            # Could expand to include parent classes if inheritance edges exist

        # Search by name across all nodes
        for nid, node in context_graph._nodes.items():
            if node.name == name:
                if valid_parents is not None:
                    if node.parent_id not in valid_parents:
                        continue
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
        """Check if a decorator is a non-auth guard."""
        non_auth_decorators = {
            # Rate limiting
            "ratelimit",
            "rate_limit",
            "throttle",
            # Caching
            "cache",
            "cached",
            "memoize",
            "lru_cache",
            # Validation
            "validate",
            "validator",
            # Logging/monitoring
            "log",
            "trace",
            "profile",
            # Async
            "async_to_sync",
            "sync_to_async",
            # Other non-auth
            "deprecated",
            "staticmethod",
            "classmethod",
            "property",
            "abstractmethod",
        }
        return modifier_name.lower() in non_auth_decorators

    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        """
        Determine trust level based on decorator patterns.

        Returns: "high", "medium", "low", "none", "review_required"
        """
        if not modifier_names:
            return "none"

        # High trust patterns (admin/auth required)
        high_trust = {
            "admin_required",
            "superuser_required",
            "staff_required",
            "permission_required",
            "login_required",
            "authenticated",
        }

        # Medium trust patterns (some auth)
        medium_trust = {
            "permission_classes",
            "has_permission",
            "is_authenticated",
            "jwt_required",
            "token_required",
        }

        # Low trust patterns (basic checks)
        low_trust = {
            "csrf_protect",
            "require_http_methods",
        }

        for mod in modifier_names:
            mod_lower = mod.lower()
            if any(ht in mod_lower for ht in high_trust):
                return "high"

        for mod in modifier_names:
            mod_lower = mod.lower()
            if any(mt in mod_lower for mt in medium_trust):
                return "medium"

        for mod in modifier_names:
            mod_lower = mod.lower()
            if any(lt in mod_lower for lt in low_trust):
                return "low"

        # Unknown decorator pattern
        return "review_required"

    def get_entrypoint_visibility(self) -> List[str]:
        """Return visibility levels that indicate public entrypoints."""
        return ["public"]

    def get_role_patterns(self) -> Dict[str, List[str]]:
        """Return decorator patterns that indicate roles."""
        return {
            "Admin": ["admin_required", "superuser_required", "staff_required"],
            "Authenticated": ["login_required", "authenticated", "jwt_required"],
            "Permission": ["permission_required", "has_permission"],
        }

    def get_guard_patterns(self) -> List[str]:
        """Return common guard/decorator patterns."""
        return [
            "login_required",
            "permission_required",
            "admin_required",
            "authenticated",
            "rate_limit",
            "cache",
        ]

    # =========================================================================
    # Lens-based invariant generation
    # =========================================================================

    def get_lens_definitions(self) -> List[LensDefinition]:
        """Python-specific lens definitions for security analysis."""
        return [
            LensDefinition(
                name="security",
                description="Injection attacks, auth bypass, credential exposure",
                invariant_types=["ACCESS", "OTHER"],
                prompt_template="""
## SECURITY LENS - Python

Focus on injection vulnerabilities, authentication bypass, and credential exposure.

### Injection Attacks (CRITICAL)
For EACH function that processes external input:
- SQL Injection: Check for string formatting in SQL queries
  - BAD: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
  - GOOD: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
- Command Injection: Check subprocess calls with shell=True
  - BAD: `subprocess.run(f"ls {user_input}", shell=True)`
  - GOOD: `subprocess.run(["ls", user_input])`
- Template Injection: Check for raw template rendering
- LDAP/XPath/XML Injection: Check for unsanitized queries

### Authentication/Authorization (REQUIRED for protected endpoints)
For EACH route handler or API endpoint:
- Verify authentication decorator is present (@login_required, @jwt_required)
- Check for authorization logic (role checks, permission checks)
- Common bug: Missing auth check on sensitive operations
- Generate ACCESS invariant: "Only [ROLE] can access [ENDPOINT]"

### Credential Exposure
Check for:
- Hardcoded secrets, API keys, passwords in source
- Logging of sensitive data (passwords, tokens)
- Credentials in error messages or responses
""",
                checklist=[
                    "Every SQL query using parameters not string formatting",
                    "Every subprocess call with shell=False or sanitized input",
                    "Every protected endpoint has auth decorator",
                    "No hardcoded credentials in source",
                ],
            ),
            LensDefinition(
                name="resource",
                description="DoS prevention, memory limits, resource exhaustion",
                invariant_types=["LIVENESS", "OTHER"],
                prompt_template="""
## RESOURCE LENS - Python

Focus on DoS prevention and resource exhaustion vulnerabilities.

### Denial of Service (LIVENESS)
For EACH function processing user-controlled data:
- Check for unbounded loops over user input
- Check for large memory allocations based on user input
- Check for regex with catastrophic backtracking (ReDoS)
  - Pattern: `(a+)+$`, `(a|a)+$`, `([a-zA-Z]+)*`
- Generate LIVENESS invariant: "Function X terminates in bounded time"

### Memory Limits
For EACH file upload or data processing function:
- Verify size limits on uploaded files
- Check for limits on collection sizes (lists, dicts)
- Verify streaming for large file processing
- Common bug: Loading entire file into memory

### Connection/Handle Exhaustion
Check for:
- Unclosed file handles (use context managers)
- Unclosed database connections
- Unclosed network sockets
- Missing timeouts on external requests
""",
                checklist=[
                    "User-controlled loops have iteration limits",
                    "File uploads have size limits",
                    "Regex patterns checked for ReDoS",
                    "Resources properly closed (context managers)",
                ],
            ),
            LensDefinition(
                name="data",
                description="Input validation, serialization safety, data integrity",
                invariant_types=["VALUE_FLOW", "OTHER"],
                prompt_template="""
## DATA LENS - Python

Focus on input validation, serialization, and data integrity.

### Input Validation (REQUIRED for external data)
For EACH function accepting external input:
- Verify type checking (isinstance, type hints with runtime validation)
- Verify bounds checking (min/max values, string lengths)
- Verify format validation (email, URL, date patterns)
- Generate VALUE_FLOW invariant: "Input X must satisfy [constraints]"

### Serialization Safety (CRITICAL)
Check for dangerous deserialization:
- `pickle.loads()` on untrusted data - ARBITRARY CODE EXECUTION
- `yaml.load()` without `Loader=SafeLoader` - CODE EXECUTION
- `eval()`, `exec()` on user input - CODE EXECUTION
- `marshal.loads()` on untrusted data

### Data Integrity
For EACH data transformation:
- Check for data loss in type conversions
- Verify encoding/decoding is consistent (UTF-8 handling)
- Check for race conditions in read-modify-write operations
""",
                checklist=[
                    "External input validated before use",
                    "No pickle/yaml/eval on untrusted data",
                    "Type conversions handle edge cases",
                    "Encoding explicitly specified",
                ],
            ),
            LensDefinition(
                name="external",
                description="Network calls, subprocess execution, file I/O security",
                invariant_types=["ACCESS", "LIVENESS", "OTHER"],
                prompt_template="""
## EXTERNAL LENS - Python

Focus on external interactions: network, subprocess, filesystem.

### Network Calls (LIVENESS + SECURITY)
For EACH HTTP/network request:
- Verify timeout is set (requests.get(url, timeout=30))
- Verify SSL/TLS certificate verification (verify=True)
- Check for SSRF vulnerabilities (user-controlled URLs)
- Generate LIVENESS invariant: "Network call X has timeout"

### Subprocess Execution (CRITICAL)
For EACH subprocess call:
- Verify shell=False when possible
- Check for command injection via user input
- Verify PATH is not user-controlled
- Generate ACCESS invariant: "Subprocess X only runs [allowed commands]"

### File I/O Security
For EACH file operation:
- Check for path traversal (../../etc/passwd)
  - Use os.path.realpath() and verify prefix
- Verify file permissions on created files
- Check for symlink attacks
- Verify temp files use secure creation (tempfile module)
""",
                checklist=[
                    "All network requests have timeouts",
                    "SSL verification enabled",
                    "Subprocess uses shell=False",
                    "File paths validated against traversal",
                ],
            ),
            LensDefinition(
                name="concurrency",
                description="Async safety, threading issues, race conditions",
                invariant_types=["ORDERING", "REENTRANCY", "OTHER"],
                prompt_template="""
## CONCURRENCY LENS - Python

Focus on async/await safety, threading issues, and race conditions.

### Async Safety (ORDERING)
For EACH async function:
- Check for blocking calls in async context (time.sleep vs asyncio.sleep)
- Verify proper await on all coroutines
- Check for shared mutable state without locks
- Generate ORDERING invariant: "Async operations in X complete in order"

### Thread Safety (REENTRANCY)
For EACH shared resource accessed by multiple threads:
- Verify proper locking (threading.Lock, RLock)
- Check for deadlock potential (lock ordering)
- Verify thread-safe data structures (queue.Queue)
- Generate REENTRANCY invariant: "Resource X protected by lock"

### Race Conditions
Check for TOCTOU (Time-of-check to time-of-use) bugs:
- File existence check then open
- Permission check then action
- Balance check then transfer
- Generate invariant for each potential race
""",
                checklist=[
                    "No blocking calls in async functions",
                    "Shared mutable state protected by locks",
                    "Lock ordering consistent (no deadlocks)",
                    "TOCTOU patterns identified",
                ],
            ),
            LensDefinition(
                name="web",
                description="Flask/Django/FastAPI: CSRF, XSS, session security",
                invariant_types=["ACCESS", "VALUE_FLOW", "OTHER"],
                prompt_template="""
## WEB LENS - Python Web Frameworks

Focus on web-specific vulnerabilities in Flask/Django/FastAPI.

### Cross-Site Scripting (XSS)
For EACH response returning user data:
- Verify HTML escaping (use template engine auto-escape)
- Check for |safe filter misuse in templates
- Verify Content-Type headers for JSON responses
- Generate VALUE_FLOW invariant: "User data in response X is escaped"

### Cross-Site Request Forgery (CSRF)
For EACH state-changing endpoint (POST/PUT/DELETE):
- Verify CSRF protection is enabled
- Check for CSRF token in forms
- Django: @csrf_protect or CsrfViewMiddleware
- Flask: Flask-WTF CSRFProtect
- Generate ACCESS invariant: "Endpoint X requires CSRF token"

### Session Security
Check session configuration:
- Secure cookie flags (HttpOnly, Secure, SameSite)
- Session timeout configured
- Session ID regeneration on auth level change
- No sensitive data in session (store server-side)

### HTTP Security Headers
Verify security headers:
- Content-Security-Policy
- X-Content-Type-Options: nosniff
- X-Frame-Options
- Strict-Transport-Security
""",
                checklist=[
                    "User data HTML-escaped in responses",
                    "State-changing endpoints have CSRF protection",
                    "Session cookies have security flags",
                    "Security headers configured",
                ],
            ),
        ]

    def get_function_metadata_extractors(self) -> Dict[str, Callable]:
        """
        Python-specific metadata extractors.

        These are called for each function to populate metadata used for bucketing.
        """

        def extract_is_async(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function is async."""
            return node.meta.get("is_async", False) or "async" in node.meta.get(
                "type", ""
            )

        def extract_has_route_decorator(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function has route decorator."""
            decorators = node.meta.get("decorators", [])
            route_patterns = {
                "route",
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "api_route",
                "api_view",
                "action",
            }
            for dec in decorators:
                dec_lower = dec.lower()
                if any(p in dec_lower for p in route_patterns):
                    return True
            return False

        def extract_has_auth_decorator(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function has authentication decorator."""
            decorators = node.meta.get("decorators", [])
            auth_patterns = {
                "login_required",
                "permission_required",
                "authenticated",
                "jwt_required",
                "token_required",
                "admin_required",
                "requires_auth",
            }
            for dec in decorators:
                dec_lower = dec.lower()
                if any(p in dec_lower for p in auth_patterns):
                    return True
            return False

        def extract_is_public(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function is public (not prefixed with underscore)."""
            name = node.name
            return not name.startswith("_") or name.startswith("__")

        def extract_takes_user_input(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function parameters suggest user input."""
            params = node.meta.get("parameters", [])
            input_patterns = {
                "request",
                "req",
                "data",
                "payload",
                "body",
                "input",
                "form",
                "query",
                "params",
            }
            for param in params:
                param_lower = param.lower() if isinstance(param, str) else ""
                if any(p in param_lower for p in input_patterns):
                    return True
            return False

        def extract_calls_subprocess(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function likely calls subprocess."""
            name_lower = node.name.lower()
            subprocess_patterns = ["exec", "shell", "subprocess", "popen", "system"]
            calls = node.meta.get("calls", [])
            calls_lower = [c.lower() for c in calls if isinstance(c, str)]
            return any(p in name_lower for p in subprocess_patterns) or any(
                p in c for c in calls_lower for p in subprocess_patterns
            )

        def extract_accesses_database(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function accesses database."""
            name_lower = node.name.lower()
            db_patterns = [
                "query",
                "execute",
                "cursor",
                "session",
                "select",
                "insert",
                "update",
                "delete",
                "fetch",
                "commit",
            ]
            calls = node.meta.get("calls", [])
            calls_lower = [c.lower() for c in calls if isinstance(c, str)]
            return any(p in name_lower for p in db_patterns) or any(
                p in c for c in calls_lower for p in db_patterns
            )

        def extract_handles_files(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function handles files."""
            name_lower = node.name.lower()
            file_patterns = [
                "file",
                "read",
                "write",
                "upload",
                "download",
                "save",
                "load",
                "open",
                "path",
            ]
            return any(p in name_lower for p in file_patterns)

        def extract_has_network_call(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function makes network calls."""
            name_lower = node.name.lower()
            network_patterns = [
                "request",
                "fetch",
                "http",
                "api",
                "url",
                "get",
                "post",
                "socket",
                "connect",
            ]
            calls = node.meta.get("calls", [])
            calls_lower = [c.lower() for c in calls if isinstance(c, str)]
            return any(p in name_lower for p in network_patterns) or any(
                p in c for c in calls_lower for p in network_patterns
            )

        def extract_modifies_state(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function modifies state."""
            name_lower = node.name.lower()
            state_patterns = [
                "set",
                "update",
                "save",
                "delete",
                "remove",
                "add",
                "create",
                "modify",
                "change",
            ]
            return any(p in name_lower for p in state_patterns)

        return {
            "is_async": extract_is_async,
            "has_route_decorator": extract_has_route_decorator,
            "has_auth_decorator": extract_has_auth_decorator,
            "is_public": extract_is_public,
            "takes_user_input": extract_takes_user_input,
            "calls_subprocess": extract_calls_subprocess,
            "accesses_database": extract_accesses_database,
            "handles_files": extract_handles_files,
            "has_network_call": extract_has_network_call,
            "modifies_state": extract_modifies_state,
        }
