"""
JavaScript-specific domain adapter for the GraphQueryEngine.

Provides domain knowledge for JavaScript/Node.js security analysis:
- Entrypoint detection (Express/Koa routes, exports, event handlers)
- Library file identification (node_modules)
- Trust level patterns
"""

from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from .base import DomainAdapter, LensDefinition
from ..models import Node, NodeKind

if TYPE_CHECKING:
    from ..graph import DependencyGraph


class JavaScriptAdapter(DomainAdapter):
    """
    JavaScript-specific implementation of DomainAdapter.

    Provides domain knowledge for:
    - Symbol resolution (modules, classes, functions)
    - Entrypoint detection (routes, exports, event handlers)
    - Test file identification
    - Library detection
    """

    @property
    def name(self) -> str:
        return "javascript"

    def get_domain_mapping(self) -> Dict[str, str]:
        """Return JavaScript-specific NodeKind mappings."""
        return {
            "class": "CONTAINER",
            "module": "CONTAINER",
            "function": "UNIT",
            "method": "UNIT",
            "arrow_function": "UNIT",
            "async_function": "UNIT",
            "variable": "VARIABLE",
            "field": "VARIABLE",
        }

    def is_public_entrypoint(self, node: Node) -> bool:
        """
        Check if a node is a public entrypoint.

        Entrypoints in JavaScript include:
        - Express/Koa/Fastify route handlers
        - Exported functions
        - Event handlers (on*, handle*)
        """
        if node.kind != NodeKind.UNIT:
            return False

        name = node.name
        meta = node.meta

        # Check if exported
        if meta.get("exported", False):
            return True

        # Check for route handler patterns
        route_patterns = {
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "use",
            "all",
            "route",
        }
        if name.lower() in route_patterns:
            return True

        # Check for event handler patterns
        if name.startswith("on") or name.startswith("handle"):
            return True

        # Check visibility - private methods start with _ or #
        visibility = meta.get("visibility", "")
        if visibility == "private":
            return False

        if name.startswith("_") or name.startswith("#"):
            return False

        # Public methods/functions are entrypoints
        return True

    def is_state_variable(self, node: Node) -> bool:
        """Check if a node is a state variable."""
        if node.kind != NodeKind.VARIABLE:
            return False

        var_type = node.meta.get("type", "")
        return var_type in ("variable", "field")

    def is_test_file(self, file_path: str) -> bool:
        """Check if a file path looks like a test file."""
        p = file_path.lower()
        return (
            "/test/" in p
            or "/tests/" in p
            or "/__tests__/" in p
            or ".test." in p
            or ".spec." in p
            or "_test." in p
            or "_spec." in p
            or "/test-" in p
        )

    def is_library_file(self, file_path: str) -> bool:
        """
        Check if a file path is from an external library.

        Identifies common JavaScript dependency patterns.
        """
        p = file_path.lower()
        library_indicators = [
            # npm modules
            "node_modules/",
            "/node_modules/",
            # TypeScript definitions
            "@types/",
            "/@types/",
            # Common library directories
            "/vendor/",
            "/bower_components/",
            # Build output
            "/dist/",
            "/build/",
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
        """Check if this is a non-auth guard pattern."""
        non_auth_patterns = {
            # Rate limiting
            "ratelimit",
            "ratelimiter",
            "throttle",
            # Caching
            "cache",
            "memoize",
            # Validation
            "validate",
            "sanitize",
            # Logging
            "log",
            "logger",
            "morgan",
            # Error handling
            "errorhandler",
            "asynchandler",
            # Cors
            "cors",
            # Compression
            "compression",
            # Body parsing
            "bodyparser",
            "json",
            "urlencoded",
        }
        return modifier_name.lower() in non_auth_patterns

    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        """
        Determine trust level based on middleware/decorator patterns.

        Returns: "high", "medium", "low", "none", "review_required"
        """
        if not modifier_names:
            return "none"

        # High trust patterns (admin/auth)
        high_trust = {
            "isadmin",
            "requireadmin",
            "adminonly",
            "superuser",
        }

        # Medium trust patterns (authenticated)
        medium_trust = {
            "isauthenticated",
            "requireauth",
            "passport",
            "jwt",
            "jwtauth",
            "authenticate",
            "ensureloggedin",
        }

        # Low trust patterns (basic)
        low_trust = {
            "csrf",
            "helmet",
            "xss",
        }

        for mod in modifier_names:
            mod_lower = mod.lower().replace("-", "").replace("_", "")
            if mod_lower in high_trust:
                return "high"

        for mod in modifier_names:
            mod_lower = mod.lower().replace("-", "").replace("_", "")
            if mod_lower in medium_trust:
                return "medium"

        for mod in modifier_names:
            mod_lower = mod.lower().replace("-", "").replace("_", "")
            if mod_lower in low_trust:
                return "low"

        return "review_required"

    def get_entrypoint_visibility(self) -> List[str]:
        """Return visibility levels that indicate public entrypoints."""
        return ["public", "exported"]

    def get_role_patterns(self) -> Dict[str, List[str]]:
        """Return patterns that indicate roles."""
        return {
            "Admin": ["isAdmin", "requireAdmin", "adminOnly"],
            "Authenticated": ["isAuthenticated", "requireAuth", "ensureLoggedIn"],
            "Permission": ["hasPermission", "checkPermission", "authorize"],
        }

    def get_guard_patterns(self) -> List[str]:
        """Return common guard/middleware patterns."""
        return [
            "authenticate",
            "authorize",
            "requireAuth",
            "isAuthenticated",
            "passport",
            "jwt",
            "rateLimit",
        ]

    # =========================================================================
    # Lens-based invariant generation
    # =========================================================================

    def get_lens_definitions(self) -> List[LensDefinition]:
        """JavaScript/TypeScript-specific lens definitions for security analysis."""
        return [
            LensDefinition(
                name="security",
                description="XSS, prototype pollution, injection attacks",
                invariant_types=["ACCESS", "OTHER"],
                prompt_template="""
## SECURITY LENS - JavaScript/TypeScript

Focus on XSS, prototype pollution, and injection vulnerabilities.

### Cross-Site Scripting (XSS) - CRITICAL
For EACH function that outputs user data to DOM:
- Check for innerHTML, outerHTML usage with user data
  - BAD: `element.innerHTML = userInput`
  - GOOD: `element.textContent = userInput`
- Check for document.write() with user data
- Check React: dangerouslySetInnerHTML usage
- Check template literals in HTML context
- Generate ACCESS invariant: "User data in X is sanitized"

### Prototype Pollution - CRITICAL
For EACH function that merges objects:
- Check for unsafe merge patterns
  - BAD: `Object.assign(target, untrustedSource)`
  - BAD: Recursive merge without __proto__ check
- Check for bracket notation with user keys
  - BAD: `obj[userKey] = value`
- Verify lodash/underscore merge is updated
- Generate invariant: "Object merge in X blocks __proto__"

### Injection Attacks
For EACH function executing dynamic code:
- eval() - NEVER with user input
- new Function() - dangerous with user input
- setTimeout/setInterval with string args
- SQL queries (if using Node.js backends)
- Command injection via child_process
""",
                checklist=[
                    "No innerHTML with unsanitized user data",
                    "Object merges check for __proto__",
                    "No eval/Function with user input",
                    "Template literals escaped in HTML context",
                ],
            ),
            LensDefinition(
                name="resource",
                description="Event loop blocking, memory leaks, resource exhaustion",
                invariant_types=["LIVENESS", "OTHER"],
                prompt_template="""
## RESOURCE LENS - JavaScript

Focus on event loop health and resource management.

### Event Loop Blocking (LIVENESS)
For EACH synchronous operation:
- Check for sync file operations (fs.readFileSync in request handlers)
- Check for CPU-intensive loops in main thread
- Check for blocking crypto operations
- Generate LIVENESS invariant: "Function X completes in bounded time"

### Memory Leaks
For EACH event listener or subscription:
- Verify cleanup in component unmount/destroy
- Check for closures holding large objects
- Verify timer cleanup (clearInterval, clearTimeout)
- Check for DOM node references after removal

### Resource Limits
For EACH user-controlled operation:
- Check for unbounded array/string operations
- Verify limits on uploaded data
- Check WebSocket message size limits
- Check for ReDoS patterns in regex
""",
                checklist=[
                    "No sync operations in request handlers",
                    "Event listeners cleaned up",
                    "Timers cleared on cleanup",
                    "User input bounded in loops",
                ],
            ),
            LensDefinition(
                name="data",
                description="Input validation, JSON parsing safety, type coercion",
                invariant_types=["VALUE_FLOW", "OTHER"],
                prompt_template="""
## DATA LENS - JavaScript

Focus on input validation and type safety issues.

### Input Validation (REQUIRED)
For EACH function accepting external input:
- Verify type checking before use
- Check for null/undefined handling
- Verify array bounds checking
- Generate VALUE_FLOW invariant: "Input X validated before use"

### JSON Parsing Safety
For EACH JSON.parse call:
- Verify error handling (try/catch)
- Check for prototype pollution in parsed data
- Verify schema validation after parse
- Check reviver function if used

### Type Coercion Bugs
Check for dangerous coercion:
- `==` vs `===` comparisons
- Array/object in boolean context
- String to number implicit conversion
- parseInt without radix
""",
                checklist=[
                    "All inputs type-checked",
                    "JSON.parse wrapped in try/catch",
                    "Strict equality (===) used",
                    "parseInt uses radix parameter",
                ],
            ),
            LensDefinition(
                name="external",
                description="HTTP requests, file system, environment variables",
                invariant_types=["ACCESS", "LIVENESS", "OTHER"],
                prompt_template="""
## EXTERNAL LENS - JavaScript/Node.js

Focus on external interactions and API security.

### HTTP Requests (LIVENESS)
For EACH HTTP request:
- Verify timeout configuration
- Check for SSRF (user-controlled URLs)
- Verify SSL certificate validation
- Generate LIVENESS invariant: "Request X has timeout"

### File System (Node.js)
For EACH file operation:
- Check for path traversal
  - Use path.resolve and verify prefix
- Verify async operations preferred
- Check file permissions on creation
- Generate ACCESS invariant: "File path X validated"

### Environment Variables
For security-sensitive code:
- Verify secrets from env, not hardcoded
- Check for default values on missing env
- Verify NODE_ENV checks are correct
""",
                checklist=[
                    "HTTP requests have timeouts",
                    "File paths validated against traversal",
                    "Secrets loaded from environment",
                    "SSL verification enabled",
                ],
            ),
            LensDefinition(
                name="async",
                description="Promise handling, callbacks, async race conditions",
                invariant_types=["ORDERING", "OTHER"],
                prompt_template="""
## ASYNC LENS - JavaScript

Focus on async/await correctness and promise handling.

### Promise Handling (ORDERING)
For EACH async function:
- Verify all promises are awaited or handled
- Check for unhandled rejection
- Verify Promise.all error handling
- Generate ORDERING invariant: "Async operations complete correctly"

### Race Conditions
Check for async race patterns:
- Check-then-act without atomicity
- Concurrent state modifications
- Parallel requests with shared state
- Generate invariant for each race condition

### Callback Safety
For EACH callback pattern:
- Verify callback error handling (error-first)
- Check for callback called multiple times
- Verify cleanup on error paths
""",
                checklist=[
                    "All promises have error handling",
                    "No unhandled rejections",
                    "Race conditions in shared state identified",
                    "Callbacks handle errors properly",
                ],
            ),
            LensDefinition(
                name="web",
                description="CORS, security headers, authentication middleware",
                invariant_types=["ACCESS", "VALUE_FLOW", "OTHER"],
                prompt_template="""
## WEB LENS - Express/Koa/Fastify

Focus on web framework security configuration.

### CORS Configuration
For EACH CORS setup:
- Verify origin whitelist (not *)
- Check credentials handling
- Verify allowed methods restricted
- Generate ACCESS invariant: "CORS allows only [origins]"

### Authentication Middleware
For EACH protected route:
- Verify auth middleware is applied
- Check middleware order (auth before handler)
- Verify session/token validation
- Generate ACCESS invariant: "Route X requires auth"

### Security Headers
Check for security middleware:
- helmet or manual headers
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options

### Cookie Security
For EACH cookie operation:
- Verify HttpOnly flag
- Verify Secure flag (HTTPS)
- Verify SameSite attribute
- Check cookie expiration
""",
                checklist=[
                    "CORS origin whitelist configured",
                    "Auth middleware on protected routes",
                    "Security headers set (helmet)",
                    "Cookies have security flags",
                ],
            ),
            LensDefinition(
                name="exception_safety",
                description="Uncaught exceptions from built-in methods with invalid arguments (CWE-248)",
                invariant_types=["EXCEPTION_SAFETY", "OTHER"],
                prompt_template="""
## EXCEPTION SAFETY LENS - JavaScript/TypeScript (CWE-248)

Focus on uncaught exceptions from built-in methods that throw on invalid arguments.

### Built-in Methods That Throw on Invalid Arguments
JavaScript built-ins that throw RangeError/TypeError with invalid inputs:

**String methods:**
- `str.repeat(count)` - throws if count < 0 or Infinity
- `str.padStart(len)` / `str.padEnd(len)` - throws if len not valid
- `str.normalize(form)` - throws on invalid form

**Array/Buffer constructors:**
- `new Array(length)` - throws if length < 0 or > 2^32-1
- `new ArrayBuffer(length)` - throws if length < 0
- TypedArray constructors - similar bounds

**Number methods:**
- `num.toFixed(digits)` - throws if digits < 0 or > 100
- `num.toPrecision(digits)` - throws if digits < 1 or > 100

For EACH usage of these methods:
1. Check if argument is computed (arithmetic, variable)
2. Check if computation could produce invalid value
3. Generate EXCEPTION_SAFETY invariant if unguarded

### Arithmetic Before Built-in Calls
Look for patterns where arithmetic feeds into throwing methods:
- Subtraction that could go negative
- Division that could produce non-integer
- User-controlled values without validation

### Functions Processing External/Untrusted Data
For functions that:
- Parse or process structured input
- Handle position/offset/index values
- Format or transform data for output

Check if computed values flow into throwing built-ins unguarded.

### Try-Catch Coverage
- Throwing operations should be wrapped or arguments validated
- Error handling code paths should not themselves throw
""",
                checklist=[
                    "Arguments to throwing built-ins are validated",
                    "Arithmetic results checked before use as counts/lengths",
                    "External data validated before flowing to built-ins",
                    "No unguarded throwing calls in error handling paths",
                ],
            ),
        ]

    def get_function_metadata_extractors(self) -> Dict[str, Callable]:
        """
        JavaScript-specific metadata extractors.

        These are called for each function to populate metadata used for bucketing.
        """

        def extract_is_async(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function is async."""
            return node.meta.get("is_async", False) or node.meta.get("async", False)

        def extract_is_exported(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function is exported."""
            return node.meta.get("exported", False) or node.meta.get(
                "is_exported", False
            )

        def extract_is_arrow_function(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function is arrow function."""
            func_type = node.meta.get("type", "")
            return "arrow" in func_type.lower() or node.meta.get(
                "is_arrow_function", False
            )

        def extract_is_static_method(node: Node, graph: "DependencyGraph") -> bool:
            """Check if method is static."""
            return node.meta.get("is_static", False) or node.meta.get("static", False)

        def extract_is_route_handler(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function is a route handler."""
            name_lower = node.name.lower()
            route_patterns = ["get", "post", "put", "delete", "patch", "use", "all"]
            # Check name patterns
            if name_lower in route_patterns:
                return True
            # Check if called on app/router
            calls = node.meta.get("calls", [])
            for call in calls:
                if isinstance(call, str) and any(
                    p in call.lower() for p in route_patterns
                ):
                    return True
            return False

        def extract_takes_request(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function takes request parameter."""
            params = node.meta.get("parameters", [])
            request_patterns = {"req", "request", "ctx", "context"}
            for param in params:
                param_lower = param.lower() if isinstance(param, str) else ""
                if param_lower in request_patterns:
                    return True
            return False

        def extract_is_middleware(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function is middleware (req, res, next signature)."""
            params = node.meta.get("parameters", [])
            if len(params) >= 3:
                params_lower = [p.lower() if isinstance(p, str) else "" for p in params]
                has_req = any(p in ["req", "request"] for p in params_lower)
                has_res = any(p in ["res", "response"] for p in params_lower)
                has_next = "next" in params_lower
                return has_req and has_res and has_next
            return False

        def extract_handles_dom(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function handles DOM operations."""
            name_lower = node.name.lower()
            dom_patterns = [
                "render",
                "html",
                "element",
                "dom",
                "component",
                "view",
                "template",
            ]
            calls = node.meta.get("calls", [])
            calls_lower = [c.lower() for c in calls if isinstance(c, str)]
            return any(p in name_lower for p in dom_patterns) or any(
                p in c for c in calls_lower for p in dom_patterns
            )

        def extract_calls_external(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function makes external calls."""
            name_lower = node.name.lower()
            external_patterns = [
                "fetch",
                "axios",
                "http",
                "request",
                "api",
                "ajax",
                "xhr",
            ]
            calls = node.meta.get("calls", [])
            calls_lower = [c.lower() for c in calls if isinstance(c, str)]
            return any(p in name_lower for p in external_patterns) or any(
                p in c for c in calls_lower for p in external_patterns
            )

        def extract_modifies_state(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function modifies state."""
            name_lower = node.name.lower()
            state_patterns = [
                "set",
                "update",
                "dispatch",
                "commit",
                "mutate",
                "save",
                "delete",
                "remove",
            ]
            return any(p in name_lower for p in state_patterns)

        def _get_calls_from_graph(node: Node, graph: "DependencyGraph") -> List[str]:
            """Get call targets for a node from graph edges."""
            from ..models import EdgeKind
            calls = []
            # Graph stores edges as Dict[(src, kind, dst), EdgeMeta]
            for (src, kind, dst) in graph._edges.keys():
                if src == node.id and kind == EdgeKind.CALLS:
                    calls.append(dst)
            return calls

        def extract_uses_throwing_builtins(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function uses JS built-ins that throw on invalid args."""
            calls = _get_calls_from_graph(node, graph)
            calls_lower = [c.lower() for c in calls if isinstance(c, str)]
            # JS built-in methods that throw RangeError/TypeError on invalid args
            throwing_builtins = [
                ".repeat",
                ".padstart",
                ".padend",
                ".tofixed",
                ".toprecision",
                ".normalize",
            ]
            return any(m in c for c in calls_lower for m in throwing_builtins)

        def extract_creates_sized_objects(node: Node, graph: "DependencyGraph") -> bool:
            """Check if function creates arrays/buffers with size arguments."""
            calls = _get_calls_from_graph(node, graph)
            calls_lower = [c.lower() for c in calls if isinstance(c, str)]
            # Constructors that throw on invalid size
            sized_constructors = [
                "array(",
                "arraybuffer(",
                "sharedarraybuffer(",
                "uint8array(",
                "uint16array(",
                "uint32array(",
                "int8array(",
                "int16array(",
                "int32array(",
                "float32array(",
                "float64array(",
                "bigint64array(",
                "biguint64array(",
                "buffer.alloc",
            ]
            return any(c in calls_lower for c in sized_constructors)

        return {
            "is_async": extract_is_async,
            "is_exported": extract_is_exported,
            "is_arrow_function": extract_is_arrow_function,
            "is_static_method": extract_is_static_method,
            "is_route_handler": extract_is_route_handler,
            "takes_request": extract_takes_request,
            "is_middleware": extract_is_middleware,
            "handles_dom": extract_handles_dom,
            "calls_external": extract_calls_external,
            "modifies_state": extract_modifies_state,
            # Exception safety extractors - based on actual JS semantics
            "uses_throwing_builtins": extract_uses_throwing_builtins,
            "creates_sized_objects": extract_creates_sized_objects,
        }
