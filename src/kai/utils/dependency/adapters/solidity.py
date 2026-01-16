"""
Solidity-specific domain adapter for the GraphQueryEngine.
"""

from typing import TYPE_CHECKING, Callable, Dict, List, Optional

from .base import DomainAdapter, LensDefinition
from ..models import Node, NodeKind

if TYPE_CHECKING:
    from ..graph import DependencyGraph


class SolidityAdapter(DomainAdapter):
    """
    Solidity-specific implementation of DomainAdapter.

    Provides domain knowledge for:
    - Symbol resolution (contracts, functions, variables)
    - Entrypoint detection (public/external)
    - Test file identification
    """

    @property
    def name(self) -> str:
        return "solidity"

    def get_domain_mapping(self) -> Dict[str, str]:
        """Return Solidity-specific NodeKind mappings."""
        return {
            "contract": "CONTAINER",
            "interface": "CONTAINER",
            "library": "CONTAINER",
            "function": "UNIT",
            "modifier": "INTERFACE",
            "state_variable": "VARIABLE",
            "struct": "TYPE_DEF",
            "enum": "TYPE_DEF",
            "event": "EVENT",
        }

    def is_public_entrypoint(self, node: Node) -> bool:
        """Check if a node is a public entrypoint."""
        if node.kind != NodeKind.UNIT:
            return False

        visibility = (node.meta.get("visibility") or "").lower()
        if visibility not in ("public", "external"):
            return False

        # Exclude constructors, fallback, receive
        if node.meta.get("is_constructor"):
            return False
        if node.meta.get("is_fallback"):
            return False
        if node.meta.get("is_receive"):
            return False

        return True

    def is_state_variable(self, node: Node) -> bool:
        """Check if a node is a state variable."""
        return node.kind == NodeKind.VARIABLE

    def is_test_file(self, file_path: str) -> bool:
        """Check if a file path looks like a test file."""
        p = file_path.lower()
        return (
            "/test/" in p
            or "/tests/" in p
            or p.endswith(".t.sol")
            or p.endswith("_test.sol")
            or p.endswith(".spec.sol")
        )

    def is_library_file(self, file_path: str) -> bool:
        """
        Check if a file path is from an external library.

        Identifies common Solidity dependency patterns:
        - node_modules/ (npm packages)
        - lib/ (forge dependencies)
        - @openzeppelin, @solmate, etc. (namespaced packages)
        - forge-std (foundry standard library)
        """
        p = file_path.lower()
        library_indicators = [
            # Dependency directories
            "node_modules/",
            "/lib/",
            # Common namespaced packages
            "@openzeppelin",
            "@solmate",
            "@rari-capital",
            "@uniswap",
            "@aave",
            "@chainlink",
            "@compound",
            # Foundry/forge
            "forge-std/",
            "ds-test/",
            # Other common libs
            "solady/",
            "solmate/",
            "openzeppelin-contracts/",
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
            symbol: The symbol name to resolve (e.g., "withdraw", "Vault")
            graph: The dependency graph to search
            scope: Optional container ID to limit search scope

        Returns:
            List of matching node IDs, ordered by relevance
        """
        candidate_ids: List[str] = []

        # Check if symbol is already a node ID
        if name in context_graph._nodes:
            return [name]

        # If scope specified, also include inherited contracts
        valid_parents: Optional[set] = None
        if scope:  # Treat empty string same as None
            valid_parents = self._get_scope_with_inheritance(context_graph, scope)

        # Search by name across all nodes
        for nid in context_graph._nodes:
            node = context_graph._nodes[nid]

            # Special handling for "constructor" - Slither stores it with empty name
            if name == "constructor" and node.kind == NodeKind.UNIT:
                if node.meta.get("is_constructor"):
                    if valid_parents is None or node.parent_id in valid_parents:
                        candidate_ids.append(nid)
                    continue

            # Match by name
            if node.name == name:
                # If scope specified, check parent (including inherited)
                if valid_parents is not None:
                    if node.parent_id not in valid_parents:
                        continue
                candidate_ids.append(nid)

            # Also check signature for functions
            if node.kind == NodeKind.UNIT:
                sig = node.meta.get("signature", "")
                if sig and sig.startswith(f"{name}("):
                    if valid_parents is None or node.parent_id in valid_parents:
                        candidate_ids.append(nid)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for cid in candidate_ids:
            if cid not in seen:
                seen.add(cid)
                unique.append(cid)

        return unique

    def _get_scope_with_inheritance(
        self, context_graph: "DependencyGraph", scope: str
    ) -> set:
        """
        Get a set containing the scope and all contracts it inherits from.

        Recursively follows INHERITS edges to find all ancestor contracts.
        """
        from kai.utils.dependency.models import EdgeKind

        # First, resolve scope name to actual node ID if it's not already one
        scope_node_id = scope
        if scope not in context_graph._nodes:
            # Search for a container node with matching name
            for nid, node in context_graph._nodes.items():
                if node.kind == NodeKind.CONTAINER and node.name == scope:
                    scope_node_id = nid
                    break

        valid_parents = {scope_node_id}
        to_visit = [scope_node_id]

        while to_visit:
            current = to_visit.pop()
            # Get contracts that 'current' inherits from (outgoing INHERITS edges)
            try:
                inherited = context_graph.neighbors(
                    current, edge_kinds={EdgeKind.INHERITS}, direction="out"
                )
                for parent_id in inherited:
                    if parent_id not in valid_parents:
                        valid_parents.add(parent_id)
                        to_visit.append(parent_id)
            except Exception:
                # Node doesn't exist or no edges - continue
                pass

        return valid_parents

    def get_non_auth_guards(self) -> List[str]:
        """
        Return guard patterns that are NOT access control (don't indicate a role).

        These protect against reentrancy, pausing, initialization, etc.
        but don't restrict WHO can call the function.
        """
        return [
            "nonReentrant",
            "noReentrancy",
            "whenNotPaused",
            "whenPaused",
            "initializer",
            "reinitializer",
            "onlyInitializing",
            "onlyProxy",
            "onlyDelegateCall",
            "noDelegateCall",
        ]

    def is_non_auth_guard(self, modifier_name: str) -> bool:
        """Check if a modifier is a non-auth guard (reentrancy, pause, etc.)."""
        non_auth = self.get_non_auth_guards()
        return modifier_name in non_auth

    def get_trust_for_modifiers(self, modifier_names: List[str]) -> str:
        """
        Determine trust level based on Solidity modifier patterns.

        Returns: "high", "medium", "low", "none", or "review_required"
        """
        if not modifier_names:
            return "none"

        # Filter out non-auth guards (reentrancy, pause, etc.)
        auth_modifiers = [m for m in modifier_names if not self.is_non_auth_guard(m)]
        if not auth_modifiers:
            return "none"

        # High trust patterns (owner/admin only)
        high_trust = {
            "onlyowner",
            "onlyadmin",
            "onlygovernance",
            "onlyguardian",
            "onlydao",
            "onlymultisig",
            "requiresauth",
            "onlytimelock",
        }

        # Medium trust patterns (role-based or operator)
        medium_trust = {
            "onlyrole",
            "onlyoperator",
            "onlyminter",
            "onlyburner",
            "onlykeeper",
            "onlyrelayer",
            "onlyvalidator",
            "hasrole",
            "auth",
        }

        # Low trust patterns (basic checks)
        low_trust = {
            "onlyeoa",
            "onlycontract",
        }

        for mod in auth_modifiers:
            mod_lower = mod.lower()
            if any(ht in mod_lower for ht in high_trust):
                return "high"

        for mod in auth_modifiers:
            mod_lower = mod.lower()
            if any(mt in mod_lower for mt in medium_trust):
                return "medium"

        for mod in auth_modifiers:
            mod_lower = mod.lower()
            if any(lt in mod_lower for lt in low_trust):
                return "low"

        # Unknown modifier pattern - needs review
        return "review_required"

    # =========================================================================
    # Lens-based invariant generation
    # =========================================================================

    def get_lens_definitions(self) -> List[LensDefinition]:
        """Solidity/DeFi-specific lens definitions."""
        return [
            LensDefinition(
                name="safety",
                description="Access control, reentrancy, authorization",
                invariant_types=["ACCESS", "REENTRANCY", "SOLVENCY"],
                prompt_template="""
## SAFETY LENS - Solidity

Focus on access control, reentrancy protection, and solvency.

### Access Control (REQUIRED for privileged functions)
For EACH function with access modifiers (onlyOwner, onlyAdmin, onlyRole):
- Generate ACCESS invariant: "Only [ROLE] can call [FUNCTION]"
- CRITICAL: Watch for INVERTED checks (== vs !=) - common bug pattern
- Example bug: `require(msg.sender != owner)` instead of `== owner`

### Reentrancy (REQUIRED for external calls)
For EACH function making external calls (.call, .transfer, .send, token transfers):
- Verify CEI pattern: Checks-Effects-Interactions
- State updates MUST happen BEFORE external calls
- Or verify nonReentrant modifier is present

### Solvency (REQUIRED if contract holds value)
Generate at least one invariant:
- "Contract balance >= sum of all pending obligations"
- List all obligation variables (pendingWithdrawals, userBalances, etc.)
""",
                checklist=[
                    "Every onlyOwner/onlyAdmin function has ACCESS invariant",
                    "Every external call verified for CEI pattern or nonReentrant",
                    "Solvency invariant generated if contract holds ETH/tokens",
                ],
            ),
            LensDefinition(
                name="economic",
                description="Value transfers, fee calculations, economic flows",
                invariant_types=["VALUE_FLOW", "FEE_BOUND", "ECONOMIC"],
                prompt_template="""
## ECONOMIC LENS - Solidity/DeFi

Focus on value flow correctness and fee calculations.

### Value Flow (CRITICAL - common bug source)
For EACH payable function or function handling value:
- Identify: Does it use msg.value or a stored threshold variable?
- Generate VALUE_FLOW invariant: "Calculation X must use [correct variable]"
- Common bug: fee increase using stored `minFee` instead of actual `msg.value`
- Example: `claimFee` (threshold) vs `msg.value` (actual payment) - which is used?

### State Progression (CRITICAL - often missed)
For EACH state variable that updates over time (fees, rates, counters):
- Check the UPDATE FORMULA: What value is used as the base?
- Generate VALUE_FLOW invariant for the progression formula itself
- Common bug pattern: `newFee = oldFee + (oldFee * percentage)` when it should
  use the actual transaction value: `newFee = msg.value + (msg.value * percentage)`
- Ask: "When this value increases, should it grow based on what was REQUIRED
  or what was actually PAID/SENT?"

### Fee Bounds (REQUIRED for percentage parameters)
For EACH fee/percentage parameter:
- Generate FEE_BOUND invariant: "feePercentage must be < 100"
- 100% fee = all value extracted, nothing for users
- Check boundary: `<= 100` allows 100% which may be unintended

### Distribution Completeness (REQUIRED for payment functions)
For EACH function receiving ETH:
- Generate ECONOMIC invariant: "platformFee + userPayout + reserve == msg.value"
- Verify no ETH is silently dropped or stuck
- Check: what happens to excess if user overpays?
""",
                checklist=[
                    "Every msg.value usage has VALUE_FLOW invariant specifying correct variable",
                    "Every fee percentage has FEE_BOUND invariant (< 100)",
                    "Payment distribution sums verified (no ETH lost)",
                    "State progression formulas checked (fee/rate updates use correct base value)",
                ],
            ),
            LensDefinition(
                name="precision",
                description="Arithmetic precision, rounding, overflow",
                invariant_types=["PRECISION"],
                prompt_template="""
## PRECISION LENS - Solidity

Focus on arithmetic precision and rounding behavior.

### Division Operations (REQUIRED for each division)
For EACH division operation found:
- Rounding direction: Solidity truncates toward zero (floor for positive)
- Generate PRECISION invariant: "Division at [location] rounds [direction]"
- Maximum precision loss per operation (in wei)
- Who benefits from rounding: protocol or user?

### Operation Ordering
Check for precision-losing patterns:
- BAD: (a / b) * c  - divides first, loses precision
- GOOD: (a * c) / b - multiplies first, preserves precision
- Generate invariant if bad pattern found

### Cumulative Effects
If multiple operations in a flow:
- Can precision loss be exploited via many small transactions?
- Generate invariant for acceptable cumulative loss bounds
""",
                checklist=[
                    "Every division operation has PRECISION invariant",
                    "Division ordering checked for precision loss",
                    "Cumulative rounding bounds specified if applicable",
                ],
            ),
            LensDefinition(
                name="liveness",
                description="State transitions, protocol progression, DoS prevention",
                invariant_types=["LIVENESS", "REACHABILITY"],
                prompt_template="""
## LIVENESS LENS - Solidity

Focus on protocol liveness and state reachability.

### Function Availability (LIVENESS)
For EACH critical state-changing function:
- Generate LIVENESS invariant: "Function X remains callable when [conditions]"
- Check: Can it be permanently DoS'd?
- Check: Are there conditions that brick the function forever?

### State Reachability (REACHABILITY)
Analyze the protocol state machine:
- Generate REACHABILITY invariant: "Terminal state is reachable from initial state"
- Check: What if no one interacts for a long time?
- Check: Can admin reset/recover if needed?

### Deadlock Detection
Identify potential deadlock scenarios:
- What if expected actor never acts?
- What if a required condition can never be met?
- Example: "What if no one claims before gracePeriod expires?"
- Generate invariant for each potential deadlock

### Time-Gated Actions (CRITICAL - often missed)
For EACH function that should only work during a specific time window:
- Generate LIVENESS invariant: "Function X must revert after [deadline/expiry]"
- Check: Does the function verify the time window is still open?
- Common bug: Function remains callable AFTER the window should have closed
- Example patterns to check:
  - `claimThrone` should fail after grace period expires (game ended)
  - `bid` should fail after auction ends
  - `deposit` should fail after funding period closes
- The bug: Code allows actions that should be blocked once deadline passes
""",
                checklist=[
                    "Critical functions have LIVENESS invariants",
                    "Protocol can reach terminal state from any valid state",
                    "No deadlock states identified (or invariants for prevention)",
                    "Time-gated functions checked for proper deadline enforcement",
                ],
            ),
            LensDefinition(
                name="information",
                description="Information exposure, MEV, timing attacks",
                invariant_types=["INFORMATION"],
                prompt_template="""
## INFORMATION LENS - Solidity/DeFi

Focus on information exposure, view function correctness, and timing attacks.

### View Function Correctness (REQUIRED)
For EACH public view function that computes and returns a value:
- Generate invariant: "Function X must return accurate [description]"
- Check arithmetic: can `lastClaimTime + gracePeriod` overflow?
- Check edge cases: what happens when denominator is 0?
- Check consistency: does returned value match what state-changing functions use?
- Example bugs:
  - `getRemainingTime` returns wrong value due to arithmetic order
  - `getBalance` doesn't account for pending withdrawals
  - Comparison uses >= when > is correct for boundary

### Arithmetic Boundary Conditions (CRITICAL for timing functions)
For EACH view function doing time arithmetic (deadline - block.timestamp):
- Generate invariant for EACH boundary case:
  - "getRemainingTime must return 0 when deadline has passed (not underflow)"
  - "getRemainingTime must return correct value at exact deadline moment"
- Check subtraction order: `deadline - now` underflows if `now > deadline`
- Check boundary comparisons:
  - `>=` vs `>` matters at exact boundary!
  - Example: `if (now >= deadline)` vs `if (now > deadline)` - one off-by-one
- Common bugs:
  - Missing check for "deadline already passed" returns garbage/reverts
  - Returns (deadline - now) when now > deadline causing underflow
  - Wrong comparison operator at exact deadline second

### View Function Analysis (for sensitive data)
For EACH public view function that returns sensitive data:
- Does it expose timing that enables front-running?
- Does it expose state that creates unfair advantage for bots?
- Is the information asymmetry intentional?

### MEV Considerations
Check for MEV-enabling patterns:
- Predictable deadlines or timing
- Observable pending state
- Deterministic ordering benefits

### Timing Attacks
For time-based mechanics:
- Can deadline be precisely calculated externally?
- Can bots snipe at exact moments humans cannot?

Note: This lens FLAGS concerns for human review.
Not all findings are bugs - some are design tradeoffs.

Generate INFORMATION invariant for each concern found.
""",
                checklist=[
                    "Every view function computing values has correctness invariant",
                    "Arithmetic edge cases checked (overflow, div-by-zero, boundaries)",
                    "Timing-sensitive view functions flagged for MEV",
                    "Information asymmetry concerns noted",
                ],
            ),
        ]

    def get_function_metadata_extractors(self) -> Dict[str, Callable]:
        """
        Solidity-specific metadata extractors.

        These are called for each function to populate metadata used for bucketing.
        """

        def extract_is_payable(node: Node, graph: "DependencyGraph") -> bool:
            return node.meta.get("is_payable", False)

        def extract_has_access_modifier(node: Node, graph: "DependencyGraph") -> bool:
            modifiers = node.meta.get("modifiers", [])
            access_patterns = {
                "onlyOwner",
                "onlyAdmin",
                "onlyRole",
                "requiresAuth",
                "auth",
                "onlyGuardian",
                "onlyOperator",
                "onlyMinter",
            }
            return bool(set(modifiers) & access_patterns)

        def extract_has_external_call(node: Node, graph: "DependencyGraph") -> bool:
            return node.meta.get("has_external_call", False)

        def extract_has_division(node: Node, graph: "DependencyGraph") -> bool:
            return node.meta.get("has_division", False)

        def extract_has_percentage_calc(node: Node, graph: "DependencyGraph") -> bool:
            name_lower = node.name.lower()
            return any(p in name_lower for p in ["percent", "fee", "rate", "ratio"])

        def extract_is_view_function(node: Node, graph: "DependencyGraph") -> bool:
            mutability = node.meta.get("state_mutability", "")
            visibility = node.meta.get("visibility", "")
            return mutability in ["view", "pure"] and visibility in [
                "public",
                "external",
            ]

        def extract_returns_timing(node: Node, graph: "DependencyGraph") -> bool:
            name_lower = node.name.lower()
            timing_patterns = [
                "time",
                "remaining",
                "deadline",
                "block",
                "timestamp",
                "duration",
            ]
            return any(p in name_lower for p in timing_patterns)

        def extract_touches_value_state(node: Node, graph: "DependencyGraph") -> bool:
            writes = node.meta.get("writes", [])
            reads = node.meta.get("reads", [])
            all_vars = [
                v.lower() if isinstance(v, str) else str(v).lower()
                for v in writes + reads
            ]
            value_patterns = [
                "balance",
                "amount",
                "fee",
                "value",
                "price",
                "pot",
                "stake",
                "reward",
            ]
            return any(p in var for var in all_vars for p in value_patterns)

        def extract_modifies_game_state(node: Node, graph: "DependencyGraph") -> bool:
            writes = node.meta.get("writes", [])
            writes_lower = [
                w.lower() if isinstance(w, str) else str(w).lower() for w in writes
            ]
            state_patterns = [
                "ended",
                "active",
                "paused",
                "state",
                "phase",
                "round",
                "winner",
                "started",
            ]
            return any(p in w for w in writes_lower for p in state_patterns)

        def extract_is_state_transition(node: Node, graph: "DependencyGraph") -> bool:
            name_lower = node.name.lower()
            transition_patterns = [
                "start",
                "end",
                "reset",
                "finalize",
                "declare",
                "conclude",
                "initialize",
            ]
            return any(p in name_lower for p in transition_patterns)

        return {
            "is_payable": extract_is_payable,
            "has_access_modifier": extract_has_access_modifier,
            "has_external_call": extract_has_external_call,
            "has_division": extract_has_division,
            "has_percentage_calc": extract_has_percentage_calc,
            "is_view_function": extract_is_view_function,
            "returns_timing": extract_returns_timing,
            "touches_value_state": extract_touches_value_state,
            "modifies_game_state": extract_modifies_game_state,
            "is_state_transition": extract_is_state_transition,
        }
