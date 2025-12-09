"""
Solidity-specific domain adapter for smart contract security analysis.

This adapter encapsulates all Solidity/EVM-specific knowledge:
- Access control modifiers (onlyOwner, onlyRole, etc.)
- Guard modifiers (nonReentrant, whenNotPaused)
- Inline access check patterns (msg.sender, require)
- Vulnerability patterns (tx.origin, impossible guards)
- Actor role extraction and trust inference
- Privilege chain tracing
"""

import re
from collections import defaultdict, deque
from typing import TYPE_CHECKING, Any

from .base import DomainAdapter, TrustLevel

if TYPE_CHECKING:
    from ..graph import DependencyGraph
    from ..models import ActorRole, GuardIssue


class SolidityAdapter(DomainAdapter):
    """
    Domain adapter for Solidity smart contracts.

    Supports frameworks: Foundry, Hardhat, Truffle, Brownie, Dapp
    """

    @property
    def name(self) -> str:
        return "solidity"

    @property
    def frameworks(self) -> list[str]:
        return ["foundry", "hardhat", "truffle", "brownie", "dapp", "remix"]

    def get_role_patterns(self) -> dict[str, tuple[str, TrustLevel]]:
        """
        Solidity modifier patterns and their inferred roles.

        Based on common OpenZeppelin and DeFi conventions.
        """
        return {
            # High trust - ownership/admin patterns
            "onlyOwner": ("Owner", "High"),
            "onlyAdmin": ("Admin", "High"),
            "onlyRole": ("RoleBased", "High"),
            "onlyGovernance": ("Governance", "High"),
            "onlyMinter": ("Minter", "High"),
            "onlyOperator": ("Operator", "Medium"),
            # Medium trust - operational patterns
            "onlyKeeper": ("Keeper", "Medium"),
            "onlyRelayer": ("Relayer", "Medium"),
            "onlyOracle": ("Oracle", "Medium"),
            "onlyStrategy": ("Strategy", "Medium"),
            "onlyVault": ("Vault", "Medium"),
            # Access control patterns (not roles themselves, but indicate protection)
            "whenNotPaused": ("Pausable", "N/A"),
            "nonReentrant": ("ReentrancyGuard", "N/A"),
            "initializer": ("Initializer", "High"),
            "reinitializer": ("Initializer", "High"),
        }

    def get_guard_patterns(self) -> set[str]:
        """
        Modifiers that are guards, not access control.

        These are filtered out when determining actor roles because
        they don't indicate WHO can call a function, just WHEN.
        """
        return {
            "whenNotPaused",
            "whenPaused",
            "nonReentrant",
            "noReentrancy",
            "lock",
            "locked",
        }

    def get_access_check_patterns(self) -> list[str]:
        """
        Regex patterns for inline access control checks in Solidity source.

        These patterns suggest a function has inline access control
        (rather than modifier-based) which may indicate:
        1. Intentional inline checks (common pattern)
        2. Potentially weaker/inconsistent access control
        """
        return [
            # Direct sender checks
            r"\bmsg\.sender\b",
            r"\b_msgSender\(\)",
            # Require statements with sender
            r"\brequire\s*\(\s*msg\.sender",
            r"\brequire\s*\(\s*_msgSender\(\)",
            # OpenZeppelin AccessControl
            r"\bhasRole\s*\(",
            r"\bonlyRole\b",
            # Owner checks
            r"\brequire\s*\([^)]*==\s*owner",
            r"\brequire\s*\([^)]*==\s*_owner",
            # If-based sender checks
            r"\bif\s*\(\s*msg\.sender\s*!=",
            r"\bif\s*\(\s*msg\.sender\s*==",
            # Custom error reverts (Solidity 0.8.4+)
            r"\brevert\s+\w*Unauthorized",
            r"\brevert\s+\w*NotOwner",
            r"\brevert\s+\w*NotAdmin",
            r"\brevert\s+\w*AccessDenied",
            r"\brevert\s+\w*Forbidden",
        ]

    def get_entrypoint_visibility(self) -> set[str]:
        """
        Solidity visibility keywords for public entrypoints.
        """
        return {"public", "external"}

    def detect_domain_issues(
        self,
        graph: "DependencyGraph",
        analyzer: Any = None,
    ) -> list["GuardIssue"]:
        """
        Detect Solidity-specific security issues.

        Patterns detected:
        - tx.origin == address(this): Always false, impossible condition
        - tx.origin in authorization: Phishing risk
        - Suspicious modifier names (onlySelf, onlyThis)
        """
        from ..models import GuardIssue

        issues: list[GuardIssue] = []

        # If we have Slither, do deep IR analysis
        if analyzer is not None:
            issues.extend(self._detect_tx_origin_issues(graph, analyzer))

        # Graph-based heuristics (work without Slither)
        issues.extend(self._detect_suspicious_modifier_patterns(graph))

        return issues

    def _detect_tx_origin_issues(
        self,
        graph: "DependencyGraph",
        slither: Any,
    ) -> list["GuardIssue"]:
        """Detect tx.origin issues using Slither IR."""
        from ..models import GuardIssue, GuardIssueType, NodeKind, Severity

        issues: list[GuardIssue] = []

        try:
            from slither.slithir.operations import Binary
            from slither.core.declarations import SolidityVariableComposed
        except ImportError:
            return issues

        for contract in getattr(slither, "contracts", []) or []:
            contract_name = str(getattr(contract, "name", ""))

            # Check functions and modifiers
            all_funcs = list(getattr(contract, "functions_declared", []) or [])
            all_funcs += list(getattr(contract, "modifiers_declared", []) or [])

            for func in all_funcs:
                func_name = str(getattr(func, "name", ""))
                is_modifier = hasattr(func, "is_modifier") or func_name in [
                    m.name for m in getattr(contract, "modifiers_declared", []) or []
                ]

                # Get source line if available
                line = None
                try:
                    sm = getattr(func, "source_mapping", None)
                    if sm:
                        line = getattr(sm, "lines", [None])[0]
                except Exception:
                    pass

                # Check for tx.origin usage
                uses_tx_origin = False
                compares_to_address_this = False

                for node in getattr(func, "nodes", []) or []:
                    for ir in getattr(node, "irs", []) or []:
                        # Check for tx.origin reads
                        if hasattr(ir, "read"):
                            for var in ir.read or []:
                                if isinstance(var, SolidityVariableComposed):
                                    if str(var) == "tx.origin":
                                        uses_tx_origin = True

                        # Check for comparison with address(this)
                        if isinstance(ir, Binary):
                            left = getattr(ir, "variable_left", None)
                            right = getattr(ir, "variable_right", None)

                            left_str = str(left) if left else ""
                            right_str = str(right) if right else ""

                            if "tx.origin" in left_str or "tx.origin" in right_str:
                                if (
                                    "address(this)" in left_str
                                    or "address(this)" in right_str
                                ):
                                    compares_to_address_this = True

                # Report issues found
                if compares_to_address_this:
                    func_id = self._find_func_id(graph, contract_name, func_name)
                    file_path = (
                        graph._nodes[func_id].file
                        if func_id and func_id in graph._nodes
                        else None
                    )

                    issues.append(
                        GuardIssue(
                            issue_type=GuardIssueType.TX_ORIGIN_ADDRESS_THIS,
                            severity=Severity.CRITICAL,
                            function_name=func_name,
                            function_id=func_id or f"{contract_name}.{func_name}",
                            modifier_name=func_name if is_modifier else None,
                            contract_name=contract_name,
                            file=file_path,
                            line=line,
                            description=(
                                "Comparison of tx.origin to address(this) is always false. "
                                "tx.origin can never equal a contract address in normal EVM execution."
                            ),
                            pattern="tx.origin == address(this) or tx.origin != address(this)",
                            recommendation=(
                                "Use msg.sender for access control. "
                                "If checking self-calls, use: if (msg.sender != address(this)) revert;"
                            ),
                        )
                    )

                elif uses_tx_origin:
                    func_id = self._find_func_id(graph, contract_name, func_name)
                    file_path = (
                        graph._nodes[func_id].file
                        if func_id and func_id in graph._nodes
                        else None
                    )

                    issues.append(
                        GuardIssue(
                            issue_type=GuardIssueType.TX_ORIGIN_IN_AUTH,
                            severity=Severity.MEDIUM,
                            function_name=func_name,
                            function_id=func_id or f"{contract_name}.{func_name}",
                            modifier_name=func_name if is_modifier else None,
                            contract_name=contract_name,
                            file=file_path,
                            line=line,
                            description=(
                                "tx.origin used in access control. This is vulnerable to phishing attacks "
                                "where a malicious contract tricks a user into calling it."
                            ),
                            pattern="tx.origin used for authorization",
                            recommendation="Use msg.sender instead of tx.origin for access control.",
                        )
                    )

        return issues

    def _detect_suspicious_modifier_patterns(
        self, graph: "DependencyGraph"
    ) -> list["GuardIssue"]:
        """Detect suspicious modifier patterns using graph data only."""
        from ..models import GuardIssue, GuardIssueType, NodeKind, Severity, EdgeKind

        issues: list[GuardIssue] = []

        # Look for modifiers with suspicious names that might have issues
        suspicious_names = ["onlyself", "onlythis", "selfonl", "internalonly"]

        for mod_id in graph.nodes(NodeKind.MODIFIER):
            mod = graph._nodes[mod_id]
            mod_name_lower = mod.name.lower()

            for sus in suspicious_names:
                if sus in mod_name_lower:
                    # Get functions using this modifier
                    protected_funcs = list(
                        graph.neighbors(
                            mod_id, edge_kinds={EdgeKind.USES_MODIFIER}, direction="in"
                        )
                    )

                    contract_name = None
                    if mod.contract and mod.contract in graph._nodes:
                        contract_name = graph._nodes[mod.contract].name

                    issues.append(
                        GuardIssue(
                            issue_type=GuardIssueType.UNSATISFIABLE_GUARD,
                            severity=Severity.HIGH,
                            function_name=mod.name,
                            function_id=mod_id,
                            modifier_name=mod.name,
                            contract_name=contract_name,
                            file=mod.file,
                            line=None,
                            description=(
                                f"Modifier '{mod.name}' has a suspicious name suggesting self-call restriction. "
                                f"Verify this guard is satisfiable. Protects {len(protected_funcs)} function(s)."
                            ),
                            pattern=f"Modifier named '{mod.name}'",
                            recommendation=(
                                "Verify the modifier logic. If checking self-calls, "
                                "ensure it uses msg.sender, not tx.origin."
                            ),
                        )
                    )
                    break

        return issues

    def _find_func_id(
        self, graph: "DependencyGraph", contract_name: str, func_name: str
    ) -> str | None:
        """Find function node ID by contract and function name."""
        from ..models import NodeKind

        for fid in graph.nodes(NodeKind.FUNCTION):
            node = graph._nodes[fid]
            if node.name == func_name:
                if node.contract and node.contract in graph._nodes:
                    if graph._nodes[node.contract].name == contract_name:
                        return fid
        # Fallback: try modifier
        for mid in graph.nodes(NodeKind.MODIFIER):
            node = graph._nodes[mid]
            if node.name == func_name:
                if node.contract and node.contract in graph._nodes:
                    if graph._nodes[node.contract].name == contract_name:
                        return mid
        return None

    # ---------------------------
    # Analysis Methods (Solidity-Specific)
    # ---------------------------

    def extract_actor_roles(
        self,
        graph: "DependencyGraph",
    ) -> list["ActorRole"]:
        """
        Extract actor roles based on Solidity modifier patterns.

        Groups functions by their modifier combinations and infers role semantics.
        """
        from ..models import ActorRole, EdgeKind, NodeKind

        role_patterns = self.get_role_patterns()
        guard_patterns = self.get_guard_patterns()
        entrypoint_visibility = self.get_entrypoint_visibility()

        # 1. Collect modifier usage per function
        function_to_modifiers: dict[str, list[str]] = defaultdict(list)

        for fid in graph.nodes(NodeKind.FUNCTION):
            fn = graph._nodes[fid]
            vis = (fn.visibility or "").lower()
            if vis not in entrypoint_visibility:
                continue
            if fn.meta.get("is_constructor", False):
                continue

            mod_ids = list(
                graph.neighbors(
                    fid, edge_kinds={EdgeKind.USES_MODIFIER}, direction="out"
                )
            )
            mod_names = [graph._nodes[mid].name for mid in mod_ids]

            if mod_names:
                function_to_modifiers[fn.name] = mod_names

        # 2. Group by access control modifier pattern (excluding guards)
        pattern_groups: dict[tuple[str, ...], list[str]] = defaultdict(list)
        for fn_name, mods in function_to_modifiers.items():
            access_mods = [m for m in mods if m not in guard_patterns]
            if access_mods:
                pattern_key = tuple(sorted(access_mods))
                pattern_groups[pattern_key].append(fn_name)

        # 3. Build ActorRole objects
        roles: list[ActorRole] = []

        for pattern, functions in sorted(
            pattern_groups.items(), key=lambda x: -len(x[1])
        ):
            role_name, trust = self.infer_role_from_pattern(pattern)

            roles.append(
                ActorRole(
                    role=role_name,
                    trust=trust,
                    modifier_pattern=list(pattern),
                    privileges=sorted(functions),
                    function_count=len(functions),
                )
            )

        # 4. Add unprotected public functions as "User" role
        unprotected = []
        for fid in graph.nodes(NodeKind.FUNCTION):
            fn = graph._nodes[fid]
            vis = (fn.visibility or "").lower()
            if vis in entrypoint_visibility and not fn.meta.get(
                "is_constructor", False
            ):
                if fn.name not in function_to_modifiers:
                    unprotected.append(fn.name)

        if unprotected:
            roles.append(
                ActorRole(
                    role="User",
                    trust="None",
                    modifier_pattern=[],
                    privileges=sorted(set(unprotected)),
                    function_count=len(set(unprotected)),
                )
            )

        return roles

    def scan_suspicious_functions(
        self,
        graph: "DependencyGraph",
        source_code: dict[str, str] | None = None,
    ) -> list[dict]:
        """
        Heuristic scan for Solidity functions with potential access control issues.

        Flags public/external functions WITHOUT modifiers that either:
        1. Contain access control patterns in their body (inline checks)
        2. Write to state variables
        """
        from ..models import EdgeKind, NodeKind

        guard_patterns = self.get_guard_patterns()
        access_check_patterns = self.get_access_check_patterns()
        entrypoint_visibility = self.get_entrypoint_visibility()

        suspicious: list[dict] = []
        entrypoints = graph.public_entrypoints()

        # Build set of functions with access control modifiers
        functions_with_modifiers: set[str] = set()
        for fid in entrypoints:
            mod_ids = list(
                graph.neighbors(
                    fid, edge_kinds={EdgeKind.USES_MODIFIER}, direction="out"
                )
            )
            access_mods = []
            for mid in mod_ids:
                if mid in graph._nodes:
                    mod_name = graph._nodes[mid].name
                    if mod_name not in guard_patterns:
                        access_mods.append(mod_name)
            if access_mods:
                functions_with_modifiers.add(fid)

        # Find unprotected functions
        unprotected = [
            fid for fid in entrypoints if fid not in functions_with_modifiers
        ]

        for fid in unprotected:
            node = graph._nodes[fid]
            contract_name = None
            if node.contract and node.contract in graph._nodes:
                contract_name = graph._nodes[node.contract].name

            patterns_matched: list[str] = []

            # Scan function body if source available
            if source_code and node.file and node.file in source_code:
                code = source_code[node.file]
                func_pattern = rf"\bfunction\s+{re.escape(node.name)}\s*\("
                match = re.search(func_pattern, code)
                if match:
                    start = match.start()
                    brace_count = 0
                    in_func = False
                    end = len(code)
                    for i, char in enumerate(code[start:], start):
                        if char == "{":
                            brace_count += 1
                            in_func = True
                        elif char == "}":
                            brace_count -= 1
                            if in_func and brace_count == 0:
                                end = i
                                break

                    func_body = code[start:end]

                    for pattern in access_check_patterns:
                        if re.search(pattern, func_body):
                            patterns_matched.append(pattern)

            # Check if function writes to state
            writes_state = (
                len(
                    list(
                        graph.neighbors(
                            fid, edge_kinds={EdgeKind.WRITES}, direction="out"
                        )
                    )
                )
                > 0
            )

            # Build reason
            reason = ""
            if patterns_matched:
                pattern_summary = ", ".join(patterns_matched[:3])
                if len(patterns_matched) > 3:
                    pattern_summary += f" (+{len(patterns_matched) - 3} more)"
                reason = (
                    f"Unprotected function with inline access checks: {pattern_summary}"
                )
            elif writes_state:
                reason = "Unprotected function that writes to state variables"

            if patterns_matched or writes_state:
                suspicious.append(
                    {
                        "function_name": node.name,
                        "function_id": fid,
                        "contract_name": contract_name,
                        "file_path": node.file,
                        "visibility": node.visibility or "public",
                        "patterns_matched": patterns_matched,
                        "has_modifier": False,
                        "reason": reason,
                        "writes_state": writes_state,
                    }
                )

        return suspicious

    def trace_privilege_chains(
        self,
        graph: "DependencyGraph",
        max_depth: int = 4,
    ) -> list[dict]:
        """
        Trace cross-contract privilege chains via HIGH_LEVEL_CALL edges.

        Finds patterns like: Keeper.harvest() -> Vault.report() -> Strategy.harvest()
        """
        from ..models import EdgeKind, NodeKind

        chains: list[dict] = []

        # Get actor roles for context
        roles = self.extract_actor_roles(graph)
        role_by_function: dict[str, str] = {}
        for role in roles:
            for func_name in role.privileges:
                role_by_function[func_name] = role.role

        entrypoint_visibility = self.get_entrypoint_visibility()

        # Find all functions that make HIGH_LEVEL_CALLs
        for src_id in graph.nodes(NodeKind.FUNCTION):
            src_node = graph._nodes[src_id]

            # Only consider public/external functions as chain starts
            vis = (src_node.visibility or "").lower()
            if vis not in entrypoint_visibility:
                continue

            # Get source contract
            src_contract = None
            if src_node.contract and src_node.contract in graph._nodes:
                src_contract = graph._nodes[src_node.contract].name

            if not src_contract:
                continue

            # BFS through HIGH_LEVEL_CALL edges
            visited: set[str] = {src_id}
            queue: deque[tuple[str, list[str], str]] = deque()
            queue.append((src_id, [f"{src_contract}.{src_node.name}"], src_contract))

            while queue:
                curr_id, path, curr_contract = queue.popleft()

                if len(path) > max_depth:
                    continue

                targets = list(
                    graph.neighbors(
                        curr_id, edge_kinds={EdgeKind.HIGH_LEVEL_CALL}, direction="out"
                    )
                )

                for target_id in targets:
                    if target_id in visited:
                        continue

                    target_node = graph._nodes.get(target_id)
                    if not target_node:
                        continue

                    # Determine target contract
                    target_contract = None
                    if target_node.kind == NodeKind.CONTRACT:
                        target_contract = target_node.name
                        target_func_name = ""
                    elif target_node.kind == NodeKind.FUNCTION:
                        if (
                            target_node.contract
                            and target_node.contract in graph._nodes
                        ):
                            target_contract = graph._nodes[target_node.contract].name
                        target_func_name = target_node.name
                    elif target_node.kind == NodeKind.EXTERNAL:
                        target_contract = target_node.name
                        target_func_name = ""
                    else:
                        continue

                    if not target_contract:
                        continue

                    # Only record if crossing contract boundary
                    if target_contract != curr_contract:
                        new_path = path + [
                            f"{target_contract}.{target_func_name}"
                            if target_func_name
                            else target_contract
                        ]

                        # Get edge metadata
                        can_send_eth = False
                        for src, kind, dst, meta_dict in graph.edges():
                            if kind == EdgeKind.HIGH_LEVEL_CALL and dst == target_id:
                                can_send_eth = meta_dict.get("can_send_eth", False)
                                break

                        chains.append(
                            {
                                "source_contract": src_contract,
                                "source_function": src_node.name,
                                "source_role": role_by_function.get(src_node.name),
                                "target_contract": target_contract,
                                "target_function": target_func_name,
                                "call_path": new_path,
                                "can_send_eth": can_send_eth,
                                "edge_count": len(new_path) - 1,
                            }
                        )

                        if target_node.kind == NodeKind.FUNCTION:
                            visited.add(target_id)
                            queue.append((target_id, new_path, target_contract))

        # Deduplicate chains
        seen: set[tuple[str, ...]] = set()
        unique_chains: list[dict] = []
        for chain in chains:
            key = tuple(chain["call_path"])
            if key not in seen:
                seen.add(key)
                unique_chains.append(chain)

        return sorted(unique_chains, key=lambda x: -x["edge_count"])

    def extract_var_names_from_rule(self, rule: str) -> list[str]:
        """
        Extract potential state variable names from an invariant rule string.

        Uses Solidity naming conventions:
        - camelCase: totalAssets, balanceOf
        - snake_case: total_supply
        - _prefixed: _balances, _owner
        """
        # Common patterns that are NOT variable names
        skip_patterns = {
            "must",
            "should",
            "not",
            "be",
            "callable",
            "by",
            "function",
            "only",
            "can",
            "cannot",
            "always",
            "never",
            "greater",
            "less",
            "equal",
            "than",
            "role",
            "admin",
            "owner",
            "user",
            "intended",
            "true",
            "false",
            "and",
            "or",
        }

        # Extract potential identifiers (camelCase, snake_case, or starting with _)
        candidates = re.findall(r"\b_?[a-z][a-zA-Z0-9_]*\b", rule)
        candidates = [c for c in candidates if c.lower() not in skip_patterns]

        # Also look for mapping-style accesses: variableName[
        mapping_candidates = re.findall(r"\b(_?[a-zA-Z][a-zA-Z0-9_]*)\s*\[", rule)
        candidates.extend(mapping_candidates)

        return list(set(candidates))
