"""
ActorAnalysisProcess - Analyzes smart contract actor roles and access control.

Six-step workflow:
1. Graph Filtering: Extract actor roles via get_actor_roles()
2. Guard Issue Detection: Detect guard issues (tx.origin, impossible guards)
3. Privilege Chain Tracing: Trace cross-contract privilege chains
4. Actor Building: Build actors with full contract coverage (direct + inheritance + delegation)
5. Heuristic Scan: Pattern matching for suspicious unprotected functions
6. Targeted LLM Review: Single inference call only for flagged suspicious functions
"""

import json
from typing import Dict

from kai.inference import get_model_pricing, get_model_response
from kai.processes.base import BaseProcess
from kai.schemas import (
    Actor,
    ActorAnalysisInput,
    ActorReport,
    LLMReviewResult,
    PrivilegeChain,
    SuspiciousFunction,
)
from kai.utils.dependency import DependencyAnalysis, DependencyGraph, EdgeKind


class ActorAnalysisProcess(BaseProcess[ActorAnalysisInput, ActorReport]):
    """
    Process to analyze actor roles and access control patterns.

    Output is consumed by InvariantAnalysis to generate access control invariants.
    """

    async def execute(self, input_data: ActorAnalysisInput) -> ActorReport:
        graph: DependencyGraph = input_data.graph

        # Create DependencyAnalysis wrapper (handles caching internally)
        analysis = DependencyAnalysis(graph, slither=input_data.slither)

        # Step 1: Graph Filtering - Extract actor roles
        self.logger.info("Step 1: Extracting actor roles from graph...")
        raw_roles = analysis.get_actor_roles()

        # Step 2: Detect guard issues
        self.logger.info("Step 2: Detecting guard issues...")
        guard_issues = analysis.detect_guard_issues()
        guard_issues_dicts = [gi.to_dict() for gi in guard_issues]
        self.logger.info(f"Found {len(guard_issues)} guard issues")

        # Step 3: Trace privilege chains (needed before building actors)
        self.logger.info("Step 3: Tracing cross-contract privilege chains...")
        privilege_chains = analysis.trace_privilege_chains()
        self.logger.info(f"Found {len(privilege_chains)} privilege chains")

        # Step 4: Build actors with full contract coverage from chains
        self.logger.info("Step 4: Building actors with privilege chain enrichment...")
        actors = self._build_actors(graph, raw_roles, privilege_chains)

        # Enrich actors with indirect privileges from chains
        self._enrich_indirect_privileges(actors, privilege_chains)
        total_indirect = sum(len(a.indirect_privileges) for a in actors)
        self.logger.info(
            f"Enriched {len(actors)} actors with {total_indirect} indirect privileges"
        )

        # Count functions
        total_public = len(graph.public_entrypoints())
        protected = sum(a.function_count for a in actors if a.trust_level != "None")
        unprotected = total_public - protected

        self.logger.info(
            f"Found {len(actors)} actor roles, {total_public} public functions "
            f"({protected} protected, {unprotected} unprotected)"
        )

        # Step 5: Heuristic scan for suspicious functions
        self.logger.info("Step 5: Scanning for suspicious functions...")
        # Get source code from Slither if available
        source_code = None
        if input_data.slither:
            source_code = getattr(input_data.slither, "source_code", None)

        suspicious_raw = analysis.scan_suspicious_functions(source_code)
        suspicious_functions = [SuspiciousFunction(**s) for s in suspicious_raw]
        self.logger.info(f"Found {len(suspicious_functions)} suspicious functions")

        # Step 6: Targeted LLM Review (if enabled and there are suspicious functions)
        llm_invoked = False
        llm_tokens_used: Dict[str, int] = {}
        llm_cost_estimate = 0.0
        llm_review_results: list[LLMReviewResult] = []

        if (
            input_data.enable_llm_review
            and suspicious_functions
            and len(suspicious_functions) <= input_data.max_suspicious_for_llm
        ):
            self.logger.info(
                f"Step 6: LLM review of {len(suspicious_functions)} suspicious functions..."
            )
            llm_invoked = True

            llm_review_results, llm_tokens_used = await self._llm_review(
                suspicious_functions=suspicious_functions,
                actors=actors,
                model_name=input_data.model_name,
                use_openai=input_data.use_openai,
            )

            # Calculate cost
            pricing = get_model_pricing(input_data.model_name, input_data.use_openai)
            llm_cost_estimate = llm_tokens_used.get("prompt_tokens", 0) * pricing.get(
                "prompt", 0
            ) + llm_tokens_used.get("completion_tokens", 0) * pricing.get(
                "completion", 0
            )

            self.logger.info(
                f"LLM review complete. Tokens: {llm_tokens_used}, Cost: ${llm_cost_estimate:.4f}"
            )
        elif (
            input_data.enable_llm_review
            and len(suspicious_functions) > input_data.max_suspicious_for_llm
        ):
            self.logger.warning(
                f"Skipping LLM review: {len(suspicious_functions)} suspicious functions "
                f"exceeds limit of {input_data.max_suspicious_for_llm}"
            )

        # Count confirmed issues
        confirmed_issues = len([r for r in llm_review_results if r.is_vulnerability])

        return ActorReport(
            actors=actors,
            privilege_chains=privilege_chains,
            guard_issues=guard_issues_dicts,
            suspicious_functions=suspicious_functions,
            llm_review_results=llm_review_results,
            llm_invoked=llm_invoked,
            llm_tokens_used=llm_tokens_used,
            llm_cost_estimate=llm_cost_estimate,
            total_public_functions=total_public,
            protected_functions=protected,
            unprotected_functions=unprotected,
            suspicious_count=len(suspicious_functions),
            confirmed_issues=confirmed_issues,
        )

    def _build_actors(
        self,
        graph: DependencyGraph,
        raw_roles: list,
        privilege_chains: list[PrivilegeChain],
    ) -> list[Actor]:
        """
        Convert raw ActorRole objects to Actor schema with complete contract coverage.

        Includes:
        - Contracts from direct privileges
        - Contracts from privilege chains (delegation targets)
        - Contracts from inheritance hierarchy
        """
        actors = []

        for role in raw_roles:
            contracts: set[str] = set()

            # 1. Direct: contracts where this actor has privileged functions
            for func_name in role.privileges:
                func_ids = graph.find_functions(func_name)
                for fid in func_ids:
                    node = graph._nodes.get(fid)
                    if node and node.contract and node.contract in graph._nodes:
                        contract_node = graph._nodes[node.contract]
                        contracts.add(contract_node.name)

                        # 2. Inheritance: add parent contracts (actor inherits access)
                        parent_ids = list(
                            graph.neighbors(
                                node.contract,
                                edge_kinds={EdgeKind.INHERITS},
                                direction="out",
                            )
                        )
                        for pid in parent_ids:
                            if pid in graph._nodes:
                                contracts.add(graph._nodes[pid].name)

            # 3. Delegation: contracts reachable via privilege chains from this role
            for chain in privilege_chains:
                if (
                    chain.source_role == role.role
                    or chain.source_function in role.privileges
                ):
                    contracts.add(chain.target_contract)
                    # Also add intermediate contracts in the call path
                    for step in chain.call_path:
                        if "." in step:
                            contract_name = step.split(".")[0]
                            contracts.add(contract_name)

            actors.append(
                Actor(
                    role=role.role,
                    trust_level=role.trust,
                    modifier_patterns=role.modifier_pattern,
                    direct_privileges=role.privileges,
                    indirect_privileges=[],  # Populated by _enrich_indirect_privileges
                    function_count=role.function_count,
                    contracts=sorted(contracts),
                )
            )

        return actors

    def _enrich_indirect_privileges(
        self,
        actors: list[Actor],
        privilege_chains: list[PrivilegeChain],
    ) -> None:
        """
        Populate indirect_privileges on actors from privilege chains.

        If Admin can call Vault.setStrategy() which calls Strategy.harvest(),
        then Admin has indirect privilege over harvest().
        """
        # Build role -> actor mapping
        actor_by_role: dict[str, Actor] = {a.role: a for a in actors}

        # Build function -> role mapping from direct privileges
        func_to_role: dict[str, str] = {}
        for actor in actors:
            for func in actor.direct_privileges:
                func_to_role[func] = actor.role

        # Traverse chains to find indirect privileges
        for chain in privilege_chains:
            # Find which role owns the source function
            source_role = chain.source_role or func_to_role.get(chain.source_function)

            if not source_role or source_role not in actor_by_role:
                continue

            actor = actor_by_role[source_role]

            # Add target function as indirect privilege (if not already direct)
            if (
                chain.target_function
                and chain.target_function not in actor.direct_privileges
            ):
                if chain.target_function not in actor.indirect_privileges:
                    actor.indirect_privileges.append(chain.target_function)

    async def _llm_review(
        self,
        suspicious_functions: list[SuspiciousFunction],
        actors: list[Actor],
        model_name: str,
        use_openai: bool,
    ) -> tuple[list[LLMReviewResult], Dict[str, int]]:
        """
        Single LLM call to review suspicious functions.

        Returns (results, tokens_used)
        """
        # Build context about actors
        actor_context = "\n".join(
            [
                f"- {a.role} (trust: {a.trust_level}): {a.function_count} functions, "
                f"modifiers: {a.modifier_patterns}"
                for a in actors
            ]
        )

        # Build suspicious functions list
        funcs_context = "\n".join(
            [
                f"- {sf.contract_name or 'Unknown'}.{sf.function_name} ({sf.visibility})\n"
                f"  File: {sf.file_path}\n"
                f"  Reason: {sf.reason}\n"
                f"  Patterns: {', '.join(sf.patterns_matched) if sf.patterns_matched else 'N/A'}"
                for sf in suspicious_functions
            ]
        )

        prompt = ACTOR_REVIEW_PROMPT.format(
            actor_context=actor_context,
            suspicious_functions=funcs_context,
            function_count=len(suspicious_functions),
        )

        response, tokens = await get_model_response(
            message=prompt,
            system_prompt=ACTOR_REVIEW_SYSTEM_PROMPT,
            model=model_name,
            use_openai=use_openai,
        )

        # Parse LLM response
        results = self._parse_llm_response(response, suspicious_functions)

        return results, tokens

    def _parse_llm_response(
        self,
        response: str,
        suspicious_functions: list[SuspiciousFunction],
    ) -> list[LLMReviewResult]:
        """Parse LLM JSON response into LLMReviewResult objects."""
        results = []

        try:
            # Try to extract JSON from response
            # Handle markdown code blocks
            clean_response = response
            if "```json" in response:
                json_start = response.find("```json") + 7
                json_end = response.find("```", json_start)
                clean_response = response[json_start:json_end].strip()
            elif "```" in response:
                json_start = response.find("```") + 3
                json_end = response.find("```", json_start)
                clean_response = response[json_start:json_end].strip()

            data = json.loads(clean_response)

            if isinstance(data, list):
                for item in data:
                    results.append(
                        LLMReviewResult(
                            function_name=item.get("function_name", ""),
                            contract_name=item.get("contract_name"),
                            is_vulnerability=item.get("is_vulnerability", False),
                            confidence=item.get("confidence", 0.5),
                            issue_type=item.get("issue_type"),
                            description=item.get("description", ""),
                            recommendation=item.get("recommendation"),
                        )
                    )
            elif isinstance(data, dict) and "functions" in data:
                for item in data["functions"]:
                    results.append(
                        LLMReviewResult(
                            function_name=item.get("function_name", ""),
                            contract_name=item.get("contract_name"),
                            is_vulnerability=item.get("is_vulnerability", False),
                            confidence=item.get("confidence", 0.5),
                            issue_type=item.get("issue_type"),
                            description=item.get("description", ""),
                            recommendation=item.get("recommendation"),
                        )
                    )
        except json.JSONDecodeError:
            self.logger.warning("Failed to parse LLM response as JSON")
            # Create placeholder results for each function
            for sf in suspicious_functions:
                results.append(
                    LLMReviewResult(
                        function_name=sf.function_name,
                        contract_name=sf.contract_name,
                        is_vulnerability=False,
                        confidence=0.0,
                        description="Failed to parse LLM response",
                    )
                )

        return results


# ---------------------------
# LLM Prompts
# ---------------------------

ACTOR_REVIEW_SYSTEM_PROMPT = """You are a smart contract security auditor specializing in access control analysis.

Your task is to review functions flagged as potentially having access control issues and determine:
1. Whether each function actually has a vulnerability
2. The type of issue (if any)
3. Your confidence level
4. Recommendations for fixing

Focus on:
- Missing access control (any user can call privileged functions)
- Weak access control (easily bypassable checks)
- Inconsistent access control (some paths protected, others not)
- Privilege escalation risks

Output your analysis as a JSON array."""

ACTOR_REVIEW_PROMPT = """# Access Control Analysis Request

## Known Actor Roles
{actor_context}

## Suspicious Functions ({function_count} total)
These functions were flagged by heuristic analysis as potentially having access control issues:

{suspicious_functions}

## Task
Analyze each suspicious function and determine if it has an actual access control vulnerability.

Return a JSON array with one object per function:
```json
[
  {{
    "function_name": "functionName",
    "contract_name": "ContractName",
    "is_vulnerability": true/false,
    "confidence": 0.0-1.0,
    "issue_type": "missing_access_control" | "weak_guard" | "privilege_escalation" | "false_positive" | null,
    "description": "Brief explanation of the finding",
    "recommendation": "How to fix (if vulnerability)"
  }}
]
```

Consider:
- Functions that write state without proper access control are HIGH priority
- Inline msg.sender checks without revert may be weak guards
- Some patterns may be intentional (e.g., permissionless deposits)

Be conservative: only mark as vulnerability if you're confident."""
