"""
ActorProcess: Grounded, hallucination-free ActorMatrix generation.

This process generates an ActorMatrix by:
1. Enumerating protocol entrypoints (attack surface)
2. Collecting access evidence from graph edges (ACCEPTS), filtering non-auth guards
3. Clustering entrypoints by access signature (using container.name tokens)
4. LLM assigns trust levels based on actual privileges (state writes, critical operations)
5. Building the final ActorMatrix with evidence anchors

All privileges are grounded to node IDs, never bare names.
LLM only interprets privilege impact - cannot hallucinate privileges.
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from kai.inference import (
    create_openai_client,
    get_model_pricing,
    _get_extra_body,
    _extract_usage,
)
from kai.processes.base import BaseProcess
from kai.schemas import (
    ActorMatrix,
    ActorMatrixInput,
    ActorMatrixOutput,
    ActorMatrixRole,
    Privilege,
    ProtocolManifesto,
    RoleEvidence,
)
from kai.utils.dependency.adapters import DomainAdapter, get_adapter
from kai.utils.dependency.analysis import FileSourceLoader, GraphQueryEngine, NodeRef
from kai.utils.dependency.graph import DependencyGraph
from kai.utils.dependency.models import EdgeKind

# Load prompt template
PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "actor_role_assignment.txt"
ROLE_ASSIGNMENT_PROMPT = PROMPT_PATH.read_text() if PROMPT_PATH.exists() else ""


class ActorProcess(BaseProcess[ActorMatrixInput, ActorMatrixOutput]):
    """
    Process to generate a grounded ActorMatrix from a DependencyGraph.

    Uses LLM to assign trust levels based on actual privileges (state writes).
    All privilege data is deterministically extracted - LLM only interprets impact.
    """

    async def execute(self, input_data: ActorMatrixInput) -> ActorMatrixOutput:
        ctx = input_data.master_context
        graph = input_data.dependency_graph
        manifesto = input_data.protocol_manifesto

        if graph is None:
            return ActorMatrixOutput(
                success=False,
                error_message="No dependency graph provided",
            )

        # Get adapter from master context using central registry
        try:
            self.adapter: DomainAdapter = get_adapter(ctx.adapter)
        except ValueError as e:
            return ActorMatrixOutput(
                success=False,
                error_message=str(e),
            )

        # Build query engine
        engine = self._build_engine(graph, ctx.root_path)

        try:
            # Step 1: Enumerate protocol entrypoints
            entrypoints = engine.protocol_entrypoints()
            self.logger.info(f"Found {len(entrypoints)} protocol entrypoints")

            if not entrypoints:
                return ActorMatrixOutput(
                    success=True,
                    actor_matrix=ActorMatrix(
                        roles=[],
                        stats={
                            "total_entrypoints": 0,
                            "unprotected_stateful": 0,
                            "unprotected_readonly": 0,
                        },
                    ),
                )

            # Step 2-4: Collect evidence, build signatures, cluster
            access_data = self._collect_access_evidence(engine, entrypoints)
            signatures = self._build_signatures(access_data)
            clusters = self._cluster_by_signature(signatures)
            self.logger.info(f"Created {len(clusters)} clusters")

            # Step 5: Build evidence
            evidence_map = self._build_evidence(engine, clusters, access_data)

            # Step 6: LLM assigns trust based on privileges
            role_assignments, llm_cost, llm_tokens = await self._assign_roles_with_llm(
                clusters=clusters,
                access_data=access_data,
                manifesto=manifesto,
                model_name=input_data.model_name,
                use_openai=input_data.use_openai,
            )

            # Step 7: Build final matrix
            actor_matrix = self._build_actor_matrix(
                clusters=clusters,
                role_assignments=role_assignments,
                access_data=access_data,
                evidence_map=evidence_map,
            )

            return ActorMatrixOutput(
                actor_matrix=actor_matrix,
                success=True,
                estimated_cost=llm_cost,
                total_tokens=llm_tokens,
            )

        except Exception as e:
            self.logger.error(f"ActorProcess failed: {e}", exc_info=True)
            return ActorMatrixOutput(
                success=False,
                error_message=str(e),
            )

    def _build_engine(self, graph: DependencyGraph, root_path: str) -> GraphQueryEngine:
        """Build a GraphQueryEngine for the given graph."""
        source_loader = FileSourceLoader(root_path)
        return GraphQueryEngine(
            graph=graph, adapter=self.adapter, source_loader=source_loader
        )

    def _collect_access_evidence(
        self,
        engine: GraphQueryEngine,
        entrypoints: List[NodeRef],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Step 2: For each entrypoint, collect access controls and state writes.

        Filters out non-auth guards (nonReentrant, whenNotPaused, etc.)

        Returns: {ep_id: {ref, controls, auth_controls, writes, write_targets}}
        """
        access_data = {}

        for ep in entrypoints:
            # Get ALL modifiers via ACCEPTS edges
            all_controls = engine.neighbors(ep.id, [EdgeKind.ACCEPTS], "out")

            # Filter out non-auth guards (reentrancy, pause, etc.)
            auth_controls = [
                c for c in all_controls if not self.adapter.is_non_auth_guard(c.name)
            ]

            # Get state variables written
            writes = engine.neighbors(ep.id, [EdgeKind.WRITES], "out")

            access_data[ep.id] = {
                "ref": ep,
                "all_controls": all_controls,  # All modifiers (for reference)
                "auth_controls": auth_controls,  # Only auth-related modifiers
                "writes": writes,  # List[NodeRef] of state vars
                "write_targets": [w.name for w in writes],  # Var names (display)
                "write_target_ids": [w.id for w in writes],  # Var node IDs (matching)
            }

        return access_data

    def _build_signatures(
        self,
        access_data: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Tuple[str, ...]]:
        """
        Step 3: Build normalized access signature per entrypoint.

        Uses container.name for tokens to disambiguate modifiers from different contracts.

        Returns: {ep_id: ("Contract.modifier1", "Contract.modifier2", ...)}
        """
        signatures = {}

        for ep_id, data in access_data.items():
            # Use container.name for disambiguation
            modifier_tokens = []
            for c in data["auth_controls"]:
                # Include container to disambiguate same-name modifiers
                token = f"{c.container}.{c.name}" if c.container else c.name
                modifier_tokens.append(token)

            # Sort for consistent clustering
            signatures[ep_id] = tuple(sorted(modifier_tokens))

        return signatures

    def _cluster_by_signature(
        self,
        signatures: Dict[str, Tuple[str, ...]],
    ) -> Dict[Tuple[str, ...], List[str]]:
        """
        Step 4: Group entrypoints by access signature.

        Returns: {signature_tuple: [ep_id1, ep_id2, ...]}
        """
        clusters: Dict[Tuple[str, ...], List[str]] = defaultdict(list)

        for ep_id, sig in signatures.items():
            clusters[sig].append(ep_id)

        return dict(clusters)

    def _build_evidence(
        self,
        engine: GraphQueryEngine,
        clusters: Dict[Tuple[str, ...], List[str]],
        access_data: Dict[str, Dict[str, Any]],
    ) -> Dict[str, List[RoleEvidence]]:
        """
        Step 5: Build evidence anchors for top 3 functions per cluster (by writes).

        Includes control body snippets for each modifier used.

        Returns: {signature_key: [RoleEvidence, ...]}
        """
        evidence_map = {}

        for sig, ep_ids in clusters.items():
            sig_key = ",".join(sig) if sig else "__unprotected__"

            # Sort by number of writes (highest first)
            sorted_eps = sorted(
                ep_ids,
                key=lambda eid: len(access_data[eid]["writes"]),
                reverse=True,
            )

            # Take top 3
            representatives = sorted_eps[:3]
            evidence_list = []

            for ep_id in representatives:
                data = access_data[ep_id]

                # Get location for snippet reference
                loc = engine.loc(ep_id)

                # Build modifier info with control body snippets
                modifier_details = []
                for ctrl in data["auth_controls"]:
                    ctrl_loc = engine.loc(ctrl.id)
                    modifier_info = {
                        "name": ctrl.name,
                        "container": ctrl.container,
                        "file": ctrl_loc.get("file"),
                        "lines": [ctrl_loc["span"]["start"], ctrl_loc["span"]["end"]]
                        if ctrl_loc.get("span")
                        else None,
                    }
                    modifier_details.append(modifier_info)

                evidence_list.append(
                    RoleEvidence(
                        function_id=ep_id,
                        modifiers=[c.name for c in data["auth_controls"]],
                        snippet_file=loc.get("file"),
                        snippet_lines=[loc["span"]["start"], loc["span"]["end"]]
                        if loc.get("span")
                        else None,
                        # Store modifier details in a separate field if needed
                    )
                )

            evidence_map[sig_key] = evidence_list

        return evidence_map

    async def _assign_roles_with_llm(
        self,
        clusters: Dict[Tuple[str, ...], List[str]],
        access_data: Dict[str, Dict[str, Any]],
        manifesto: Optional[ProtocolManifesto],
        model_name: str,
        use_openai: bool,
    ) -> Tuple[Dict[str, Dict[str, Any]], float, Dict[str, int]]:
        """
        Use LLM to assign trust levels based on actual privileges.

        The LLM receives grounded privilege data (what state each role can write)
        and returns trust assignments with reasoning.

        Returns: (assignments_dict, cost, tokens)
        """
        # Build the prompt with privilege summaries per cluster
        cluster_summaries = []
        for sig, ep_ids in clusters.items():
            sig_key = ",".join(sig) if sig else "__unprotected__"

            # Collect all state writes for this cluster
            all_writes: set[str] = set()
            functions: list[str] = []
            for ep_id in ep_ids:
                data = access_data[ep_id]
                ref = data["ref"]
                functions.append(
                    f"{ref.container}.{ref.name}" if ref.container else ref.name
                )
                all_writes.update(data["write_targets"])

            # Take representative functions (first 5)
            func_sample = functions[:5]
            if len(functions) > 5:
                func_sample.append(f"... and {len(functions) - 5} more")

            cluster_summaries.append(
                {
                    "signature_key": sig_key,
                    "modifiers": list(sig) if sig else ["(none - unprotected)"],
                    "function_count": len(ep_ids),
                    "functions": func_sample,
                    "state_writes": sorted(all_writes)
                    if all_writes
                    else ["(none - read-only)"],
                }
            )

        # Build protocol context
        protocol_context = ""
        if manifesto:
            protocol_context = f"""Protocol: {manifesto.name}
Purpose: {manifesto.purpose}
Domain: {manifesto.domain}"""

        # Format the prompt template
        prompt = ROLE_ASSIGNMENT_PROMPT.format(
            protocol_context=protocol_context,
            cluster_summaries=json.dumps(cluster_summaries, indent=2),
        )

        client = create_openai_client(use_openai=use_openai)

        response = await client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,  # Deterministic
            extra_body=_get_extra_body(use_openai),
        )

        # Parse response
        content = response.choices[0].message.content or ""

        json_str = content
        if "```json" in content:
            json_str = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            json_str = content.split("```")[1].split("```")[0].strip()

        try:
            assignments_list: List[Dict[str, Any]] = json.loads(json_str)
        except json.JSONDecodeError:
            self.logger.warning(
                f"Failed to parse LLM response, using fallback: {content[:200]}"
            )
            # Fallback to deterministic assignment
            return self._assign_roles_fallback(clusters), 0.0, {}

        # Convert to dict keyed by signature_key
        assignments = {}
        for item in assignments_list:
            sig_key = item.get("signature_key", "")
            assignments[sig_key] = {
                "name": item.get("name", "Unknown"),
                "trust": item.get("trust", "medium"),
                "reasoning": item.get("reasoning", ""),
            }

        # Calculate cost
        tokens = _extract_usage(response.usage)

        # Prefer API-provided cost, fall back to calculated
        if "cost" in tokens and tokens["cost"] is not None:
            cost = tokens["cost"]
        else:
            pricing = get_model_pricing(model_name, use_openai)
            cost = (
                tokens["prompt_tokens"] * pricing["prompt"]
                + tokens["completion_tokens"] * pricing["completion"]
            )

        return assignments, cost, tokens

    def _assign_roles_fallback(
        self,
        clusters: Dict[Tuple[str, ...], List[str]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Fallback: Assign role names and trust levels deterministically using the adapter.

        Used when LLM call fails.

        Returns: {signature_key: {"name": "Owner", "trust": "high", "reasoning": ""}}
        """
        assignments = {}

        for sig, ep_ids in clusters.items():
            sig_key = ",".join(sig) if sig else "__unprotected__"

            # Extract just the modifier names (without container prefix) for trust lookup
            modifier_names = [s.split(".")[-1] for s in sig] if sig else []

            # Adapter determines trust
            trust = self.adapter.get_trust_for_modifiers(modifier_names)

            # Derive name from modifier
            if not sig:
                name = "User"
            elif len(modifier_names) == 1:
                # Strip common prefixes to get cleaner name
                raw_name = modifier_names[0]
                name = raw_name.replace("only", "").replace("Only", "")
                name = name if name else "Protected"
            else:
                # Multiple modifiers - combine them
                name = "_".join(
                    m.replace("only", "").replace("Only", "") for m in modifier_names
                )
                name = name if name else "MultiGuard"

            assignments[sig_key] = {
                "name": name,
                "trust": trust,
                "reasoning": "(fallback - LLM unavailable)",
            }

        return assignments

    def _build_actor_matrix(
        self,
        clusters: Dict[Tuple[str, ...], List[str]],
        role_assignments: Dict[str, Dict[str, Any]],
        access_data: Dict[str, Dict[str, Any]],
        evidence_map: Dict[str, List[RoleEvidence]],
    ) -> ActorMatrix:
        """
        Step 7: Assemble the final ActorMatrix.

        Splits unprotected into stateful vs readonly.
        """
        roles = []
        total_entrypoints = 0
        unprotected_stateful = 0
        unprotected_readonly = 0
        review_required_count = 0

        for sig, ep_ids in clusters.items():
            sig_key = ",".join(sig) if sig else "__unprotected__"
            assignment = role_assignments.get(
                sig_key, {"name": "Unknown", "trust": "review_required"}
            )

            # Build privileges
            privileges = []
            risk_score = 0

            for ep_id in ep_ids:
                data = access_data[ep_id]
                ref = data["ref"]
                writes = data["writes"]
                write_targets = data["write_targets"]
                write_target_ids = data["write_target_ids"]

                privileges.append(
                    Privilege(
                        id=ep_id,
                        name=ref.name,
                        container=ref.container or "",
                        signature=ref.signature,
                        file=ref.file,
                        writes_state=bool(writes),
                        write_targets=write_targets,
                        write_target_ids=write_target_ids,
                    )
                )

                risk_score += len(writes)

                # Track unprotected stateful vs readonly
                if not sig:  # Empty signature = unprotected
                    if writes:
                        unprotected_stateful += 1
                    else:
                        unprotected_readonly += 1

            total_entrypoints += len(ep_ids)

            if assignment.get("trust") == "review_required":
                review_required_count += len(ep_ids)

            roles.append(
                ActorMatrixRole(
                    name=assignment.get("name", "Unknown"),
                    trust=assignment.get("trust", "review_required"),
                    reasoning=assignment.get("reasoning", ""),
                    access_signature=list(sig),
                    privileges=privileges,
                    evidence=evidence_map.get(sig_key, []),
                    risk_score=risk_score,
                )
            )

        # Sort roles by trust level (high risk first)
        trust_order = {
            "high": 0,
            "medium": 1,
            "low": 2,
            "review_required": 3,
            "none": 4,
        }
        roles.sort(key=lambda r: (trust_order.get(r.trust, 5), -r.risk_score))

        return ActorMatrix(
            roles=roles,
            stats={
                "total_entrypoints": total_entrypoints,
                "unprotected_stateful": unprotected_stateful,
                "unprotected_readonly": unprotected_readonly,
                "review_required_count": review_required_count,
            },
        )
