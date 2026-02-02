"""
InvariantProcess: Lens-based invariant generation from ActorMatrix + DependencyGraph.

This process generates invariants by:
1. Building vocab tables from the graph (functions, vars, files)
2. Getting function metadata for bucketing
3. Using BucketingAgent to categorize functions into lens buckets
4. Per-lens LLM invariant generation with focused prompts
5. Validation to ensure all IDs exist in vocab
6. Merging/deduplication across lenses

LLM can only reference IDs from the provided vocabulary - cannot hallucinate locations.
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from kai.agents.agent_types.bucketing_agent import BucketingAgent
from kai.inference import (
    create_openai_client,
    get_model_pricing,
    _get_extra_body,
    _extract_usage,
)
from kai.processes.base import BaseProcess
from kai.schemas import (
    ActorMatrix,
    FileVocabEntry,
    FunctionVocabEntry,
    Invariant,
    InvariantProcessInput,
    InvariantProcessOutput,
    InvariantType,
    ProtocolManifesto,
    VarVocabEntry,
)
from kai.utils.dependency.adapters import DomainAdapter, get_adapter
from kai.utils.dependency.adapters.base import LensDefinition
from kai.utils.dependency.analysis import FileSourceLoader, GraphQueryEngine
from kai.utils.dependency.models import EdgeKind

# Load base prompt template
PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "invariant_generation.txt"
BASE_INVARIANT_PROMPT = PROMPT_PATH.read_text() if PROMPT_PATH.exists() else ""


class InvariantProcess(BaseProcess[InvariantProcessInput, InvariantProcessOutput]):
    """
    Process to generate grounded invariants using lens-based generation.

    Uses BucketingAgent to categorize functions, then generates focused
    invariants per lens using lens-specific prompts.
    """

    async def execute(
        self, input_data: InvariantProcessInput
    ) -> InvariantProcessOutput:
        ctx = input_data.master_context
        graph = input_data.dependency_graph
        actor_matrix = input_data.actor_matrix
        manifesto = input_data.protocol_manifesto

        if graph is None:
            return InvariantProcessOutput(
                success=False,
                error_message="No dependency graph provided",
            )

        # Get adapter
        try:
            self.adapter: DomainAdapter = get_adapter(ctx.adapter)
        except ValueError as e:
            return InvariantProcessOutput(
                success=False,
                error_message=str(e),
            )

        # Build query engine
        source_loader = FileSourceLoader(ctx.root_path)
        engine = GraphQueryEngine(
            graph=graph, adapter=self.adapter, source_loader=source_loader
        )

        try:
            # Step 1: Build vocab tables
            self.logger.info("Building vocabulary tables from graph...")
            vocab = self._build_vocab(engine, actor_matrix)
            self.logger.info(
                f"Vocab: {len(vocab['functions'])} functions, "
                f"{len(vocab['vars'])} vars, {len(vocab['files'])} files"
            )

            if not vocab["functions"]:
                return InvariantProcessOutput(
                    success=True,
                    invariants=[],
                    stats={
                        "total_generated": 0,
                        "validated": 0,
                        "dropped": 0,
                        "merged": 0,
                    },
                )

            # Step 2: Get function metadata for bucketing
            self.logger.info("Getting function metadata...")
            metadata_extractors = self.adapter.get_function_metadata_extractors()
            functions_with_metadata = engine.get_functions_with_metadata(
                metadata_extractors=metadata_extractors
            )
            self.logger.info(
                f"Got metadata for {len(functions_with_metadata)} functions"
            )

            # Step 3: Run BucketingAgent
            self.logger.info("Running BucketingAgent to categorize functions...")
            lens_definitions = self.adapter.get_lens_definitions()
            self.logger.info(f"Lenses: {[lens.name for lens in lens_definitions]}")
            buckets = await self._run_bucketing_agent(
                functions=functions_with_metadata,
                lens_definitions=lens_definitions,
                model_name=input_data.model_name,
                use_openai=input_data.use_openai,
            )

            self.logger.info(
                f"Bucketing complete: {', '.join(f'{k}={len(v)}' for k, v in buckets.items())}"
            )

            # Step 4: Per-lens invariant generation
            raw_invariants: List[Invariant] = []
            total_cost = 0.0
            total_tokens: Dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0}

            for lens in lens_definitions:
                lens_function_ids = buckets.get(lens.name, [])
                if not lens_function_ids:
                    self.logger.info(f"Skipping lens '{lens.name}' - no functions")
                    continue

                self.logger.info(
                    f"Generating invariants for lens '{lens.name}' ({len(lens_function_ids)} functions)..."
                )

                lens_invs, cost, tokens = await self._generate_invariants_for_lens(
                    lens=lens,
                    function_ids=lens_function_ids,
                    vocab=vocab,
                    manifesto=manifesto,
                    actor_matrix=actor_matrix,
                    model_name=input_data.model_name,
                    use_openai=input_data.use_openai,
                )

                raw_invariants.extend(lens_invs)
                total_cost += cost
                total_tokens["prompt_tokens"] += tokens.get("prompt_tokens", 0)
                total_tokens["completion_tokens"] += tokens.get("completion_tokens", 0)

            self.logger.info(f"Generated {len(raw_invariants)} raw invariants from LLM")

            # Step 4b: Synthesis pass - generate cross-function invariants from graph
            self.logger.info("Running synthesis pass for cross-function invariants...")
            synthesized = self._synthesize_cross_function_invariants(
                engine=engine,
                vocab=vocab,
                functions_with_metadata=functions_with_metadata,
            )
            if synthesized:
                self.logger.info(
                    f"Synthesized {len(synthesized)} additional invariants"
                )
                raw_invariants.extend(synthesized)
            else:
                self.logger.info("No cross-function invariants synthesized")

            self.logger.info(f"Total raw invariants: {len(raw_invariants)}")

            # Step 5: Validate
            valid_set = self._build_valid_id_sets(vocab)
            validated, dropped = self._validate_invariants(raw_invariants, valid_set)
            self.logger.info(f"Validated: {len(validated)}, Dropped: {dropped}")

            # Step 6: Merge/dedupe
            final_invariants = self._merge_invariants(validated)
            merged_count = len(validated) - len(final_invariants)
            self.logger.info(
                f"Final: {len(final_invariants)} invariants (merged {merged_count})"
            )

            return InvariantProcessOutput(
                invariants=final_invariants,
                success=True,
                estimated_cost=total_cost,
                total_tokens=total_tokens,
                stats={
                    "total_generated": len(raw_invariants),
                    "validated": len(validated),
                    "dropped": dropped,
                    "merged": merged_count,
                },
            )

        except Exception as e:
            self.logger.error(f"InvariantProcess failed: {e}", exc_info=True)
            return InvariantProcessOutput(
                success=False,
                error_message=str(e),
            )

    async def _run_bucketing_agent(
        self,
        functions: List[Dict[str, Any]],
        lens_definitions: List[LensDefinition],
        model_name: str,
        use_openai: bool,
    ) -> Dict[str, List[str]]:
        """
        Run the BucketingAgent to categorize functions into lens buckets.

        Returns: {lens_name: [function_ids]}
        """
        self.logger.info(f"Creating BucketingAgent for {len(functions)} functions")

        agent = BucketingAgent(
            functions=functions,
            lens_definitions=lens_definitions,
            model=model_name,
            use_openai=use_openai,
        )

        self.logger.info(f"BucketingAgent max_tool_turns: {agent.max_tool_turns}")

        try:
            task_message = agent.build_task_message()
            self.logger.info(f"Task message length: {len(task_message)} chars")
            self.logger.info("Starting BucketingAgent chat_with_tools...")

            # Run with progress logging
            await agent.chat_with_tools(task_message)

            # Log final results
            self.logger.info("BucketingAgent finished")
            self.logger.info(
                f"  Assigned: {len(agent.assigned_functions)}/{len(agent.all_function_ids)}"
            )
            self.logger.info(f"  Skipped: {len(agent.skipped_functions)}")
            for lens_name, func_ids in agent.buckets.items():
                self.logger.info(f"  {lens_name}: {len(func_ids)} functions")

            return agent.get_buckets()
        finally:
            await agent.close()

    def _build_vocab(
        self,
        engine: GraphQueryEngine,
        actor_matrix: ActorMatrix,
    ) -> Dict[str, List[Any]]:
        """
        Build vocabulary tables from graph + ActorMatrix.

        Includes protocol entrypoints AND their immediate callees (internal helpers)
        to ensure security-critical helper functions are in scope for invariant generation.

        Returns: {functions: [...], vars: [...], files: [...]}
        """
        # Build role lookup from ActorMatrix
        func_to_role: Dict[str, Tuple[str, str]] = {}  # func_id -> (role_name, trust)
        for role in actor_matrix.roles:
            for priv in role.privileges:
                func_to_role[priv.id] = (role.name, role.trust)

        # Get protocol entrypoints
        entrypoints = engine.protocol_entrypoints()
        entrypoint_ids = {ep.id for ep in entrypoints}

        # Expand to include immediate callees (internal helper functions)
        # This ensures functions like shouldRemoveHeader are included when
        # their caller (onHeaders) is an entrypoint
        callee_refs = []
        for ep in entrypoints:
            callees = engine.callees(ep.id)
            for callee in callees:
                # Only include callees that are in the same file (internal helpers)
                # and not already entrypoints
                if callee.id not in entrypoint_ids and callee.file == ep.file:
                    # Also skip library/test files for callees
                    if callee.file and not self.adapter.is_library_file(callee.file):
                        if not self.adapter.is_test_file(callee.file):
                            callee_refs.append(callee)
                            entrypoint_ids.add(callee.id)  # Avoid duplicates

        # Combine entrypoints and callees
        all_functions = list(entrypoints) + callee_refs

        functions: List[FunctionVocabEntry] = []
        vars_map: Dict[str, VarVocabEntry] = {}  # var_id -> entry
        files_map: Dict[str, Set[str]] = defaultdict(set)  # file -> contracts

        for ep in all_functions:
            # Get reads/writes
            reads = engine.neighbors(ep.id, [EdgeKind.READS], "out")
            writes = engine.neighbors(ep.id, [EdgeKind.WRITES], "out")

            role_name, trust = func_to_role.get(ep.id, ("", ""))

            functions.append(
                FunctionVocabEntry(
                    id=ep.id,
                    name=ep.name,
                    container=ep.container or "",
                    file=ep.file or "",
                    role=role_name,
                    trust=trust,
                    reads=[r.name for r in reads],
                    writes=[w.name for w in writes],
                )
            )

            # Track file -> contracts
            if ep.file and ep.container:
                files_map[ep.file].add(ep.container)

            # Build var entries
            for var_ref in reads + writes:
                if var_ref.id not in vars_map:
                    vars_map[var_ref.id] = VarVocabEntry(
                        id=var_ref.id,
                        name=var_ref.name,
                        container=var_ref.container or "",
                        file=var_ref.file or "",
                        writers=[],
                        readers=[],
                    )

                if var_ref in writes:
                    if ep.id not in vars_map[var_ref.id].writers:
                        vars_map[var_ref.id].writers.append(ep.id)
                if var_ref in reads:
                    if ep.id not in vars_map[var_ref.id].readers:
                        vars_map[var_ref.id].readers.append(ep.id)

        files: List[FileVocabEntry] = [
            FileVocabEntry(id=f, contracts=sorted(contracts))
            for f, contracts in files_map.items()
        ]

        return {
            "functions": functions,
            "vars": list(vars_map.values()),
            "files": files,
        }

    async def _generate_invariants_for_lens(
        self,
        lens: LensDefinition,
        function_ids: List[str],
        vocab: Dict[str, List[Any]],
        manifesto: Optional[ProtocolManifesto],
        actor_matrix: ActorMatrix,
        model_name: str,
        use_openai: bool,
    ) -> Tuple[List[Invariant], float, Dict[str, int]]:
        """
        Generate invariants for a single lens.

        Returns: (invariants, cost, tokens)
        """
        # Filter vocab to only functions in this lens
        func_id_set = set(function_ids)
        lens_functions = [f for f in vocab["functions"] if f.id in func_id_set]

        # Get related vars
        var_names_needed: Set[str] = set()
        file_ids_needed: Set[str] = set()
        for func in lens_functions:
            var_names_needed.update(func.reads)
            var_names_needed.update(func.writes)
            if func.file:
                file_ids_needed.add(func.file)

        lens_vars = [v for v in vocab["vars"] if v.name in var_names_needed]
        lens_files = [f for f in vocab["files"] if f.id in file_ids_needed]

        # Format vocab for prompt
        functions_vocab = json.dumps([f.model_dump() for f in lens_functions], indent=2)
        vars_vocab = json.dumps([v.model_dump() for v in lens_vars], indent=2)
        files_vocab = json.dumps([f.model_dump() for f in lens_files], indent=2)

        # Actor matrix summary
        actor_summary_lines = []
        for role in actor_matrix.roles:
            funcs = [p.name for p in role.privileges[:5]]
            if len(role.privileges) > 5:
                funcs.append(f"... +{len(role.privileges) - 5} more")
            actor_summary_lines.append(
                f"- {role.name} (trust: {role.trust}): {', '.join(funcs)}"
            )
        actor_matrix_summary = "\n".join(actor_summary_lines)

        # Protocol context
        protocol_context = self._build_protocol_context(manifesto)

        # Build lens-specific prompt
        prompt = self._build_lens_prompt(
            lens=lens,
            protocol_context=protocol_context,
            functions_vocab=functions_vocab,
            vars_vocab=vars_vocab,
            files_vocab=files_vocab,
            actor_matrix_summary=actor_matrix_summary,
        )

        # Call LLM
        client = create_openai_client(use_openai=use_openai)

        response = await client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            extra_body=_get_extra_body(use_openai),
        )

        # Handle API errors where choices is None or empty
        if not response.choices:
            raise RuntimeError(
                f"LLM API returned no choices for lens '{lens.name}'. "
                "This may be due to rate limiting, content filtering, or an API error."
            )

        content = response.choices[0].message.content or ""

        # Parse response
        invariants = self._parse_invariants_response(content, lens.name)

        # Calculate tokens and cost
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

        return invariants, cost, tokens

    def _build_protocol_context(self, manifesto: Optional[ProtocolManifesto]) -> str:
        """Build minimal protocol context string."""
        if not manifesto:
            return ""

        lines: List[str] = []
        if getattr(manifesto, "name", None):
            lines.append(f"Protocol: {manifesto.name}")
        if getattr(manifesto, "purpose", None):
            purpose = manifesto.purpose or ""
            lines.append(f"Purpose: {purpose[:160]}")
        if getattr(manifesto, "domain", None):
            dom = manifesto.domain
            if dom:
                lines.append(f"Domain: {dom}")

        users = list(getattr(manifesto, "intended_users", []) or [])
        if users:
            lines.append("Users: " + ", ".join(users[:3]))

        concepts = list((getattr(manifesto, "key_concepts", {}) or {}).keys())
        if concepts:
            lines.append("Key Concepts: " + ", ".join(concepts[:3]))

        return "\n".join(lines)

    def _build_lens_prompt(
        self,
        lens: LensDefinition,
        protocol_context: str,
        functions_vocab: str,
        vars_vocab: str,
        files_vocab: str,
        actor_matrix_summary: str,
    ) -> str:
        """Build the full prompt for a lens."""
        # Combine base prompt structure with lens-specific guidance
        prompt = f"""You are a security auditor generating {lens.name.upper()} invariants.

## LENS FOCUS: {lens.name.upper()}
{lens.description}

## TARGET INVARIANT TYPES
{", ".join(lens.invariant_types)}

{lens.prompt_template}

## MANDATORY CHECKLIST
Before finishing, verify you have addressed:
{chr(10).join(f"- [ ] {item}" for item in lens.checklist)}

## PROJECT CONTEXT
{protocol_context}

## VOCABULARY

You may ONLY reference IDs from this vocabulary. Do NOT invent new IDs.

### Functions
{functions_vocab}

### State Variables
{vars_vocab}

### Files
{files_vocab}

## ACTOR MATRIX SUMMARY
{actor_matrix_summary}

## OUTPUT FORMAT

Respond with a JSON object containing an "invariants" array:
```json
{{
  "invariants": [
    {{
      "type": "{lens.invariant_types[0] if lens.invariant_types else "OTHER"}",
      "rule": "Human-readable invariant statement",
      "principle": "Abstract vulnerability pattern (language-agnostic, e.g., 'unchecked numeric input')",
      "explanation": "Why this invariant matters and how it could be violated",
      "target_function_ids": ["exact_function_id_from_vocab"],
      "target_var_ids": ["exact_var_id_from_vocab"],
      "target_file_ids": ["exact_file_path_from_vocab"],
      "confidence": 0.0-1.0
    }}
  ]
}}
```

IMPORTANT:
- Every ID in target_*_ids MUST exist in the vocabulary above
- The `principle` should be abstract (e.g., "unchecked numeric input to string operation" not "padStart with negative")
- Focus ONLY on {lens.name} concerns for this pass
- Generate focused, high-quality invariants (prefer quality over quantity)
- Do NOT include IDs that aren't in the vocabulary
"""
        return prompt

    def _parse_invariants_response(
        self, content: str, lens_name: str
    ) -> List[Invariant]:
        """Parse LLM response into Invariant objects."""
        json_str = content
        if "```json" in content:
            json_str = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            json_str = content.split("```")[1].split("```")[0].strip()

        invariants: List[Invariant] = []
        try:
            data = json.loads(json_str)
            inv_list = data.get("invariants", [])

            for item in inv_list:
                try:
                    inv_type = InvariantType(item.get("type", "other").lower())
                except ValueError:
                    inv_type = InvariantType.OTHER

                invariants.append(
                    Invariant(
                        type=inv_type,
                        rule=item.get("rule", ""),
                        principle=item.get("principle", ""),
                        explanation=item.get("explanation", ""),
                        target_function_ids=item.get("target_function_ids", []),
                        target_var_ids=item.get("target_var_ids", []),
                        target_file_ids=item.get("target_file_ids", []),
                        confidence=item.get("confidence", 0.5),
                        source="llm",
                        chunk_id=f"lens_{lens_name}",
                    )
                )
        except json.JSONDecodeError:
            self.logger.warning(f"Failed to parse LLM response for lens {lens_name}")

        return invariants

    def _build_valid_id_sets(
        self,
        vocab: Dict[str, List[Any]],
    ) -> Dict[str, Set[str]]:
        """Build sets of valid IDs for validation."""
        return {
            "functions": {f.id for f in vocab["functions"]},
            "vars": {v.id for v in vocab["vars"]},
            "files": {f.id for f in vocab["files"]},
        }

    def _validate_invariants(
        self,
        invariants: List[Invariant],
        valid_sets: Dict[str, Set[str]],
    ) -> Tuple[List[Invariant], int]:
        """
        Validate invariants - drop those with invalid IDs or empty targets.

        Returns: (valid_invariants, dropped_count)
        """
        valid: List[Invariant] = []
        dropped = 0

        for inv in invariants:
            # Check all function IDs are valid
            invalid_funcs = [
                fid
                for fid in inv.target_function_ids
                if fid not in valid_sets["functions"]
            ]
            # Check all var IDs are valid
            invalid_vars = [
                vid for vid in inv.target_var_ids if vid not in valid_sets["vars"]
            ]
            # Check all file IDs are valid
            invalid_files = [
                fid for fid in inv.target_file_ids if fid not in valid_sets["files"]
            ]

            # Drop if any invalid IDs
            if invalid_funcs or invalid_vars or invalid_files:
                self.logger.debug(
                    f"Dropping {inv.id}: invalid IDs - "
                    f"funcs={invalid_funcs}, vars={invalid_vars}, files={invalid_files}"
                )
                dropped += 1
                continue

            # Drop if all target lists are empty
            if (
                not inv.target_function_ids
                and not inv.target_var_ids
                and not inv.target_file_ids
            ):
                self.logger.debug(f"Dropping {inv.id}: no targets")
                dropped += 1
                continue

            valid.append(inv)

        return valid, dropped

    def _merge_invariants(
        self,
        invariants: List[Invariant],
    ) -> List[Invariant]:
        """
        Merge/dedupe invariants with similar rules and targets.

        Simple approach: group by normalized rule + target set, keep highest confidence.
        """
        groups: Dict[Tuple[str, frozenset], List[Invariant]] = defaultdict(list)

        for inv in invariants:
            norm_rule = inv.rule.lower().strip()
            target_key = frozenset(
                inv.target_function_ids + inv.target_var_ids + inv.target_file_ids
            )
            groups[(norm_rule, target_key)].append(inv)

        merged: List[Invariant] = []
        for group in groups.values():
            group.sort(key=lambda x: -x.confidence)
            merged.append(group[0])

        return merged

    # =========================================================================
    # Synthesis Pass: Cross-function invariants from graph analysis
    # =========================================================================

    def _synthesize_cross_function_invariants(
        self,
        engine: GraphQueryEngine,
        vocab: Dict[str, List[Any]],
        functions_with_metadata: List[Dict[str, Any]],
    ) -> List[Invariant]:
        """
        Synthesize cross-function invariants from graph analysis.

        This generates grounded invariants based on:
        1. Co-read patterns: view + mutation reading same timer vars
        2. Role-based patterns: time_view + time_guard_mutation pairs
        3. Economic patterns: participation_entry + distribution pairs

        These invariants are grounded in the actual code structure,
        not hallucinated by the LLM.
        """
        synthesized: List[Invariant] = []

        # Build function metadata lookup
        func_meta: Dict[str, Dict[str, Any]] = {
            f["id"]: f for f in functions_with_metadata
        }

        # Get valid function IDs from vocab
        valid_func_ids = {f.id for f in vocab["functions"]}

        # Find functions by role
        time_views: List[str] = []
        time_guard_mutations: List[str] = []
        time_resets: List[str] = []
        participation_entries: List[str] = []
        distributions: List[str] = []

        for fid, meta in func_meta.items():
            if fid not in valid_func_ids:
                continue

            timerish_roles = meta.get("timerish_roles", [])
            economic_roles = meta.get("economic_roles", [])

            if "time_view" in timerish_roles:
                time_views.append(fid)
            if "time_guard_mutation" in timerish_roles:
                time_guard_mutations.append(fid)
            if "time_reset" in timerish_roles:
                time_resets.append(fid)
            if "participation_entry" in economic_roles:
                participation_entries.append(fid)
            if "distribution" in economic_roles:
                distributions.append(fid)

        # Synthesize view/mutation boundary alignment invariants
        for view_id in time_views:
            for mutation_id in time_guard_mutations:
                # Check if they share timer-related variables (co-read)
                view_meta = func_meta.get(view_id, {})
                mutation_meta = func_meta.get(mutation_id, {})

                # Get reads from vocab entries
                view_entry = next(
                    (f for f in vocab["functions"] if f.id == view_id), None
                )
                mutation_entry = next(
                    (f for f in vocab["functions"] if f.id == mutation_id), None
                )

                if not view_entry or not mutation_entry:
                    continue

                view_reads = set(view_entry.reads)
                mutation_reads = set(mutation_entry.reads)
                shared_vars = view_reads & mutation_reads

                # Check if shared vars look like timer vars
                time_var_pats = self.adapter.get_time_var_patterns()
                shared_timer_vars = [
                    v
                    for v in shared_vars
                    if any(p.lower() in v.lower() for p in time_var_pats)
                ]

                if shared_timer_vars:
                    view_name = view_entry.name
                    mutation_name = mutation_entry.name

                    synthesized.append(
                        Invariant(
                            type=InvariantType.ORDERING,
                            rule=(
                                f"Boundary alignment: If {view_name}() returns 0 (deadline passed), "
                                f"then {mutation_name}() must revert. "
                                f"If {view_name}() > 0, then {mutation_name}() may succeed."
                            ),
                            principle="view/mutation boundary consistency on shared timer variable",
                            explanation=(
                                f"Functions {view_name} (view) and {mutation_name} (mutation) "
                                f"both read timer variables: {', '.join(shared_timer_vars)}. "
                                f"Their boundary behavior must be consistent - if the view indicates "
                                f"the deadline has passed, the mutation should not allow the action."
                            ),
                            target_function_ids=[view_id, mutation_id],
                            target_var_ids=[],
                            target_file_ids=[],
                            confidence=0.7,
                            source="synthesis",
                            chunk_id="synthesis_boundary",
                        )
                    )

        # Synthesize post-expiry gating invariants
        for mutation_id in time_guard_mutations:
            mutation_entry = next(
                (f for f in vocab["functions"] if f.id == mutation_id), None
            )
            if not mutation_entry:
                continue

            mutation_name = mutation_entry.name
            mutation_reads = set(mutation_entry.reads)

            # Check if reads timer vars
            time_var_pats = self.adapter.get_time_var_patterns()
            timer_vars = [
                v
                for v in mutation_reads
                if any(p.lower() in v.lower() for p in time_var_pats)
            ]

            if timer_vars:
                synthesized.append(
                    Invariant(
                        type=InvariantType.LIVENESS,
                        rule=(
                            f"Post-expiry gating: {mutation_name}() must revert when "
                            f"block.timestamp >= deadline (or equivalent time condition)"
                        ),
                        principle="time-gated function must enforce deadline",
                        explanation=(
                            f"Function {mutation_name} reads timer variables: {', '.join(timer_vars)}. "
                            f"If this is a participation/entry function, it must enforce that "
                            f"the action cannot occur after the time window closes."
                        ),
                        target_function_ids=[mutation_id],
                        target_var_ids=[],
                        target_file_ids=[],
                        confidence=0.6,
                        source="synthesis",
                        chunk_id="synthesis_expiry",
                    )
                )

        # Synthesize reset ordering invariants
        for reset_id in time_resets:
            reset_entry = next(
                (f for f in vocab["functions"] if f.id == reset_id), None
            )
            if not reset_entry:
                continue

            reset_name = reset_entry.name

            synthesized.append(
                Invariant(
                    type=InvariantType.ORDERING,
                    rule=(
                        f"Reset ordering: {reset_name}() must only be callable "
                        f"after the current round/epoch has ended (ended == true or equivalent)"
                    ),
                    principle="reset function gated by end-of-round flag",
                    explanation=(
                        f"Function {reset_name} appears to reset round state. "
                        f"It should only be callable after the current round is properly finished, "
                        f"not while a round is still active."
                    ),
                    target_function_ids=[reset_id],
                    target_var_ids=[],
                    target_file_ids=[],
                    confidence=0.5,
                    source="synthesis",
                    chunk_id="synthesis_reset",
                )
            )

        # Synthesize obligation preservation on reset
        if time_resets and distributions:
            for reset_id in time_resets:
                reset_entry = next(
                    (f for f in vocab["functions"] if f.id == reset_id), None
                )
                if not reset_entry:
                    continue

                reset_name = reset_entry.name

                synthesized.append(
                    Invariant(
                        type=InvariantType.VALUE_FLOW,
                        rule=(
                            f"Obligation preservation: {reset_name}() must not clear "
                            f"pending withdrawals or outstanding obligations when resetting round state"
                        ),
                        principle="reset preserves accumulated obligations",
                        explanation=(
                            f"When {reset_name} resets the round/epoch, any pending withdrawals "
                            f"or claimable balances must be preserved. Users should not lose "
                            f"their accumulated rewards due to a round reset."
                        ),
                        target_function_ids=[reset_id],
                        target_var_ids=[],
                        target_file_ids=[],
                        confidence=0.6,
                        source="synthesis",
                        chunk_id="synthesis_obligation",
                    )
                )

        return synthesized
