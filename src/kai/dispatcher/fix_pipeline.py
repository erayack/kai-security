"""
Fix pipeline: generates patches for verified exploits.
"""

import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional

from kai.agents import settings
from kai.schemas import (
    ExploitCandidate,
    Fix,
    MasterContext,
    Verdict,
    WorkspacePreset,
)
from kai.state_manager import KaiStateManager
from kai.utils.dependency.graph import DependencyGraph

from kai.dispatcher._helpers import persist
from kai.dispatcher.usage_tracker import UsageTracker
from kai.dispatcher.verification import VerificationPipeline
from kai.dispatcher.workspace import WorkspaceManager


class FixPipeline:
    """Generates patches for verified exploits."""

    def __init__(
        self,
        *,
        config,  # DispatcherConfig
        workspace_manager: WorkspaceManager,
        state_manager: Optional[KaiStateManager],
        usage_tracker: UsageTracker,
        logger: logging.Logger,
    ) -> None:
        self._config = config
        self._workspace_manager = workspace_manager
        self._state_manager = state_manager
        self._usage_tracker = usage_tracker
        self.logger = logger

    async def fix_verified_exploits(
        self,
        verdicts: List[Verdict],
        exploit_candidates: List[ExploitCandidate],
        master_context: MasterContext,
        dependency_graph: Optional[DependencyGraph],
        verification: VerificationPipeline,
    ) -> List[Fix]:
        """
        Generate fixes for all verified exploits.

        Deduplicates by root cause, then runs FixerAgent on each unique
        exploit concurrently (limited by semaphore).

        Args:
            verdicts: All collected verdicts
            exploit_candidates: All exploit candidates
            master_context: MasterContext from boot
            dependency_graph: DependencyGraph from boot
            verification: VerificationPipeline (for deduplication)

        Returns:
            List of generated Fix objects
        """
        valid_verdicts = [v for v in verdicts if v.is_valid]

        if not valid_verdicts:
            self.logger.info("No verified exploits to fix")
            return []

        # Deduplicate by root cause
        if self._config.enable_deduplication:
            valid_verdicts = await verification.dedupe_verified_exploits(
                valid_verdicts, exploit_candidates
            )

        if self._config.disable_fixer:
            self.logger.info(
                "Fixer disabled (config.disable_fixer=True), skipping fix generation"
            )
            return []

        self.logger.info(
            f"Generating fixes for {len(valid_verdicts)} verified exploit(s) "
            f"(max {self._config.max_concurrent_fixers} concurrent)..."
        )

        semaphore = asyncio.Semaphore(self._config.max_concurrent_fixers)

        async def fix_with_semaphore(
            candidate: ExploitCandidate, verdict: Verdict
        ) -> tuple[List[Fix], Verdict]:
            async with semaphore:
                fixes = await self._fix_single_exploit(
                    candidate, verdict, master_context, dependency_graph
                )
                return fixes, verdict

        tasks = []
        for verdict in valid_verdicts:
            candidate = next(
                (
                    c
                    for c in exploit_candidates
                    if c.mission_id == verdict.mission_id
                    and c.invariant_id == verdict.invariant_id
                ),
                None,
            )

            if not candidate:
                self.logger.warning(
                    f"No exploit candidate found for verdict {verdict.mission_id}"
                )
                continue

            tasks.append(fix_with_semaphore(candidate, verdict))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_fixes: List[Fix] = []
        for result in results:
            if isinstance(result, BaseException):
                self.logger.error(f"Fixer task failed with exception: {result}")
                continue

            fixes, verdict = result
            for fix in fixes:
                all_fixes.append(fix)
                verdict.fixes.append(fix)
                await persist(
                    self._state_manager,
                    self._state_manager.save_fix(fix) if self._state_manager else None,
                    self.logger,
                )

        self.logger.info(f"Generated {len(all_fixes)} fix(es) for verified exploits")
        return all_fixes

    async def _fix_single_exploit(
        self,
        candidate: ExploitCandidate,
        verdict: Verdict,
        master_context: MasterContext,
        dependency_graph: Optional[DependencyGraph],
    ) -> List[Fix]:
        """
        Generate fixes for a single verified exploit using FixerAgent.

        Args:
            candidate: The exploit candidate
            verdict: The verification verdict
            master_context: MasterContext from boot
            dependency_graph: DependencyGraph from boot

        Returns:
            List of Fix objects (may be empty if fixer failed)
        """
        from kai.agents.agent_types.fixer_agent import FixerAgent

        self.logger.info(f"Fixing exploit: {candidate.mission_id}")

        agent = None
        try:
            workspace_path = self._workspace_manager.provision(
                workspace_id=f"fixer_{candidate.mission_id}",
                master_path=master_context.root_path,
                preset=WorkspacePreset.WRITEABLE,
            )

            agent = FixerAgent(
                exploit_candidate=candidate,
                verdict=verdict,
                repo_path=workspace_path,
                dependency_graph=dependency_graph,
                max_tool_turns=settings.DEFAULT_MAX_TURNS,
                model=self._config.fixer_model,
                use_openai=self._config.use_openai,
            )

            await agent.chat_with_tools("Begin.")

            registered_fixes = getattr(agent, "_registered_fixes", [])

            if not registered_fixes:
                self.logger.warning(
                    f"Fixer did not register any fixes for {candidate.mission_id}"
                )
                return []

            fixes = []
            for fix_record in registered_fixes:
                fix = Fix(
                    fix_id=fix_record.get("fix_id", f"fix_{uuid.uuid4().hex}"),
                    mission_id=candidate.mission_id,
                    invariant_id=candidate.invariant_id,
                    summary=fix_record.get("summary", ""),
                    reasoning=fix_record.get("reasoning", ""),
                    canonical_diff=fix_record.get("canonical_diff", ""),
                    files_changed=fix_record.get("files_changed", []),
                    compiled=fix_record.get("compiled", False),
                    tests_passed=fix_record.get("tests_passed", False),
                )
                fixes.append(fix)

            self.logger.info(
                f"FIX GENERATED: {candidate.mission_id} - {len(fixes)} fix(es)"
            )
            return fixes

        except Exception as e:
            self.logger.error(f"Fix generation failed for {candidate.mission_id}: {e}")
            return []

        finally:
            if agent is not None:
                self._usage_tracker.save_rollout(
                    agent, "fixer", f"fixer_{candidate.mission_id}"
                )
                self._usage_tracker.aggregate_agent_usage(
                    agent=agent,
                    phase="fixer",
                    agent_type="fixer",
                )
                try:
                    await agent.close()
                except Exception:
                    pass
            try:
                self._workspace_manager.cleanup(f"fixer_{candidate.mission_id}")
            except Exception:
                pass
