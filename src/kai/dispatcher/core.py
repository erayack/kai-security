"""
Dispatcher: Mission control for Kai v2.
"""

import asyncio

from kai.exceptions import (
    DispatcherBootError,
    EnvironmentSetupError,
    StaticAnalysisError,
    WorkspaceValidationError,
    ActorAnalysisError,
)
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from kai.agents import settings  # noqa: E402
from kai.state_manager import KaiStateManager  # noqa: E402

from kai.schemas import (  # noqa: E402
    ActorMatrix,
    CampaignBrief,
    CampaignBudget,
    ExploitCandidate,
    Fix,
    Invariant,
    MasterContext,
    Mission,
    MissionAgentType,
    Observation,
    ProtocolManifesto,
    Verdict,
    VerdictSeverity,
)
from kai.utils.dependency.graph import DependencyGraph  # noqa: E402

from kai.dispatcher._helpers import persist  # noqa: E402
from kai.dispatcher.boot_pipeline import BootPipeline, BootResult, SetupResult  # noqa: E402
from kai.dispatcher.fix_pipeline import FixPipeline  # noqa: E402
from kai.dispatcher.planner import MissionPlanner  # noqa: E402
from kai.dispatcher.usage_tracker import UsageTracker  # noqa: E402
from kai.dispatcher.verification import VerificationPipeline  # noqa: E402
from kai.dispatcher.workspace import WorkspaceManager  # noqa: E402
from kai.dispatcher.agent_factories import AGENT_FACTORIES as DEFAULT_AGENT_FACTORIES  # noqa: E402

# Type alias for shutdown trigger callable
ShutdownTrigger = Callable[[], bool]

# Mission queue priority constants (lower = higher priority)
PRIORITY_BLACKBOX = 0  # Phase 0: Blackbox runs first
PRIORITY_STATE_QUANT_HTTP = 1  # Phase 1: State/Quant/HTTP run together
PRIORITY_GAMIFIED = 2  # Phase 2: Gamified runs last

if TYPE_CHECKING:
    from kai.agents.base import BaseAgent

logger = logging.getLogger(__name__)

# Type alias for agent factory function
AgentFactory = Callable[..., "BaseAgent"]


@dataclass
class DispatcherConfig:
    """Configuration for Dispatcher."""

    max_concurrent_agents: int = settings.MAX_CONCURRENT_AGENTS
    max_invariants_per_cluster: int = 5
    max_campaigns: int = 10
    include_exploration: bool = True
    default_budget: CampaignBudget = field(default_factory=CampaignBudget)
    workspace_dir: str = "./kai_workspaces"
    # Model settings for agents
    model: str = settings.MAIN_DEFAULT_MODEL
    verifier_model: str = settings.VERIFIER_DEFAULT_MODEL
    invariant_model: str = settings.INVARIANT_DEFAULT_MODEL
    use_openai: bool = False
    # Rollout saving
    save_rollouts: bool = False
    rollouts_dir: Optional[str] = None  # If None, uses workspace_dir/rollouts
    # Setup agent settings
    setup_model: str = settings.SETUP_DEFAULT_MODEL
    setup_max_turns: int = settings.SETUP_MAX_TURNS
    # Profiler agent settings
    profiler_max_turns: int = settings.PROFILER_MAX_TURNS
    # Disable gamified agents (useful for BountyBench)
    disable_gamified: bool = False
    # Disable fixer agent (useful for debugging to reduce costs)
    disable_fixer: bool = False
    # Extra instructions to pass to agents (e.g., CWE hints)
    extra_instructions: Optional[str] = None
    # Skip workspace validation (useful when context is pre-validated)
    skip_workspace_validation: bool = False
    # Deduplication settings (cluster verified exploits by root cause before fixing)
    enable_deduplication: bool = True
    dedupe_model: str = settings.DEDUPE_DEFAULT_MODEL
    # Fixer agent settings
    fixer_model: str = settings.FIXER_DEFAULT_MODEL
    # Fallback model (used when primary model fails after retries)
    fallback_model: str = settings.FALLBACK_MODEL
    # Output directory (if None, derives from rollouts_dir or workspace_dir)
    output_dir: Optional[str] = None
    # Turn configuration
    main_agent_max_turns: int = settings.DEFAULT_MAX_TURNS
    fixer_max_turns: int = settings.DEFAULT_MAX_TURNS
    verifier_max_turns: int = settings.VERIFIER_MAX_TURNS
    invariant_synth_max_turns: int = settings.INVARIANT_SYNTH_MAX_TURNS
    validation_max_turns: int = settings.VALIDATION_MAX_TURNS
    # Concurrent fixer limit
    max_concurrent_fixers: int = settings.MAX_CONCURRENT_FIXERS
    # Enable HTTP agent (for HTTP-based exploitation of live services)
    enable_http_agent: bool = False
    # HTTP agent configuration - maps service names to URLs
    # e.g., {"app": "http://localhost:8080", "db": "http://localhost:5432"}
    http_target_hosts: Optional[dict[str, str]] = None
    # Iterative runs: skip redundant work when graph unchanged
    enable_iterative: bool = False


class Dispatcher:
    """
    Mission control: turns global knowledge into precise agent missions.

    Orchestrates preprocessing, mission planning, and agent dispatch.

    Agent factories are callables that create BaseAgent instances for missions.
    Factory signature: (mission: Mission, workspace_path: str) -> BaseAgent

    Example:
        def create_state_agent(mission: Mission, workspace: str) -> BaseAgent:
            return StateAgent(repo_path=workspace, max_tool_turns=mission.max_turns)

        dispatcher = Dispatcher(
            agent_factories={MissionAgentType.STATE: create_state_agent},
            config=DispatcherConfig(),
        )
    """

    def __init__(
        self,
        agent_factories: Optional[Dict[MissionAgentType, AgentFactory]] = None,
        config: Optional[DispatcherConfig] = None,
        shutdown_trigger: Optional[ShutdownTrigger] = None,
        state_manager: Optional[KaiStateManager] = None,
    ):
        # Use default factories if none provided
        self.agent_factories = agent_factories or dict(DEFAULT_AGENT_FACTORIES)
        self.config = config or DispatcherConfig()

        self.logger = logger.getChild("Dispatcher")

        # External state manager for persistence (mongo/s3/local)
        self._state_manager = state_manager

        # Shutdown trigger - callable that returns True when shutdown requested
        self._shutdown_trigger = shutdown_trigger
        self._shutdown_requested = False
        self._shutdown_reason: Optional[str] = None

        # State populated by boot()
        self.master_context: Optional[MasterContext] = None
        self.dependency_graph: Optional[DependencyGraph] = None
        self.protocol_manifesto: Optional[ProtocolManifesto] = None
        self.actor_matrix: Optional[ActorMatrix] = None
        # Store invariants keyed by ID (Pydantic models are not reliably hashable)
        self.invariants: Dict[str, Invariant] = {}

        # Mission queue: (priority, mission_id, mission)
        self.mission_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.active_missions: Dict[str, Mission] = {}

        # Results
        self.campaigns: List[CampaignBrief] = []
        self.completed_missions: List[Mission] = []
        self.exploit_candidates: List[ExploitCandidate] = []
        self.verdicts: List[Verdict] = []
        self.fixes: List[Fix] = []
        # Prior verdicts carried forward from iterative runs
        self._prior_verdicts: List[Verdict] = []

        # Sub-components
        self._workspace_manager = WorkspaceManager(
            workspace_dir=self.config.workspace_dir, logger=self.logger
        )
        self._usage_tracker = UsageTracker(
            save_rollouts=self.config.save_rollouts,
            rollouts_dir=self.config.rollouts_dir,
            workspace_dir=self.config.workspace_dir,
            logger=self.logger,
        )
        self._boot_pipeline = BootPipeline(
            config=self.config,
            workspace_manager=self._workspace_manager,
            state_manager=self._state_manager,
            usage_tracker=self._usage_tracker,
            logger=self.logger,
        )
        self._verification = VerificationPipeline(
            config=self.config,
            state_manager=self._state_manager,
            usage_tracker=self._usage_tracker,
            logger=self.logger,
        )
        self._fix_pipeline = FixPipeline(
            config=self.config,
            workspace_manager=self._workspace_manager,
            state_manager=self._state_manager,
            usage_tracker=self._usage_tracker,
            logger=self.logger,
        )
        self._planner: Optional[MissionPlanner] = None

    # ------------------------------------------------------------------
    # Property delegates to UsageTracker
    # ------------------------------------------------------------------

    @property
    def total_tokens(self) -> Dict[str, int]:
        return self._usage_tracker.total_tokens

    @total_tokens.setter
    def total_tokens(self, value: Dict[str, int]) -> None:
        self._usage_tracker.total_tokens = value

    @property
    def total_cost(self) -> float:
        return self._usage_tracker.total_cost

    @total_cost.setter
    def total_cost(self, value: float) -> None:
        self._usage_tracker.total_cost = value

    @property
    def token_usage_by_phase(self) -> Dict[str, Dict[str, Any]]:
        return self._usage_tracker.token_usage_by_phase

    @token_usage_by_phase.setter
    def token_usage_by_phase(self, value: Dict[str, Dict[str, Any]]) -> None:
        self._usage_tracker.token_usage_by_phase = value

    # ------------------------------------------------------------------
    # Boot
    # ------------------------------------------------------------------

    async def boot(
        self,
        repo_url: Optional[str] = None,
        repo_path: Optional[str] = None,
        model_name: str = settings.MAIN_DEFAULT_MODEL,
        use_openai: bool = False,
        master_context: Optional[MasterContext] = None,
    ) -> None:
        """
        Run preprocess chain to populate global knowledge.

        When enable_iterative=True, detects what changed since the prior run
        and skips redundant LLM steps:
        - Graph unchanged: reuse cached manifesto, actor_matrix, invariants
        - Graph changed: re-run LLM steps, diff invariants, only dispatch novel ones
        - No prior: full run

        Args:
            repo_url: Git URL of the repository
            repo_path: Local path to the repository (overrides repo_url)
            model_name: Model to use for agent inference
            use_openai: Whether to use OpenAI API directly
            master_context: Pre-built MasterContext (BountyBench mode, skips EnvironmentSetup)

        Raises:
            EnvironmentSetupError: If environment setup fails
            StaticAnalysisError: If dependency graph building fails
            WorkspaceValidationError: If workspace validation fails
            ActorAnalysisError: If actor analysis fails
            DispatcherBootError: For other boot failures
        """
        if not self.config.enable_iterative:
            # Non-iterative: run all steps as before
            result = await self._boot_pipeline.run(
                repo_url=repo_url,
                repo_path=repo_path,
                model_name=model_name,
                use_openai=use_openai,
                master_context=master_context,
            )
        else:
            result = await self._boot_iterative(
                repo_url=repo_url,
                repo_path=repo_path,
                model_name=model_name,
                use_openai=use_openai,
                master_context=master_context,
            )

        # Unpack BootResult into dispatcher state
        self.master_context = result.master_context
        self.dependency_graph = result.dependency_graph
        self.protocol_manifesto = result.protocol_manifesto
        self.actor_matrix = result.actor_matrix
        self.invariants = result.invariants
        self._planner = result.planner

    async def _boot_iterative(
        self,
        *,
        repo_url: Optional[str] = None,
        repo_path: Optional[str] = None,
        model_name: str = settings.MAIN_DEFAULT_MODEL,
        use_openai: bool = False,
        master_context: Optional[MasterContext] = None,
    ) -> BootResult:
        """Iterative boot: skip redundant LLM work when graph is unchanged."""
        from kai.dispatcher.coverage import hash_graph, diff_invariants

        # Phase 1: always run setup + graph + workspace validation
        setup = await self._boot_pipeline.run_setup_and_graph(
            repo_url=repo_url,
            repo_path=repo_path,
            use_openai=use_openai,
            master_context=master_context,
        )

        graph_hash = hash_graph(setup.dependency_graph)
        prior = await self._state_manager.load_run_snapshot() if self._state_manager else None

        if prior and prior.get("graph_hash") == graph_hash:
            # Graph unchanged → load cached artifacts, skip LLM steps
            self.logger.info("Graph unchanged, reusing cached boot artifacts")
            result = self._build_boot_result_from_snapshot(setup, prior)
            self._prior_verdicts = [Verdict(**v) for v in prior.get("verdicts", [])]
            return result

        if prior:
            # Graph changed → run LLM steps, then diff invariants
            result = await self._boot_pipeline.run_llm_steps(
                setup=setup,
                model_name=model_name,
                use_openai=use_openai,
            )
            prior_invariants = [Invariant(**inv) for inv in prior.get("invariants", [])]
            novel = await diff_invariants(
                list(result.invariants.values()),
                prior_invariants,
                model=self.config.dedupe_model,
                use_openai=self.config.use_openai,
                logger=self.logger,
            )
            result.invariants = {inv.id: inv for inv in novel}
            self._prior_verdicts = [Verdict(**v) for v in prior.get("verdicts", [])]
            self.logger.info(
                f"Iterative: {len(novel)} novel invariants "
                f"(from {len(prior_invariants)} prior)"
            )
            return result

        # First run: full boot
        return await self._boot_pipeline.run_llm_steps(
            setup=setup,
            model_name=model_name,
            use_openai=use_openai,
        )

    def _build_boot_result_from_snapshot(
        self,
        setup: "SetupResult",
        prior: Dict[str, Any],
    ) -> BootResult:
        """Reconstruct a BootResult from a prior snapshot (graph-unchanged path)."""
        manifesto = None
        if prior.get("manifesto"):
            manifesto = ProtocolManifesto(**prior["manifesto"])

        actor_matrix = ActorMatrix(**prior["actor_matrix"])

        invariants = {
            inv_data["id"]: Invariant(**inv_data)
            for inv_data in prior.get("invariants", [])
        }

        planner = MissionPlanner(
            dependency_graph=setup.dependency_graph,
            actor_matrix=actor_matrix,
            max_invariants_per_cluster=self.config.max_invariants_per_cluster,
            max_campaigns=self.config.max_campaigns,
            include_exploration=self.config.include_exploration,
            default_budget=self.config.default_budget,
            master_context=setup.master_context,
        )

        return BootResult(
            master_context=setup.master_context,
            dependency_graph=setup.dependency_graph,
            protocol_manifesto=manifesto,
            actor_matrix=actor_matrix,
            invariants=invariants,
            planner=planner,
        )

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _check_shutdown(self) -> bool:
        """
        Check if shutdown has been requested.

        Returns True if shutdown triggered, False otherwise.
        """
        if self._shutdown_requested:
            return True

        if self._shutdown_trigger and self._shutdown_trigger():
            self._shutdown_requested = True
            self.logger.warning("Shutdown triggered by external signal")
            return True

        return False

    @property
    def shutdown_requested(self) -> bool:
        """Whether shutdown has been requested."""
        return self._shutdown_requested

    @property
    def shutdown_reason(self) -> Optional[str]:
        """Reason for shutdown, if available."""
        return self._shutdown_reason

    def request_shutdown(self, reason: str = "Manual shutdown") -> None:
        """
        Request graceful shutdown of the dispatcher.

        Args:
            reason: Human-readable reason for shutdown
        """
        self._shutdown_requested = True
        self._shutdown_reason = reason
        self.logger.info(f"Shutdown requested: {reason}")

    # ------------------------------------------------------------------
    # Run loop
    # ------------------------------------------------------------------

    async def run_loop(self) -> None:
        """
        Three-phase execution:
        - Phase 0: Blackbox -> observations -> new invariants
        - Phase 1: State/Quant (with updated invariants)
        - Phase 2: Gamified on clusters
        """
        # Carry forward prior verdicts from iterative runs
        if self._prior_verdicts:
            self.logger.info(
                f"Carrying forward {len(self._prior_verdicts)} prior verdicts"
            )
            self.verdicts.extend(self._prior_verdicts)
            self._prior_verdicts = []

        # Phase 0: Blackbox
        if self.config.include_exploration and self._planner:
            self.logger.info("Phase 0: Blackbox...")
            await self._queue_blackbox_missions()
            await self._drain_mission_queue()
            self.logger.info(f"Phase 0 done: {len(self.invariants)} invariants")

        if self._shutdown_requested:
            return

        # Phase 1: State/Quant (plan with all invariants including any from blackbox)
        self.logger.info("Phase 1: State/Quant...")
        await self._plan_state_quant_missions()

        # Queue HTTP missions if enabled (runs alongside state/quant)
        if self.config.enable_http_agent:
            self.logger.info("Queueing HTTP exploitation missions...")
            await self._queue_http_missions()

        await self._drain_mission_queue()
        self.logger.info(f"Phase 1 done: {len(self.completed_missions)} missions")

        if self._shutdown_requested:
            return

        # Phase 2: Gamified
        if self.invariants and self._planner:
            self.logger.info("Phase 2: Gamified...")
            await self._queue_gamified_missions()
            await self._drain_mission_queue()
            self.logger.info("Phase 2 done")

        self.logger.info(f"Total: {len(self.exploit_candidates)} candidates")

        # Fix verified exploits
        if self.master_context is not None:
            new_fixes = await self._fix_pipeline.fix_verified_exploits(
                verdicts=self.verdicts,
                exploit_candidates=self.exploit_candidates,
                master_context=self.master_context,
                dependency_graph=self.dependency_graph,
                verification=self._verification,
            )
            self.fixes.extend(new_fixes)

        # Save snapshot for future iterative runs
        if self.config.enable_iterative and self._state_manager and self.dependency_graph:
            await self._save_run_snapshot()

    async def _save_run_snapshot(self) -> None:
        """Persist run snapshot for future iterative runs."""
        from kai.dispatcher.coverage import hash_graph
        from datetime import datetime, timezone

        assert self.dependency_graph is not None  # guarded by caller

        snapshot = {
            "graph_hash": hash_graph(self.dependency_graph),
            "invariants": [inv.model_dump() for inv in self.invariants.values()],
            "verdicts": [v.model_dump() for v in self.verdicts],
            "manifesto": self.protocol_manifesto.model_dump() if self.protocol_manifesto else None,
            "actor_matrix": self.actor_matrix.model_dump() if self.actor_matrix else None,
            "dependency_graph": self.dependency_graph.to_dict(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await persist(
            self._state_manager,
            self._state_manager.save_run_snapshot(snapshot) if self._state_manager else None,
            self.logger,
        )
        self.logger.info("Saved iterative run snapshot")

    async def _drain_mission_queue(self) -> None:
        """Run missions from queue until empty."""
        while not self.mission_queue.empty() or self.active_missions:
            if self._check_shutdown():
                while self.active_missions:
                    await asyncio.sleep(0.5)
                break

            while (
                len(self.active_missions) < self.config.max_concurrent_agents
                and not self.mission_queue.empty()
            ):
                _, _, mission = await self.mission_queue.get()
                self.active_missions[mission.mission_id] = mission
                asyncio.create_task(self._execute_mission(mission))

            await asyncio.sleep(0.1)

    async def _queue_blackbox_missions(self) -> None:
        """Queue blackbox missions (phase 0)."""
        if not self._planner:
            return
        campaign, missions = self._planner.build_blackbox_campaign()
        self.campaigns.append(campaign)
        await persist(
            self._state_manager,
            self._state_manager.save_campaigns([campaign])
            if self._state_manager
            else None,
            self.logger,
        )
        if missions:
            await persist(
                self._state_manager,
                self._state_manager.save_missions(missions)
                if self._state_manager
                else None,
                self.logger,
            )
        for mission in missions:
            self.mission_queue.put_nowait(
                (PRIORITY_BLACKBOX, mission.mission_id, mission)
            )

    async def _plan_state_quant_missions(self) -> None:
        """Plan state/quant missions with all invariants (phase 1)."""
        if not self._planner or not self.invariants:
            return
        campaigns, missions = self._planner.plan(
            invariants=list(self.invariants.values())
        )
        self.campaigns.extend(campaigns)
        if campaigns:
            await persist(
                self._state_manager,
                self._state_manager.save_campaigns(campaigns)
                if self._state_manager
                else None,
                self.logger,
            )
        if missions:
            await persist(
                self._state_manager,
                self._state_manager.save_missions(missions)
                if self._state_manager
                else None,
                self.logger,
            )
        for mission in missions:
            self.mission_queue.put_nowait(
                (PRIORITY_STATE_QUANT_HTTP, mission.mission_id, mission)
            )

    async def _queue_gamified_missions(self) -> None:
        """Queue gamified missions from invariant clusters (phase 2)."""
        if not self._planner:
            return
        campaigns, missions = self._planner.build_gamified_campaigns(
            list(self.invariants.values())
        )
        self.campaigns.extend(campaigns)
        if campaigns:
            await persist(
                self._state_manager,
                self._state_manager.save_campaigns(campaigns)
                if self._state_manager
                else None,
                self.logger,
            )
        if missions:
            await persist(
                self._state_manager,
                self._state_manager.save_missions(missions)
                if self._state_manager
                else None,
                self.logger,
            )
        for mission in missions:
            self.mission_queue.put_nowait(
                (PRIORITY_GAMIFIED, mission.mission_id, mission)
            )

    async def _queue_http_missions(self) -> None:
        """Queue HTTP exploitation missions (runs alongside state/quant)."""
        if not self._planner:
            return
        invariants = list(self.invariants.values()) if self.invariants else None
        campaign, missions = self._planner.build_http_campaign(invariants)
        self.campaigns.append(campaign)
        await persist(
            self._state_manager,
            self._state_manager.save_campaigns([campaign])
            if self._state_manager
            else None,
            self.logger,
        )
        if missions:
            await persist(
                self._state_manager,
                self._state_manager.save_missions(missions)
                if self._state_manager
                else None,
                self.logger,
            )
        for mission in missions:
            self.mission_queue.put_nowait(
                (PRIORITY_STATE_QUANT_HTTP, mission.mission_id, mission)
            )

    # ------------------------------------------------------------------
    # Mission execution
    # ------------------------------------------------------------------

    async def _execute_mission(self, mission: Mission) -> None:
        """Execute a single mission with an agent."""
        mission.status = "in_progress"
        await persist(
            self._state_manager,
            self._state_manager.update_mission_status(mission.mission_id, "in_progress")
            if self._state_manager
            else None,
            self.logger,
        )

        factory = self.agent_factories.get(mission.agent_type)
        if not factory:
            self.logger.warning(f"No agent factory for type {mission.agent_type}")
            mission.status = "failed"
            await persist(
                self._state_manager,
                self._state_manager.update_mission_status(
                    mission.mission_id,
                    "failed",
                    error=f"No agent factory for type {mission.agent_type}",
                )
                if self._state_manager
                else None,
                self.logger,
            )
            self.active_missions.pop(mission.mission_id, None)
            self.completed_missions.append(mission)
            return

        agent = None
        try:
            # Provision workspace
            workspace_path = self._provision_workspace(mission)

            # Build factory kwargs based on agent type
            factory_kwargs: Dict[str, Any] = {
                "mission": mission,
                "workspace_path": workspace_path,
                "master_context": self.master_context,
                "dependency_graph": self.dependency_graph,
                "actor_matrix": self.actor_matrix,
                "model": self.config.model,
                "use_openai": self.config.use_openai,
                "execution_id": mission.mission_id,
                "extra_instructions": self.config.extra_instructions,
            }

            # Add HTTP-specific config for HTTP agents
            if mission.agent_type == MissionAgentType.HTTP:
                factory_kwargs["target_hosts"] = self.config.http_target_hosts

            # Create agent instance via factory with full context
            agent = factory(**factory_kwargs)

            self.logger.info(
                f"Executing {mission.mission_id} with {mission.agent_type.value}"
            )

            await agent.chat_with_tools("Begin.")
            await self._handle_agent_result(mission, agent)

            mission.status = "completed"
            await persist(
                self._state_manager,
                self._state_manager.update_mission_status(
                    mission.mission_id, "completed"
                )
                if self._state_manager
                else None,
                self.logger,
            )

        except Exception as e:
            self.logger.error(
                f"Mission {mission.mission_id} failed: {e}", exc_info=True
            )
            mission.status = "failed"
            await persist(
                self._state_manager,
                self._state_manager.update_mission_status(
                    mission.mission_id, "failed", error=str(e)
                )
                if self._state_manager
                else None,
                self.logger,
            )

        finally:
            if agent is not None:
                self._usage_tracker.save_rollout(agent, "missions", mission.mission_id)
                self._usage_tracker.aggregate_agent_usage(
                    agent=agent,
                    phase="run_loop",
                    agent_type=mission.agent_type.value
                    if mission.agent_type
                    else "unknown",
                )
                try:
                    await agent.close()
                except Exception:
                    pass
            self.active_missions.pop(mission.mission_id, None)
            self.completed_missions.append(mission)
            self._cleanup_workspace(mission)

    async def _handle_agent_result(self, mission: Mission, agent: Any) -> None:
        """
        Unified result handler for all agent types.

        Processes exploit candidates (tag, persist, verify) and observations
        (persist, synthesize invariants, schedule missions).
        """
        # --- Exploit candidates ---
        candidates = agent.get_exploit_candidates()

        if candidates:
            self.logger.info(
                f"{mission.agent_type.value} {mission.mission_id} found "
                f"{len(candidates)} exploit candidate(s)"
            )

            for candidate in candidates:
                if hasattr(candidate, "mission_id") and not candidate.mission_id:
                    candidate.mission_id = mission.mission_id
                if (
                    hasattr(candidate, "invariant_id")
                    and not candidate.invariant_id
                    and mission.invariant
                ):
                    candidate.invariant_id = mission.invariant.id

                self.exploit_candidates.append(candidate)

                await persist(
                    self._state_manager,
                    self._state_manager.save_exploit_candidate(candidate)
                    if self._state_manager
                    else None,
                    self.logger,
                )

                # Verify compiled candidates
                if candidate.compiled and self.master_context:
                    verdict = await self._verification.verify_candidate(
                        candidate=candidate,
                        invariants=self.invariants,
                        master_context=self.master_context,
                        dependency_graph=self.dependency_graph,
                        active_missions=self.active_missions,
                    )
                    if verdict:
                        self.verdicts.append(verdict)

        # --- Observations ---
        observations = agent.get_observations()

        if observations:
            self.logger.info(
                f"{mission.agent_type.value} {mission.mission_id} recorded "
                f"{len(observations)} observation(s)"
            )

            await persist(
                self._state_manager,
                self._state_manager.save_observations(observations)
                if self._state_manager
                else None,
                self.logger,
            )

            new_invariants: List[Invariant] = []
            for obs in observations:
                new_inv = await self._synthesize_invariant(obs)
                if new_inv and new_inv.id not in self.invariants:
                    self.logger.info(f"New invariant discovered: {new_inv.id}")
                    self.invariants[new_inv.id] = new_inv
                    new_invariants.append(new_inv)
                    await self._schedule_missions_for_invariant(new_inv)

            if new_invariants:
                await persist(
                    self._state_manager,
                    self._state_manager.save_invariants(new_invariants)
                    if self._state_manager
                    else None,
                    self.logger,
                )

        if not candidates and not observations:
            self.logger.info(f"No results from {mission.mission_id}")

    # ------------------------------------------------------------------
    # Invariant synthesis and mission scheduling
    # ------------------------------------------------------------------

    async def _synthesize_invariant(
        self, observation: Observation
    ) -> Optional[Invariant]:
        """
        Synthesize a tentative invariant from an observation.

        Uses LLM to convert unstructured logs into a rule.
        """
        if not self.master_context or not self.dependency_graph:
            return None

        from kai.processes.invariant_synthesizer import InvariantSynthesizerProcess
        from kai.schemas import InvariantSynthesizerInput

        process = InvariantSynthesizerProcess(context=self.master_context)
        input_data = InvariantSynthesizerInput(
            observations=[observation],
            master_context=self.master_context,
            dependency_graph=self.dependency_graph,
            protocol_manifesto=self.protocol_manifesto,
            model_name=self.config.model,
            use_openai=self.config.use_openai,
        )

        try:
            output = await process.run(input_data)
            if output.success and output.invariants:
                return output.invariants[0]
        except Exception as e:
            self.logger.error(f"Failed to synthesize invariant: {e}")

        return None

    async def _schedule_missions_for_invariant(self, invariant: Invariant) -> None:
        """Schedule new missions for a dynamically discovered invariant."""
        if not self._planner:
            self.logger.warning("Cannot schedule missions: planner not initialized")
            return

        base_id = len(self.completed_missions) + self.mission_queue.qsize()
        campaign, missions = self._planner.create_missions_for_invariant(
            invariant, base_id
        )

        await persist(
            self._state_manager,
            self._state_manager.save_campaigns([campaign])
            if self._state_manager
            else None,
            self.logger,
        )

        if missions:
            await persist(
                self._state_manager,
                self._state_manager.save_missions(missions)
                if self._state_manager
                else None,
                self.logger,
            )

        for mission in missions:
            self.mission_queue.put_nowait(
                (PRIORITY_STATE_QUANT_HTTP, mission.mission_id, mission)
            )

    # ------------------------------------------------------------------
    # Workspace helpers
    # ------------------------------------------------------------------

    def _provision_workspace(self, mission: Mission) -> str:
        if not self.master_context:
            raise RuntimeError("MasterContext not initialized")
        return self._workspace_manager.provision_for_mission(
            mission, self.master_context
        )

    def _cleanup_workspace(self, mission: Mission) -> None:
        self._workspace_manager.cleanup_for_mission(mission)

    # ------------------------------------------------------------------
    # Public query API
    # ------------------------------------------------------------------

    def get_verified_exploits(
        self, min_severity: VerdictSeverity = VerdictSeverity.LOW
    ) -> List[Verdict]:
        """Get verified exploits at or above a minimum severity."""
        severity_order = [
            VerdictSeverity.INFORMATIONAL,
            VerdictSeverity.LOW,
            VerdictSeverity.MEDIUM,
            VerdictSeverity.HIGH,
            VerdictSeverity.CRITICAL,
        ]
        min_idx = severity_order.index(min_severity)

        return [
            v
            for v in self.verdicts
            if v.is_valid and severity_order.index(v.severity) >= min_idx
        ]

    def get_verification_stats(self) -> Dict[str, Any]:
        """Get verification statistics."""
        verified = [v for v in self.verdicts if v.is_valid]
        rejected = [
            v for v in self.verdicts if not v.is_valid and not v.blocked_by_root_cause
        ]
        blocked = [v for v in self.verdicts if v.blocked_by_root_cause]

        severity_counts: Dict[str, int] = {}
        for verdict in verified:
            sev = verdict.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        blocking_invariants: Dict[str, int] = {}
        for v in blocked:
            if v.blocking_invariant_id:
                blocking_invariants[v.blocking_invariant_id] = (
                    blocking_invariants.get(v.blocking_invariant_id, 0) + 1
                )

        return {
            "total_candidates": len(self.exploit_candidates),
            "verified_count": len(verified),
            "rejected_count": len(rejected),
            "blocked_by_root_cause_count": len(blocked),
            "by_severity": severity_counts,
            "rejection_reasons": [
                v.rejection_reason for v in rejected if v.rejection_reason
            ],
            "blocking_invariants": blocking_invariants,
        }

    def export_results(self, output_path: str) -> None:
        """
        Export all dispatcher results to a JSON file.

        Includes campaigns, missions, exploit candidates, verdicts, stats,
        and cost tracking (total tokens, total cost, breakdown by phase).

        Args:
            output_path: Path to the output JSON file
        """
        summary = {
            "total_campaigns": len(self.campaigns),
            "total_missions": len(self.completed_missions),
            "successful_missions": len(
                [m for m in self.completed_missions if m.status == "completed"]
            ),
            "failed_missions": len(
                [m for m in self.completed_missions if m.status == "failed"]
            ),
            "total_exploit_candidates": len(self.exploit_candidates),
            "total_verdicts": len(self.verdicts),
            "verified_exploits": len([v for v in self.verdicts if v.is_valid]),
            "rejected_exploits": len(
                [
                    v
                    for v in self.verdicts
                    if not v.is_valid and not v.blocked_by_root_cause
                ]
            ),
            "blocked_by_root_cause": len(
                [v for v in self.verdicts if v.blocked_by_root_cause]
            ),
        }

        cost_tracking = {
            "total_tokens": self.total_tokens,
            "total_cost": self.total_cost,
            "by_phase": self.token_usage_by_phase,
        }

        campaigns_data = [c.model_dump() for c in self.campaigns]
        missions_data = [m.model_dump() for m in self.completed_missions]

        exploits_by_mission: Dict[str, List[Dict]] = {}
        for candidate in self.exploit_candidates:
            mission_id = candidate.mission_id
            if mission_id not in exploits_by_mission:
                exploits_by_mission[mission_id] = []
            exploits_by_mission[mission_id].append(candidate.model_dump())

        verdicts_data = [v.model_dump() for v in self.verdicts]

        report = {
            "summary": summary,
            "cost_tracking": cost_tracking,
            "verification_stats": self.get_verification_stats(),
            "campaigns": campaigns_data,
            "missions": missions_data,
            "exploits_by_mission": exploits_by_mission,
            "verdicts": verdicts_data,
        }

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        self.logger.info(f"Results exported to {output_path}")
