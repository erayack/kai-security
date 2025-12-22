"""
Dispatcher: Mission control for Kai v2.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from kai.schemas import (
    ActorMatrix,
    CampaignBrief,
    CampaignBudget,
    ExploitCandidate,
    Invariant,
    InvariantType,
    MasterContext,
    Mission,
    MissionAgentType,
    Observation,
    ProtocolManifesto,
    Verdict,
    VerdictSeverity,
    VerifierProcessInput,
)
from kai.utils.dependency.graph import DependencyGraph

from kai.dispatcher.planner import MissionPlanner
from kai.dispatcher.workspace import WorkspaceManager
from kai.dispatcher.agent_factories import AGENT_FACTORIES as DEFAULT_AGENT_FACTORIES

if TYPE_CHECKING:
    from kai.agents.base import BaseAgent

logger = logging.getLogger(__name__)

# Type alias for agent factory function
AgentFactory = Callable[..., "BaseAgent"]


@dataclass
class DispatcherConfig:
    """Configuration for Dispatcher."""

    max_concurrent_agents: int = 4
    max_invariants_per_cluster: int = 5
    max_campaigns: int = 10
    include_exploration: bool = True
    default_budget: CampaignBudget = field(default_factory=CampaignBudget)
    workspace_dir: str = "./kai_workspaces"
    # Model settings for agents
    model: str = "openai/gpt-5.2"
    use_openai: bool = False


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
    ):
        # Use default factories if none provided
        self.agent_factories = agent_factories or dict(DEFAULT_AGENT_FACTORIES)
        self.config = config or DispatcherConfig()

        self.logger = logger.getChild("Dispatcher")

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

        self._workspace_manager = WorkspaceManager(
            workspace_dir=self.config.workspace_dir, logger=self.logger
        )
        self._planner: Optional[MissionPlanner] = None

    async def boot(
        self,
        repo_url: Optional[str] = None,
        repo_path: Optional[str] = None,
        model_name: str = "openai/gpt-5.2",
        use_openai: bool = False,
    ) -> bool:
        """
        Run preprocess chain to populate global knowledge.

        Chain: EnvironmentSetup - StaticAnalysis - Profiler - ActorProcess - InvariantProcess
        """
        self.logger.info("Booting Dispatcher...")

        from kai.processes.envsetup import EnvironmentSetupProcess
        from kai.processes.profiler import ProfilerProcess
        from kai.processes.actors import ActorProcess
        from kai.processes.invariants import InvariantProcess
        from kai.schemas import (
            EnvironmentSetupInput,
            ProfilerInput,
            ActorMatrixInput,
            InvariantProcessInput,
        )

        try:
            self.logger.info("Step 1/5: Environment Setup...")
            env_process = EnvironmentSetupProcess(
                MasterContext(
                    root_path="./", compile_success=True
                )  # TODO: get path from env
            )
            env_input = EnvironmentSetupInput(
                repo_url=repo_url or "",
                num_turns=10,
                model_name=model_name,
                use_openai=use_openai,
                repo_path_override=repo_path,
            )
            env_output = await env_process.run(env_input)

            if not env_output.success or not env_output.master_context:
                self.logger.error(
                    f"Environment setup failed: {env_output.error_message}"
                )
                return False

            self.master_context = env_output.master_context
            self.logger.info(f"MasterContext ready: {self.master_context.root_path}")

            self.logger.info("Step 2/5: Building DependencyGraph...")
            self.dependency_graph = await self._build_dependency_graph()
            if not self.dependency_graph:
                self.logger.error("Static analysis failed")
                return False

            self.logger.info("Step 3/5: Profiler...")
            profiler_process = ProfilerProcess(context=self.master_context)
            profiler_input = ProfilerInput(
                master_context=self.master_context,
                num_turns=5,
                model_name=model_name,
                use_openai=use_openai,
            )
            profiler_output = await profiler_process.run(profiler_input)

            if profiler_output.success and profiler_output.protocol_manifesto:
                self.protocol_manifesto = profiler_output.protocol_manifesto
                self.logger.info(
                    f"ProtocolManifesto ready: {self.protocol_manifesto.name}"
                )
            else:
                self.logger.warning("Profiler failed, continuing without manifesto")

            self.logger.info("Step 4/5: Actor Analysis...")
            actor_process = ActorProcess(context=self.master_context)
            actor_input = ActorMatrixInput(
                master_context=self.master_context,
                dependency_graph=self.dependency_graph,
                protocol_manifesto=self.protocol_manifesto,
                model_name=model_name,
                use_openai=use_openai,
            )
            actor_output = await actor_process.run(actor_input)

            if not actor_output.success or not actor_output.actor_matrix:
                self.logger.error(
                    f"Actor analysis failed: {actor_output.error_message}"
                )
                return False

            self.actor_matrix = actor_output.actor_matrix
            self.logger.info(f"ActorMatrix ready: {len(self.actor_matrix.roles)} roles")

            self.logger.info("Step 5/5: Invariant Analysis...")
            inv_process = InvariantProcess(context=self.master_context)
            inv_input = InvariantProcessInput(
                master_context=self.master_context,
                dependency_graph=self.dependency_graph,
                actor_matrix=self.actor_matrix,
                protocol_manifesto=self.protocol_manifesto,
                model_name=model_name,
                use_openai=use_openai,
            )
            inv_output = await inv_process.run(inv_input)

            if inv_output.success:
                self.invariants = {inv.id: inv for inv in inv_output.invariants}
                self.logger.info(f"Invariants ready: {len(self.invariants)} invariants")
            else:
                self.logger.warning(
                    f"Invariant analysis failed: {inv_output.error_message}"
                )

            self.logger.info("Planning missions...")
            self._plan_missions()

            self.logger.info(
                f"Boot complete: {len(self.campaigns)} campaigns, "
                f"{self.mission_queue.qsize()} missions queued"
            )
            return True

        except Exception as e:
            self.logger.error(f"Boot failed: {e}", exc_info=True)
            return False

    async def _build_dependency_graph(self) -> Optional[DependencyGraph]:
        """
        Run static analysis to build DependencyGraph.

        Uses the appropriate builder based on MasterContext.adapter.
        """
        from pathlib import Path
        from kai.utils.dependency.builders import get_builder

        if not self.master_context:
            return None

        root_path = Path(self.master_context.root_path)

        try:
            builder = get_builder(self.master_context.adapter)
            graph = builder.build(root_path)
            self.logger.info(f"Built graph with {len(graph._nodes)} nodes")
            return graph
        except Exception as e:
            self.logger.error(f"Failed to build DependencyGraph: {e}")
        return None

    def _plan_missions(self) -> None:
        """Plan missions from invariants (delegates to MissionPlanner)."""
        if (
            not self.invariants
            or not self.dependency_graph
            or not self.actor_matrix
            or not self.master_context
        ):
            self.logger.warning("Cannot plan missions: missing prerequisites")
            return

        self._planner = MissionPlanner(
            dependency_graph=self.dependency_graph,
            actor_matrix=self.actor_matrix,
            max_invariants_per_cluster=self.config.max_invariants_per_cluster,
            max_campaigns=self.config.max_campaigns,
            include_exploration=self.config.include_exploration,
            default_budget=self.config.default_budget,
            master_context=self.master_context,
        )

        base_index = len(self.completed_missions) + self.mission_queue.qsize()
        campaigns, missions = self._planner.plan(
            invariants=list(self.invariants.values()), base_mission_index=base_index
        )
        self.campaigns = campaigns

        for mission in missions:
            campaign = next(
                (c for c in campaigns if c.campaign_id == mission.campaign_id), None
            )
            priority = campaign.priority if campaign else 1
            self.mission_queue.put_nowait((priority, mission.mission_id, mission))

    async def run_loop(self) -> None:
        """
        Event loop: dispatch missions to agents, handle results.

        Runs until mission queue is empty and no active agents.
        """
        self.logger.info("Starting run loop...")

        while not self.mission_queue.empty() or self.active_missions:
            # Spawn agents if slots available
            while (
                len(self.active_missions) < self.config.max_concurrent_agents
                and not self.mission_queue.empty()
            ):
                _, _, mission = await self.mission_queue.get()
                # Track immediately to prevent over-spawning
                self.active_missions[mission.mission_id] = mission
                asyncio.create_task(self._execute_mission(mission))

            # Brief pause to allow task switching
            await asyncio.sleep(0.1)

        self.logger.info(
            f"Run loop complete: {len(self.completed_missions)} missions, "
            f"{len(self.exploit_candidates)} candidates"
        )

    async def _execute_mission(self, mission: Mission) -> None:
        """Execute a single mission with an agent."""
        mission.status = "in_progress"
        # Note: mission already added to active_missions in run_loop

        factory = self.agent_factories.get(mission.agent_type)
        if not factory:
            self.logger.warning(f"No agent factory for type {mission.agent_type}")
            mission.status = "failed"
            self.active_missions.pop(mission.mission_id, None)
            self.completed_missions.append(mission)
            return

        agent = None
        try:
            # Provision workspace
            workspace_path = self._provision_workspace(mission)

            # Create agent instance via factory with full context
            agent = factory(
                mission=mission,
                workspace_path=workspace_path,
                master_context=self.master_context,
                dependency_graph=self.dependency_graph,
                actor_matrix=self.actor_matrix,
                model=self.config.model,
                use_openai=self.config.use_openai,
                execution_id=mission.mission_id,
            )

            self.logger.info(
                f"Executing {mission.mission_id} with {mission.agent_type.value}"
            )

            # Agent-type specific execution
            if mission.agent_type == MissionAgentType.STATE:
                await agent.chat_with_tools("Begin.")
                await self._handle_state_agent_result(mission, agent)

            elif mission.agent_type == MissionAgentType.QUANT:
                await agent.chat_with_tools("Begin.")
                await self._handle_state_agent_result(mission, agent)

            elif mission.agent_type == MissionAgentType.BLACKBOX:
                await agent.chat_with_tools("Begin.")
                await self._handle_blackbox_agent_result(mission, agent)

            else:
                # Generic fallback
                prompt = self._build_mission_prompt(mission)
                result = await agent.chat(prompt)
                await self._handle_result(mission, result)

            mission.status = "completed"

        except Exception as e:
            self.logger.error(
                f"Mission {mission.mission_id} failed: {e}", exc_info=True
            )
            mission.status = "failed"

        finally:
            # Cleanup agent
            if agent is not None:
                try:
                    await agent.close()
                except Exception:
                    pass
            self.active_missions.pop(mission.mission_id, None)
            self.completed_missions.append(mission)
            # Cleanup workspace
            self._cleanup_workspace(mission)

    @staticmethod
    def _build_mission_prompt(mission: Mission) -> str:
        """Build the initial prompt for an agent based on mission details."""
        # TODO: Feed context to prompt template instead
        lines = [f"Mission: {mission.mission_id}"]

        if mission.invariant:
            lines.append(f"\nTarget Invariant: {mission.invariant.rule}")
            lines.append(f"Type: {mission.invariant.type.value}")
            if mission.invariant.explanation:
                lines.append(f"Explanation: {mission.invariant.explanation}")
            if mission.invariant.target_function_ids:
                lines.append(
                    f"Target Functions: {', '.join(mission.invariant.target_function_ids)}"
                )
            if mission.invariant.target_var_ids:
                lines.append(
                    f"Target Variables: {', '.join(mission.invariant.target_var_ids)}"
                )

        if mission.scope.entrypoints_subset.ids:
            lines.append(
                f"\nEntrypoints: {', '.join(mission.scope.entrypoints_subset.ids[:10])}"
            )
            if len(mission.scope.entrypoints_subset.ids) > 10:
                lines.append(
                    f"  ... and {len(mission.scope.entrypoints_subset.ids) - 10} more"
                )

        if mission.scope.actor_roles:
            lines.append(f"Actor Roles: {', '.join(mission.scope.actor_roles)}")

        lines.append(f"\nObjective: {mission.objectives.notes or 'Find exploit'}")
        lines.append(f"Max Turns: {mission.max_turns}")

        return "\n".join(lines)

    async def _handle_result(self, mission: Mission, result: Any) -> None:
        """Handle agent result: ExploitCandidate or Observation."""
        if isinstance(result, ExploitCandidate):
            self.logger.info(f"ExploitCandidate from {mission.mission_id}")
            if result.compiled and self.master_context:
                await self._verify_candidate(result)
            self.exploit_candidates.append(result)

        elif isinstance(result, Observation):
            self.logger.info(f"Observation from {mission.mission_id}")
            # Synthesize new invariant from observation
            new_inv = await self._synthesize_invariant(result)
            if new_inv and new_inv.id not in self.invariants:
                self.logger.info(f"New invariant discovered: {new_inv.id}")
                self.invariants[new_inv.id] = new_inv
                # Schedule new missions for this invariant
                self._schedule_missions_for_invariant(new_inv)

    async def _handle_state_agent_result(self, mission: Mission, agent: Any) -> None:
        """
        Extract and handle results from StateAgent.

        StateAgent stores exploit candidates in _registered_exploits via register_exploit tool.
        """
        # Get exploit candidates from agent
        candidates = []
        if hasattr(agent, "get_exploit_candidates"):
            candidates = agent.get_exploit_candidates()
        elif hasattr(agent, "_registered_exploits"):
            candidates = agent._registered_exploits

        if not candidates:
            self.logger.info(f"No exploit candidates from {mission.mission_id}")
            return

        self.logger.info(
            f"StateAgent {mission.mission_id} found {len(candidates)} exploit candidate(s)"
        )

        for candidate in candidates:
            # Tag candidate with mission context
            if hasattr(candidate, "mission_id") and not candidate.mission_id:
                candidate.mission_id = mission.mission_id
            if (
                hasattr(candidate, "invariant_id")
                and not candidate.invariant_id
                and mission.invariant
            ):
                candidate.invariant_id = mission.invariant.id

            # Verify compiled candidates
            if candidate.compiled and self.master_context:
                await self._verify_candidate(candidate)

            self.exploit_candidates.append(candidate)

    async def _verify_candidate(self, candidate: ExploitCandidate) -> Optional[Verdict]:
        """
        Verify an exploit candidate using VerifierProcess.

        Args:
            candidate: The exploit candidate to verify

        Returns:
            Verdict if verification completed, None if failed
        """
        if not self.master_context:
            return None

        from kai.processes.verifier import VerifierProcess

        # Get the invariant for this candidate
        invariant = self.invariants.get(candidate.invariant_id)
        if not invariant:
            self.logger.warning(
                f"No invariant found for {candidate.invariant_id}, creating placeholder"
            )
            invariant = Invariant(
                id=candidate.invariant_id,
                type=InvariantType.OTHER,
                rule=f"Unknown invariant: {candidate.invariant_id}",
            )

        self.logger.info(f"Verifying exploit candidate: {candidate.mission_id}")

        try:
            process = VerifierProcess(context=self.master_context)
            process_input = VerifierProcessInput(
                exploit_candidate=candidate,
                invariant=invariant,
                master_context=self.master_context,
                dependency_graph=self.dependency_graph,
                model_name=self.config.model,
                use_openai=self.config.use_openai,
                max_turns=16,
            )

            output = await process.run(process_input)

            if output.success and output.verdict:
                verdict = output.verdict
                self.verdicts.append(verdict)

                if verdict.is_valid:
                    self.logger.info(
                        f"VERIFIED: {candidate.mission_id} - "
                        f"{verdict.severity.value.upper()} - {verdict.vulnerability_class}"
                    )
                else:
                    self.logger.info(
                        f"REJECTED: {candidate.mission_id} - {verdict.rejection_reason}"
                    )

                return verdict
            else:
                self.logger.warning(
                    f"Verifier did not submit verdict for {candidate.mission_id}: "
                    f"{output.error_message}"
                )
                return None

        except Exception as e:
            self.logger.error(f"Verification failed for {candidate.mission_id}: {e}")
            return None

    async def _handle_blackbox_agent_result(self, mission: Mission, agent: Any) -> None:
        """
        Extract and handle results from BlackboxAgent.

        BlackboxAgent stores observations in blackbox_observations via add_observation tool.
        """
        observations = []
        if hasattr(agent, "blackbox_observations"):
            observations = agent.blackbox_observations

        if not observations:
            self.logger.info(f"No observations from {mission.mission_id}")
            return

        self.logger.info(
            f"BlackboxAgent {mission.mission_id} recorded {len(observations)} observation(s)"
        )

        for obs in observations:
            # Synthesize invariant from observation
            new_inv = await self._synthesize_invariant(obs)
            if new_inv and new_inv.id not in self.invariants:
                self.logger.info(f"New invariant discovered: {new_inv.id}")
                self.invariants[new_inv.id] = new_inv
                self._schedule_missions_for_invariant(new_inv)

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

    def _schedule_missions_for_invariant(self, invariant: Invariant) -> None:
        """Schedule new missions for a dynamically discovered invariant."""
        if not self._planner:
            self.logger.warning("Cannot schedule missions: planner not initialized")
            return

        base_id = len(self.completed_missions) + self.mission_queue.qsize()
        missions = self._planner.create_missions_for_invariant(invariant, base_id)

        for mission in missions:
            self.mission_queue.put_nowait((1, mission.mission_id, mission))

    def _provision_workspace(self, mission: Mission) -> str:
        if not self.master_context:
            raise RuntimeError("MasterContext not initialized")
        return self._workspace_manager.provision_for_mission(
            mission, self.master_context
        )

    def _cleanup_workspace(self, mission: Mission) -> None:
        self._workspace_manager.cleanup_for_mission(mission)

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
        rejected = [v for v in self.verdicts if not v.is_valid]

        severity_counts: Dict[str, int] = {}
        for verdict in verified:
            sev = verdict.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_candidates": len(self.exploit_candidates),
            "verified_count": len(verified),
            "rejected_count": len(rejected),
            "by_severity": severity_counts,
            "rejection_reasons": [
                v.rejection_reason for v in rejected if v.rejection_reason
            ],
        }

    def export_results(self, output_path: str) -> None:
        """
        Export all dispatcher results to a JSON file.

        Includes campaigns, missions, exploit candidates, verdicts, and stats.

        Args:
            output_path: Path to the output JSON file
        """
        import json
        from pathlib import Path

        # Build summary
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
            "rejected_exploits": len([v for v in self.verdicts if not v.is_valid]),
        }

        # Serialize campaigns
        campaigns_data = [c.model_dump() for c in self.campaigns]

        # Serialize missions
        missions_data = [m.model_dump() for m in self.completed_missions]

        # Group exploit candidates by mission
        exploits_by_mission: Dict[str, List[Dict]] = {}
        for candidate in self.exploit_candidates:
            mission_id = candidate.mission_id
            if mission_id not in exploits_by_mission:
                exploits_by_mission[mission_id] = []
            exploits_by_mission[mission_id].append(candidate.model_dump())

        # Serialize verdicts with full details
        verdicts_data = [v.model_dump() for v in self.verdicts]

        # Build final report
        report = {
            "summary": summary,
            "verification_stats": self.get_verification_stats(),
            "campaigns": campaigns_data,
            "missions": missions_data,
            "exploits_by_mission": exploits_by_mission,
            "verdicts": verdicts_data,
        }

        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        self.logger.info(f"Results exported to {output_path}")
