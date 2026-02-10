"""
Boot pipeline: 6-step preprocessing chain for Dispatcher.
"""

import logging
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from kai.agents import settings
from kai.exceptions import (
    ActorAnalysisError,
    DispatcherBootError,
    EnvironmentSetupError,
    StaticAnalysisError,
    WorkspaceValidationError,
)
from kai.schemas import (
    ActorMatrix,
    CampaignBudget,
    Invariant,
    MasterContext,
    ProtocolManifesto,
    WorkspacePreset,
)
from kai.state_manager import KaiStateManager
from kai.utils.dependency.graph import DependencyGraph

from kai.dispatcher._helpers import persist
from kai.dispatcher.planner import MissionPlanner
from kai.dispatcher.usage_tracker import UsageTracker
from kai.dispatcher.workspace import WorkspaceManager


@dataclass
class SetupResult:
    """Intermediate result from steps 1-3 (setup, graph, workspace validation)."""

    master_context: MasterContext
    dependency_graph: DependencyGraph


@dataclass
class BootResult:
    """Bundles all outputs from the boot pipeline."""

    master_context: MasterContext
    dependency_graph: DependencyGraph
    protocol_manifesto: Optional[ProtocolManifesto]
    actor_matrix: ActorMatrix
    invariants: Dict[str, Invariant]
    planner: MissionPlanner


@dataclass
class BootConfig:
    """Boot-time parameters (subset of DispatcherConfig relevant to boot)."""

    workspace_dir: str = "./kai_workspaces"
    setup_model: str = settings.SETUP_DEFAULT_MODEL
    setup_max_turns: int = settings.SETUP_MAX_TURNS
    profiler_max_turns: int = settings.PROFILER_MAX_TURNS
    invariant_model: str = settings.INVARIANT_DEFAULT_MODEL
    save_rollouts: bool = False
    rollouts_dir: Optional[str] = None
    skip_workspace_validation: bool = False
    max_invariants_per_cluster: int = 5
    max_campaigns: int = 10
    include_exploration: bool = True
    default_budget: CampaignBudget = field(default_factory=CampaignBudget)


class BootPipeline:
    """Runs the 6-step preprocessing chain."""

    def __init__(
        self,
        *,
        config,  # DispatcherConfig (avoid import cycle via duck-typing)
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

    async def run(
        self,
        *,
        repo_url: Optional[str] = None,
        repo_path: Optional[str] = None,
        model_name: str = settings.MAIN_DEFAULT_MODEL,
        use_openai: bool = False,
        master_context: Optional[MasterContext] = None,
    ) -> BootResult:
        """
        Run the full 6-step preprocess chain (backward-compatible entry point).

        Calls run_setup_and_graph() then run_llm_steps() sequentially.
        """
        setup = await self.run_setup_and_graph(
            repo_url=repo_url,
            repo_path=repo_path,
            use_openai=use_openai,
            master_context=master_context,
        )
        return await self.run_llm_steps(
            setup=setup,
            model_name=model_name,
            use_openai=use_openai,
        )

    # ------------------------------------------------------------------
    # Phase 1: Steps 1-3 (setup, graph, workspace validation)
    # ------------------------------------------------------------------

    async def run_setup_and_graph(
        self,
        *,
        repo_url: Optional[str] = None,
        repo_path: Optional[str] = None,
        use_openai: bool = False,
        master_context: Optional[MasterContext] = None,
    ) -> SetupResult:
        """
        Run steps 1-3: Environment Setup, DependencyGraph, Workspace Validation.

        Returns:
            SetupResult with MasterContext and DependencyGraph.

        Raises:
            EnvironmentSetupError, StaticAnalysisError, WorkspaceValidationError,
            DispatcherBootError
        """
        from kai.processes.envsetup import EnvironmentSetupProcess
        from kai.schemas import EnvironmentSetupInput

        self.logger.info("Booting Dispatcher...")

        try:
            # Step 1: Environment Setup
            if master_context:
                mc = master_context
                self.logger.info(f"Using provided MasterContext: {mc.root_path}")
            else:
                self.logger.info("Step 1/6: Environment Setup...")
                env_process = EnvironmentSetupProcess(
                    MasterContext(root_path="./", compile_success=True)
                )
                env_input = EnvironmentSetupInput(
                    repo_url=repo_url or "",
                    num_turns=self._config.setup_max_turns,
                    model_name=self._config.setup_model,
                    use_openai=use_openai,
                    repo_path_override=repo_path,
                    save_rollouts=self._config.save_rollouts,
                    rollouts_dir=self._config.rollouts_dir,
                )
                env_output = await env_process.run(env_input)

                if not env_output.success or not env_output.master_context:
                    error_msg = env_output.error_message or "Environment setup failed"
                    self.logger.error(f"Environment setup failed: {error_msg}")
                    raise EnvironmentSetupError(error_msg)

                mc = env_output.master_context

            self.logger.info(f"MasterContext ready: {mc.root_path}")

            await persist(
                self._state_manager,
                self._state_manager.save_master_context(mc)
                if self._state_manager
                else None,
                self.logger,
            )
            await persist(
                self._state_manager,
                self._state_manager.update_state("setup")
                if self._state_manager
                else None,
                self.logger,
            )

            # Step 2: Build DependencyGraph
            self.logger.info("Step 2/6: Building DependencyGraph...")
            dependency_graph = await self._build_dependency_graph(mc)
            if not dependency_graph:
                self.logger.error("Static analysis failed")
                raise StaticAnalysisError("Failed to build dependency graph")

            await persist(
                self._state_manager,
                self._state_manager.save_dependency_graph(dependency_graph.to_dict())
                if self._state_manager
                else None,
                self.logger,
            )

            # Step 3: Workspace Validation
            if not self._config.skip_workspace_validation:
                self.logger.info("Step 3/6: Workspace Validation...")
                mc = await self._run_workspace_validation(mc, use_openai)
            else:
                self.logger.info(
                    "Skipping workspace validation (config.skip_workspace_validation=True)"
                )

            return SetupResult(
                master_context=mc,
                dependency_graph=dependency_graph,
            )

        except (
            EnvironmentSetupError,
            StaticAnalysisError,
            WorkspaceValidationError,
        ):
            raise
        except Exception as e:
            self.logger.error(f"Boot setup failed: {e}", exc_info=True)
            raise DispatcherBootError(f"Boot setup failed: {e}") from e

    # ------------------------------------------------------------------
    # Phase 2: Steps 4-6 (profiler, actors, invariants)
    # ------------------------------------------------------------------

    async def run_llm_steps(
        self,
        *,
        setup: SetupResult,
        model_name: str = settings.MAIN_DEFAULT_MODEL,
        use_openai: bool = False,
    ) -> BootResult:
        """
        Run steps 4-6: Profiler, Actor Analysis, Invariant Analysis.

        Args:
            setup: Result from run_setup_and_graph().
            model_name: Model to use for agent inference.
            use_openai: Whether to use OpenAI API directly.

        Returns:
            BootResult with all boot outputs.

        Raises:
            ActorAnalysisError, DispatcherBootError
        """
        from kai.processes.profiler import ProfilerProcess
        from kai.processes.actors import ActorProcess
        from kai.processes.invariants import InvariantProcess
        from kai.schemas import (
            ProfilerInput,
            ActorMatrixInput,
            InvariantProcessInput,
        )

        mc = setup.master_context
        dependency_graph = setup.dependency_graph

        try:
            # Step 4: Profiler
            self.logger.info("Step 4/6: Profiler...")
            profiler_process = ProfilerProcess(context=mc)
            profiler_input = ProfilerInput(
                master_context=mc,
                dependency_graph=dependency_graph,
                num_turns=5,
                model_name=model_name,
                use_openai=use_openai,
            )
            profiler_output = await profiler_process.run(profiler_input)

            protocol_manifesto: Optional[ProtocolManifesto] = None
            if profiler_output.success and profiler_output.protocol_manifesto:
                protocol_manifesto = profiler_output.protocol_manifesto
                self.logger.info(f"ProtocolManifesto ready: {protocol_manifesto.name}")
                await persist(
                    self._state_manager,
                    self._state_manager.save_protocol_manifesto(protocol_manifesto)
                    if self._state_manager
                    else None,
                    self.logger,
                )
            else:
                self.logger.warning("Profiler failed, continuing without manifesto")

            await persist(
                self._state_manager,
                self._state_manager.update_state("profiler")
                if self._state_manager
                else None,
                self.logger,
            )

            # Step 5: Actor Analysis
            self.logger.info("Step 5/6: Actor Analysis...")
            actor_process = ActorProcess(context=mc)
            actor_input = ActorMatrixInput(
                master_context=mc,
                dependency_graph=dependency_graph,
                protocol_manifesto=protocol_manifesto,
                model_name=model_name,
                use_openai=use_openai,
            )
            actor_output = await actor_process.run(actor_input)

            if not actor_output.success or not actor_output.actor_matrix:
                error_msg = actor_output.error_message or "Actor analysis failed"
                self.logger.error(f"Actor analysis failed: {error_msg}")
                raise ActorAnalysisError(error_msg)

            actor_matrix = actor_output.actor_matrix
            self.logger.info(f"ActorMatrix ready: {len(actor_matrix.roles)} roles")

            await persist(
                self._state_manager,
                self._state_manager.save_actor_matrix(actor_matrix)
                if self._state_manager
                else None,
                self.logger,
            )

            # Step 6: Invariant Analysis
            self.logger.info("Step 6/6: Invariant Analysis...")
            inv_process = InvariantProcess(context=mc)
            inv_input = InvariantProcessInput(
                master_context=mc,
                dependency_graph=dependency_graph,
                actor_matrix=actor_matrix,
                protocol_manifesto=protocol_manifesto,
                model_name=self._config.invariant_model,
                use_openai=use_openai,
            )
            inv_output = await inv_process.run(inv_input)

            invariants: Dict[str, Invariant] = {}
            if inv_output.success:
                invariants = {inv.id: inv for inv in inv_output.invariants}
                self.logger.info(f"Invariants ready: {len(invariants)} invariants")
            else:
                self.logger.warning(
                    f"Invariant analysis failed: {inv_output.error_message}"
                )

            await persist(
                self._state_manager,
                self._state_manager.update_state("invariant")
                if self._state_manager
                else None,
                self.logger,
            )
            await persist(
                self._state_manager,
                self._state_manager.save_invariants(list(invariants.values()))
                if self._state_manager
                else None,
                self.logger,
            )

            # Initialize planner
            planner = MissionPlanner(
                dependency_graph=dependency_graph,
                actor_matrix=actor_matrix,
                max_invariants_per_cluster=self._config.max_invariants_per_cluster,
                max_campaigns=self._config.max_campaigns,
                include_exploration=self._config.include_exploration,
                default_budget=self._config.default_budget,
                master_context=mc,
            )

            self.logger.info(
                f"Boot complete: {len(invariants)} invariants, planner ready"
            )

            return BootResult(
                master_context=mc,
                dependency_graph=dependency_graph,
                protocol_manifesto=protocol_manifesto,
                actor_matrix=actor_matrix,
                invariants=invariants,
                planner=planner,
            )

        except ActorAnalysisError:
            raise
        except Exception as e:
            self.logger.error(f"Boot LLM steps failed: {e}", exc_info=True)
            raise DispatcherBootError(f"Boot LLM steps failed: {e}") from e

    async def _run_workspace_validation(
        self, mc: MasterContext, use_openai: bool
    ) -> MasterContext:
        """Run workspace validation and return (possibly updated) MasterContext."""
        from kai.processes.workspace_validation import WorkspaceValidationProcess
        from kai.schemas import WorkspaceValidationInput

        ws_output = await WorkspaceValidationProcess(
            context=mc, workspace_dir=self._config.workspace_dir
        ).run(
            WorkspaceValidationInput(
                master_context=mc,
                presets=[
                    WorkspacePreset.LIGHTWEIGHT,
                    WorkspacePreset.CLEAN,
                    WorkspacePreset.WRITEABLE,
                    WorkspacePreset.SANDBOX,
                ],
                timeout_compile_s=120,
                timeout_test_s=120,
                save_rollouts=self._config.save_rollouts,
                rollouts_dir=self._config.rollouts_dir,
            )
        )
        if not ws_output.success:
            error_msg = ws_output.error_message or "Workspace validation failed"
            self.logger.error(error_msg)
            preset_errors = []
            for r in ws_output.results:
                preset_info = (
                    f"WorkspaceValidation {r.preset.value}: "
                    f"compiled={r.compiled}, test_success={r.test_success}, "
                    f"workspace={r.workspace_path}, error={r.error}"
                )
                self.logger.error(preset_info)
                preset_errors.append(preset_info)
            raise WorkspaceValidationError(
                f"{error_msg}. Details: {'; '.join(preset_errors)}"
            )

        self.logger.info("Workspace validation passed")
        try:
            for r in ws_output.results:
                ir = getattr(r, "import_recipe", None)
                if ir and getattr(ir, "validated", False):
                    mc = mc.model_copy(update={"import_recipe": ir})
                    break
        except Exception:
            pass

        return mc

    async def _build_dependency_graph(
        self, mc: MasterContext
    ) -> Optional[DependencyGraph]:
        """
        Run static analysis to build DependencyGraph.

        Uses the appropriate builder based on MasterContext.adapter.
        May update mc.adapter via model_copy (returns the graph; mc mutation
        is handled by the caller via BootResult.master_context).
        """
        from kai.utils.dependency.builders import get_builder

        adapter = mc.adapter
        if adapter == "solidity" and mc.frameworks:
            inferred = self._infer_adapter_from_framework(mc.frameworks)
            if inferred == "__unsupported_rust__":
                self.logger.error(
                    "Unsupported project: only Cargo/Rust detected. Rust adapter is not available yet."
                )
                return None
            if inferred and inferred != "solidity":
                self.logger.info(
                    f"Adapter inferred from frameworks {mc.frameworks}: {inferred}"
                )
                adapter = inferred
                mc = mc.model_copy(update={"adapter": inferred})

        if not adapter:
            raise RuntimeError(
                "MasterContext.adapter must be set before building dependency graph"
            )

        adapter = adapter.lower()

        if adapter == "javascript":
            master_root_check = Path(mc.root_path).resolve()
            has_ts_files = (
                any(master_root_check.glob("src/**/*.ts"))
                or any(master_root_check.glob("*.ts"))
                or any(master_root_check.glob("lib/**/*.ts"))
            )
            if has_ts_files:
                self.logger.info(
                    "TypeScript files detected - upgrading adapter from 'javascript' to 'typescript'"
                )
                adapter = "typescript"
                mc = mc.model_copy(update={"adapter": "typescript"})

        needs_writable_workspace = adapter == "solidity"

        master_root = Path(mc.root_path).resolve()
        analysis_root = master_root

        if needs_writable_workspace and not os.access(str(master_root), os.W_OK):
            try:
                ws_id = f"analysis_{uuid.uuid4().hex[:8]}"
                ws_path = self._workspace_manager.provision(
                    workspace_id=ws_id,
                    master_path=str(master_root),
                    preset=WorkspacePreset.CLEAN,
                    master_context=mc,
                )
                analysis_root = Path(ws_path).resolve()
                self.logger.info(
                    f"Provisioned analysis workspace for DependencyGraph: {analysis_root}"
                )
            except Exception as e:
                self.logger.warning(
                    f"Failed to provision analysis workspace; falling back to master root: {e}"
                )
                analysis_root = master_root

        try:
            builder = get_builder(mc.adapter)
            graph = builder.build(analysis_root)
            self.logger.info(f"Built graph with {len(graph._nodes)} nodes")
            return graph
        except Exception as e:
            self.logger.error(f"Failed to build DependencyGraph: {e}")
        return None

    @staticmethod
    def _infer_adapter_from_framework(
        frameworks: Optional[List[str]],
    ) -> Optional[str]:
        """
        Infer the adapter type from the detected framework(s).

        Uses the canonical ``FRAMEWORK_TO_ADAPTER`` mapping from
        ``kai.utils.framework`` as the single source of truth.

        Returns the appropriate adapter string, or None if no mapping found.
        """
        from kai.utils.framework import FRAMEWORK_TO_ADAPTER

        if not frameworks:
            return None

        fw = {str(x).lower() for x in frameworks}
        for fw_name, adapter in FRAMEWORK_TO_ADAPTER.items():
            if fw_name in fw:
                return adapter
        # Check for unsupported frameworks
        if fw and fw <= {"cargo", "rust"}:
            return "__unsupported_rust__"
        return None
