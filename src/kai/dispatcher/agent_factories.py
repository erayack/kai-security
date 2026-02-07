"""
Agent factories for Dispatcher.

Factory functions create properly configured agent instances for missions.
Each factory handles agent-specific setup (prompts, workspace paths, etc.).
"""

from typing import Optional, Dict, Any, List

from kai.agents import settings
from kai.schemas import (
    ActorMatrix,
    Invariant,
    MasterContext,
    Mission,
    MissionAgentType,
)
from kai.utils.dependency.graph import DependencyGraph


def derive_scope_paths(
    invariant: Optional[Invariant],
    dependency_graph: Optional[DependencyGraph],
) -> Optional[List[str]]:
    """
    Derive scope_paths from invariant targets using the dependency graph.

    This ensures agents stay focused on files relevant to the invariant,
    preventing drift to unrelated code.

    Args:
        invariant: The target invariant (may be None for exploration)
        dependency_graph: DependencyGraph for resolving node locations

    Returns:
        List of file paths to scope the agent to, or None if no scoping needed
    """
    if not invariant or not dependency_graph:
        return None

    # Collect all target IDs
    target_ids = set()
    if invariant.target_function_ids:
        target_ids.update(invariant.target_function_ids)
    if invariant.target_var_ids:
        target_ids.update(invariant.target_var_ids)
    if invariant.target_file_ids:
        target_ids.update(invariant.target_file_ids)

    if not target_ids:
        return None

    # Resolve to file paths
    file_paths = set()
    for node_id in target_ids:
        node = dependency_graph._nodes.get(node_id)
        if node and node.span and node.span.file:
            file_paths.add(node.span.file)

    # Also include files that contain callers/callees of target functions
    # This gives agents the "scoped halo" around targets
    from kai.utils.dependency.models import EdgeKind

    for (src, kind, dst), _ in dependency_graph._edges.items():
        if kind == EdgeKind.CALLS:
            # If src or dst is a target, include both
            if src in target_ids or dst in target_ids:
                for nid in [src, dst]:
                    node = dependency_graph._nodes.get(nid)
                    if node and node.span and node.span.file:
                        file_paths.add(node.span.file)

    return list(file_paths) if file_paths else None


def derive_scope_paths_from_cluster(
    invariant_cluster: Optional[List[Invariant]],
    dependency_graph: Optional[DependencyGraph],
) -> Optional[List[str]]:
    """
    Derive scope_paths from a cluster of invariants.

    Combines targets from all invariants in the cluster.

    Args:
        invariant_cluster: List of invariants
        dependency_graph: DependencyGraph for resolving node locations

    Returns:
        List of file paths to scope the agent to, or None if no scoping needed
    """
    if not invariant_cluster or not dependency_graph:
        return None

    # Combine all file paths from individual invariants
    all_paths = set()
    for inv in invariant_cluster:
        paths = derive_scope_paths(inv, dependency_graph)
        if paths:
            all_paths.update(paths)

    return list(all_paths) if all_paths else None


def filter_actor_context(
    actor_matrix: Optional[ActorMatrix],
    invariant: Optional[Invariant],
) -> str:
    """
    Filter actor matrix to roles relevant to the invariant's targets.

    Returns a formatted string for embedding in agent prompts.

    Args:
        actor_matrix: The full ActorMatrix from preprocessing
        invariant: The target invariant (may be None for exploration missions)

    Returns:
        Formatted string describing relevant roles and privileges
    """
    if not actor_matrix:
        return "No actor matrix available."

    if not invariant:
        # For exploration missions, return all roles summary
        lines = ["All protocol roles:\n"]
        for role in actor_matrix.roles:
            lines.append(f"**{role.name}** (trust: {role.trust})")
            if role.access_signature:
                lines.append(f"  - Access via: {', '.join(role.access_signature)}")
            lines.append(f"  - Privileges: {len(role.privileges)} functions")
            lines.append("")
        return "\n".join(lines)

    # Get target function IDs and variable IDs from invariant
    target_func_ids = set(invariant.target_function_ids or [])
    target_var_ids = set(invariant.target_var_ids or [])

    # Also match by function name (in case IDs don't match exactly)
    target_func_names = set()
    for fid in target_func_ids:
        # Extract function name from ID like "Contract.funcName(args)"
        if "." in fid:
            name_part = fid.split(".")[-1].split("(")[
                0
            ]  # TODO: check if works on other languages
            target_func_names.add(name_part)

    relevant_roles = []
    for role in actor_matrix.roles:
        role_name = role.name
        trust = role.trust
        privileges = role.privileges
        access_sig = role.access_signature

        # Check if any privilege touches our targets
        relevant_privs = []
        for priv in privileges:
            priv_id = priv.id
            priv_name = priv.name
            write_target_ids = set(priv.write_target_ids or [])

            # Match by function ID, function name, or written variable IDs
            if (
                priv_id in target_func_ids
                or priv_name in target_func_names
                or write_target_ids & target_var_ids
            ):
                relevant_privs.append(priv)

        if relevant_privs:
            relevant_roles.append(
                {
                    "name": role_name,
                    "trust": trust,
                    "access_signature": access_sig,
                    "privileges": relevant_privs,
                }
            )

    if not relevant_roles:
        return "No roles directly touch the target functions/variables."

    # Format output
    lines = ["Roles relevant to this invariant:\n"]
    for role in relevant_roles:
        lines.append(f"**{role['name']}** (trust: {role['trust']})")
        if role["access_signature"]:
            lines.append(f"  - Access via: {', '.join(role['access_signature'])}")
        lines.append("  - Can call:")
        for priv in role["privileges"]:
            sig = priv.signature or priv.name
            container = priv.container or ""
            writes = priv.write_targets or []
            write_str = f" -> writes: {', '.join(writes)}" if writes else ""
            lines.append(f"    - {container}.{sig}{write_str}")
        lines.append("")

    return "\n".join(lines)


def _create_invariant_agent(
    agent_cls,
    mission: Mission,
    workspace_path: str,
    master_context: MasterContext,
    dependency_graph: Optional[DependencyGraph] = None,
    actor_matrix: Optional[ActorMatrix] = None,
    model: str = settings.MAIN_DEFAULT_MODEL,
    use_openai: bool = False,
    execution_id: Optional[str] = None,
    extra_instructions: Optional[str] = None,
):
    """
    Shared factory logic for invariant-based agents (StateAgent, QuantAgent).

    Args:
        agent_cls: The agent class to instantiate
        mission: The mission to execute
        workspace_path: Path to the provisioned workspace
        master_context: MasterContext from preprocessing
        dependency_graph: Optional DependencyGraph for code analysis tools
        actor_matrix: Optional ActorMatrix for actor context filtering
        model: Model to use for inference
        use_openai: Whether to use OpenAI API directly
        execution_id: Optional execution ID for logging
        extra_instructions: Additional instructions (e.g., CWE hints)

    Returns:
        Configured agent ready for chat_with_tools()
    """
    # Derive scope paths from invariant targets
    scope_paths = derive_scope_paths(mission.invariant, dependency_graph)

    # Create agent with scope paths for focus
    agent = agent_cls(
        mission=mission,
        master_context=master_context,
        dependency_graph=dependency_graph,
        max_tool_turns=mission.max_turns,
        repo_path=workspace_path,
        model=model,
        use_openai=use_openai,
        execution_id=execution_id,
        scope_paths=scope_paths,
    )

    # Set workspace path for tools
    agent.workspace_path = workspace_path

    # Set up toolcalling prompt with invariant context
    if mission.invariant:
        actor_context = filter_actor_context(actor_matrix, mission.invariant)
        # Add scope paths info to extra instructions
        scope_info = ""
        if scope_paths:
            scope_info = f"\n\n### Scoped Files\nFocus analysis on these files: {', '.join(scope_paths)}"
        # Import recipe hint
        import_info = ""
        try:
            ir = getattr(master_context, "import_recipe", None)
            if ir and getattr(ir, "validated", False):
                ex = (
                    getattr(ir, "example_import", None)
                    or getattr(ir, "main_import", None)
                    or ""
                )
                if ex:
                    import_info = (
                        f"\n\n### Validated Import\nUse this import in PoCs: {ex}"
                    )
        except Exception:
            pass
        agent.set_toolcalling_prompt(
            invariant=mission.invariant,
            actor_context=actor_context,
            extra_instructions=(extra_instructions or "") + scope_info + import_info,
        )

    return agent


def create_state_agent(
    mission: Mission,
    workspace_path: str,
    master_context: MasterContext,
    dependency_graph: Optional[DependencyGraph] = None,
    actor_matrix: Optional[ActorMatrix] = None,
    model: str = settings.MAIN_DEFAULT_MODEL,
    use_openai: bool = False,
    execution_id: Optional[str] = None,
    extra_instructions: Optional[str] = None,
):
    """Factory function to create a properly configured StateAgent."""
    from kai.agents.agent_types.state_agent import StateAgent

    return _create_invariant_agent(
        StateAgent,
        mission,
        workspace_path,
        master_context,
        dependency_graph,
        actor_matrix,
        model,
        use_openai,
        execution_id,
        extra_instructions,
    )


def create_quant_agent(
    mission: Mission,
    workspace_path: str,
    master_context: MasterContext,
    dependency_graph: Optional[DependencyGraph] = None,
    actor_matrix: Optional[ActorMatrix] = None,
    model: str = settings.MAIN_DEFAULT_MODEL,
    use_openai: bool = False,
    execution_id: Optional[str] = None,
    extra_instructions: Optional[str] = None,
):
    """Factory function to create a properly configured QuantAgent."""
    from kai.agents.agent_types.quant_agent import QuantAgent

    return _create_invariant_agent(
        QuantAgent,
        mission,
        workspace_path,
        master_context,
        dependency_graph,
        actor_matrix,
        model,
        use_openai,
        execution_id,
        extra_instructions,
    )


def create_blackbox_agent(
    mission: Mission,
    workspace_path: str,
    master_context: MasterContext,
    dependency_graph: Optional[DependencyGraph] = None,
    actor_matrix: Optional[ActorMatrix] = None,
    model: str = settings.MAIN_DEFAULT_MODEL,
    use_openai: bool = False,
    execution_id: Optional[str] = None,
    extra_instructions: Optional[str] = None,
):
    """
    Factory function to create a properly configured BlackboxAgent.

    Note: BlackboxAgent uses a different setup flow via BlackboxProcess.
    This factory provides a simpler interface for Dispatcher integration.
    """
    from kai.agents.agent_types.blackbox_agent import BlackboxAgent
    from kai.schemas import CampaignBrief, CampaignScope
    from kai.utils.tool_adapters import get_supported_frameworks

    # Create a CampaignBrief from mission context
    framework = None
    if master_context and getattr(master_context, "frameworks", None):
        supported = set(get_supported_frameworks())
        for fw in master_context.frameworks or []:
            fw_lower = str(fw).lower()
            if fw_lower in supported:
                framework = fw_lower
                break

    campaign_brief = CampaignBrief(
        campaign_id=mission.campaign_id,
        agent_types=[mission.agent_type],
        framework=framework,
        scope=CampaignScope(),
        invariants=[mission.invariant] if mission.invariant else [],
        master_context=master_context,
    )

    agent = BlackboxAgent(
        campaign_brief=campaign_brief,
        dependency_graph=dependency_graph,
        repo_path=workspace_path,
        max_tool_turns=mission.max_turns,
        model=model,
        use_openai=use_openai,
        execution_id=execution_id,
    )

    return agent


def create_gamified_agent(
    mission: Mission,
    workspace_path: str,
    master_context: MasterContext,
    dependency_graph: Optional[DependencyGraph] = None,
    actor_matrix: Optional[ActorMatrix] = None,
    protocol_manifesto=None,
    model: str = settings.GAMIFIED_DEFAULT_MODEL,
    use_openai: bool = False,
    execution_id: Optional[str] = None,
    extra_instructions: Optional[str] = None,
):
    """
    Factory function to create a properly configured GamifiedAgent.

    GamifiedAgent receives an invariant cluster and discovers exploitation
    opportunities by reasoning about gaps between invariants.

    Args:
        mission: The mission to execute (must have invariant_cluster set)
        workspace_path: Path to the provisioned workspace
        master_context: MasterContext from preprocessing
        dependency_graph: Optional DependencyGraph for code analysis tools
        actor_matrix: Optional ActorMatrix for actor context
        protocol_manifesto: Optional ProtocolManifesto for system context
        model: Model to use for inference (defaults to GAMIFIED_DEFAULT_MODEL)
        use_openai: Whether to use OpenAI API directly
        execution_id: Optional execution ID for logging

    Returns:
        Configured GamifiedAgent ready for chat_with_tools()
    """
    from kai.agents.agent_types.gamified_agent import GamifiedAgent

    # Get the invariant cluster from mission
    invariant_cluster = mission.invariant_cluster or []
    if not invariant_cluster and mission.invariant:
        # Fallback: wrap single invariant in a list
        invariant_cluster = [mission.invariant]

    # Extract vars in scope from the cluster's target variables
    vars_in_scope = []
    if dependency_graph and invariant_cluster:
        from kai.schemas import VarVocabEntry

        seen_var_ids = set()
        for inv in invariant_cluster:
            for var_id in inv.target_var_ids:
                if var_id in seen_var_ids:
                    continue
                seen_var_ids.add(var_id)
                node = dependency_graph._nodes.get(var_id)
                if node:
                    # Get writers and readers from graph edges
                    # _edges is Dict[(src, kind, dst), EdgeMeta]
                    writers = []
                    readers = []
                    for src, kind, dst in dependency_graph._edges:
                        if dst == var_id and kind.name == "WRITES":
                            writers.append(src)
                        if src == var_id and kind.name == "READS":
                            readers.append(dst)
                    vars_in_scope.append(
                        VarVocabEntry(
                            id=var_id,
                            name=node.name,
                            container=node.parent_id or "",
                            file=node.span.file if node.span else "",
                            writers=writers,
                            readers=readers,
                        )
                    )

    # Derive scope paths from the invariant cluster
    scope_paths = derive_scope_paths_from_cluster(invariant_cluster, dependency_graph)

    # Create the agent with scope paths for focus
    agent = GamifiedAgent(
        mission=mission,
        master_context=master_context,
        invariant_cluster=invariant_cluster,
        vars_in_scope=vars_in_scope,
        actor_matrix=actor_matrix,
        protocol_manifesto=protocol_manifesto,
        dependency_graph=dependency_graph,
        max_tool_turns=mission.max_turns,
        repo_path=workspace_path,
        model=model,
        use_openai=use_openai,
        execution_id=execution_id,
        scope_paths=scope_paths,
    )

    # Set workspace path for tools
    agent.workspace_path = workspace_path

    # Set up toolcalling prompt
    cluster_id = mission.campaign_id or "default"
    agent.set_toolcalling_prompt(cluster_id=cluster_id)

    return agent


def create_http_agent(
    mission: Mission,
    workspace_path: str,
    master_context: MasterContext,
    dependency_graph: Optional[DependencyGraph] = None,
    actor_matrix: Optional[ActorMatrix] = None,
    target_hosts: Optional[dict[str, str]] = None,
    model: str = settings.MAIN_DEFAULT_MODEL,
    use_openai: bool = False,
    execution_id: Optional[str] = None,
    extra_instructions: Optional[str] = None,
):
    """
    Factory function to create a properly configured HTTPAgent.

    HTTPAgent makes actual HTTP requests to running services and produces
    PoC scripts that can be verified.

    Args:
        mission: The mission to execute
        workspace_path: Path to the provisioned workspace
        master_context: MasterContext from preprocessing
        dependency_graph: Optional DependencyGraph for code analysis tools
        actor_matrix: Optional ActorMatrix for auth/privilege analysis
        target_hosts: Dict of service name to URL (e.g., {"app": "http://localhost:8080"})
        model: Model to use for inference
        use_openai: Whether to use OpenAI API directly
        execution_id: Optional execution ID for logging
        extra_instructions: Additional instructions (e.g., task-specific hints)

    Returns:
        Configured HTTPAgent ready for chat_with_tools()
    """
    from kai.agents.agent_types.http_agent import HTTPAgent

    # Validate target_hosts
    if not target_hosts:
        raise ValueError("target_hosts is required (dict of service name to URL)")
    # Validate at least one URL is valid
    valid_urls = [url for url in target_hosts.values() if url.startswith("http")]
    if not valid_urls:
        raise ValueError("target_hosts must contain at least one valid http URL")

    agent = HTTPAgent(
        mission=mission,
        master_context=master_context,
        target_hosts=target_hosts,
        dependency_graph=dependency_graph,
        actor_matrix=actor_matrix,
        max_tool_turns=mission.max_turns,
        repo_path=workspace_path,
        model=model,
        use_openai=use_openai,
        execution_id=execution_id,
    )

    # Set workspace path for tools
    agent.workspace_path = workspace_path

    # Set up toolcalling prompt
    agent.set_toolcalling_prompt(extra_instructions=extra_instructions or "")

    return agent


# Registry of agent factories by type
AGENT_FACTORIES: Dict[MissionAgentType, Any] = {
    MissionAgentType.STATE: create_state_agent,
    MissionAgentType.QUANT: create_quant_agent,
    MissionAgentType.BLACKBOX: create_blackbox_agent,
    MissionAgentType.GAMIFIED: create_gamified_agent,
    MissionAgentType.HTTP: create_http_agent,
}


def get_agent_factory(agent_type: MissionAgentType):
    """
    Get the factory function for an agent type.

    Args:
        agent_type: The MissionAgentType

    Returns:
        Factory function or None if not supported
    """
    return AGENT_FACTORIES.get(agent_type)
