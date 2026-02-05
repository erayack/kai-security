"""
Common tools shared across all agents.

This module re-exports tools from specialized submodules for backwards compatibility.
New code should import directly from the submodules:
- kai.agents.tools.shared - Context management, path utilities
- kai.agents.tools.graph_tools - Dependency graph queries
- kai.agents.tools.file_tools - File I/O operations
- kai.agents.tools.build_tools - Framework test runners
- kai.agents.tools.workspace_tools - Workspace/PoC tools
"""

# =============================================================================
# Re-exports from shared.py
# =============================================================================
from .shared import (
    set_current_agent,
    get_current_agent,
    normalize_agent_path,
    get_dependency_graph,
    get_query_engine,
    get_agent_framework,
    get_adapter,
)

# Backwards compatibility aliases (internal functions used _ prefix)
_current_agent_var = None  # Not directly importable, use get_current_agent()
_get_current_agent = get_current_agent
_normalize_agent_path = normalize_agent_path
_get_dependency_graph = get_dependency_graph
_get_query_engine = get_query_engine
_get_agent_framework = get_agent_framework
_get_adapter = get_adapter

# =============================================================================
# Re-exports from graph_tools.py
# =============================================================================
from .graph_tools import (  # noqa: E402
    dependency_graph_resolve,
    dependency_graph_loc,
    dependency_graph_snippet,
    dependency_graph_neighbors,
    dependency_graph_callers,
    dependency_graph_callees,
    dependency_graph_public_entrypoints,
    dependency_graph_protocol_entrypoints,
    dependency_graph_paths,
    dependency_graph_data_paths,
    dependency_graph_slice,
    dependency_graph_explain,
)

# =============================================================================
# Re-exports from file_tools.py
# =============================================================================
from .file_tools import (  # noqa: E402
    read_file,
    list_files,
    update_file,
    create_file,
)

# =============================================================================
# Re-exports from build_tools.py
# =============================================================================
from .build_tools import (  # noqa: E402
    forge_test,
    cargo_test,
    anchor_test,
    ctest,
)

# =============================================================================
# Re-exports from workspace_tools.py
# =============================================================================
from .workspace_tools import (  # noqa: E402
    write_and_compile,
    register_exploit,
    get_tool_description,
    ADAPTER_DESCRIBED_TOOLS,
)

# =============================================================================
# All public exports
# =============================================================================
__all__ = [
    # shared
    "set_current_agent",
    "get_current_agent",
    "normalize_agent_path",
    "get_dependency_graph",
    "get_query_engine",
    "get_agent_framework",
    "get_adapter",
    # graph_tools
    "dependency_graph_resolve",
    "dependency_graph_loc",
    "dependency_graph_snippet",
    "dependency_graph_neighbors",
    "dependency_graph_callers",
    "dependency_graph_callees",
    "dependency_graph_public_entrypoints",
    "dependency_graph_protocol_entrypoints",
    "dependency_graph_paths",
    "dependency_graph_data_paths",
    "dependency_graph_slice",
    "dependency_graph_explain",
    # file_tools
    "read_file",
    "list_files",
    "update_file",
    "create_file",
    # build_tools
    "forge_test",
    "cargo_test",
    "anchor_test",
    "ctest",
    # workspace_tools
    "write_and_compile",
    "register_exploit",
    "get_tool_description",
    "ADAPTER_DESCRIBED_TOOLS",
]
