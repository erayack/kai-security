"""Kai agents module."""

# Lazy imports to avoid circular import issues
# Import agent types only when accessed via this module

__all__ = ["SetupAgent", "ProfilerAgent", "BlackboxAgent"]


def __getattr__(name: str):
    """Lazy import agent types to avoid circular imports."""
    if name == "SetupAgent":
        from kai.agents.agent_types.setup_agent import SetupAgent

        return SetupAgent
    if name == "ProfilerAgent":
        from kai.agents.agent_types.profiler_agent import ProfilerAgent

        return ProfilerAgent
    if name == "BlackboxAgent":
        from kai.agents.agent_types.blackbox_agent import BlackboxAgent

        return BlackboxAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
