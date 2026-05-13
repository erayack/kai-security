"""
Docstring for ra.environments
"""

from typing import Any, Literal

from ra.environments.base_env import BaseEnv, SupportsPersistence
from ra.environments.local_repl import LocalREPL

__all__ = ["BaseEnv", "LocalREPL", "SupportsPersistence", "get_environment"]


def get_environment(
    environment: Literal["local", "docker"],
    environment_kwargs: dict[str, Any],
) -> BaseEnv:
    """
    Routes a specific environment and the args (as a dict) to the appropriate environment if supported.
    Currently supported environments: ['local', 'docker']
    """
    if environment == "local":
        return LocalREPL(**environment_kwargs)
    elif environment == "docker":
        from ra.environments.docker_repl import DockerREPL

        return DockerREPL(**environment_kwargs)
    else:
        raise ValueError(
            f"Unknown environment: {environment}. Supported: ['local', 'docker']"
        )
