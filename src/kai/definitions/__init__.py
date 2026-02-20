"""Kai agent definitions — domain-specific RecursiveAgentConfig trees."""

from kai.definitions.exploit import SPAWN_PARSERS as exploit_spawn_parsers
from kai.definitions.exploit import config as exploit_config
from kai.definitions.setup import config as setup_config

__all__ = ["exploit_config", "exploit_spawn_parsers", "setup_config"]
