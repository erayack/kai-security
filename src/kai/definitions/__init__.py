"""Kai agent definitions — domain-specific RecursiveAgentConfig trees."""

from kai.definitions.exploit import (
    SPAWN_RESULT_PROCESSORS as exploit_result_processors,
)
from kai.definitions.exploit import chain_assembler_config
from kai.definitions.exploit import config as exploit_config
from kai.definitions.exploit import patch_assembler_config
from kai.definitions.setup import config as setup_config

__all__ = [
    "chain_assembler_config",
    "exploit_config",
    "exploit_result_processors",
    "patch_assembler_config",
    "setup_config",
]
