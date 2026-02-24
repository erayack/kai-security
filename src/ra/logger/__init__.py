"""
Docstring for kai.logger
"""

from ra.logger.ra_logger import RecursiveAgentLogger
from ra.logger.structured import StructuredPrinter
from ra.logger.verbose import VerbosePrinter

__all__ = ["RecursiveAgentLogger", "StructuredPrinter", "VerbosePrinter"]


def create_printer(
    *,
    enabled: bool = True,
    name: str = "",
    depth: int = 0,
    log_file: str = "",
    structured: bool = False,
) -> VerbosePrinter | StructuredPrinter:
    """Select the right printer based on the *structured* flag."""
    cls = StructuredPrinter if structured else VerbosePrinter
    return cls(enabled=enabled, name=name, depth=depth, log_file=log_file)
