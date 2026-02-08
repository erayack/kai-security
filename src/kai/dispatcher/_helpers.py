"""
Shared helpers for Dispatcher sub-components.
"""

import logging
from typing import Optional

from kai.state_manager import KaiStateManager


async def persist(
    state_manager: Optional[KaiStateManager],
    coro,
    logger: logging.Logger,
) -> bool:
    """Safely call state manager method. No-op if no state manager."""
    if not state_manager:
        return True
    try:
        return await coro
    except Exception as e:
        logger.warning(f"State persistence failed: {e}")
        return False
