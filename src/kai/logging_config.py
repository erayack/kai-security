"""Centralized Python logging configuration.

Call ``configure_logging()`` once early in ``main()`` to set up
consistent log formatting and suppress noisy third-party loggers.
"""

import json
import logging
import sys


class _JSONFormatter(logging.Formatter):
    """Emit one JSON object per log record on a single line."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        )


_NOISY_LOGGERS = (
    "httpx",
    "urllib3",
    "httpcore",
    "openai",
    "anthropic",
)


def configure_logging(*, structured: bool = False) -> None:
    """Set up root logging and quiet noisy third-party loggers.

    Parameters
    ----------
    structured:
        When ``True``, emit JSON lines on stderr.
        When ``False``, use a concise human-readable format.
    """
    handler = logging.StreamHandler(sys.stderr)
    if structured:
        handler.setFormatter(_JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)-5s %(name)s: %(message)s"))

    root = logging.getLogger()
    root.setLevel(logging.WARNING)
    root.handlers.clear()
    root.addHandler(handler)

    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
