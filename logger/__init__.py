from typing import cast

from logging import Logger
import logging as std_logging

from .setup_logger import setup_logger


class LoggingProxy:
    """Proxy class for the logging module. Wraps logger for keep other structures same"""

    def __init__(self) -> None:
        self._app_logger: Logger = setup_logger()

    def getLogger(self, name: str | None = None) -> Logger:
        if name in (None, "", self._app_logger.name):
            return self._app_logger
        return std_logging.getLogger(name)

    def setLevel(self, level: int) -> None:
        self._app_logger.setLevel(level)

    def debug(self, msg: str, *args, **kwargs) -> None:
        self._app_logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs) -> None:
        self._app_logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        self._app_logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        self._app_logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs) -> None:
        self._app_logger.critical(msg, *args, **kwargs)

    def __getattr__(self, attr: str) -> object:
        return cast(object, getattr(std_logging, attr))


logging = LoggingProxy()
logger = logging.getLogger()
