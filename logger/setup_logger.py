from typing import TextIO
from logging import Handler, Logger, StreamHandler, getLogger, INFO, Formatter

from logger.mongo_adapter import MongoDBHandler

from agent.settings import MONGO_URI, MONGO_DB_NAME


def setup_logger() -> Logger:
    """Set up and configure the application logger."""

    logger: Logger = getLogger(name="Exploit Agent")
    logger.setLevel(level=INFO)

    # Prevent propagation to root logger to avoid duplicate logs
    logger.propagate = False

    if not logger.handlers:
        # Create console handler with same format as main.py
        console: Handler = StreamHandler[TextIO]()
        formatter = Formatter(fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        console.setFormatter(formatter)
        logger.addHandler(hdlr=console)

        mongo_handler: MongoDBHandler = MongoDBHandler(
            uri=MONGO_URI,
            db_name=MONGO_DB_NAME,
        )
        logger.addHandler(mongo_handler)

    return logger
