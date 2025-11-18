from typing import TextIO
from logging import Handler, Logger, StreamHandler, getLogger, INFO

from logger.mongo_adapter import MongoDBHandler

from agent.settings import MONGO_URI, MONGO_DB_NAME


def setup_logger() -> Logger:
    """Set up and configure the application logger."""

    logger: Logger = getLogger(name="app")
    logger.setLevel(level=INFO)

    if not logger.handlers:
        console: Handler = StreamHandler[TextIO]()
        logger.addHandler(hdlr=console)

        mongo_handler: MongoDBHandler = MongoDBHandler(
            uri=MONGO_URI,
            db_name=MONGO_DB_NAME,
        )
        logger.addHandler(mongo_handler)

    return logger
