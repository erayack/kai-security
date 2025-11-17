from typing import TextIO
from logging import Handler, Logger, StreamHandler, getLogger, INFO

from config.settings import settings
from logger.mongo_adapter import MongoDBHandler


def setup_logger() -> Logger:
    """Set up and configure the application logger."""

    logger: Logger = getLogger(name="app")
    logger.setLevel(level=INFO)

    if not logger.handlers:
        console: Handler = StreamHandler[TextIO]()
        logger.addHandler(hdlr=console)

        mongo_handler: MongoDBHandler = MongoDBHandler(
            uri=settings.MONGO_URI,
            db_name=settings.MONGO_DB_NAME,
            collection_name=settings.MONGO_COLLECTION_NAME,
        )
        logger.addHandler(mongo_handler)

    return logger
