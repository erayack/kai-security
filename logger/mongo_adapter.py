import logging
from datetime import datetime, timezone
from logging import Handler, LogRecord
from typing import TypeAlias

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError
from typing_extensions import override

Document: TypeAlias = dict[str, str | int | float | bool | datetime | None]


class MongoDBHandler(Handler):
    """Logging handler that stores MongoDB-specific events into a collection."""

    def __init__(
        self,
        uri: str,
        db_name: str,
        collection_name: str,
        level: int = logging.INFO,
    ) -> None:
        super().__init__(level)
        self.client: MongoClient[Document] = MongoClient[Document](host=uri)
        self.db: Database[Document] = self.client[db_name]
        self.collection: Collection[Document] = self.db[collection_name]

    @override
    def emit(self, record: LogRecord) -> None:
        try:
            if not getattr(record, "mongo", False):
                return

            doc: Document = {
                "timestamp": datetime.now(timezone.utc),
                "level": record.levelname,
                "message": record.getMessage(),
            }

            for key, value in record.__dict__.items():
                ## This sends all the fields also logging module fields /
                # TODO: Maybe we should filter out the logging module fields
                if isinstance(value, (str, int, float, bool, type(None))):
                    doc[key] = value
                else:
                    doc[key] = str(value)

            self.collection.insert_one(document=doc)

        except PyMongoError:
            self.handleError(record=record)


__all__ = ["MongoDBHandler"]
