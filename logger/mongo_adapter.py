import logging
from datetime import datetime, timezone
from logging import Handler, LogRecord
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import PyMongoError
from typing_extensions import override
from bson import ObjectId


class MongoDBHandler(Handler):
    """Logging handler that stores structured execution data."""

    def __init__(
        self,
        uri: str,
        db_name: str,
        level: int = logging.INFO,
    ) -> None:
        super().__init__(level)
        self.client = MongoClient(host=uri)
        self.db: Database = self.client[db_name]

        # Three main collections
        self.executions = self.db["executions"]
        self.agents = self.db["agents"]
        self.exploits = self.db["exploits"]

        # Create indexes for performance
        self.executions.create_index("status")
        self.agents.create_index("executionId")
        self.agents.create_index("parentAgentId")
        self.agents.create_index("kind")
        self.exploits.create_index("executionId")
        self.exploits.create_index("foundBy")
        self.exploits.create_index("verifiedBy")
        self.exploits.create_index("fixedBy")
        self.exploits.create_index("filePath")

    @override
    def emit(self, record: LogRecord) -> None:
        try:
            if not getattr(record, "mongo", False):
                return

            event_type = getattr(record, "event_type", None)

            if event_type == "execution_state":
                self._handle_execution_state(record)
            elif event_type == "agent_start":
                self._handle_agent_start(record)
            elif event_type == "agent_update":
                self._handle_agent_update(record)
            elif event_type == "agent_complete":
                self._handle_agent_complete(record)
            elif event_type == "exploit_discovered":
                self._handle_exploit(record)
            elif event_type == "exploit_verified":
                self._handle_exploit_verified(record)

        except PyMongoError as e:
            print(f"MongoDB Error in {event_type}: {e}")
            self.handleError(record=record)
        except Exception as e:
            print(f"Error in {event_type}: {e}")
            self.handleError(record=record)

    def _handle_execution_state(self, record: LogRecord) -> None:
        """Create or update execution document"""
        execution_id = getattr(record, "execution_id", None)
        status = getattr(record, "status", "pending")

        # Convert execution_id to ObjectId if it's a string
        if isinstance(execution_id, str):
            execution_id = ObjectId(execution_id)

        existing = self.executions.find_one({"_id": execution_id})

        if existing:
            # Update execution status
            update_data = {"status": status, "updatedAt": datetime.now(timezone.utc)}

            if status == "in_progress":
                update_data["startedAt"] = datetime.now(timezone.utc)
            elif status in ["completed", "failed"]:
                update_data["completedAt"] = datetime.now(timezone.utc)
                if status == "failed":
                    update_data["error"] = getattr(record, "error", "Unknown error")

            self.executions.update_one({"_id": execution_id}, {"$set": update_data})
        else:
            # Create new execution document
            self.executions.insert_one(
                {
                    "_id": execution_id,
                    "repoUrl": getattr(record, "repo_url", ""),
                    "status": status,
                    "model": getattr(record, "model", ""),
                    "createdAt": datetime.now(timezone.utc),
                    "startedAt": (
                        datetime.now(timezone.utc) if status == "in_progress" else None
                    ),
                    "completedAt": None,
                    "totalCost": 0.0,
                    "totalTokens": 0,
                    "exploitCounts": {"found": 0, "verified": 0},
                    "agentCounts": {"finder": 0, "verifier": 0, "setup": 0},
                    "updatedAt": datetime.now(timezone.utc),
                }
            )

    def _handle_agent_start(self, record: LogRecord) -> None:
        """Create agent document and increment execution agent count"""
        agent_id = getattr(record, "agent_id", None)
        execution_id = getattr(record, "execution_id", None)

        # Convert to ObjectId if they are strings
        if isinstance(agent_id, str):
            agent_id = ObjectId(agent_id)
        if isinstance(execution_id, str):
            execution_id = ObjectId(execution_id)

        # Check if execution exists
        execution = self.executions.find_one({"_id": execution_id})
        if not execution:
            print(f"Warning: No execution found for agent {agent_id}")
            print(f"Looking for execution_id: {execution_id}")
            return

        # Create agent document with agent_id as _id
        scope_paths_str = getattr(record, "scope_paths", "")
        parent_agent_id = getattr(record, "parent_agent_id", None)

        # Convert parent_agent_id to ObjectId if it's a non-empty string
        if (
            parent_agent_id
            and isinstance(parent_agent_id, str)
            and parent_agent_id.strip()
        ):
            parent_agent_id = ObjectId(parent_agent_id)
        else:
            parent_agent_id = None

        agent_kind = getattr(record, "kind", "unknown")

        self.agents.insert_one(
            {
                "_id": agent_id,
                "executionId": execution_id,
                "parentAgentId": parent_agent_id,
                "depth": int(getattr(record, "depth", 0)),
                "kind": agent_kind,
                "scopePath": scope_paths_str if scope_paths_str else None,
                "createdAt": datetime.now(timezone.utc),
                "completedAt": None,
                "cost": 0.0,
                "tokens": {"prompt": 0, "completion": 0, "total": 0},
                "updatedAt": datetime.now(timezone.utc),
            }
        )

        # Increment execution agent count in real-time based on agent kind
        if agent_kind in ["finder", "verifier", "setup"]:
            self.executions.update_one(
                {"_id": execution_id}, {"$inc": {f"agentCounts.{agent_kind}": 1}}
            )

    def _handle_agent_update(self, record: LogRecord) -> None:
        """Update agent metrics in real-time"""

        agent_id = getattr(record, "agent_id", None)

        # Convert agent_id to ObjectId if it's a string
        if isinstance(agent_id, str):
            agent_id = ObjectId(agent_id)

        self.agents.update_one(
            {"_id": agent_id},
            {
                "$set": {
                    "cost": float(getattr(record, "current_cost", 0)),
                    "tokens.prompt": int(getattr(record, "prompt_tokens", 0)),
                    "tokens.completion": int(getattr(record, "completion_tokens", 0)),
                    "tokens.total": int(getattr(record, "total_tokens", 0)),
                    "updatedAt": datetime.now(timezone.utc),
                }
            },
        )

        # Update execution totals
        agent = self.agents.find_one({"_id": agent_id})
        if agent:
            pipeline = [
                {"$match": {"executionId": agent["executionId"]}},
                {
                    "$group": {
                        "_id": None,
                        "totalCost": {"$sum": "$cost"},
                        "totalTokens": {"$sum": "$tokens.total"},
                    }
                },
            ]
            result = list(self.agents.aggregate(pipeline))
            if result:
                self.executions.update_one(
                    {"_id": agent["executionId"]},
                    {
                        "$set": {
                            "totalCost": result[0]["totalCost"],
                            "totalTokens": result[0]["totalTokens"],
                        }
                    },
                )

    def _handle_agent_complete(self, record: LogRecord) -> None:
        """Mark agent as completed"""

        agent_id = getattr(record, "agent_id", None)

        # Convert agent_id to ObjectId if it's a string
        if isinstance(agent_id, str):
            agent_id = ObjectId(agent_id)

        self.agents.update_one(
            {"_id": agent_id},
            {
                "$set": {
                    "completedAt": datetime.now(timezone.utc),
                    "cost": float(getattr(record, "total_cost", 0)),
                    "tokens.total": int(getattr(record, "total_tokens", 0)),
                    "updatedAt": datetime.now(timezone.utc),
                }
            },
        )

    def _handle_exploit(self, record: LogRecord) -> None:
        """Create exploit document and increment counters"""

        agent_id = getattr(record, "agent_id", None)

        # Convert agent_id to ObjectId if it's a string
        if isinstance(agent_id, str):
            agent_id = ObjectId(agent_id)

        agent = self.agents.find_one({"_id": agent_id})

        if not agent:
            print(f"Warning: No agent found for exploit from agent_id: {agent_id}")
            return

        exploit_id = getattr(record, "exploit_id", "")

        # Insert with exploit_id as _id
        exploit_doc = {
            "_id": exploit_id,
            "executionId": agent["executionId"],
            "foundBy": agent_id,  # ObjectId reference to agent who found it
            "category": getattr(record, "category", ""),
            "severity": getattr(record, "severity", ""),
            "filePath": getattr(record, "file_path", ""),
            "lineStart": int(getattr(record, "line_start", 0)),
            "lineEnd": (
                int(getattr(record, "line_end", 0))
                if getattr(record, "line_end", None)
                else None
            ),
            "className": getattr(record, "class_name", None),
            "functionName": getattr(record, "function_name", None),
            "description": getattr(record, "description", ""),
            "suggestedFix": getattr(record, "suggested_fix", None),
            "foundAt": datetime.now(timezone.utc),
            "updatedAt": datetime.now(timezone.utc),
        }

        # Add optional verified_at if provided
        verified_at = getattr(record, "verified_at", None)
        if verified_at:
            exploit_doc["verifiedAt"] = (
                datetime.fromisoformat(verified_at)
                if isinstance(verified_at, str)
                else verified_at
            )

        # Add optional verifiedBy if provided
        verified_by = getattr(record, "verified_by", None)
        if verified_by:
            exploit_doc["verifiedBy"] = verified_by  # ObjectId reference

        # Add optional fixedAt if provided
        fixed_at = getattr(record, "fixed_at", None)
        if fixed_at:
            exploit_doc["fixedAt"] = (
                datetime.fromisoformat(fixed_at)
                if isinstance(fixed_at, str)
                else fixed_at
            )

        # Add optional fixedBy if provided
        fixed_by = getattr(record, "fixed_by", None)
        if fixed_by:
            exploit_doc["fixedBy"] = fixed_by  # ObjectId reference

        self.exploits.insert_one(exploit_doc)

        # Increment exploit count in real-time
        # When an exploit is discovered, it increments the 'found' count
        self.executions.update_one(
            {"_id": agent["executionId"]}, {"$inc": {"exploitCounts.found": 1}}
        )

    def _handle_exploit_verified(self, record: LogRecord) -> None:
        """Update exploit with verification info when generator agent validates it"""
        exploit_id = getattr(record, "exploit_id", None)
        verified_by_agent_id = getattr(record, "verified_by_agent_id", None)

        if not exploit_id:
            print("Warning: No exploit_id provided for verification")
            return

        # Update exploit document with verification info
        update_data = {
            "verifiedAt": datetime.now(timezone.utc),
            "updatedAt": datetime.now(timezone.utc),
        }

        if verified_by_agent_id:
            update_data["verifiedBy"] = verified_by_agent_id

        self.exploits.update_one({"_id": exploit_id}, {"$set": update_data})

        # Increment verified exploit count in real-time
        # Get the exploit to find its executionId
        exploit = self.exploits.find_one({"_id": exploit_id})
        if exploit and "executionId" in exploit:
            self.executions.update_one(
                {"_id": exploit["executionId"]}, {"$inc": {"exploitCounts.verified": 1}}
            )


__all__ = ["MongoDBHandler"]
