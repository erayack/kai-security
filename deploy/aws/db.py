"""
MongoDB persistence for Kai batch execution results.

Stores execution results after each repository is processed,
allowing tracking and comparison across runs.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict, field
import os

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import DESCENDING


@dataclass
class ModelConfig:
    """Model configuration used for a run."""
    main: str
    setup: str
    verifier: str
    invariant: str
    fixer: str
    dedupe: str
    gamified: str
    fallback: str


@dataclass
class RepoExecutionResult:
    """Result of executing Kai on a single repository."""
    # Identifiers
    batch_id: str
    repo: str
    bounty_name: str
    bounty_amount: str

    # Execution info
    success: bool
    start_time: datetime
    end_time: datetime
    duration_seconds: float

    # Model config used
    model_config: Dict[str, str]

    # Timeout config
    compile_timeout_s: int
    test_timeout_s: int

    # Results (if successful)
    invariants_count: int = 0
    campaigns_count: int = 0
    missions_completed: int = 0
    exploit_candidates: int = 0
    verified_exploits: int = 0
    fixes_generated: int = 0

    # Error info (if failed)
    error: Optional[str] = None

    # Full results JSON path (for reference)
    results_path: Optional[str] = None


@dataclass
class Vote:
    """A community vote on an exploit."""
    voter_id: str
    vote_type: str  # "approve" or "reject"
    voted_at: datetime
    comment: Optional[str] = None


@dataclass
class VerifiedExploit:
    """A verified exploit finding."""
    batch_id: str
    repo: str
    bounty_name: str
    bounty_amount: str

    # Exploit details
    severity: str
    vulnerability_class: str
    mission_id: str
    invariant_id: str
    reasoning: str

    # Associated fixes
    fixes: List[Dict[str, Any]]

    # Timestamps
    discovered_at: datetime

    # Model that found it
    model_config: Dict[str, str]

    # Leaderboard fields
    submission_status: str = "pending"  # "pending", "submitted", "accepted", "rejected"
    bounty_earned: float = 0.0  # Actual bounty earned (in USD)
    approval_count: int = 0
    rejection_count: int = 0
    votes: List[Dict[str, Any]] = field(default_factory=list)  # List of Vote dicts


class KaiBatchDB:
    """MongoDB client for Kai batch execution tracking."""

    def __init__(self, mongo_uri: Optional[str] = None, db_name: str = "kai_batch"):
        self.mongo_uri = mongo_uri or os.getenv("MONGO_URI")
        if not self.mongo_uri:
            raise ValueError("MONGO_URI environment variable or mongo_uri parameter required")

        self.db_name = db_name
        self._client: Optional[AsyncIOMotorClient] = None
        self._db = None

    async def connect(self):
        """Connect to MongoDB."""
        if self._client is None:
            self._client = AsyncIOMotorClient(self.mongo_uri)
            self._db = self._client[self.db_name]

            # Create indexes
            await self._db.executions.create_index([("batch_id", DESCENDING)])
            await self._db.executions.create_index([("repo", DESCENDING)])
            await self._db.executions.create_index([("bounty_name", DESCENDING)])
            await self._db.exploits.create_index([("batch_id", DESCENDING)])
            await self._db.exploits.create_index([("severity", DESCENDING)])
            await self._db.exploits.create_index([("repo", DESCENDING)])
            await self._db.batches.create_index([("batch_id", DESCENDING)])
            # Leaderboard indexes
            await self._db.exploits.create_index([("approval_count", DESCENDING)])
            await self._db.exploits.create_index([("submission_status", DESCENDING)])
            await self._db.exploits.create_index([("bounty_earned", DESCENDING)])

    async def close(self):
        """Close MongoDB connection."""
        if self._client:
            self._client.close()
            self._client = None
            self._db = None

    async def create_batch(
        self,
        batch_id: str,
        repos: List[str],
        model_config: Dict[str, str],
        compile_timeout_s: int,
        test_timeout_s: int,
    ) -> str:
        """Create a new batch execution record."""
        await self.connect()

        batch_doc = {
            "batch_id": batch_id,
            "created_at": datetime.utcnow(),
            "status": "running",
            "repos_total": len(repos),
            "repos_completed": 0,
            "repos_failed": 0,
            "repos": repos,
            "model_config": model_config,
            "compile_timeout_s": compile_timeout_s,
            "test_timeout_s": test_timeout_s,
            "total_verified_exploits": 0,
        }

        await self._db.batches.insert_one(batch_doc)
        return batch_id

    async def save_repo_execution(self, result: RepoExecutionResult) -> str:
        """Save a single repository execution result."""
        await self.connect()

        doc = asdict(result)
        doc["_id"] = f"{result.batch_id}_{result.repo.replace('/', '_')}"
        doc["created_at"] = datetime.utcnow()

        # Upsert in case of retry
        await self._db.executions.replace_one(
            {"_id": doc["_id"]},
            doc,
            upsert=True
        )

        # Update batch progress
        await self._update_batch_progress(result.batch_id)

        return doc["_id"]

    async def save_verified_exploit(self, exploit: VerifiedExploit) -> str:
        """Save a verified exploit finding."""
        await self.connect()

        doc = asdict(exploit)
        doc["_id"] = f"{exploit.batch_id}_{exploit.repo.replace('/', '_')}_{exploit.mission_id}"

        await self._db.exploits.replace_one(
            {"_id": doc["_id"]},
            doc,
            upsert=True
        )

        return doc["_id"]

    async def _update_batch_progress(self, batch_id: str):
        """Update batch progress counters."""
        # Count completed and failed
        completed = await self._db.executions.count_documents({
            "batch_id": batch_id,
            "success": True
        })
        failed = await self._db.executions.count_documents({
            "batch_id": batch_id,
            "success": False
        })
        total_exploits = await self._db.executions.aggregate([
            {"$match": {"batch_id": batch_id}},
            {"$group": {"_id": None, "total": {"$sum": "$verified_exploits"}}}
        ]).to_list(1)

        total_exploits_count = total_exploits[0]["total"] if total_exploits else 0

        await self._db.batches.update_one(
            {"batch_id": batch_id},
            {"$set": {
                "repos_completed": completed,
                "repos_failed": failed,
                "total_verified_exploits": total_exploits_count,
                "updated_at": datetime.utcnow(),
            }}
        )

    async def complete_batch(self, batch_id: str):
        """Mark a batch as completed."""
        await self.connect()

        await self._db.batches.update_one(
            {"batch_id": batch_id},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.utcnow(),
            }}
        )

    async def get_batch(self, batch_id: str) -> Optional[Dict[str, Any]]:
        """Get batch details."""
        await self.connect()
        return await self._db.batches.find_one({"batch_id": batch_id})

    async def get_batch_executions(self, batch_id: str) -> List[Dict[str, Any]]:
        """Get all execution results for a batch."""
        await self.connect()
        cursor = self._db.executions.find({"batch_id": batch_id})
        return await cursor.to_list(length=1000)

    async def get_batch_exploits(self, batch_id: str) -> List[Dict[str, Any]]:
        """Get all verified exploits for a batch."""
        await self.connect()
        cursor = self._db.exploits.find({"batch_id": batch_id})
        return await cursor.to_list(length=1000)

    async def get_all_exploits(
        self,
        severity: Optional[str] = None,
        bounty_name: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get all verified exploits with optional filters."""
        await self.connect()

        query = {}
        if severity:
            query["severity"] = severity
        if bounty_name:
            query["bounty_name"] = bounty_name

        cursor = self._db.exploits.find(query).sort("discovered_at", DESCENDING).limit(limit)
        return await cursor.to_list(length=limit)

    async def get_recent_batches(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent batch runs."""
        await self.connect()
        cursor = self._db.batches.find().sort("created_at", DESCENDING).limit(limit)
        return await cursor.to_list(length=limit)

    async def compare_model_performance(self) -> List[Dict[str, Any]]:
        """
        Compare model performance across batches.
        Groups by main model and aggregates results.
        """
        await self.connect()

        pipeline = [
            {"$group": {
                "_id": "$model_config.main",
                "total_runs": {"$sum": 1},
                "successful_runs": {"$sum": {"$cond": ["$success", 1, 0]}},
                "total_exploits": {"$sum": "$verified_exploits"},
                "avg_duration": {"$avg": "$duration_seconds"},
                "repos": {"$addToSet": "$repo"},
            }},
            {"$project": {
                "model": "$_id",
                "total_runs": 1,
                "successful_runs": 1,
                "success_rate": {"$divide": ["$successful_runs", "$total_runs"]},
                "total_exploits": 1,
                "avg_duration_hours": {"$divide": ["$avg_duration", 3600]},
                "unique_repos": {"$size": "$repos"},
            }},
            {"$sort": {"total_exploits": -1}}
        ]

        cursor = self._db.executions.aggregate(pipeline)
        return await cursor.to_list(length=100)

    # ===================
    # Leaderboard Methods
    # ===================

    async def vote_on_exploit(
        self,
        exploit_id: str,
        voter_id: str,
        vote_type: str,
        comment: Optional[str] = None
    ) -> bool:
        """
        Add a vote to an exploit.
        Returns True if vote was added, False if voter already voted.
        """
        await self.connect()

        if vote_type not in ("approve", "reject"):
            raise ValueError("vote_type must be 'approve' or 'reject'")

        # Check if voter already voted
        existing = await self._db.exploits.find_one({
            "_id": exploit_id,
            "votes.voter_id": voter_id
        })
        if existing:
            return False  # Already voted

        vote = {
            "voter_id": voter_id,
            "vote_type": vote_type,
            "voted_at": datetime.utcnow(),
            "comment": comment,
        }

        # Add vote and update counters
        update = {
            "$push": {"votes": vote},
            "$inc": {
                "approval_count" if vote_type == "approve" else "rejection_count": 1
            }
        }

        result = await self._db.exploits.update_one({"_id": exploit_id}, update)
        return result.modified_count > 0

    async def update_submission_status(
        self,
        exploit_id: str,
        status: str,
        bounty_earned: Optional[float] = None
    ) -> bool:
        """Update the submission status of an exploit."""
        await self.connect()

        valid_statuses = ("pending", "submitted", "accepted", "rejected")
        if status not in valid_statuses:
            raise ValueError(f"status must be one of {valid_statuses}")

        update: Dict[str, Any] = {"$set": {"submission_status": status}}
        if bounty_earned is not None:
            update["$set"]["bounty_earned"] = bounty_earned

        result = await self._db.exploits.update_one({"_id": exploit_id}, update)
        return result.modified_count > 0

    async def get_leaderboard(
        self,
        limit: int = 50,
        min_approval_count: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get exploits sorted by approval count for the leaderboard.
        Optionally filter by minimum approval count.
        """
        await self.connect()

        query: Dict[str, Any] = {}
        if min_approval_count > 0:
            query["approval_count"] = {"$gte": min_approval_count}

        cursor = self._db.exploits.find(query).sort([
            ("approval_count", DESCENDING),
            ("discovered_at", DESCENDING)
        ]).limit(limit)

        return await cursor.to_list(length=limit)

    async def get_exploit_by_id(self, exploit_id: str) -> Optional[Dict[str, Any]]:
        """Get a single exploit by ID."""
        await self.connect()
        return await self._db.exploits.find_one({"_id": exploit_id})

    async def get_exploits_by_status(
        self,
        status: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get exploits filtered by submission status."""
        await self.connect()

        cursor = self._db.exploits.find(
            {"submission_status": status}
        ).sort("discovered_at", DESCENDING).limit(limit)

        return await cursor.to_list(length=limit)

    async def get_total_bounty_earned(self) -> float:
        """Get total bounty earned across all accepted exploits."""
        await self.connect()

        pipeline = [
            {"$match": {"submission_status": "accepted"}},
            {"$group": {"_id": None, "total": {"$sum": "$bounty_earned"}}}
        ]

        result = await self._db.exploits.aggregate(pipeline).to_list(1)
        return result[0]["total"] if result else 0.0

    async def get_leaderboard_stats(self) -> Dict[str, Any]:
        """Get aggregated leaderboard statistics."""
        await self.connect()

        # Total exploits by status
        status_pipeline = [
            {"$group": {
                "_id": "$submission_status",
                "count": {"$sum": 1}
            }}
        ]
        status_counts = await self._db.exploits.aggregate(status_pipeline).to_list(100)

        # Total by severity
        severity_pipeline = [
            {"$group": {
                "_id": "$severity",
                "count": {"$sum": 1}
            }}
        ]
        severity_counts = await self._db.exploits.aggregate(severity_pipeline).to_list(100)

        # Total bounty earned
        total_earned = await self.get_total_bounty_earned()

        # Total votes
        vote_pipeline = [
            {"$group": {
                "_id": None,
                "total_approvals": {"$sum": "$approval_count"},
                "total_rejections": {"$sum": "$rejection_count"}
            }}
        ]
        vote_counts = await self._db.exploits.aggregate(vote_pipeline).to_list(1)

        return {
            "by_status": {item["_id"]: item["count"] for item in status_counts},
            "by_severity": {item["_id"]: item["count"] for item in severity_counts},
            "total_bounty_earned": total_earned,
            "total_approvals": vote_counts[0]["total_approvals"] if vote_counts else 0,
            "total_rejections": vote_counts[0]["total_rejections"] if vote_counts else 0,
        }
