"""
Token/cost aggregation and rollout persistence for Dispatcher.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional


class UsageTracker:
    """Owns token/cost aggregation and rollout persistence."""

    def __init__(
        self,
        *,
        save_rollouts: bool,
        rollouts_dir: Optional[str],
        workspace_dir: str,
        logger: logging.Logger,
    ) -> None:
        self._save_rollouts = save_rollouts
        self._rollouts_dir = rollouts_dir
        self._workspace_dir = workspace_dir
        self.logger = logger

        # Mutable state
        self.total_tokens: Dict[str, int] = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
        }
        self.total_cost: float = 0.0
        self.token_usage_by_phase: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Rollout persistence
    # ------------------------------------------------------------------

    def save_rollout(
        self,
        agent: Any,
        rollout_type: str,
        identifier: str,
    ) -> None:
        """
        Save agent conversation rollout to disk.

        Args:
            agent: The agent with messages attribute
            rollout_type: Type of rollout (e.g., "mission", "verifier")
            identifier: Unique identifier (e.g., mission_id)
        """
        if not self._save_rollouts:
            return

        rollouts_dir = self._rollouts_dir
        if not rollouts_dir:
            rollouts_dir = str(Path(self._workspace_dir) / "rollouts")

        rollout_path = Path(rollouts_dir) / rollout_type
        rollout_path.mkdir(parents=True, exist_ok=True)

        messages = getattr(agent, "messages", [])
        if not messages:
            return

        serialized = _serialize_messages(messages)

        rollout_data = {
            "identifier": identifier,
            "type": rollout_type,
            "model": getattr(agent, "model", "unknown"),
            "agent_type": str(getattr(agent, "agent_type", "unknown")),
            "messages": serialized,
            "total_tokens": getattr(agent, "total_tokens", {}),
            "estimated_cost": getattr(agent, "estimated_cost", 0.0),
        }

        output_file = rollout_path / f"{identifier}.json"
        try:
            with open(output_file, "w") as f:
                json.dump(rollout_data, f, indent=2, default=str)
            self.logger.debug(f"Saved rollout: {output_file}")
        except Exception as e:
            self.logger.warning(f"Failed to save rollout {identifier}: {e}")

    def save_verifier_rollout(
        self,
        mission_id: str,
        messages: List[Any],
        model: str,
        total_tokens: Dict[str, int],
        estimated_cost: float,
    ) -> None:
        """
        Save verifier conversation rollout to disk.

        Similar to save_rollout but takes messages directly instead of agent object.
        """
        if not self._save_rollouts:
            return

        rollouts_dir = self._rollouts_dir
        if not rollouts_dir:
            rollouts_dir = str(Path(self._workspace_dir) / "rollouts")

        rollout_path = Path(rollouts_dir) / "verifier"
        rollout_path.mkdir(parents=True, exist_ok=True)

        serialized = _serialize_messages(messages)

        rollout_data = {
            "identifier": f"verify_{mission_id}",
            "type": "verifier",
            "model": model,
            "agent_type": "verifier",
            "messages": serialized,
            "total_tokens": total_tokens,
            "estimated_cost": estimated_cost,
        }

        output_file = rollout_path / f"verify_{mission_id}.json"
        try:
            with open(output_file, "w") as f:
                json.dump(rollout_data, f, indent=2, default=str)
            self.logger.debug(f"Saved verifier rollout: {output_file}")
        except Exception as e:
            self.logger.warning(f"Failed to save verifier rollout {mission_id}: {e}")

    # ------------------------------------------------------------------
    # Usage aggregation
    # ------------------------------------------------------------------

    def aggregate_usage(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        cost: float,
        phase: str,
        agent_type: str,
    ) -> None:
        """Core method to aggregate token usage into totals."""
        self.total_tokens["prompt_tokens"] += prompt_tokens
        self.total_tokens["completion_tokens"] += completion_tokens
        self.total_cost += cost

        if phase not in self.token_usage_by_phase:
            self.token_usage_by_phase[phase] = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "cost": 0.0,
                "by_agent_type": {},
            }

        phase_data = self.token_usage_by_phase[phase]
        phase_data["prompt_tokens"] += prompt_tokens
        phase_data["completion_tokens"] += completion_tokens
        phase_data["cost"] += cost

        if agent_type not in phase_data["by_agent_type"]:
            phase_data["by_agent_type"][agent_type] = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "cost": 0.0,
                "count": 0,
            }

        agent_data = phase_data["by_agent_type"][agent_type]
        agent_data["prompt_tokens"] += prompt_tokens
        agent_data["completion_tokens"] += completion_tokens
        agent_data["cost"] += cost
        agent_data["count"] += 1

    def aggregate_agent_usage(
        self, agent: Any, phase: str, agent_type: str = "unknown"
    ) -> None:
        """Aggregate token usage from an agent."""
        agent_tokens = getattr(agent, "total_tokens", {})
        self.aggregate_usage(
            prompt_tokens=agent_tokens.get("prompt_tokens", 0),
            completion_tokens=agent_tokens.get("completion_tokens", 0),
            cost=getattr(agent, "estimated_cost", 0.0),
            phase=phase,
            agent_type=agent_type,
        )

    def aggregate_process_usage(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        cost: float,
        phase: str,
        agent_type: str = "process",
    ) -> None:
        """Aggregate token usage from a process."""
        self.aggregate_usage(prompt_tokens, completion_tokens, cost, phase, agent_type)


def _serialize_messages(messages: List[Any]) -> List[Any]:
    """Serialize a list of messages to JSON-safe dicts."""
    serialized = []
    for msg in messages:
        if hasattr(msg, "model_dump"):
            serialized.append(msg.model_dump())
        elif hasattr(msg, "__dict__"):
            serialized.append(msg.__dict__)
        else:
            serialized.append(str(msg))
    return serialized
