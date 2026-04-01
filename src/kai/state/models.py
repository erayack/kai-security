"""Data models for state tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ThreatContext:
    """User-provided threat model for the target codebase."""

    deployment_type: str  # "cli-tool" | "web-app" | "smart-contract" | ...
    environment: str = ""  # "local" | "server" | "on-chain" | "cloud"
    access_roles: list[dict[str, Any]] = field(default_factory=list)
    boundaries: list[str] = field(default_factory=list)
    known_constraints: list[str] = field(default_factory=list)
    design_specs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "deployment_type": self.deployment_type,
            "environment": self.environment,
            "access_roles": self.access_roles,
            "boundaries": self.boundaries,
            "known_constraints": self.known_constraints,
            "design_specs": self.design_specs,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThreatContext:
        """Deserialize from a dict."""
        return cls(
            deployment_type=data["deployment_type"],
            environment=data.get("environment", ""),
            access_roles=data.get("access_roles", []),
            boundaries=data.get("boundaries", []),
            known_constraints=data.get("known_constraints", []),
            design_specs=data.get("design_specs", []),
        )


@dataclass
class ChainRecord:
    """Record of a multi-step exploit chain."""

    run_id: str
    chain_id: str
    timestamp: str
    status: str  # "proposed" | "verified" | "rejected"
    description: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    anchor_exploit_ids: list[str] = field(default_factory=list)
    composite_cvss_vector: str | None = None
    composite_cvss_score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "run_id": self.run_id,
            "chain_id": self.chain_id,
            "timestamp": self.timestamp,
            "status": self.status,
            "description": self.description,
            "steps": self.steps,
            "anchor_exploit_ids": self.anchor_exploit_ids,
            "composite_cvss_vector": self.composite_cvss_vector,
            "composite_cvss_score": self.composite_cvss_score,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChainRecord:
        """Deserialize from a dict."""
        return cls(
            run_id=data["run_id"],
            chain_id=data["chain_id"],
            timestamp=data["timestamp"],
            status=data.get("status", "proposed"),
            description=data.get("description", ""),
            steps=data.get("steps", []),
            anchor_exploit_ids=data.get("anchor_exploit_ids", []),
            composite_cvss_vector=data.get("composite_cvss_vector"),
            composite_cvss_score=data.get("composite_cvss_score"),
        )


@dataclass
class RunRecord:
    """Record of a single pipeline run."""

    run_id: str
    repo_path: str
    started_at: str  # ISO 8601
    status: str  # "running" | "completed" | "failed"
    root_model: str
    finished_at: str | None = None
    config_snapshot: dict[str, Any] = field(default_factory=dict)
    usage_summary: dict[str, Any] | None = None
    execution_time: float | None = None
    total_exploits: int = 0
    total_fixes: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "run_id": self.run_id,
            "repo_path": self.repo_path,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "root_model": self.root_model,
            "config_snapshot": self.config_snapshot,
            "usage_summary": self.usage_summary,
            "execution_time": self.execution_time,
            "total_exploits": self.total_exploits,
            "total_fixes": self.total_fixes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunRecord:
        """Deserialize from a dict."""
        return cls(
            run_id=data["run_id"],
            repo_path=data["repo_path"],
            started_at=data["started_at"],
            finished_at=data.get("finished_at"),
            status=data.get("status", "running"),
            root_model=data.get("root_model", "unknown"),
            config_snapshot=data.get("config_snapshot", {}),
            usage_summary=data.get("usage_summary"),
            execution_time=data.get("execution_time"),
            total_exploits=data.get("total_exploits", 0),
            total_fixes=data.get("total_fixes", 0),
        )


@dataclass
class StatusUpdate:
    """A single iteration status update for progress tracking."""

    run_id: str
    iteration_num: int
    timestamp: str  # ISO 8601
    agent_name: str  # "exploit" for root, or sub-agent name
    has_spawn_calls: bool = False
    iteration_time: float | None = None
    spawn_agent: str | None = None
    spawn_kwargs: dict[str, Any] | None = None
    spawn_result: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "run_id": self.run_id,
            "iteration_num": self.iteration_num,
            "timestamp": self.timestamp,
            "agent_name": self.agent_name,
            "has_spawn_calls": self.has_spawn_calls,
            "iteration_time": self.iteration_time,
            "spawn_agent": self.spawn_agent,
            "spawn_kwargs": self.spawn_kwargs,
            "spawn_result": self.spawn_result,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StatusUpdate:
        """Deserialize from a dict."""
        return cls(
            run_id=data["run_id"],
            iteration_num=data["iteration_num"],
            timestamp=data["timestamp"],
            agent_name=data["agent_name"],
            has_spawn_calls=data.get("has_spawn_calls", False),
            iteration_time=data.get("iteration_time"),
            spawn_agent=data.get("spawn_agent"),
            spawn_kwargs=data.get("spawn_kwargs"),
            spawn_result=data.get("spawn_result"),
        )


@dataclass
class ExploitRecord:
    """Record of a discovered exploit, progressively enriched."""

    run_id: str
    exploit_id: str
    timestamp: str
    source_agent: str  # "analyzer" | "verifier"
    # "candidate" | "verified" | "rejected" | "verified_and_fixed" | "failed"
    status: str
    hypothesis: str
    file: str
    function: str
    exploit_sketch: str = ""
    attacker_role: str = ""
    required_privileges: str = ""
    category: str = ""  # active_exploit | trust_assumption_violation | ...
    trusted_component_abused: str = ""
    affected_files: list[str] = field(default_factory=list)
    confirmed: bool | None = None
    poc_code: str | None = None
    test_output: str | None = None
    severity: str | None = None
    patch: str | None = None
    test_results: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    cvss_justification: dict[str, str] | None = None
    chain_id: str | None = None
    # Critic enrichment fields
    adversarial_viability: str | None = None
    profit_model: str | None = None
    external_mitigations: str | None = None
    platform_validity: str | None = None
    critic_summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "run_id": self.run_id,
            "exploit_id": self.exploit_id,
            "timestamp": self.timestamp,
            "source_agent": self.source_agent,
            "status": self.status,
            "hypothesis": self.hypothesis,
            "file": self.file,
            "function": self.function,
            "exploit_sketch": self.exploit_sketch,
            "attacker_role": self.attacker_role,
            "required_privileges": self.required_privileges,
            "category": self.category,
            "trusted_component_abused": self.trusted_component_abused,
            "affected_files": self.affected_files,
            "confirmed": self.confirmed,
            "poc_code": self.poc_code,
            "test_output": self.test_output,
            "severity": self.severity,
            "patch": self.patch,
            "test_results": self.test_results,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "cvss_justification": self.cvss_justification,
            "chain_id": self.chain_id,
            "adversarial_viability": self.adversarial_viability,
            "profit_model": self.profit_model,
            "external_mitigations": self.external_mitigations,
            "platform_validity": self.platform_validity,
            "critic_summary": self.critic_summary,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExploitRecord:
        """Deserialize from a dict."""
        return cls(
            run_id=data["run_id"],
            exploit_id=data["exploit_id"],
            timestamp=data["timestamp"],
            source_agent=data["source_agent"],
            status=data.get("status", "candidate"),
            hypothesis=data["hypothesis"],
            file=data["file"],
            function=data["function"],
            exploit_sketch=data.get("exploit_sketch", ""),
            attacker_role=data.get("attacker_role", ""),
            required_privileges=data.get("required_privileges", ""),
            category=data.get("category", ""),
            trusted_component_abused=data.get("trusted_component_abused", ""),
            affected_files=data.get("affected_files", []),
            confirmed=data.get("confirmed"),
            poc_code=data.get("poc_code"),
            test_output=data.get("test_output"),
            severity=data.get("severity"),
            patch=data.get("patch"),
            test_results=data.get("test_results"),
            cvss_vector=data.get("cvss_vector"),
            cvss_score=data.get("cvss_score"),
            cvss_justification=data.get("cvss_justification"),
            chain_id=data.get("chain_id"),
            adversarial_viability=data.get("adversarial_viability"),
            profit_model=data.get("profit_model"),
            external_mitigations=data.get(
                "external_mitigations", data.get("off_chain_mitigations")
            ),
            platform_validity=data.get("platform_validity"),
            critic_summary=data.get("critic_summary"),
        )


@dataclass
class FixRecord:
    """Record of a fix applied to an exploit."""

    run_id: str
    fix_id: str
    exploit_id: str
    timestamp: str
    hypothesis: str
    file: str
    function: str
    severity: str
    patch: str
    test_results: str
    applied: bool = False
    cvss_vector: str = ""
    cvss_score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "run_id": self.run_id,
            "fix_id": self.fix_id,
            "exploit_id": self.exploit_id,
            "timestamp": self.timestamp,
            "hypothesis": self.hypothesis,
            "file": self.file,
            "function": self.function,
            "severity": self.severity,
            "patch": self.patch,
            "test_results": self.test_results,
            "applied": self.applied,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FixRecord:
        """Deserialize from a dict."""
        return cls(
            run_id=data["run_id"],
            fix_id=data["fix_id"],
            exploit_id=data["exploit_id"],
            timestamp=data["timestamp"],
            hypothesis=data["hypothesis"],
            file=data["file"],
            function=data["function"],
            severity=data.get("severity", ""),
            patch=data["patch"],
            test_results=data["test_results"],
            applied=data.get("applied", False),
            cvss_vector=data.get("cvss_vector", ""),
            cvss_score=data.get("cvss_score"),
        )


@dataclass
class FixAttemptRecord:
    """Record of a single attempt to fix an exploit."""

    run_id: str
    exploit_id: str
    attempt_num: int
    timestamp: str
    strategy: str  # one-line description of the defense mechanism tried
    patch: str  # the diff
    failure_reason: str  # why the PoC still passed (empty if succeeded)
    succeeded: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "run_id": self.run_id,
            "exploit_id": self.exploit_id,
            "attempt_num": self.attempt_num,
            "timestamp": self.timestamp,
            "strategy": self.strategy,
            "patch": self.patch,
            "failure_reason": self.failure_reason,
            "succeeded": self.succeeded,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FixAttemptRecord:
        """Deserialize from a dict."""
        return cls(
            run_id=data["run_id"],
            exploit_id=data["exploit_id"],
            attempt_num=data["attempt_num"],
            timestamp=data["timestamp"],
            strategy=data["strategy"],
            patch=data["patch"],
            failure_reason=data["failure_reason"],
            succeeded=data["succeeded"],
        )
