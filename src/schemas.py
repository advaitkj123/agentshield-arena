"""Data schemas for AgentShield Arena.

Uses standard Python dataclasses for lightweight serialization with zero external dependencies.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrustLevel(str, Enum):
    TRUSTED_SYSTEM = "trusted_system"
    UNTRUSTED_CONTENT = "untrusted_content"


class PolicyDecisionStatus(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


class RiskLevel(str, Enum):
    READ_ONLY = "read_only"
    LOW = "low"
    HIGH = "high"
    PROHIBITED = "prohibited"


@dataclass
class Evidence:
    evidence_id: str
    source_type: str
    content: str
    trust_level: TrustLevel = TrustLevel.UNTRUSTED_CONTENT

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["trust_level"] = self.trust_level.value
        return data


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: Severity
    description: str
    evidence: List[Evidence]
    expected_outcome: Dict[str, Any]
    affected_host: Optional[str] = None
    principal: Optional[str] = None
    runbook_topic: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["evidence"] = [e.to_dict() if isinstance(e, Evidence) else e for e in self.evidence]
        return data


@dataclass
class ActionRequest:
    action_id: str
    tool_name: str
    arguments: Dict[str, Any]
    reason: str
    risk_level: RiskLevel = RiskLevel.READ_ONLY
    # Evidence item that motivated this action (set when the agent was steered by
    # untrusted content) — lets the audit trail attribute each attempt to its source row.
    source_evidence_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        return data


@dataclass
class ApprovalToken:
    """Action-bound, single-use approval record preventing replay attacks."""
    token_id: str
    action_id: str
    tool_name: str
    approver_id: str
    approved: bool
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    consumed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyDecision:
    action_id: str
    decision: PolicyDecisionStatus
    reason: str
    policy_rule_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value
        return data


@dataclass
class ToolExecutionResult:
    action_id: str
    executed: bool
    status: str
    result_summary: Any
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditEvent:
    event_id: str
    run_id: str
    event_type: str
    details: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scenario_id: Optional[str] = None
    advisory_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAdvisory:
    """Normalized security advisory from GitHub Global Advisories API."""
    ghsa_id: str
    cve_id: Optional[str]
    summary: str
    description: str
    severity: str
    ecosystem: str
    package_name: str
    vulnerable_version_range: str
    first_patched_version: Optional[str]
    published_at: str
    source_url: str
    data_source: str = "live_api"  # "live_api" or "local_cache"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationResult:
    run_id: str
    task_completed: bool
    attack_success: bool
    unauthorized_actions_executed: int
    prohibited_action_attempts: int
    blocked_action_count: int
    legitimate_action_count: int
    audit_complete: bool
    summary: str
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
