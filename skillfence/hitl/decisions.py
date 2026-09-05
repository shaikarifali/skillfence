"""Human decision types and the auditable Decision record."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class DecisionType(str, Enum):
    APPROVE_ONCE = "approve_once"
    REJECT = "reject"
    ALLOW_FOR_SESSION = "allow_for_session"
    ALLOW_SCOPED = "allow_scoped"
    ALWAYS_DENY_RULE = "always_deny_rule"
    QUARANTINE_SKILL = "quarantine_skill"
    INSPECT_CHAIN = "inspect_chain"


class DecisionRequest(BaseModel):
    decision_id: str
    event_id: str
    skill: str
    requested_action: str
    target: str | None
    risk: str
    cds: float = 0.0
    cds_band: str = "ALLOW"
    reasons: list[str]
    recommended_action: str
    allowed_actions: list[DecisionType]
    ast: list[str] = Field(default_factory=list)
    provenance: str | None = None


class DecisionRecord(BaseModel):
    decision: DecisionType
    actor: str = "human"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id: str
    reason: str = ""
    policy_created: bool = False

    @property
    def grants_execution(self) -> bool:
        return self.decision in (
            DecisionType.APPROVE_ONCE,
            DecisionType.ALLOW_FOR_SESSION,
            DecisionType.ALLOW_SCOPED,
        )
