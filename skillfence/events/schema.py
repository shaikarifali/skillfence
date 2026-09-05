"""Normalized runtime event model.

Every agent action, regardless of which adapter produced it, is normalized
into one Event shape before it reaches policy/risk/correlation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EventType(str, Enum):
    # skill.*
    SKILL_INSTALL = "skill.install"
    SKILL_LOAD = "skill.load"
    SKILL_INVOKE = "skill.invoke"
    SKILL_UPDATE = "skill.update"
    SKILL_DISABLE = "skill.disable"
    SKILL_UNINSTALL = "skill.uninstall"

    # tool.*
    TOOL_REQUEST = "tool.request"
    TOOL_EXECUTE = "tool.execute"
    TOOL_RESULT = "tool.result"
    TOOL_DENIED = "tool.denied"

    # filesystem.*
    FS_READ = "filesystem.read"
    FS_WRITE = "filesystem.write"
    FS_DELETE = "filesystem.delete"
    FS_RENAME = "filesystem.rename"

    # process.*
    PROCESS_SPAWN = "process.spawn"
    PROCESS_EXEC = "process.exec"
    PROCESS_SHELL = "process.shell"

    # network.*
    NET_DNS = "network.dns"
    NET_CONNECT = "network.connect"
    NET_HTTP_REQUEST = "network.http_request"
    NET_HTTP_RESPONSE = "network.http_response"

    # secret.* / credential.*
    SECRET_ACCESS = "secret.access"
    CREDENTIAL_ACCESS = "credential.access"
    SSH_KEY_ACCESS = "ssh_key.access"
    CLOUD_TOKEN_ACCESS = "cloud_token.access"
    ENV_SECRET_ACCESS = "environment_secret.access"

    # external_content.*
    EXTERNAL_CONTENT_FETCH = "external_content.fetch"
    EXTERNAL_CONTENT_REDIRECT = "external_content.redirect"
    EXTERNAL_CONTENT_INSTRUCTION_DETECTED = "external_content.instruction_detected"
    EXTERNAL_CONTENT_BEHAVIOR_CHANGE = "external_content.behavior_change"

    # skill.* logic-layer (LPCI): an instruction-like directive
    # found not in fetched external content but in the skill's *own*
    # definition (SKILL.md) — distinct from AST05, since no external fetch
    # is involved. This is what a code-pattern static scanner (grep for
    # exec/curl/subprocess) cannot see: the payload is prose, not code.
    LOGIC_LAYER_INSTRUCTION_DETECTED = "skill.logic_layer_instruction_detected"

    # metadata.*
    METADATA_MISMATCH = "metadata.mismatch"

    # policy.*
    POLICY_VIOLATION = "policy.violation"

    # human_decision.*
    HUMAN_DECISION = "human_decision.made"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionState(str, Enum):
    PENDING = "pending"
    ALLOWED = "allowed"
    REJECTED = "rejected"
    APPROVED_ONCE = "approved_once"
    QUARANTINED = "quarantined"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Event(BaseModel):
    """Normalized runtime event."""

    event_id: str = Field(default_factory=lambda: new_id("evt"))
    timestamp: str = Field(default_factory=_now)
    session_id: str
    agent: str
    skill: Optional[str] = None
    event_type: EventType
    resource: Optional[str] = None
    declared: Optional[bool] = None
    sensitive: bool = False
    initiator: str = "tool_call"
    parent_event: Optional[str] = None
    decision: DecisionState = DecisionState.PENDING

    # extra structured context (args, destination host, content excerpt, etc.)
    details: dict[str, Any] = Field(default_factory=dict)

    def model_dump_jsonl(self) -> str:
        return self.model_dump_json(exclude_none=False)
