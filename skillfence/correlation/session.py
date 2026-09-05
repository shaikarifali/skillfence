"""Behavioral attack-chain correlation.

Keeps short-lived per-session state so a single sensitive read doesn't fire
the loudest alert on its own -- but read -> encode -> egress within a window
does. This is what separates SkillFence from a keyword/regex detector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from skillfence.events.schema import Event, EventType

CORRELATION_WINDOW = timedelta(seconds=30)

# AST05 flagship chain
AST05_CHAIN = [
    EventType.EXTERNAL_CONTENT_FETCH,
    EventType.EXTERNAL_CONTENT_INSTRUCTION_DETECTED,
    EventType.TOOL_REQUEST,
]

# Exfiltration chain. FS_READ is included because sensitive-path
# reads (credentials, ssh keys, ...) surface as filesystem.read with
# `sensitive=True` here rather than a dedicated credential.access
# event -- see policy/sensitive.py.
EXFIL_TRIGGERS = {
    EventType.FS_READ,
    EventType.SECRET_ACCESS,
    EventType.CREDENTIAL_ACCESS,
    EventType.SSH_KEY_ACCESS,
}
EXFIL_EGRESS = {EventType.NET_CONNECT, EventType.NET_HTTP_REQUEST}


@dataclass
class AttackChain:
    chain_id: str
    label: str
    ast_mapping: list[str]
    confidence: str
    event_ids: list[str] = field(default_factory=list)


@dataclass
class SessionState:
    session_id: str
    events: list[Event] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)
    external_instruction_seen: bool = False
    external_instruction_event_id: Optional[str] = None
    sensitive_access_seen_at: Optional[tuple[str, datetime]] = None  # (event_id, ts)


class CorrelationEngine:
    """One SessionState per session_id; call `observe` for every event."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._chain_seq = 0

    def session(self, session_id: str) -> SessionState:
        return self._sessions.setdefault(session_id, SessionState(session_id=session_id))

    def observe(self, event: Event) -> list[AttackChain]:
        state = self.session(event.session_id)
        state.events.append(event)
        new_chains: list[AttackChain] = []

        ts = datetime.fromisoformat(event.timestamp)

        # --- AST05: external content -> instruction -> sensitive tool request
        if event.event_type == EventType.EXTERNAL_CONTENT_INSTRUCTION_DETECTED:
            state.external_instruction_seen = True
            state.external_instruction_event_id = event.event_id
        if (
            event.event_type in (EventType.TOOL_REQUEST, EventType.FS_READ, EventType.FS_WRITE)
            and state.external_instruction_seen
            and event.sensitive
        ):
            chain = self._new_chain(
                label="External Content -> Instruction -> Sensitive Tool Request",
                ast_mapping=["AST05"],
                confidence="high",
                event_ids=[e.event_id for e in state.events[-6:]],
            )
            state.chains.append(chain)
            new_chains.append(chain)

        # --- AST01: credential access -> collection/egress within window
        if event.event_type in EXFIL_TRIGGERS and event.sensitive:
            state.sensitive_access_seen_at = (event.event_id, ts)

        if event.event_type in EXFIL_EGRESS and state.sensitive_access_seen_at:
            prior_id, prior_ts = state.sensitive_access_seen_at
            if ts - prior_ts <= CORRELATION_WINDOW:
                chain = self._new_chain(
                    label="Credential Access -> Collection -> Exfiltration",
                    ast_mapping=["AST01", "AST03"],
                    confidence="high",
                    event_ids=[prior_id, event.event_id],
                )
                state.chains.append(chain)
                new_chains.append(chain)

        return new_chains

    def _new_chain(self, *, label: str, ast_mapping: list[str], confidence: str, event_ids: list[str]) -> AttackChain:
        self._chain_seq += 1
        return AttackChain(
            chain_id=f"chain-{self._chain_seq:04d}",
            label=label,
            ast_mapping=ast_mapping,
            confidence=confidence,
            event_ids=event_ids,
        )
