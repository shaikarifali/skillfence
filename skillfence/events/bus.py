"""In-process event bus with a JSONL sink (JSONL/SQLite, no Kafka)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from skillfence.events.schema import DecisionState, Event

Subscriber = Callable[[Event], None]


class EventBus:
    """Synchronous pub/sub bus. Every published event is appended to a JSONL
    file (the audit log) and fanned out to subscribers
    (policy/correlation/risk engines) in the order they registered.
    """

    def __init__(self, jsonl_path: Path) -> None:
        self.jsonl_path = jsonl_path
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self._subscribers: list[Subscriber] = []
        self._events: list[Event] = []

    def subscribe(self, fn: Subscriber) -> None:
        self._subscribers.append(fn)

    def publish(self, event: Event) -> Event:
        self._events.append(event)
        with self.jsonl_path.open("a", encoding="utf-8") as fh:
            fh.write(event.model_dump_jsonl() + "\n")
        for sub in self._subscribers:
            sub(event)
        return event

    def all_events(self) -> list[Event]:
        return list(self._events)

    def events_for_session(self, session_id: str) -> list[Event]:
        return [e for e in self._events if e.session_id == session_id]

    def update_decision(self, event_id: str, decision: DecisionState) -> None:
        """Patches a previously published event's `decision` field, both
        in memory and in the persisted JSONL.

        An action event has to be published (necessarily `PENDING`, since
        the decision doesn't exist yet) before policy/risk/the human gate
        can produce a verdict for it -- so the on-disk row is written
        before its own outcome is known. Without this, that row stays
        `PENDING` forever: it's never rewritten, so every consumer that
        reads the JSONL back (`skillfence replay`, the dashboard) sees the
        wrong decision for the very event whose outcome the audit trail
        exists to record. Rewrites the file in place rather than
        appending a duplicate line, so a reader always sees exactly one
        row per event -- the fields that mattered at publish time
        (timestamp, resource, event_type, ...) are untouched; only the
        one field that was legitimately unknowable until now is corrected.
        """
        for e in self._events:
            if e.event_id == event_id:
                e.decision = decision
                break

        if not self.jsonl_path.exists():
            return
        lines = self.jsonl_path.read_text(encoding="utf-8").splitlines()
        rewritten: list[str] = []
        for line in lines:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("event_id") == event_id:
                row["decision"] = decision.value
                rewritten.append(json.dumps(row))
            else:
                rewritten.append(line)
        self.jsonl_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
