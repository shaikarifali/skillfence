"""In-process event bus with a JSONL sink (JSONL/SQLite, no Kafka)."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from skillfence.events.schema import Event

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
