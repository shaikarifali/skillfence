"""Regression coverage for `EventBus.update_decision()`.

`publish()` writes an event to the JSONL file the moment it's published --
necessarily with `decision=PENDING`, since a gated action's real decision
doesn't exist until later (policy/risk/the human gate resolve it). Without
a way to patch the already-flushed line, every consumer that reads the
JSONL back (`skillfence replay`, the dashboard) would see PENDING forever
for the one event whose outcome the audit trail exists to record — this
was a real, silent bug for the whole project's history before this method
existed, caught visually via the dashboard.
"""

from __future__ import annotations

import json
from pathlib import Path

from skillfence.events.bus import EventBus
from skillfence.events.schema import DecisionState, Event, EventType


def _read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_update_decision_patches_the_persisted_jsonl_line(tmp_path: Path):
    bus = EventBus(tmp_path / "events.jsonl")
    event = bus.publish(Event(session_id="s1", agent="a", event_type=EventType.FS_READ, resource="./x"))

    rows = _read_rows(bus.jsonl_path)
    assert rows[0]["decision"] == "pending"  # true at publish time

    bus.update_decision(event.event_id, DecisionState.REJECTED)

    rows = _read_rows(bus.jsonl_path)
    assert len(rows) == 1  # patched in place, not appended as a second row
    assert rows[0]["decision"] == "rejected"
    assert rows[0]["event_id"] == event.event_id


def test_update_decision_updates_the_in_memory_event_too(tmp_path: Path):
    bus = EventBus(tmp_path / "events.jsonl")
    event = bus.publish(Event(session_id="s1", agent="a", event_type=EventType.FS_READ, resource="./x"))
    bus.update_decision(event.event_id, DecisionState.ALLOWED)
    assert event.decision == DecisionState.ALLOWED
    assert bus.all_events()[0].decision == DecisionState.ALLOWED


def test_update_decision_only_touches_the_matching_event(tmp_path: Path):
    bus = EventBus(tmp_path / "events.jsonl")
    first = bus.publish(Event(session_id="s1", agent="a", event_type=EventType.FS_READ, resource="./a"))
    second = bus.publish(Event(session_id="s1", agent="a", event_type=EventType.FS_READ, resource="./b"))

    bus.update_decision(first.event_id, DecisionState.REJECTED)

    rows = {r["event_id"]: r["decision"] for r in _read_rows(bus.jsonl_path)}
    assert rows[first.event_id] == "rejected"
    assert rows[second.event_id] == "pending"  # untouched


def test_update_decision_preserves_every_other_field(tmp_path: Path):
    bus = EventBus(tmp_path / "events.jsonl")
    event = bus.publish(
        Event(session_id="s1", agent="a", skill="my-skill", event_type=EventType.FS_READ, resource="~/.aws/credentials", sensitive=True)
    )
    bus.update_decision(event.event_id, DecisionState.REJECTED)

    row = _read_rows(bus.jsonl_path)[0]
    assert row["skill"] == "my-skill"
    assert row["resource"] == "~/.aws/credentials"
    assert row["sensitive"] is True
    assert row["event_type"] == "filesystem.read"


def test_update_decision_on_unknown_event_id_is_a_safe_no_op(tmp_path: Path):
    bus = EventBus(tmp_path / "events.jsonl")
    bus.publish(Event(session_id="s1", agent="a", event_type=EventType.FS_READ, resource="./x"))
    bus.update_decision("evt-does-not-exist", DecisionState.REJECTED)  # must not raise

    rows = _read_rows(bus.jsonl_path)
    assert len(rows) == 1
    assert rows[0]["decision"] == "pending"
