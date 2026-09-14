"""Unit tests for the AST09 (No Governance) fleet inventory
(`skillfence/governance/inventory.py`). Builds real skill directories
with real manifest.yaml files, real EventBus-written session JSONL, and
a real (in-memory-backed) PolicyStore -- no mocking of the data layer
this reuses (`skillfence.dashboard.data.discover_sessions`).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from skillfence.events.bus import EventBus
from skillfence.events.schema import Event, EventType
from skillfence.governance.inventory import build_inventory
from skillfence.policy.store import PolicyStore


def _write_manifest(root: Path, skill_dir: str, name: str) -> None:
    manifest_path = root / skill_dir / "skill" / "manifest.yaml"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        f'name: {name}\nversion: "0.1"\npurpose: [test]\n'
        "capabilities:\n  filesystem:\n    read: []\n"
        "  process:\n    execute: []\n  network:\n    enabled: false\n    domains: []\n"
        "  secrets:\n    access: false\n",
        encoding="utf-8",
    )


def _record_session(root: Path, skill_dir: str, *, skill: str, session_id: str) -> None:
    events_path = root / skill_dir / ".runs" / f"{session_id}.events.jsonl"
    bus = EventBus(events_path)
    bus.publish(
        Event(session_id=session_id, agent="test-agent", skill=skill, event_type=EventType.SKILL_INVOKE, resource=skill)
    )


def _empty_store(tmp_path: Path) -> PolicyStore:
    return PolicyStore(tmp_path / "policy_grants.json")


def test_skill_with_no_session_anywhere_is_flagged_never_reviewed(tmp_path: Path):
    _write_manifest(tmp_path, "skill-a", "skill-a")
    rows = build_inventory(tmp_path, policy_store=_empty_store(tmp_path))
    assert len(rows) == 1
    assert rows[0].ever_reviewed is False
    assert "never reviewed" in rows[0].flags
    assert not rows[0].clean


def test_skill_with_a_session_is_not_flagged(tmp_path: Path):
    _write_manifest(tmp_path, "skill-a", "skill-a")
    _record_session(tmp_path, "skill-a", skill="skill-a", session_id="s1")
    rows = build_inventory(tmp_path, policy_store=_empty_store(tmp_path))
    assert len(rows) == 1
    assert rows[0].ever_reviewed is True
    assert rows[0].session_count == 1
    assert rows[0].clean


def test_active_grant_issued_after_last_review_is_ungoverned(tmp_path: Path):
    _write_manifest(tmp_path, "skill-a", "skill-a")
    _record_session(tmp_path, "skill-a", skill="skill-a", session_id="s1")

    store = _empty_store(tmp_path)
    store.add_grant(skill="skill-a", event_type="filesystem.read", resource="~/.aws/credentials", decision="allow_scoped", ttl=None)

    rows = build_inventory(tmp_path, policy_store=store)
    assert rows[0].active_grants == 1
    assert rows[0].ungoverned_grants == 1
    assert any("ungoverned grant" in f for f in rows[0].flags)


def test_active_grant_with_no_review_at_all_is_ungoverned(tmp_path: Path):
    _write_manifest(tmp_path, "skill-a", "skill-a")  # never reviewed at all

    store = _empty_store(tmp_path)
    store.add_grant(skill="skill-a", event_type="filesystem.read", resource="~/.aws/credentials", decision="allow_scoped", ttl=None)

    rows = build_inventory(tmp_path, policy_store=store)
    assert rows[0].ungoverned_grants == 1
    assert "never reviewed" in rows[0].flags
    assert any("ungoverned grant" in f for f in rows[0].flags)


def test_expired_grant_is_never_counted_as_active_or_ungoverned(tmp_path: Path):
    _write_manifest(tmp_path, "skill-a", "skill-a")
    _record_session(tmp_path, "skill-a", skill="skill-a", session_id="s1")

    store = _empty_store(tmp_path)
    store.add_grant(
        skill="skill-a",
        event_type="filesystem.read",
        resource="~/.aws/credentials",
        decision="allow_scoped",
        ttl=timedelta(hours=-1),  # already expired
    )

    rows = build_inventory(tmp_path, policy_store=store)
    assert rows[0].active_grants == 0
    assert rows[0].ungoverned_grants == 0
    assert rows[0].clean


def test_grant_for_a_different_skill_never_attributed_to_this_one(tmp_path: Path):
    _write_manifest(tmp_path, "skill-a", "skill-a")
    _write_manifest(tmp_path, "skill-b", "skill-b")
    _record_session(tmp_path, "skill-a", skill="skill-a", session_id="s1")
    _record_session(tmp_path, "skill-b", skill="skill-b", session_id="s2")

    store = _empty_store(tmp_path)
    store.add_grant(skill="skill-b", event_type="filesystem.read", resource="~/.aws/credentials", decision="allow_scoped", ttl=None)

    rows = {r.skill: r for r in build_inventory(tmp_path, policy_store=store)}
    assert rows["skill-a"].active_grants == 0
    assert rows["skill-b"].active_grants == 1


def test_highest_severity_reflects_the_worst_finding_across_that_skills_sessions(tmp_path: Path):
    _write_manifest(tmp_path, "skill-a", "skill-a")
    events_path = tmp_path / "skill-a" / ".runs" / "s1.events.jsonl"
    bus = EventBus(events_path)
    evt = bus.publish(
        Event(session_id="s1", agent="test-agent", skill="skill-a", event_type=EventType.FS_READ, resource="~/.aws/credentials")
    )
    findings_path = tmp_path / "skill-a" / ".runs" / "findings.jsonl"
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    import json

    findings_path.write_text(
        json.dumps(
            {
                "title": "t",
                "ast": ["AST03"],
                "severity": "critical",
                "confidence": "high",
                "skill": "skill-a",
                "action": "filesystem.read",
                "resource": "~/.aws/credentials",
                "declared_capability": "-",
                "observed_capability": "filesystem.read",
                "why_flagged": [],
                "evidence": [evt.event_id],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    rows = build_inventory(tmp_path, policy_store=_empty_store(tmp_path))
    assert rows[0].highest_severity == "critical"


def test_multiple_skills_produce_independent_rows(tmp_path: Path):
    _write_manifest(tmp_path, "skill-a", "skill-a")
    _write_manifest(tmp_path, "skill-b", "skill-b")
    _record_session(tmp_path, "skill-a", skill="skill-a", session_id="s1")
    # skill-b left unreviewed

    rows = {r.skill: r for r in build_inventory(tmp_path, policy_store=_empty_store(tmp_path))}
    assert rows["skill-a"].clean
    assert not rows["skill-b"].clean
    assert "never reviewed" in rows["skill-b"].flags


def test_empty_root_with_no_manifests_returns_no_rows(tmp_path: Path):
    assert build_inventory(tmp_path, policy_store=_empty_store(tmp_path)) == []
