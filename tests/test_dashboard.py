"""Dashboard data-layer and server tests. Fixture data is written through
the real `EventBus`/`Finding` model, not hand-typed JSON, so a schema
mismatch fails these tests instead of silently drifting.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from skillfence.dashboard.data import discover_sessions, find_session, session_detail
from skillfence.dashboard.server import build_server
from skillfence.events.bus import EventBus
from skillfence.events.schema import DecisionState, Event, EventType
from skillfence.findings.schema import Finding
from skillfence.storage.jsonl_store import append_jsonl


def _write_lab_session(lab_dir: Path, *, skill: str, session_id: str) -> tuple[Event, Event]:
    """Lab-run convention: `<lab>/.runs/<session_id>.events.jsonl`, shared
    `<lab>/.runs/findings.jsonl`.
    """
    runs_dir = lab_dir / ".runs"
    bus = EventBus(runs_dir / f"{session_id}.events.jsonl")
    root = bus.publish(Event(session_id=session_id, agent="test-agent", skill=skill, event_type=EventType.SKILL_LOAD))
    leaf = bus.publish(
        Event(
            session_id=session_id, agent="test-agent", skill=skill, event_type=EventType.FS_READ,
            resource="~/.aws/credentials", parent_event=root.event_id, decision=DecisionState.REJECTED,
        )
    )
    return root, leaf


def _append_finding(lab_dir: Path, *, skill: str, severity: str, evidence: list[str]) -> None:
    finding = Finding(
        title=f"{severity} finding", ast=["AST03"], severity=severity, confidence="high", skill=skill,
        action="filesystem.read", resource="~/.aws/credentials", declared_capability="not declared",
        observed_capability="filesystem.read", why_flagged=["undeclared capability"], evidence=evidence,
        status="blocked", human_decision="reject",
    )
    append_jsonl(lab_dir / ".runs" / "findings.jsonl", finding.model_dump())


def _write_mcp_session(audit_dir: Path, *, skill: str, session_id: str) -> Event:
    """MCP proxy convention: `<audit_dir>/<session_id>.events.jsonl` and a
    *per-session* `<audit_dir>/<session_id>.findings.jsonl`.
    """
    bus = EventBus(audit_dir / f"{session_id}.events.jsonl")
    event = bus.publish(
        Event(session_id=session_id, agent="mcp-proxy", skill=skill, event_type=EventType.TOOL_REQUEST, resource="mystery_tool")
    )
    finding = Finding(
        title="unresolvable tool mapping", ast=["AST03"], severity="high", confidence="medium", skill=skill,
        action="tool.request", resource="mystery_tool", declared_capability="no entry in tool map",
        observed_capability="tool.request", why_flagged=["unresolvable tool mapping"], evidence=[event.event_id],
        status="blocked", human_decision="reject",
    )
    append_jsonl(audit_dir / f"{session_id}.findings.jsonl", finding.model_dump())
    return event


# -- data layer ------------------------------------------------------------


def test_discover_sessions_finds_both_conventions(tmp_path: Path):
    _write_lab_session(tmp_path / "lab_a", skill="skill-a", session_id="session-aaa")
    _write_mcp_session(tmp_path / ".skillfence" / "mcp", skill="skill-b", session_id="session-bbb")

    sessions = discover_sessions(tmp_path)
    ids = {s.session_id for s in sessions}
    assert ids == {"session-aaa", "session-bbb"}


def test_shared_findings_file_is_partitioned_by_evidence_intersection(tmp_path: Path):
    # two sessions in the SAME lab dir, sharing one findings.jsonl -- the
    # real thing this correlation logic exists to get right.
    lab_dir = tmp_path / "lab_a"
    _root1, leaf1 = _write_lab_session(lab_dir, skill="skill-a", session_id="session-1")
    _root2, leaf2 = _write_lab_session(lab_dir, skill="skill-a", session_id="session-2")
    _append_finding(lab_dir, skill="skill-a", severity="high", evidence=[leaf1.event_id])
    _append_finding(lab_dir, skill="skill-a", severity="critical", evidence=[leaf2.event_id])

    detail1 = session_detail(tmp_path, "session-1")
    detail2 = session_detail(tmp_path, "session-2")
    assert len(detail1["findings"]) == 1
    assert detail1["findings"][0]["severity"] == "high"
    assert len(detail2["findings"]) == 1
    assert detail2["findings"][0]["severity"] == "critical"


def test_per_session_mcp_findings_file_is_used_directly(tmp_path: Path):
    audit_dir = tmp_path / ".skillfence" / "mcp"
    _write_mcp_session(audit_dir, skill="skill-b", session_id="session-bbb")
    detail = session_detail(tmp_path, "session-bbb")
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["severity"] == "high"


def test_session_summary_reports_highest_severity_and_counts(tmp_path: Path):
    lab_dir = tmp_path / "lab_a"
    _root, leaf = _write_lab_session(lab_dir, skill="skill-a", session_id="session-1")
    _append_finding(lab_dir, skill="skill-a", severity="high", evidence=[leaf.event_id])

    info = find_session(tmp_path, "session-1")
    assert info.highest_severity == "high"
    assert info.finding_count == 1
    assert info.event_count == 2
    assert info.skill == "skill-a"


def test_session_with_no_findings_reports_none_severity(tmp_path: Path):
    lab_dir = tmp_path / "lab_clean"
    _write_lab_session(lab_dir, skill="skill-clean", session_id="session-clean")
    info = find_session(tmp_path, "session-clean")
    assert info.highest_severity == "none"
    assert info.finding_count == 0


def test_find_session_returns_none_for_unknown_id(tmp_path: Path):
    assert find_session(tmp_path, "does-not-exist") is None


def test_session_detail_returns_none_for_unknown_id(tmp_path: Path):
    assert session_detail(tmp_path, "does-not-exist") is None


def test_discover_sessions_reflects_new_events_without_restart(tmp_path: Path):
    # the whole point of re-scanning instead of caching: a dashboard left
    # open during a live run must see events appended after the first look.
    lab_dir = tmp_path / "lab_a"
    _write_lab_session(lab_dir, skill="skill-a", session_id="session-1")
    before = find_session(tmp_path, "session-1")
    assert before.event_count == 2

    bus = EventBus(lab_dir / ".runs" / "session-1.events.jsonl")
    bus.publish(Event(session_id="session-1", agent="test-agent", skill="skill-a", event_type=EventType.SKILL_INVOKE))
    # EventBus starts empty in-memory even against an existing file, but it
    # still *appends* to the jsonl -- exactly what a second process would do.
    after = find_session(tmp_path, "session-1")
    assert after.event_count == 3


# -- server ------------------------------------------------------------


@pytest.fixture()
def running_server(tmp_path: Path):
    _write_lab_session(tmp_path / "lab_a", skill="skill-a", session_id="session-aaa")
    _append_finding(tmp_path / "lab_a", skill="skill-a", severity="high", evidence=["nonexistent"])
    server = build_server(tmp_path, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}", tmp_path
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _get_json(url: str):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def test_server_root_page_serves_html(running_server):
    base_url, _root = running_server
    with urllib.request.urlopen(f"{base_url}/", timeout=5) as resp:
        assert resp.status == 200
        assert "text/html" in resp.headers.get("Content-Type", "")
        body = resp.read().decode("utf-8")
    assert "SkillFence Dashboard" in body


def test_server_api_root_reports_scanned_path(running_server):
    base_url, root = running_server
    data = _get_json(f"{base_url}/api/root")
    assert data["path"] == str(root.resolve())


def test_server_api_sessions_lists_the_real_session(running_server):
    base_url, _root = running_server
    sessions = _get_json(f"{base_url}/api/sessions")
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == "session-aaa"
    assert sessions[0]["skill"] == "skill-a"


def test_server_api_session_detail_round_trips_real_data(running_server):
    base_url, _root = running_server
    detail = _get_json(f"{base_url}/api/session/session-aaa")
    assert detail["session"]["session_id"] == "session-aaa"
    assert len(detail["events"]) == 2
    assert detail["events"][0]["event_type"] == "skill.load"


def test_server_api_session_404_for_unknown_id(running_server):
    base_url, _root = running_server
    req = urllib.request.Request(f"{base_url}/api/session/nope")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req, timeout=5)
    assert excinfo.value.code == 404


def test_server_unknown_route_404s(running_server):
    base_url, _root = running_server
    req = urllib.request.Request(f"{base_url}/api/nonsense")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req, timeout=5)
    assert excinfo.value.code == 404
