"""Unit tests for OS-telemetry-to-session correlation. All synthetic: this
layer is pure comparison logic over two already-parsed event lists, so it
needs no real auditd feed to test thoroughly.
"""

from __future__ import annotations

from datetime import datetime, timezone

from skillfence.telemetry.auditd import AuditEvent
from skillfence.telemetry.correlate import correlate

SESSION_START = 1700000000.0
SESSION_END = 1700000010.0


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _session_events(*rows: dict) -> list[dict]:
    # every event needs a timestamp so the correlator can derive the
    # session's time window -- default to mid-session if not given.
    return [{"timestamp": _iso(SESSION_START + 1), **row} for row in rows]


def _audit(*, kind: str, pid: int, ts: float = SESSION_START + 1, **kwargs) -> AuditEvent:
    return AuditEvent(audit_id="1", timestamp=ts, kind=kind, pid=pid, **kwargs)


def test_process_exec_matches_tracked_resource():
    session = _session_events({"event_type": "process.exec", "resource": "curl -s https://example.test"})
    audit = [_audit(kind="process_exec", pid=1234, comm="curl")]
    report = correlate(session, audit, pid=1234)
    assert len(report.matched) == 1
    assert report.untracked == []
    assert report.bypass_suspected is False


def test_process_exec_with_no_tracked_event_is_flagged_as_bypass():
    # the whole point: SkillFence's own log shows nothing at all for this
    # process kind, while auditd shows a real execve.
    session = _session_events({"event_type": "filesystem.read", "resource": "./logs/app.log"})
    audit = [_audit(kind="process_exec", pid=1234, comm="bash", exe="/bin/bash")]
    report = correlate(session, audit, pid=1234)
    assert report.matched == []
    assert len(report.untracked) == 1
    assert report.untracked[0].confidence == "high"
    assert "bash" in report.untracked[0].reason
    assert report.bypass_suspected is True


def test_file_open_matches_via_path_suffix():
    session = _session_events({"event_type": "filesystem.read", "resource": "~/.aws/credentials"})
    audit = [_audit(kind="file_open", pid=1234, paths=["/home/user/.aws/credentials"])]
    report = correlate(session, audit, pid=1234)
    assert len(report.matched) == 1
    assert report.untracked == []


def test_file_open_with_no_matching_suffix_is_flagged():
    session = _session_events({"event_type": "filesystem.read", "resource": "./logs/app.log"})
    audit = [_audit(kind="file_open", pid=1234, paths=["/home/user/.ssh/id_rsa"])]
    report = correlate(session, audit, pid=1234)
    assert len(report.untracked) == 1
    assert report.untracked[0].confidence == "medium"
    assert "id_rsa" in report.untracked[0].reason


def test_network_connect_is_always_observed_never_matched_or_untracked():
    session = _session_events({"event_type": "network.http_request", "resource": "https://example.test"})
    audit = [_audit(kind="network_connect", pid=1234)]
    report = correlate(session, audit, pid=1234)
    assert report.matched == []
    assert report.untracked == []
    assert len(report.observed_network) == 1


def test_other_kind_syscalls_are_ignored_entirely():
    session = _session_events({"event_type": "filesystem.read", "resource": "./logs/app.log"})
    audit = [_audit(kind="other", pid=1234)]
    report = correlate(session, audit, pid=1234)
    assert report.matched == []
    assert report.untracked == []
    assert report.observed_network == []


def test_pid_filter_excludes_other_processes():
    session = _session_events({"event_type": "filesystem.read", "resource": "./logs/app.log"})
    audit = [_audit(kind="process_exec", pid=9999, comm="nc")]  # different process entirely
    report = correlate(session, audit, pid=1234)
    assert report.matched == []
    assert report.untracked == []  # excluded by pid filter, not flagged


def test_without_pid_filter_all_processes_in_window_are_considered():
    session = _session_events({"event_type": "filesystem.read", "resource": "./logs/app.log"})
    audit = [_audit(kind="process_exec", pid=9999, comm="nc")]
    report = correlate(session, audit, pid=None)
    assert len(report.untracked) == 1


def test_audit_event_outside_session_time_window_is_excluded():
    session = _session_events({"event_type": "filesystem.read", "resource": "./logs/app.log"})
    audit = [_audit(kind="process_exec", pid=1234, comm="bash", ts=SESSION_START + 3600)]  # an hour later
    report = correlate(session, audit, pid=1234)
    assert report.matched == []
    assert report.untracked == []


def test_bypass_suspected_false_when_nothing_untracked():
    session = _session_events({"event_type": "filesystem.read", "resource": "~/.aws/credentials"})
    audit = [_audit(kind="file_open", pid=1234, paths=["/home/user/.aws/credentials"])]
    report = correlate(session, audit, pid=1234)
    assert report.bypass_suspected is False
