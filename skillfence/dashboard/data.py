"""Dashboard data layer — discovers sessions and correlates events/findings
straight from the same JSONL files every other command reads
(`skillfence findings`/`replay`/`profile`). No new storage format, no
database: the dashboard is a read-only view over evidence that already
exists, re-scanned on every request rather than cached at the *session*
level, so it reflects a lab run or MCP proxy session that's still in
progress.

Two on-disk conventions exist and both are handled here:
  - a lab run (`skillfence run`): `<lab>/.runs/<session_id>.events.jsonl`,
    one shared `<lab>/.runs/findings.jsonl` across every session in that dir.
  - an MCP proxy session: `<audit_dir>/<session_id>.events.jsonl` and a
    *per-session* `<audit_dir>/<session_id>.findings.jsonl`.
Findings are correlated to a session by testing whether any of the
finding's `evidence` (event id) list intersects that session's own event
ids — works for both conventions without hard-coding either one.

Parsed *file contents* are cached, keyed by (path, size in bytes) --
correct because every JSONL file SkillFence writes is strictly append-only
(`EventBus.publish`/`append_jsonl` only ever append), so an unchanged size
guarantees unchanged content. Without this, a dashboard left open with
auto-refresh polling every few seconds would re-parse every session's
entire history on every single poll.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from skillfence.storage.jsonl_store import read_jsonl

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3, "none": -1}
_FILE_CACHE: dict[str, tuple[int, list[dict]]] = {}


def _read_jsonl_cached(path: Path) -> list[dict]:
    if not path.exists():
        return []
    key = str(path)
    size = path.stat().st_size
    cached = _FILE_CACHE.get(key)
    if cached is not None and cached[0] == size:
        return cached[1]
    rows = list(read_jsonl(path))
    _FILE_CACHE[key] = (size, rows)
    return rows


@dataclass
class SessionInfo:
    session_id: str
    skill: str | None
    agent: str | None
    source_dir: str  # relative to the dashboard root, for display
    event_count: int
    finding_count: int
    highest_severity: str
    first_timestamp: str | None
    last_timestamp: str | None
    events_path: str  # absolute, used by /api/session/<id>

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "skill": self.skill,
            "agent": self.agent,
            "source_dir": self.source_dir,
            "event_count": self.event_count,
            "finding_count": self.finding_count,
            "highest_severity": self.highest_severity,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
        }


def _findings_for_session(events_path: Path, session_id: str, event_ids: set[str]) -> list[dict]:
    per_session = events_path.parent / f"{session_id}.findings.jsonl"
    if per_session.exists():
        return _read_jsonl_cached(per_session)

    shared = events_path.parent / "findings.jsonl"
    if not shared.exists():
        return []
    return [f for f in _read_jsonl_cached(shared) if event_ids.intersection(f.get("evidence") or [])]


def _session_info(events_path: Path, root: Path) -> SessionInfo | None:
    events = _read_jsonl_cached(events_path)
    if not events:
        return None
    session_id = events[0].get("session_id") or events_path.stem.removesuffix(".events")
    event_ids = {e.get("event_id") for e in events if e.get("event_id")}
    findings = _findings_for_session(events_path, session_id, event_ids)

    highest = "none"
    for f in findings:
        sev = str(f.get("severity", "low")).lower()
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(highest, -1):
            highest = sev

    try:
        source_dir = str(events_path.parent.relative_to(root))
    except ValueError:
        source_dir = str(events_path.parent)

    return SessionInfo(
        session_id=session_id,
        skill=events[0].get("skill"),
        agent=events[0].get("agent"),
        source_dir=source_dir,
        event_count=len(events),
        finding_count=len(findings),
        highest_severity=highest,
        first_timestamp=events[0].get("timestamp"),
        last_timestamp=events[-1].get("timestamp"),
        events_path=str(events_path),
    )


def discover_sessions(root: Path) -> list[SessionInfo]:
    """Every session found under `root`, newest first. Re-scans the
    filesystem on every call -- deliberately, so a dashboard left open
    during a live `run`/`mcp-proxy` session picks up new events without a
    restart.
    """
    root = root.resolve()
    sessions = [
        info
        for events_path in sorted(root.rglob("*.events.jsonl"))
        if (info := _session_info(events_path, root)) is not None
    ]
    sessions.sort(key=lambda s: s.last_timestamp or "", reverse=True)
    return sessions


def find_session(root: Path, session_id: str) -> SessionInfo | None:
    root = root.resolve()
    for events_path in root.rglob(f"{session_id}.events.jsonl"):
        info = _session_info(events_path, root)
        if info is not None:
            return info
    # fall back to a full scan -- the session_id came from event *content*,
    # not necessarily the filename, if a producer other than SkillFence's
    # own EventBus ever names files differently.
    for info in discover_sessions(root):
        if info.session_id == session_id:
            return info
    return None


def session_detail(root: Path, session_id: str) -> dict | None:
    info = find_session(root, session_id)
    if info is None:
        return None
    events_path = Path(info.events_path)
    events = _read_jsonl_cached(events_path)
    event_ids = {e.get("event_id") for e in events if e.get("event_id")}
    findings = _findings_for_session(events_path, info.session_id, event_ids)
    return {"session": info.to_dict(), "events": events, "findings": findings}
