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

Parsed *file contents*, and the directory walk that finds session files in
the first place, are both cached in a persistent on-disk index
(`skillfence.dashboard.index`) rather than an in-memory dict -- correct
because every JSONL file SkillFence writes is strictly append-only
(`EventBus.publish`/`append_jsonl` only ever append), so an unchanged size
guarantees unchanged content. Without this, a dashboard left open with
auto-refresh polling every few seconds would re-parse every session's
entire history, and re-walk the whole directory tree, on every single
poll -- and lose all of that work again on every restart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from skillfence.dashboard import index as _index
from skillfence.storage.jsonl_store import read_jsonl

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3, "none": -1}


def _read_jsonl_cached(path: Path, conn) -> list[dict]:
    if not path.exists():
        return []
    size = path.stat().st_size
    cached = _index.get_cached_rows(conn, path, size)
    if cached is not None:
        return cached
    rows = list(read_jsonl(path))
    _index.store_rows(conn, path, size, rows)
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


def _findings_for_session(events_path: Path, session_id: str, event_ids: set[str], conn) -> list[dict]:
    per_session = events_path.parent / f"{session_id}.findings.jsonl"
    if per_session.exists():
        return _read_jsonl_cached(per_session, conn)

    shared = events_path.parent / "findings.jsonl"
    if not shared.exists():
        return []
    return [f for f in _read_jsonl_cached(shared, conn) if event_ids.intersection(f.get("evidence") or [])]


def _session_info(events_path: Path, root: Path, conn) -> SessionInfo | None:
    events = _read_jsonl_cached(events_path, conn)
    if not events:
        return None
    session_id = events[0].get("session_id") or events_path.stem.removesuffix(".events")
    event_ids = {e.get("event_id") for e in events if e.get("event_id")}
    findings = _findings_for_session(events_path, session_id, event_ids, conn)

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


def _discover_event_paths(root: Path, conn) -> list[Path]:
    """The list of every `*.events.jsonl` under `root` -- cached for
    `index.WALK_TTL_SECONDS` (see `skillfence.dashboard.index`) so a
    "whole fleet" root isn't walked in full on every single browser poll.
    """
    cached = _index.get_cached_walk(conn, root)
    if cached is not None:
        return [Path(p) for p in cached]
    paths = sorted(root.rglob("*.events.jsonl"))
    _index.store_walk(conn, root, [str(p) for p in paths])
    return paths


def discover_sessions(root: Path) -> list[SessionInfo]:
    """Every session found under `root`, newest first. The underlying
    directory walk and file contents are both cached (persistently, see
    `skillfence.dashboard.index`) so this stays cheap on repeated polls
    and after a dashboard restart, while still picking up a lab/mcp-proxy
    session that's still in progress -- new events change a tracked
    file's size, invalidating its cache entry; a session created since
    the last walk shows up once the walk cache's short TTL expires.
    """
    root = root.resolve()
    conn = _index.open_index(root)
    sessions = [
        info
        for events_path in _discover_event_paths(root, conn)
        if (info := _session_info(events_path, root, conn)) is not None
    ]
    sessions.sort(key=lambda s: s.last_timestamp or "", reverse=True)
    return sessions


def find_session(root: Path, session_id: str) -> SessionInfo | None:
    root = root.resolve()
    conn = _index.open_index(root)
    for events_path in _discover_event_paths(root, conn):
        if events_path.name == f"{session_id}.events.jsonl":
            info = _session_info(events_path, root, conn)
            if info is not None:
                return info
    # fall back to a full, uncached scan -- the session_id came from event
    # *content*, not necessarily the filename, if a producer other than
    # SkillFence's own EventBus ever names files differently, or if the
    # walk cache is stale and hasn't picked up a brand-new file yet.
    for events_path in sorted(root.rglob(f"{session_id}.events.jsonl")):
        info = _session_info(events_path, root, conn)
        if info is not None:
            return info
    return None


def session_detail(root: Path, session_id: str) -> dict | None:
    root = root.resolve()
    conn = _index.open_index(root)
    info = find_session(root, session_id)
    if info is None:
        return None
    events_path = Path(info.events_path)
    events = _read_jsonl_cached(events_path, conn)
    event_ids = {e.get("event_id") for e in events if e.get("event_id")}
    findings = _findings_for_session(events_path, info.session_id, event_ids, conn)
    return {"session": info.to_dict(), "events": events, "findings": findings}
