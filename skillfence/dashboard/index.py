"""A persistent, on-disk index for the dashboard's data layer — closes the
two real costs `discover_sessions()` used to pay on every single request:
(1) re-parsing every session's entire JSONL history from scratch after
every dashboard *restart* (an in-memory-only cache starts empty again the
moment the process restarts), and (2) walking a "whole fleet" root's
entire directory tree on every single browser poll, even when nothing on
disk has changed since the last one.

Stored at `<root>/.skillfence/dashboard_index.sqlite3` — the same
per-root local-state convention `.skillfence/policy_grants.json` already
uses (`skillfence/policy/store.py`). Correctness rests on the same
append-only guarantee the earlier in-memory cache relied on: every JSONL
file SkillFence writes only ever grows, so a file whose size matches
what's recorded has unchanged content. stdlib `sqlite3` only — no new
dependency for something this size.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS file_cache (
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    rows_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS walk_cache (
    root TEXT PRIMARY KEY,
    paths_json TEXT NOT NULL,
    walked_at REAL NOT NULL
);
"""

# How long a directory-walk result is trusted before re-scanning for new
# session files. Short enough that a session created moments ago still
# shows up quickly; long enough that a dashboard auto-refreshing every few
# seconds isn't re-walking a huge tree on every single one of them.
WALK_TTL_SECONDS = 5.0

_connections: dict[str, sqlite3.Connection] = {}


def _db_path(root: Path) -> Path:
    return root / ".skillfence" / "dashboard_index.sqlite3"


def open_index(root: Path) -> sqlite3.Connection:
    """One connection per root, reused across calls within this process --
    reopening a sqlite file on every request would defeat the point.
    """
    key = str(root)
    conn = _connections.get(key)
    if conn is not None:
        return conn
    db_path = _db_path(root)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.executescript(_SCHEMA)
    _connections[key] = conn
    return conn


def get_cached_rows(conn: sqlite3.Connection, path: Path, size: int) -> list[dict] | None:
    row = conn.execute("SELECT size, rows_json FROM file_cache WHERE path = ?", (str(path),)).fetchone()
    if row is None or row[0] != size:
        return None
    return json.loads(row[1])


def store_rows(conn: sqlite3.Connection, path: Path, size: int, rows: list[dict]) -> None:
    conn.execute(
        "INSERT INTO file_cache (path, size, rows_json) VALUES (?, ?, ?) "
        "ON CONFLICT(path) DO UPDATE SET size = excluded.size, rows_json = excluded.rows_json",
        (str(path), size, json.dumps(rows)),
    )
    conn.commit()


def get_cached_walk(conn: sqlite3.Connection, root: Path) -> list[str] | None:
    row = conn.execute("SELECT paths_json, walked_at FROM walk_cache WHERE root = ?", (str(root),)).fetchone()
    if row is None:
        return None
    paths_json, walked_at = row
    if time.time() - walked_at > WALK_TTL_SECONDS:
        return None
    return json.loads(paths_json)


def store_walk(conn: sqlite3.Connection, root: Path, paths: list[str]) -> None:
    conn.execute(
        "INSERT INTO walk_cache (root, paths_json, walked_at) VALUES (?, ?, ?) "
        "ON CONFLICT(root) DO UPDATE SET paths_json = excluded.paths_json, walked_at = excluded.walked_at",
        (str(root), json.dumps(paths), time.time()),
    )
    conn.commit()
