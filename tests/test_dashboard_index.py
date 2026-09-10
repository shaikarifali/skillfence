"""Unit tests for the dashboard's persistent sqlite index. The one that
matters most (`test_cache_survives_a_process_restart`) opens a *second,
independent* sqlite connection straight at the same file — not through
`index.open_index()`'s per-root connection reuse — specifically so it
can't be satisfied by an in-memory cache that merely looks persistent
within one process. That's the actual bug this module exists to fix.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from skillfence.dashboard import index


def test_uncached_file_returns_none(tmp_path: Path):
    conn = index.open_index(tmp_path)
    assert index.get_cached_rows(conn, tmp_path / "events.jsonl", size=100) is None


def test_store_then_get_round_trips(tmp_path: Path):
    conn = index.open_index(tmp_path)
    rows = [{"event_type": "skill.load"}, {"event_type": "filesystem.read"}]
    index.store_rows(conn, tmp_path / "events.jsonl", size=42, rows=rows)
    assert index.get_cached_rows(conn, tmp_path / "events.jsonl", size=42) == rows


def test_size_mismatch_invalidates_the_cache_entry(tmp_path: Path):
    conn = index.open_index(tmp_path)
    index.store_rows(conn, tmp_path / "events.jsonl", size=42, rows=[{"a": 1}])
    # the file grew (append-only) -- the old cached size no longer matches
    assert index.get_cached_rows(conn, tmp_path / "events.jsonl", size=99) is None


def test_store_rows_overwrites_a_prior_entry_for_the_same_path(tmp_path: Path):
    conn = index.open_index(tmp_path)
    index.store_rows(conn, tmp_path / "events.jsonl", size=10, rows=[{"a": 1}])
    index.store_rows(conn, tmp_path / "events.jsonl", size=20, rows=[{"a": 1}, {"b": 2}])
    assert index.get_cached_rows(conn, tmp_path / "events.jsonl", size=20) == [{"a": 1}, {"b": 2}]
    assert index.get_cached_rows(conn, tmp_path / "events.jsonl", size=10) is None


def test_open_index_returns_the_same_connection_for_the_same_root(tmp_path: Path):
    assert index.open_index(tmp_path) is index.open_index(tmp_path)


def test_walk_cache_round_trips_within_ttl(tmp_path: Path):
    conn = index.open_index(tmp_path)
    paths = [str(tmp_path / "a.events.jsonl"), str(tmp_path / "b.events.jsonl")]
    index.store_walk(conn, tmp_path, paths)
    assert index.get_cached_walk(conn, tmp_path) == paths


def test_walk_cache_expires_after_ttl(tmp_path: Path):
    conn = index.open_index(tmp_path)
    index.store_walk(conn, tmp_path, [str(tmp_path / "a.events.jsonl")])
    # simulate the TTL having elapsed, without a real sleep in the suite
    stale = time.time() - index.WALK_TTL_SECONDS - 1
    conn.execute("UPDATE walk_cache SET walked_at = ? WHERE root = ?", (stale, str(tmp_path)))
    conn.commit()
    assert index.get_cached_walk(conn, tmp_path) is None


def test_walk_cache_missing_for_an_unseen_root_returns_none(tmp_path: Path):
    conn = index.open_index(tmp_path)
    assert index.get_cached_walk(conn, tmp_path / "never-walked") is None


def test_index_is_stored_under_dot_skillfence_in_the_root(tmp_path: Path):
    index.open_index(tmp_path)
    assert (tmp_path / ".skillfence" / "dashboard_index.sqlite3").exists()


def test_cache_survives_a_process_restart(tmp_path: Path):
    """The actual point of this module: open a completely independent
    sqlite connection at the same on-disk file (not `index.open_index()`,
    which would just hand back the process-cached one) to prove the cache
    is real, on-disk state -- not something that only looks persistent
    because it's still the same Python process.
    """
    conn1 = index.open_index(tmp_path)
    index.store_rows(conn1, tmp_path / "events.jsonl", size=42, rows=[{"event_type": "skill.load"}])
    index.store_walk(conn1, tmp_path, [str(tmp_path / "events.jsonl")])
    conn1.close()

    db_path = tmp_path / ".skillfence" / "dashboard_index.sqlite3"
    fresh_conn = sqlite3.connect(db_path)
    try:
        assert index.get_cached_rows(fresh_conn, tmp_path / "events.jsonl", size=42) == [
            {"event_type": "skill.load"}
        ]
        assert index.get_cached_walk(fresh_conn, tmp_path) == [str(tmp_path / "events.jsonl")]
    finally:
        fresh_conn.close()
