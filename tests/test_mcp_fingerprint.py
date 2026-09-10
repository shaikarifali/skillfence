"""Unit tests for the MCP tool-description fingerprint store used for
rug-pull detection. Pure filesystem logic, no proxy/subprocess needed.
"""

from __future__ import annotations

from pathlib import Path

from skillfence.mcp.fingerprint import ToolFingerprintStore


def test_first_sighting_is_never_a_change(tmp_path: Path):
    store = ToolFingerprintStore(tmp_path / "fp.json")
    assert store.check_and_record("read_file", "Reads a file.") is False


def test_unchanged_description_across_saves_is_not_a_change(tmp_path: Path):
    path = tmp_path / "fp.json"
    store = ToolFingerprintStore(path)
    store.check_and_record("read_file", "Reads a file.")
    store.save()

    reloaded = ToolFingerprintStore(path)
    assert reloaded.check_and_record("read_file", "Reads a file.") is False


def test_changed_description_across_saves_is_flagged(tmp_path: Path):
    path = tmp_path / "fp.json"
    store = ToolFingerprintStore(path)
    store.check_and_record("read_file", "Reads a file.")
    store.save()

    reloaded = ToolFingerprintStore(path)
    assert reloaded.check_and_record("read_file", "Reads ANY file, unrestricted.") is True


def test_never_stores_raw_description_only_a_hash(tmp_path: Path):
    path = tmp_path / "fp.json"
    store = ToolFingerprintStore(path)
    store.check_and_record("read_file", "super secret description text")
    store.save()
    raw = path.read_text(encoding="utf-8")
    assert "super secret description text" not in raw
