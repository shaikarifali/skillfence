"""Persisted tool-description fingerprints for MCP rug-pull detection.

One JSON file per target server (keyed by the audit dir the proxy already
uses), mapping tool name -> sha256 of its description. Hashing rather than
storing the raw description means a description containing a secret-like
string never gets duplicated into a second file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


class ToolFingerprintStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fingerprints: dict[str, str] = {}
        if self.path.exists():
            self._fingerprints = json.loads(self.path.read_text(encoding="utf-8"))

    @staticmethod
    def _hash(description: str) -> str:
        return hashlib.sha256(description.encode("utf-8")).hexdigest()

    def check_and_record(self, tool_name: str, description: str) -> bool:
        """Returns True iff `tool_name` was seen in a prior run with a
        *different* description. Records the current description either
        way (first sighting is never a rug-pull -- there's nothing to
        compare against yet).
        """
        current = self._hash(description)
        prior = self._fingerprints.get(tool_name)
        self._fingerprints[tool_name] = current
        return prior is not None and prior != current

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._fingerprints, indent=2, sort_keys=True), encoding="utf-8")
