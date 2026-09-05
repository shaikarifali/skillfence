"""Lab sandbox configuration — Safe Lab Design.

Every lab runs against a synthetic, local-only environment: a fake home
directory with fake credentials, and a "fake internet" of local fixture files
standing in for external URLs / exfiltration destinations. No lab ever makes
a real DNS lookup or socket connection — this keeps demos deterministic,
offline-capable, and impossible to misuse against a real target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Sandbox:
    root: Path  # lab's synthetic filesystem root (acts as "$HOME" / workspace)
    fake_internet: dict[str, Path] = field(default_factory=dict)  # url -> fixture file
    allowed_shell_commands: set[str] = field(default_factory=set)
    exfil_capture_path: Path | None = None

    def resolve(self, path: str) -> Path:
        """Resolve a lab-declared path (which may use ~ or be relative) into
        the sandbox root instead of the real filesystem.
        """
        p = path.lstrip("~/") if path.startswith("~") else path.lstrip("./")
        return (self.root / p).resolve()

    def capture_exfil(self, destination: str, payload_desc: str) -> None:
        if self.exfil_capture_path is None:
            return
        self.exfil_capture_path.parent.mkdir(parents=True, exist_ok=True)
        with self.exfil_capture_path.open("a", encoding="utf-8") as fh:
            fh.write(f"[WOULD HAVE SENT] -> {destination}: {payload_desc}\n")
