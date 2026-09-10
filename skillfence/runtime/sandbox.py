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

        Strips an exact `~`/`~/` or `./` *prefix* -- not a leading run of
        `.`/`/` characters. `str.lstrip` strips a character class, not a
        prefix: `"../../../etc/passwd".lstrip("./")` collapses the entire
        leading dot/slash run down to `"etc/passwd"`, silently neutering
        real path traversal before `escapes_root()` below ever sees it.
        A bare `../../x` (no `~` or `./` prefix) and an absolute `/x` both
        fall through unchanged, so `(root / p).resolve()` walks them for
        real -- which is exactly what a traversal/escape check needs.
        """
        if path.startswith("~"):
            p = path[1:]
            if p.startswith("/"):
                p = p[1:]
        elif path.startswith("./"):
            p = path[2:]
        else:
            p = path
        return (self.root / p).resolve()

    def escapes_root(self, path: str) -> bool:
        """AST06 (weak isolation): does this path, once resolved, actually
        fall outside this sandbox's own root? Catches both `../../`-style
        traversal and an absolute path smuggled in disguised as workspace-
        relative -- either way, this is a skill trying to touch something
        that was never its own sandboxed "home directory" in the first place.
        """
        resolved = self.resolve(path)
        root = self.root.resolve()
        return resolved != root and root not in resolved.parents

    def capture_exfil(self, destination: str, payload_desc: str) -> None:
        if self.exfil_capture_path is None:
            return
        self.exfil_capture_path.parent.mkdir(parents=True, exist_ok=True)
        with self.exfil_capture_path.open("a", encoding="utf-8") as fh:
            fh.write(f"[WOULD HAVE SENT] -> {destination}: {payload_desc}\n")
