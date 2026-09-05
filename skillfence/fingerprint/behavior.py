"""Behavior fingerprinting.

Complements the AST02 manifest-diff (`apply_update`) with a cross-run
*observed behavior* diff that doesn't require an explicit version bump: any
two runs of the same lab, whatever changed between them, produce a
comparable fingerprint. A skill whose declared manifest never changes but
whose actual behavior gains a new capability (credential access, process
execution, a new network destination) is exactly the "silent update" /
compromised-dependency scenario static, manifest-only diffing misses.

A fingerprint is a set of capability tokens derived from the *kind* of
action observed (event type, plus a coarse resource discriminator such as a
network domain), not literal paths — so re-running the same lab against the
same sandbox naturally reproduces the same fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from skillfence.storage.jsonl_store import read_jsonl

# Event types that are pure plumbing/meta and carry no capability signal of
# their own (the sensitive filesystem/network/process/secret events they
# wrap are what matters).
_NON_CAPABILITY_TYPES = {
    "skill.install",
    "skill.load",
    "skill.invoke",
    "skill.update",
    "skill.disable",
    "skill.uninstall",
    "tool.request",
    "tool.execute",
    "tool.result",
    "tool.denied",
    "external_content.instruction_detected",
    "external_content.behavior_change",
    "metadata.mismatch",
    "policy.violation",
    "human_decision.made",
}

_NETWORK_TYPES = {"network.dns", "network.connect", "network.http_request", "external_content.fetch"}
_FS_TYPES = {"filesystem.read", "filesystem.write", "filesystem.delete", "filesystem.rename"}
_PROCESS_TYPES = {"process.spawn", "process.exec", "process.shell"}
_SECRET_TYPES = {
    "secret.access",
    "credential.access",
    "ssh_key.access",
    "cloud_token.access",
    "environment_secret.access",
}


def _domain_of(resource: str | None) -> str | None:
    if not resource:
        return None
    if "://" in resource:
        host = urlparse(resource).netloc
        return host or None
    # bare hostnames used directly as the resource (network.connect)
    if "/" not in resource and "." in resource:
        return resource
    return None


def capability_tokens(events: list[dict]) -> set[str]:
    """Reduce a run's raw events to a set of coarse capability tokens.

    Examples: ``filesystem.read``, ``filesystem.read:sensitive``,
    ``network.connect:evil-c2.example``, ``process.exec``, ``credential.access``.
    """
    tokens: set[str] = set()
    for e in events:
        et = e.get("event_type")
        if not et or et in _NON_CAPABILITY_TYPES:
            continue
        if et in _FS_TYPES:
            tokens.add(f"{et}:sensitive" if e.get("sensitive") else et)
        elif et in _NETWORK_TYPES:
            domain = _domain_of(e.get("resource"))
            tokens.add(f"{et}:{domain}" if domain else et)
        elif et in _PROCESS_TYPES:
            tokens.add(et)
        elif et in _SECRET_TYPES:
            tokens.add(et)
        else:
            tokens.add(et)
    return tokens


def fingerprint_id(tokens: set[str]) -> str:
    """Short, stable id for a token set — order-independent."""
    digest = hashlib.sha256("|".join(sorted(tokens)).encode("utf-8")).hexdigest()
    return f"FP-{digest[:10]}"


def compact_label(tokens: set[str]) -> str:
    """Doc-style compact label, e.g. ``F2-N1-P1-S1-T0``."""
    f = sum(1 for t in tokens if t.split(":")[0] in _FS_TYPES)
    n = sum(1 for t in tokens if t.split(":")[0] in _NETWORK_TYPES)
    p = sum(1 for t in tokens if t.split(":")[0] in _PROCESS_TYPES)
    s = sum(1 for t in tokens if t.split(":")[0] in _SECRET_TYPES)
    return f"F{f}-N{n}-P{p}-S{s}"


@dataclass
class FingerprintResult:
    tokens: set[str]
    fingerprint_id: str
    label: str
    baseline_exists: bool
    added: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


def _history_path(runs_dir: Path) -> Path:
    return runs_dir / "fingerprints.json"


def record_and_diff(runs_dir: Path, *, invocation_number: int, session_id: str, events_path: Path) -> FingerprintResult:
    """Compute this run's fingerprint, diff it against the most recent prior
    entry (if any), append it to the lab's fingerprint history, and return
    the result. Pure observed-behavior comparison — independent of whether
    the manifest declared a version bump.
    """
    events = list(read_jsonl(events_path))
    tokens = capability_tokens(events)
    fid = fingerprint_id(tokens)
    label = compact_label(tokens)

    history_path = _history_path(runs_dir)
    history: list[dict] = []
    if history_path.exists():
        try:
            history = json.loads(history_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            history = []

    baseline = history[-1] if history else None
    if baseline is not None:
        prev_tokens = set(baseline.get("tokens", []))
        added = tokens - prev_tokens
        removed = prev_tokens - tokens
    else:
        added = set()
        removed = set()

    history.append(
        {
            "invocation": invocation_number,
            "session_id": session_id,
            "fingerprint_id": fid,
            "label": label,
            "tokens": sorted(tokens),
        }
    )
    runs_dir.mkdir(parents=True, exist_ok=True)
    history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")

    return FingerprintResult(
        tokens=tokens,
        fingerprint_id=fid,
        label=label,
        baseline_exists=baseline is not None,
        added=added,
        removed=removed,
    )
