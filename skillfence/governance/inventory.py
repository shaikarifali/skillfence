"""Fleet-wide governance inventory (AST09 — No Governance).

Every other AST category is about a single skill's runtime behavior.
AST09 is different: it's about a *fleet* — an org that installs many
skills has no answer to "which of these were ever actually reviewed, and
which still have a standing elevated grant nobody has looked at since."
That gap is real regardless of how good the per-skill detection is.

This module answers it read-only, from evidence that already exists on
disk: the same session/findings JSONL `skillfence dashboard` already
reads (`skillfence.dashboard.data.discover_sessions`), plus the org-wide
policy store (`skillfence.policy.store.PolicyStore`) — no new storage
format, no new source of truth.

Two signals, both purely evidentiary (this never blocks anything — an
inventory is a report, not an enforcement point):

  - **never reviewed**: a skill directory with a manifest but zero
    discovered sessions anywhere under the scanned root. Nobody has ever
    run `skillfence run`/`observe`/`protect` (or the MCP proxy) against
    it, so nothing is actually known about what it does at runtime.
  - **ungoverned grant**: an active (non-expired) policy grant for that
    skill whose `granted_at` is not backed by any session review at or
    after it was issued. A grant issued before the skill was ever
    reviewed, or with no review at all, is exactly the "approved once,
    forgotten forever" gap a human-in-the-loop system can otherwise hide
    behind -- the whole point of Decision Memory is to *not* re-ask for
    the same thing forever, but that only stays safe if someone can see
    which standing grants exist and when they were last actually vouched
    for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from skillfence.dashboard.data import discover_sessions
from skillfence.policy.manifest import CapabilityManifest
from skillfence.policy.store import PolicyStore, default_policy_store_path

_SEVERITY_RANK = {"none": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class SkillGovernanceRow:
    skill: str
    manifest_path: str
    ever_reviewed: bool
    session_count: int
    highest_severity: str
    active_grants: int
    ungoverned_grants: int
    flags: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.flags


def build_inventory(root: Path, *, policy_store: PolicyStore | None = None) -> list[SkillGovernanceRow]:
    """One row per `skill/manifest.yaml` found anywhere under `root`,
    fleet-governance flags attached. `policy_store` is injectable for
    tests; defaults to the real org-wide store every other `policy *`
    command reads.
    """
    root = root.resolve()
    store = policy_store if policy_store is not None else PolicyStore(default_policy_store_path())
    now = datetime.now(timezone.utc)
    sessions = discover_sessions(root)

    rows: list[SkillGovernanceRow] = []
    for manifest_path in sorted(root.rglob("skill/manifest.yaml")):
        try:
            manifest = CapabilityManifest.load(manifest_path)
        except Exception:
            continue  # unparseable manifest -- not this report's job to diagnose

        skill_sessions = [s for s in sessions if s.skill == manifest.name]
        highest = "none"
        for s in skill_sessions:
            if _SEVERITY_RANK.get(s.highest_severity, -1) > _SEVERITY_RANK.get(highest, -1):
                highest = s.highest_severity
        # Both `PolicyGrant.granted_at` and `SessionInfo.last_timestamp`
        # are `datetime.now(timezone.utc).isoformat()` strings -- identical
        # format, so lexicographic comparison orders them correctly
        # without parsing either back into a datetime.
        last_reviewed = max((s.last_timestamp for s in skill_sessions if s.last_timestamp), default=None)

        active_grants = [g for g in store.grants if g.skill == manifest.name and g.is_active(now)]
        ungoverned = sum(1 for g in active_grants if last_reviewed is None or g.granted_at > last_reviewed)

        flags: list[str] = []
        if not skill_sessions:
            flags.append("never reviewed")
        if ungoverned:
            flags.append(f"{ungoverned} ungoverned grant(s)")

        rows.append(
            SkillGovernanceRow(
                skill=manifest.name,
                manifest_path=str(manifest_path),
                ever_reviewed=bool(skill_sessions),
                session_count=len(skill_sessions),
                highest_severity=highest,
                active_grants=len(active_grants),
                ungoverned_grants=ungoverned,
                flags=flags,
            )
        )
    return rows
