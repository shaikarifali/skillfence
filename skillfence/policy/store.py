"""Persistent scoped policy grants — "Decision Memory Without Blind
Automation".

An `ALLOW_SCOPED` human decision creates a narrowly-scoped, expiring grant
tied to the exact (skill, action, resource) — never a blanket "always trust
this skill." Grants are org-wide, not tied to any one lab directory (they
key purely on skill name + action + resource), and are consulted on every
subsequent `skillfence run`/`observe`/`protect` of any lab, so a human's — or
a security team's, via `skillfence policy allow` — earlier authorization
genuinely isn't re-asked for the same action, without silently promoting it
to "always allow."
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from skillfence.events.schema import new_id

GRANT_DEFAULT_TTL = timedelta(hours=2)

# Org-wide by default (not per-lab): override with SKILLFENCE_POLICY_STORE to
# point every `skillfence` invocation in an org at a shared location (e.g. a
# path on a mounted volume). Falls back to a project-local dotfile so labs
# stay fully offline/self-contained with no config required.
POLICY_STORE_ENV_VAR = "SKILLFENCE_POLICY_STORE"
DEFAULT_POLICY_STORE_PATH = Path(".skillfence/policy_grants.json")


def default_policy_store_path() -> Path:
    override = os.environ.get(POLICY_STORE_ENV_VAR)
    return Path(override) if override else DEFAULT_POLICY_STORE_PATH


@dataclass
class PolicyGrant:
    skill: str
    event_type: str
    resource: str
    decision: str
    granted_at: str
    expires_at: Optional[str]
    reason: str = ""
    grant_id: str = field(default_factory=lambda: new_id("grant"))

    def is_active(self, now: datetime) -> bool:
        if self.expires_at is None:
            return True
        return datetime.fromisoformat(self.expires_at) > now


class PolicyStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.grants: list[PolicyGrant] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.grants = [PolicyGrant(**g) for g in data.get("grants", [])]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"grants": [asdict(g) for g in self.grants]}, indent=2),
            encoding="utf-8",
        )

    def is_granted(self, *, skill: str, event_type: str, resource: str, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return any(
            g.skill == skill and g.event_type == event_type and g.resource == resource and g.is_active(now)
            for g in self.grants
        )

    def add_grant(
        self,
        *,
        skill: str,
        event_type: str,
        resource: str,
        decision: str,
        ttl: Optional[timedelta] = GRANT_DEFAULT_TTL,
        reason: str = "",
    ) -> PolicyGrant:
        now = datetime.now(timezone.utc)
        expires = (now + ttl).isoformat() if ttl else None
        grant = PolicyGrant(
            skill=skill,
            event_type=event_type,
            resource=resource,
            decision=decision,
            granted_at=now.isoformat(),
            expires_at=expires,
            reason=reason,
        )
        self.grants.append(grant)
        self.save()
        return grant

    def revoke(self, grant_id: str) -> bool:
        """Remove a grant by id. Returns False if no grant with that id
        exists (e.g. it already expired and was pruned, or the id was
        mistyped) so the caller can report that instead of silently no-op'ing.
        """
        before = len(self.grants)
        self.grants = [g for g in self.grants if g.grant_id != grant_id]
        found = len(self.grants) != before
        if found:
            self.save()
        return found
