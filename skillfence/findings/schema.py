"""Finding schema — built for explainability.

Every finding must be reconstructable into these fields:
TITLE, AST CATEGORY, RISK, SKILL, ACTION, RESOURCE, DECLARED CAPABILITY,
OBSERVED CAPABILITY, WHY FLAGGED, ATTACK CHAIN, RAW EVENTS, HUMAN DECISION.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from skillfence.events.schema import new_id


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: new_id("finding"))
    title: str
    ast: list[str]
    severity: str
    cds: float = 0.0
    cds_band: str = "ALLOW"
    confidence: str
    skill: str
    action: str
    resource: str | None
    declared_capability: str
    observed_capability: str
    why_flagged: list[str]
    attack_chain: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    provenance_root: str | None = None
    human_gate: bool = True
    status: str = "pending"
    human_decision: str | None = None

    def explain(self) -> str:
        lines = [
            f"TITLE: {self.title}",
            f"AST CATEGORY: {', '.join(self.ast)}",
            f"RISK: {self.severity.upper()}",
            f"CDS: {self.cds:.2f} ({self.cds_band})",
            f"SKILL: {self.skill}",
            f"ACTION: {self.action}",
            f"RESOURCE: {self.resource or '-'}",
            f"DECLARED CAPABILITY: {self.declared_capability}",
            f"OBSERVED CAPABILITY: {self.observed_capability}",
            "WHY FLAGGED:",
            *[f"  - {r}" for r in self.why_flagged],
        ]
        if self.attack_chain:
            lines.append(f"ATTACK CHAIN: {' -> '.join(self.attack_chain)}")
        lines.append(f"RAW EVENTS: {', '.join(self.evidence)}")
        lines.append(f"HUMAN DECISION: {self.human_decision or 'pending'}")
        return "\n".join(lines)
