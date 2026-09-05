"""Security report (`skillfence report`).

Rolls up a lab's recorded findings.jsonl (+ its most recent run's raw event
count, for the "N runtime events" evidence line) into a report shape:
skill, overall risk, AST categories, numbered findings, attack chain,
decision, human decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from skillfence.risk.engine import cds_band as _cds_band
from skillfence.storage.jsonl_store import read_jsonl

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class SecurityReport:
    lab: str
    skill: str | None
    risk: str
    cds: float
    cds_band: str
    ast: list[str]
    findings: list[dict]
    attack_chains: list[list[str]]
    decision: str
    human_decisions: list[str]
    evidence_event_count: int

    def to_dict(self) -> dict:
        return {
            "lab": self.lab,
            "skill": self.skill,
            "risk": self.risk,
            "cds": self.cds,
            "cds_band": self.cds_band,
            "ast": self.ast,
            "findings": [
                {
                    "id": f.get("finding_id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "cds": f.get("cds"),
                    "cds_band": f.get("cds_band"),
                    "status": f.get("status"),
                }
                for f in self.findings
            ],
            "attack_chains": self.attack_chains,
            "decision": self.decision,
            "human_decisions": self.human_decisions,
            "evidence_event_count": self.evidence_event_count,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# DVAS Security Assessment — {self.lab}",
            "",
            f"**Skill:** {self.skill or '-'}  ",
            f"**Risk:** {self.risk.upper()}  ",
            f"**CDS:** {self.cds:.2f} ({self.cds_band})  ",
            f"**AST:** {', '.join(self.ast) if self.ast else '-'}  ",
            f"**Decision:** {self.decision}  ",
            f"**Evidence:** {self.evidence_event_count} runtime events",
            "",
            "## Findings",
            "",
        ]
        if not self.findings:
            lines.append("_No findings — every action stayed within declared capability / low risk._")
        for i, f in enumerate(self.findings, start=1):
            lines.append(f"**F-{i:03d}** {f.get('title')}  ")
            lines.append(f"- severity: {f.get('severity')}")
            lines.append(f"- status: {f.get('status')}")
            lines.append(f"- human decision: {f.get('human_decision') or 'pending'}")
            lines.append("")
        if self.attack_chains:
            lines.append("## Attack chains")
            lines.append("")
            for chain in self.attack_chains:
                lines.append("```")
                lines.append("\n      |\n      v\n".join(chain))
                lines.append("```")
                lines.append("")
        return "\n".join(lines)

    def to_text(self) -> str:
        lines = [
            "DVAS Security Assessment",
            "",
            f"Skill:\n  {self.skill or '-'}",
            "",
            f"Risk:\n  {self.risk.upper()}",
            "",
            f"CDS:\n  {self.cds:.2f} ({self.cds_band})",
            "",
            f"AST:\n  " + "\n  ".join(self.ast or ["-"]),
            "",
            "Findings:",
            "",
        ]
        if not self.findings:
            lines.append("  (none — every action stayed within declared capability / low risk)")
        for i, f in enumerate(self.findings, start=1):
            lines.append(f"F-{i:03d}")
            lines.append(f"{f.get('title')}")
            lines.append("")
        if self.attack_chains:
            lines.append("Attack chain:")
            lines.append("")
            for chain in self.attack_chains:
                lines.append("\n      |\n      v\n".join(chain))
                lines.append("")
        lines.append(f"Decision:\n  {self.decision}")
        lines.append("")
        lines.append(f"Human:\n  " + (", ".join(self.human_decisions) if self.human_decisions else "n/a"))
        lines.append("")
        lines.append(f"Evidence:\n  {self.evidence_event_count} runtime events")
        return "\n".join(lines)


def build_report(lab_dir: Path) -> SecurityReport:
    lab_dir = lab_dir.resolve()
    runs_dir = lab_dir / ".runs"
    findings_path = runs_dir / "findings.jsonl"
    findings = list(read_jsonl(findings_path))

    ast: list[str] = sorted({tag for f in findings for tag in f.get("ast", [])})
    risk = "low"
    for f in findings:
        sev = str(f.get("severity", "low")).lower()
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(risk, 0):
            risk = sev
    cds = max((float(f.get("cds", 0.0)) for f in findings), default=0.0)

    attack_chains = [f["attack_chain"] for f in findings if f.get("attack_chain")]
    human_decisions = [f["human_decision"] for f in findings if f.get("human_decision")]
    decision = "BLOCKED" if any(f.get("status") == "blocked" for f in findings) else (
        "ALLOWED" if findings else "ALLOWED (no findings)"
    )

    event_count = 0
    for events_file in runs_dir.glob("*.events.jsonl"):
        event_count += sum(1 for _ in read_jsonl(events_file))

    skill = findings[0].get("skill") if findings else None

    return SecurityReport(
        lab=lab_dir.name,
        skill=skill,
        risk=risk,
        cds=cds,
        cds_band=_cds_band(cds),
        ast=ast,
        findings=findings,
        attack_chains=attack_chains,
        decision=decision,
        human_decisions=human_decisions,
        evidence_event_count=event_count,
    )
