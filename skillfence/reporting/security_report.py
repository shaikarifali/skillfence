"""Security report (`skillfence report`).

Rolls up a lab's recorded findings.jsonl (+ its most recent run's raw event
count, for the "N runtime events" evidence line) into a report shape:
skill, overall risk, AST categories, numbered findings, attack chain,
decision, human decision.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

    def to_sarif(self) -> dict:
        """SARIF 2.1.0, for `github/codeql-action/upload-sarif` — lets a
        repo gate PRs on `skillfence bench`/`report` the same way it
        already gates on any other code-scanning tool, no bespoke
        SkillFence-specific CI step required on the consuming side.
        """
        _SEVERITY_TO_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        rule_ids = sorted({tag for f in self.findings for tag in f.get("ast", [])}) or ["SKILLFENCE"]
        rules = [
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"OWASP Agentic Skills Top 10 — {rule_id}"},
                "helpUri": "https://owasp.org/www-project-agentic-skills-top-10/",
            }
            for rule_id in rule_ids
        ]
        results = []
        for f in self.findings:
            ast_tags = f.get("ast") or ["SKILLFENCE"]
            severity = str(f.get("severity", "low")).lower()
            message = f.get("title", "SkillFence finding")
            why = f.get("why_flagged") or []
            if why:
                message += " — " + "; ".join(why)
            results.append(
                {
                    "ruleId": ast_tags[0],
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),
                    "message": {"text": message},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": self.lab}, "region": {"startLine": 1}}}
                    ],
                    "properties": {
                        "ast": ast_tags,
                        "cds": f.get("cds"),
                        "cdsBand": f.get("cds_band"),
                        "status": f.get("status"),
                        "humanDecision": f.get("human_decision"),
                    },
                }
            )
        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SkillFence",
                            "informationUri": "https://github.com/shaikarifali/skillfence",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    def to_html(self) -> str:
        """A single, self-contained HTML file — no external assets, no
        server, nothing to stand up. Something you can email a reviewer or
        drop in a PR comment, not a dashboard. All dynamic content (titles,
        resource paths, why-flagged text) is escaped: findings ultimately
        trace back to something a skill or a fetched document "said," which
        in a real deployment (the MCP proxy) is attacker-reachable text a
        report generator has no business trusting.
        """
        e = html.escape
        severity_color = {
            "critical": "#b3261e",
            "high": "#a15a16",
            "medium": "#7a6a16",
            "low": "#2e7d4f",
        }
        risk_color = severity_color.get(self.risk, "#2e7d4f")

        findings_html = ""
        if not self.findings:
            findings_html = '<p class="muted">No findings — every action stayed within declared capability / low risk.</p>'
        for i, f in enumerate(self.findings, start=1):
            sev = str(f.get("severity", "low")).lower()
            color = severity_color.get(sev, "#2e7d4f")
            why = f.get("why_flagged") or []
            why_html = "".join(f"<li>{e(str(w))}</li>" for w in why)
            chain = f.get("attack_chain") or []
            chain_html = ""
            if chain:
                chain_html = f'<div class="chain">{" &rarr; ".join(e(str(c)) for c in chain)}</div>'
            ast_tags = "".join(f'<span class="pill">{e(t)}</span>' for t in (f.get("ast") or []))
            findings_html += f"""
            <div class="finding" style="border-left-color:{color}">
              <div class="finding-head">
                <span class="badge" style="background:{color}">{e(sev.upper())}</span>
                <strong>F-{i:03d} — {e(str(f.get('title', '')))}</strong>
              </div>
              <div class="finding-meta">{ast_tags}</div>
              <div class="finding-row"><span class="label">Action:</span> {e(str(f.get('action', '-')))}</div>
              <div class="finding-row"><span class="label">Resource:</span> {e(str(f.get('resource', '-')))}</div>
              <div class="finding-row"><span class="label">Status:</span> {e(str(f.get('status', '-')))}</div>
              <div class="finding-row"><span class="label">Human decision:</span> {e(str(f.get('human_decision') or 'pending'))}</div>
              {f'<div class="finding-row"><span class="label">Why flagged:</span><ul>{why_html}</ul></div>' if why else ''}
              {chain_html}
            </div>"""

        ast_pills = "".join(f'<span class="pill">{e(t)}</span>' for t in self.ast) or '<span class="muted">-</span>'
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SkillFence report — {e(self.lab)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; max-width: 860px; margin: 2.5rem auto; padding: 0 1.5rem;
          background: #fff; color: #16201d; }}
  @media (prefers-color-scheme: dark) {{ body {{ background: #101715; color: #e7ece7; }} }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.2rem; }}
  .subtitle {{ color: #6b7a72; margin-top: 0; }}
  .summary {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 1.5rem 0; padding: 1rem 1.25rem;
              border: 1px solid #d8ded9; border-radius: 8px; }}
  @media (prefers-color-scheme: dark) {{ .summary {{ border-color: #2b3733; }} }}
  .summary div {{ min-width: 120px; }}
  .summary .label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: #6b7a72; }}
  .summary .value {{ font-size: 1.1rem; font-weight: 600; }}
  .risk-badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 4px; color: #fff; font-weight: 700;
                 background: {risk_color}; }}
  .pill {{ display: inline-block; font-size: 0.75rem; padding: 0.1rem 0.5rem; margin: 0.1rem 0.2rem 0.1rem 0;
           border-radius: 10px; background: #e4e7e1; }}
  @media (prefers-color-scheme: dark) {{ .pill {{ background: #1f2b28; }} }}
  .finding {{ border-left: 4px solid; padding: 0.75rem 1rem; margin: 1rem 0; background: #f6f7f5; border-radius: 0 6px 6px 0; }}
  @media (prefers-color-scheme: dark) {{ .finding {{ background: #182220; }} }}
  .finding-head {{ display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.4rem; }}
  .badge {{ color: #fff; font-size: 0.7rem; font-weight: 700; padding: 0.1rem 0.5rem; border-radius: 4px; }}
  .finding-row {{ font-size: 0.9rem; margin: 0.2rem 0; }}
  .finding-row .label {{ color: #6b7a72; margin-right: 0.3rem; }}
  .chain {{ font-family: monospace; font-size: 0.8rem; margin-top: 0.4rem; padding: 0.4rem 0.6rem;
            background: rgba(0,0,0,0.05); border-radius: 4px; }}
  @media (prefers-color-scheme: dark) {{ .chain {{ background: rgba(255,255,255,0.06); }} }}
  .muted {{ color: #6b7a72; }}
  footer {{ margin-top: 2.5rem; padding-top: 1rem; border-top: 1px solid #d8ded9; font-size: 0.8rem; color: #6b7a72; }}
  @media (prefers-color-scheme: dark) {{ footer {{ border-color: #2b3733; }} }}
</style>
</head>
<body>
  <h1>SkillFence Security Report</h1>
  <p class="subtitle">{e(self.lab)}</p>

  <div class="summary">
    <div><div class="label">Skill</div><div class="value">{e(self.skill or '-')}</div></div>
    <div><div class="label">Risk</div><div class="value"><span class="risk-badge">{e(self.risk.upper())}</span></div></div>
    <div><div class="label">CDS</div><div class="value">{self.cds:.2f} ({e(self.cds_band)})</div></div>
    <div><div class="label">Decision</div><div class="value">{e(self.decision)}</div></div>
    <div><div class="label">Evidence</div><div class="value">{self.evidence_event_count} events</div></div>
  </div>

  <div>{ast_pills}</div>

  <h2>Findings</h2>
  {findings_html}

  <footer>
    Generated by <strong>SkillFence</strong> — github.com/shaikarifali/skillfence — {generated_at}<br>
    Deterministic, no LLM in the security-decision path. Sign this report with
    <code>skillfence audit sign</code> before sharing it if independent tamper-evidence matters.
  </footer>
</body>
</html>
"""

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
