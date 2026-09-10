"""Skill Security Profile (`skillfence profile`).

Everything below already exists somewhere in SkillFence's output —
`inspect` shows declared capabilities, the fingerprint history
(`skillfence/fingerprint/behavior.py`) shows observed behavior drift
across runs, `findings.jsonl` shows the finding history. This module is
deliberately not a new detector: it's a consolidated, single view over
data that already exists, because "what does this skill actually do,
compared to what it claims, and what's its track record" is a question a
human keeps having to reassemble from three separate commands otherwise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from skillfence.policy.manifest import CapabilityManifest
from skillfence.storage.jsonl_store import read_jsonl

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class SkillProfile:
    skill: str
    version: str
    purpose: list[str]
    declared_fs_read: list[str]
    declared_fs_write: list[str]
    declared_process: list[str]
    declared_network: str
    declared_secrets: bool
    run_count: int
    latest_tokens: list[str]
    drift_added: list[str]
    drift_removed: list[str]
    finding_counts: dict[str, int]
    latest_finding_title: str | None
    latest_finding_severity: str | None
    status: str
    status_reason: str

    def to_dict(self) -> dict:
        return {
            "skill": self.skill,
            "version": self.version,
            "purpose": self.purpose,
            "declared": {
                "filesystem.read": self.declared_fs_read,
                "filesystem.write": self.declared_fs_write,
                "process.execute": self.declared_process,
                "network": self.declared_network,
                "secrets.access": self.declared_secrets,
            },
            "observed": {
                "run_count": self.run_count,
                "latest_tokens": self.latest_tokens,
                "drift_added": self.drift_added,
                "drift_removed": self.drift_removed,
            },
            "history": {
                "finding_counts": self.finding_counts,
                "latest_finding_title": self.latest_finding_title,
                "latest_finding_severity": self.latest_finding_severity,
            },
            "status": self.status,
            "status_reason": self.status_reason,
        }

    def to_text(self) -> str:
        lines = [
            f"SKILL SECURITY PROFILE — {self.skill}",
            f"Version: {self.version}",
            "",
            "Declared",
            f"  filesystem.read:  {self.declared_fs_read or '[]'}",
            f"  filesystem.write: {self.declared_fs_write or '[]'}",
            f"  process.execute:  {self.declared_process or '[]'}",
            f"  network:          {self.declared_network}",
            f"  secrets.access:   {self.declared_secrets}",
            "",
        ]
        if self.run_count == 0:
            lines.append("Observed")
            lines.append("  no runs recorded yet — this is the declared side only")
        else:
            lines.append(f"Observed (most recent of {self.run_count} run(s))")
            lines.append(f"  tokens: {sorted(self.latest_tokens) or '[]'}")
            lines.append("")
            lines.append("Behavior drift (vs the previous invocation)")
            if not self.drift_added and not self.drift_removed:
                lines.append("  NONE")
            else:
                lines += [f"  + {t}" for t in sorted(self.drift_added)]
                lines += [f"  - {t}" for t in sorted(self.drift_removed)]
        lines.append("")
        lines.append("History")
        total_findings = sum(self.finding_counts.values())
        if total_findings == 0:
            lines.append("  0 findings recorded")
        else:
            breakdown = ", ".join(f"{n} {sev}" for sev, n in self.finding_counts.items() if n)
            lines.append(f"  {total_findings} finding(s): {breakdown}")
            lines.append(f"  most recent: {self.latest_finding_title} ({self.latest_finding_severity})")
        lines.append("")
        lines.append(f"Current status: {self.status}")
        lines.append(f"  {self.status_reason}")
        return "\n".join(lines)


def build_profile(lab_dir: Path) -> SkillProfile:
    lab_dir = lab_dir.resolve()
    manifest_path = lab_dir / "skill" / "manifest.yaml"
    manifest = CapabilityManifest.load(manifest_path)

    runs_dir = lab_dir / ".runs"
    fp_history_path = runs_dir / "fingerprints.json"
    history: list[dict] = []
    if fp_history_path.exists():
        try:
            history = json.loads(fp_history_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            history = []

    latest_tokens: list[str] = list(history[-1]["tokens"]) if history else []
    drift_added: list[str] = []
    drift_removed: list[str] = []
    if len(history) >= 2:
        prev_tokens = set(history[-2]["tokens"])
        curr_tokens = set(history[-1]["tokens"])
        drift_added = sorted(curr_tokens - prev_tokens)
        drift_removed = sorted(prev_tokens - curr_tokens)

    findings_path = runs_dir / "findings.jsonl"
    findings = list(read_jsonl(findings_path))
    finding_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = str(f.get("severity", "low")).lower()
        if sev in finding_counts:
            finding_counts[sev] += 1
    latest_finding = findings[-1] if findings else None

    if not history and not findings:
        status, reason = "NOT YET RUN", "declared-only — run or observe this skill to build a profile"
    elif finding_counts["critical"] > 0:
        status, reason = "CRITICAL HISTORY", f"{finding_counts['critical']} critical finding(s) on record — review before trusting further runs"
    elif finding_counts["high"] > 0:
        status, reason = "REVIEW REQUIRED", f"{finding_counts['high']} high-severity finding(s) on record"
    elif drift_added:
        status, reason = "REVIEW REQUIRED", f"behavior drifted since the previous run: {', '.join(drift_added)}"
    else:
        status, reason = "TRUSTED", "no undeclared or drifted behavior on record"

    network_declared = (
        f"enabled -> {manifest.capabilities.network.domains}" if manifest.capabilities.network.enabled else "disabled"
    )

    return SkillProfile(
        skill=manifest.name,
        version=manifest.version,
        purpose=manifest.purpose,
        declared_fs_read=manifest.capabilities.filesystem.read,
        declared_fs_write=manifest.capabilities.filesystem.write,
        declared_process=manifest.capabilities.process.execute,
        declared_network=network_declared,
        declared_secrets=manifest.capabilities.secrets.access,
        run_count=len(history),
        latest_tokens=latest_tokens,
        drift_added=drift_added,
        drift_removed=drift_removed,
        finding_counts=finding_counts,
        latest_finding_title=latest_finding.get("title") if latest_finding else None,
        latest_finding_severity=latest_finding.get("severity") if latest_finding else None,
        status=status,
        status_reason=reason,
    )
