"""Attributes OS-level `auditd` observations back to a SkillFence session —
the actual differentiated piece, not another syscall monitor (see
`skillfence.telemetry.auditd`'s module docstring for why).

Deliberately a *separate, lower-confidence* class of evidence from the
rest of the engine, not fed through `RiskEngine`/`HumanGate` as if it were
equally certain: matching is name/suffix-based (an audit-log real path
like `/home/user/.aws/credentials` against a tracked resource string like
`~/.aws/credentials`), not exact, because SkillFence's own event log
records the *requested* path string, not always its resolved absolute
form. A `TelemetryFinding` is a lead worth a human's attention, not a
deterministic verdict.

What this actually catches: a session whose SkillFence event log shows,
say, only filesystem reads, while auditd shows that same process (by pid)
also called `execve` — conclusive evidence of a Layer-A bypass (an agent
with real shell/code-exec access did something no instrumented tool
wrapper ever saw), independent of whether any individual path matches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from skillfence.telemetry.auditd import AuditEvent

_TRACKED_EVENT_TYPES = {
    "process_exec": {"process.exec"},
    "file_open": {"filesystem.read", "filesystem.write"},
}


@dataclass
class TelemetryFinding:
    audit_event: AuditEvent
    reason: str
    confidence: str  # "high" | "medium" -- never "certain": this is a heuristic layer


@dataclass
class TelemetryReport:
    matched: list[AuditEvent] = field(default_factory=list)
    untracked: list[TelemetryFinding] = field(default_factory=list)
    observed_network: list[AuditEvent] = field(default_factory=list)  # informational only, see module docstring

    @property
    def bypass_suspected(self) -> bool:
        return len(self.untracked) > 0


def _epoch(iso_timestamp: str) -> float:
    return datetime.fromisoformat(iso_timestamp).timestamp()


def _normalize_resource(resource: str) -> str:
    if resource.startswith("~/"):
        return resource[2:]
    if resource.startswith("./"):
        return resource[2:]
    return resource.lstrip("/")


def correlate(
    session_events: list[dict],
    audit_events: list[AuditEvent],
    *,
    pid: int | None = None,
) -> TelemetryReport:
    """`session_events` is a session's raw event rows (as read from its
    `*.events.jsonl` — the same shape `skillfence findings`/the dashboard
    already read). Restricts `audit_events` to the session's own time
    window automatically (derived from the events' own timestamps) and
    optionally to one `pid` (the real agent/proxy process being watched --
    pass it whenever you have it; without it, correlation is time-window
    only, which is weaker evidence).
    """
    timestamps = [_epoch(e["timestamp"]) for e in session_events if e.get("timestamp")]
    window = (min(timestamps), max(timestamps)) if timestamps else None

    tracked_exec_names: set[str] = set()
    tracked_path_suffixes: set[str] = set()
    for e in session_events:
        resource = e.get("resource")
        event_type = e.get("event_type")
        if not resource or not event_type:
            continue
        if event_type in _TRACKED_EVENT_TYPES["process_exec"]:
            tracked_exec_names.add(resource.split()[0])
        elif event_type in _TRACKED_EVENT_TYPES["file_open"]:
            tracked_path_suffixes.add(_normalize_resource(resource))

    report = TelemetryReport()
    for ae in audit_events:
        if pid is not None and ae.pid != pid:
            continue
        if window is not None and not (window[0] - 1 <= ae.timestamp <= window[1] + 1):
            continue  # +/-1s slack for clock/logging granularity, not a real tolerance for drift

        if ae.kind == "process_exec":
            candidate = ae.comm or (ae.exe.rsplit("/", 1)[-1] if ae.exe else None)
            if candidate and candidate in tracked_exec_names:
                report.matched.append(ae)
            else:
                report.untracked.append(
                    TelemetryFinding(
                        audit_event=ae,
                        reason=f"process executed at the OS level ({candidate or 'unknown'}) with no "
                        "matching process.exec event in this session's SkillFence log",
                        confidence="high",
                    )
                )
        elif ae.kind == "file_open":
            if any(any(path.endswith(suffix) for suffix in tracked_path_suffixes) for path in ae.paths):
                report.matched.append(ae)
            else:
                report.untracked.append(
                    TelemetryFinding(
                        audit_event=ae,
                        reason=f"file opened at the OS level ({', '.join(ae.paths) or 'unknown path'}) with "
                        "no matching filesystem event in this session's SkillFence log",
                        confidence="medium",  # path-suffix matching, not exact -- see module docstring
                    )
                )
        elif ae.kind == "network_connect":
            # `ae.remote_address` is decoded from the SOCKADDR record when
            # one was present (see auditd.parse_sockaddr) -- but it's still
            # reported as *observed*, not matched/unmatched: it's a raw
            # IP:port, and SkillFence's own network events record a
            # requested domain/URL string, not a resolved address. Matching
            # one against the other would need a DNS lookup this module
            # deliberately doesn't do (a live network dependency inside a
            # detector is exactly what this project's whole testing
            # philosophy avoids) -- so this stays informational, now with
            # the real destination visible instead of just "something
            # connected."
            report.observed_network.append(ae)

    return report
