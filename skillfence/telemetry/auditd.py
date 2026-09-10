"""Parser for Linux `auditd` log records — the OS-level telemetry source
this project deliberately builds *on top of* rather than reimplementing.

Why auditd, not a bespoke eBPF program: SkillFence's whole value is Layer A
(the agent-tool boundary) — declared-vs-observed capability diffing,
deterministic scoring, a human gate. That has no existing equivalent.
Syscall-level tracing does: Falco, Tetragon, osquery, and auditd itself
already do it far better than a from-scratch effort would, and are
already deployed on plenty of hosts running agents. The differentiated,
actually-useful piece is *attribution* — pairing an OS-level event back to
the specific SkillFence session/skill that produced it — not another
syscall monitor. This module reads what auditd already wrote;
`skillfence.telemetry.correlate` does the attribution.

The auditd log format is standardized and has been stable for well over a
decade (`man ausearch`, `man audit.rules`): one line per record, multiple
record types (SYSCALL, EXECVE, PATH, CWD, ...) sharing one audit id --
the `:NNN)` suffix inside `msg=audit(<epoch>.<msec>:<id>):` -- which is
how several lines reconstruct one real event.

Honesty note: this parser is built and tested against that documented
format, with realistic fixture lines, not against a live auditd feed --
the sandbox this was written in has no systemd and no kernel audit
subsystem available (WSL2), so there was nothing live to verify against.
If you hit a real-world auditd log this doesn't parse correctly, that's
useful signal — please open an issue with a redacted sample line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_MSG_HEADER = re.compile(r"type=(?P<type>\S+)\s+msg=audit\((?P<ts>[\d.]+):(?P<aid>\d+)\):\s*(?P<rest>.*)")
_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

# x86_64 syscall numbers only -- ARM64/other architectures use a different
# table entirely. A syscall not in this map is kept as kind="other" rather
# than dropped, so it's still visible, just unclassified.
_SYSCALL_KIND = {
    59: "process_exec",  # execve
    322: "process_exec",  # execveat
    2: "file_open",  # open
    257: "file_open",  # openat
    42: "network_connect",  # connect
}


@dataclass
class AuditEvent:
    audit_id: str
    timestamp: float
    kind: str  # "process_exec" | "file_open" | "network_connect" | "other"
    pid: int | None = None
    ppid: int | None = None
    comm: str | None = None
    exe: str | None = None
    paths: list[str] = field(default_factory=list)
    argv: list[str] | None = None
    success: bool | None = None
    key: str | None = None  # the `-k` tag on the audit rule that produced this, if any


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _parse_kv(rest: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for m in _KV.finditer(rest):
        key, val = m.group(1), m.group(2)
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            val = val[1:-1]
        fields[key] = val
    return fields


def parse_audit_log(text: str) -> list[AuditEvent]:
    """Parses raw auditd log text (as read from `/var/log/audit/audit.log`,
    or the output of `ausearch --format raw`/`-i` without interpretation)
    into one `AuditEvent` per syscall — records sharing an audit id are
    merged into a single event. Unrecognized or malformed lines are
    skipped, not raised on; a partial/truncated log (e.g. a live-tailed
    window) should degrade gracefully, not crash the correlator.
    """
    groups: dict[str, dict[str, list[dict[str, str]]]] = {}
    timestamps: dict[str, float] = {}
    order: list[str] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _MSG_HEADER.match(line)
        if not m:
            continue
        rtype, aid = m.group("type"), m.group("aid")
        try:
            ts = float(m.group("ts"))
        except ValueError:
            continue
        fields = _parse_kv(m.group("rest"))
        if aid not in groups:
            groups[aid] = {}
            order.append(aid)
        timestamps[aid] = ts
        groups[aid].setdefault(rtype, []).append(fields)

    events: list[AuditEvent] = []
    for aid in order:
        rec = groups[aid]
        syscall_records = rec.get("SYSCALL")
        if not syscall_records:
            continue  # no SYSCALL record -- nothing to classify this group as
        syscall_fields = syscall_records[0]

        syscall_num = _to_int(syscall_fields.get("syscall"))
        kind = _SYSCALL_KIND.get(syscall_num, "other") if syscall_num is not None else "other"

        paths = [p["name"] for p in rec.get("PATH", []) if p.get("name")]

        argv: list[str] | None = None
        execve_records = rec.get("EXECVE")
        if execve_records:
            execve_fields = execve_records[0]
            argc = _to_int(execve_fields.get("argc")) or 0
            argv = [execve_fields[f"a{i}"] for i in range(argc) if f"a{i}" in execve_fields]

        events.append(
            AuditEvent(
                audit_id=aid,
                timestamp=timestamps[aid],
                kind=kind,
                pid=_to_int(syscall_fields.get("pid")),
                ppid=_to_int(syscall_fields.get("ppid")),
                comm=syscall_fields.get("comm"),
                exe=syscall_fields.get("exe"),
                paths=paths,
                argv=argv,
                success=(syscall_fields.get("success") == "yes") if "success" in syscall_fields else None,
                key=syscall_fields.get("key"),
            )
        )
    return events
