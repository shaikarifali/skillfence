"""Unit tests for the auditd log parser. Fixture lines are hand-built
against the documented, decade-stable auditd record format (`man
ausearch`) — this sandbox has no kernel audit subsystem to capture a real
feed from (no systemd, WSL2), which is disclosed in the module docstring.
"""

from __future__ import annotations

from skillfence.telemetry.auditd import parse_audit_log

EXECVE_GROUP = """\
type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=1000 pid=1234 auid=1000 uid=1000 gid=1000 comm="curl" exe="/usr/bin/curl" key="skillfence"
type=EXECVE msg=audit(1700000000.123:456): argc=3 a0="curl" a1="-s" a2="https://exfil.test/collect"
type=CWD msg=audit(1700000000.123:456): cwd="/home/user"
type=PATH msg=audit(1700000000.123:456): item=0 name="/usr/bin/curl" inode=100 dev=08:01 mode=0100755
type=PROCTITLE msg=audit(1700000000.123:456): proctitle=6375726C
"""

OPENAT_GROUP = """\
type=SYSCALL msg=audit(1700000001.456:457): arch=c000003e syscall=257 success=yes exit=3 items=1 ppid=1000 pid=1234 comm="cat" exe="/usr/bin/cat" key="skillfence"
type=PATH msg=audit(1700000001.456:457): item=0 name="/home/user/.aws/credentials" inode=200 dev=08:01 mode=0100600
"""

CONNECT_GROUP = """\
type=SYSCALL msg=audit(1700000002.789:458): arch=c000003e syscall=42 success=yes exit=0 items=0 ppid=1 pid=9999 comm="nc" exe="/usr/bin/nc"
"""

UNRECOGNIZED_SYSCALL_GROUP = """\
type=SYSCALL msg=audit(1700000003.000:459): arch=c000003e syscall=0 success=yes exit=4 items=0 ppid=1000 pid=1234 comm="cat" exe="/usr/bin/cat"
"""

FAILED_OPEN_GROUP = """\
type=SYSCALL msg=audit(1700000004.000:460): arch=c000003e syscall=257 success=no exit=-13 items=1 ppid=1000 pid=1234 comm="cat" exe="/usr/bin/cat"
type=PATH msg=audit(1700000004.000:460): item=0 name="/root/.bashrc" inode=300 dev=08:01 mode=0100644
"""


def test_execve_group_parsed_as_process_exec():
    events = parse_audit_log(EXECVE_GROUP)
    assert len(events) == 1
    e = events[0]
    assert e.kind == "process_exec"
    assert e.audit_id == "456"
    assert e.timestamp == 1700000000.123
    assert e.pid == 1234
    assert e.ppid == 1000
    assert e.comm == "curl"
    assert e.exe == "/usr/bin/curl"
    assert e.key == "skillfence"
    assert e.argv == ["curl", "-s", "https://exfil.test/collect"]
    assert e.success is True


def test_openat_group_parsed_as_file_open():
    events = parse_audit_log(OPENAT_GROUP)
    assert len(events) == 1
    e = events[0]
    assert e.kind == "file_open"
    assert e.paths == ["/home/user/.aws/credentials"]
    assert e.pid == 1234


def test_connect_group_parsed_as_network_connect():
    events = parse_audit_log(CONNECT_GROUP)
    assert len(events) == 1
    assert events[0].kind == "network_connect"
    assert events[0].pid == 9999


def test_unrecognized_syscall_kept_as_other_not_dropped():
    events = parse_audit_log(UNRECOGNIZED_SYSCALL_GROUP)
    assert len(events) == 1
    assert events[0].kind == "other"


def test_failed_syscall_success_flag_is_false():
    events = parse_audit_log(FAILED_OPEN_GROUP)
    assert events[0].success is False


def test_multiple_groups_in_one_log_all_parsed():
    combined = EXECVE_GROUP + OPENAT_GROUP + CONNECT_GROUP
    events = parse_audit_log(combined)
    assert len(events) == 3
    assert {e.audit_id for e in events} == {"456", "457", "458"}


def test_malformed_lines_are_skipped_not_raised():
    garbage = "this is not an audit log line at all\n\n   \nneither is this=one\n"
    assert parse_audit_log(garbage) == []


def test_syscall_only_group_with_no_path_records_has_empty_paths():
    events = parse_audit_log(CONNECT_GROUP)
    assert events[0].paths == []


def test_group_without_any_syscall_record_is_dropped():
    orphan_path = 'type=PATH msg=audit(1700000005.000:461): item=0 name="/tmp/x" inode=1 dev=08:01 mode=0100644\n'
    assert parse_audit_log(orphan_path) == []
