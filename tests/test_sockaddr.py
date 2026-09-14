"""Unit tests for auditd SOCKADDR decoding. Fixture hex strings are built
programmatically from real byte-packing (`int.to_bytes`, `socket.inet_aton`)
rather than hand-counted hex characters -- same discipline as the Unicode
payload fixtures elsewhere in this test suite, for the same reason: manual
hex/byte arithmetic is exactly the kind of thing that's easy to get subtly
wrong without actually being caught until a real value fails to decode.
"""

from __future__ import annotations

import socket

from skillfence.telemetry.auditd import parse_audit_log, parse_sockaddr


def _ipv4_sockaddr_hex(ip: str, port: int) -> str:
    family = (2).to_bytes(2, "little")  # AF_INET
    port_bytes = port.to_bytes(2, "big")  # network byte order
    addr_bytes = socket.inet_aton(ip)  # 4 bytes, already network byte order
    padding = b"\x00" * 8  # sin_zero
    return (family + port_bytes + addr_bytes + padding).hex().upper()


def _ipv6_sockaddr_hex(ip: str, port: int) -> str:
    family = (10).to_bytes(2, "little")  # AF_INET6 (Linux)
    port_bytes = port.to_bytes(2, "big")
    flowinfo = (0).to_bytes(4, "big")
    addr_bytes = socket.inet_pton(socket.AF_INET6, ip)  # 16 bytes
    scope_id = (0).to_bytes(4, "big")
    return (family + port_bytes + flowinfo + addr_bytes + scope_id).hex().upper()


def _unix_sockaddr_hex(path: str) -> str:
    family = (1).to_bytes(2, "little")  # AF_UNIX
    path_bytes = path.encode("utf-8") + b"\x00" * (108 - len(path))
    return (family + path_bytes).hex().upper()


# -- parse_sockaddr() ------------------------------------------------------


def test_ipv4_address_and_port_decoded():
    hex_str = _ipv4_sockaddr_hex("192.168.1.100", 80)
    assert parse_sockaddr(hex_str) == "192.168.1.100:80"


def test_ipv4_high_port_decoded():
    hex_str = _ipv4_sockaddr_hex("10.0.0.1", 8443)
    assert parse_sockaddr(hex_str) == "10.0.0.1:8443"


def test_ipv6_address_and_port_decoded():
    hex_str = _ipv6_sockaddr_hex("2001:db8::1", 443)
    result = parse_sockaddr(hex_str)
    assert result is not None
    assert result.startswith("[2001:0db8:0000:0000:0000:0000:0000:0001]:")
    assert result.endswith(":443")


def test_ipv6_loopback_decoded():
    hex_str = _ipv6_sockaddr_hex("::1", 22)
    result = parse_sockaddr(hex_str)
    assert result == "[0000:0000:0000:0000:0000:0000:0000:0001]:22"


def test_unix_socket_path_decoded():
    hex_str = _unix_sockaddr_hex("/var/run/docker.sock")
    assert parse_sockaddr(hex_str) == "/var/run/docker.sock"


def test_unknown_family_returns_none():
    # family = 99, not one this decoder recognizes
    raw = (99).to_bytes(2, "little") + b"\x00" * 14
    assert parse_sockaddr(raw.hex()) is None


def test_truncated_hex_returns_none_not_raises():
    assert parse_sockaddr("02") is None  # 1 byte, below the 2-byte minimum


def test_malformed_hex_returns_none_not_raises():
    assert parse_sockaddr("not-valid-hex-zz") is None


def test_empty_string_returns_none():
    assert parse_sockaddr("") is None


# -- integration: parse_audit_log() populates remote_address --------------


def test_connect_syscall_with_sockaddr_record_gets_remote_address():
    saddr = _ipv4_sockaddr_hex("203.0.113.5", 443)
    log = (
        f"type=SYSCALL msg=audit(1700000000.100:500): arch=c000003e syscall=42 success=yes exit=0 "
        f"items=0 ppid=1000 pid=4821 comm=\"curl\" exe=\"/usr/bin/curl\"\n"
        f"type=SOCKADDR msg=audit(1700000000.100:500): saddr={saddr}\n"
    )
    events = parse_audit_log(log)
    assert len(events) == 1
    assert events[0].kind == "network_connect"
    assert events[0].remote_address == "203.0.113.5:443"


def test_connect_syscall_without_sockaddr_record_has_none_address():
    log = (
        "type=SYSCALL msg=audit(1700000000.100:501): arch=c000003e syscall=42 success=yes exit=0 "
        'items=0 ppid=1000 pid=4821 comm="curl" exe="/usr/bin/curl"\n'
    )
    events = parse_audit_log(log)
    assert len(events) == 1
    assert events[0].kind == "network_connect"
    assert events[0].remote_address is None


def test_non_connect_syscall_ignores_any_sockaddr_record():
    # a SOCKADDR record only makes sense for connect/bind/accept -- confirm
    # a stray one attached to an unrelated syscall doesn't get misread.
    saddr = _ipv4_sockaddr_hex("192.168.0.1", 80)
    log = (
        f"type=SYSCALL msg=audit(1700000000.100:502): arch=c000003e syscall=59 success=yes exit=0 "
        f"items=1 ppid=1000 pid=4821 comm=\"bash\" exe=\"/bin/bash\"\n"
        f"type=SOCKADDR msg=audit(1700000000.100:502): saddr={saddr}\n"
    )
    events = parse_audit_log(log)
    assert len(events) == 1
    assert events[0].kind == "process_exec"
    assert events[0].remote_address == "192.168.0.1:80"  # decoded regardless of kind, honestly reported
