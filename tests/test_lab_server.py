"""Unit tests for `LabMCPServer` (Live Mode's JSON-RPC dispatch) — direct
`tools/call` dicts through the dispatcher, no real network round-trip.
Confirms each of the six generic tools reaches the right gateway method,
that a blocked action becomes an `isError` tool result (not a crashed
session), and that the top-level JSON-RPC framing (notifications get no
response, unknown methods get a real JSON-RPC error) is correct.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skillfence.mcp.lab_server import TOOLS, LabMCPServer


def _build_lab(tmp_path: Path) -> Path:
    lab_dir = tmp_path / "demo-lab"
    (lab_dir / "skill").mkdir(parents=True)
    (lab_dir / "sandbox" / "logs").mkdir(parents=True)
    (lab_dir / "sandbox" / "logs" / "app.log").write_text("hello from the sandbox", encoding="utf-8")

    (lab_dir / "skill" / "manifest.yaml").write_text(
        'name: demo-skill\nversion: "0.1"\npurpose: [demo purpose]\n'
        'capabilities:\n  filesystem:\n    read: ["${workspace}/logs/**"]\n'
        "  process:\n    execute: []\n  network:\n    enabled: false\n    domains: []\n"
        "  secrets:\n    access: false\n",
        encoding="utf-8",
    )
    (lab_dir / "skill" / "SKILL.md").write_text(
        "# demo-skill\n\nA demo skill for Live Mode dispatch tests.\n", encoding="utf-8"
    )
    return lab_dir


def _server(tmp_path: Path) -> LabMCPServer:
    lab_dir = _build_lab(tmp_path)
    return LabMCPServer(lab_dir, decision="reject")


def test_initialize_surfaces_skill_md_as_instructions(tmp_path: Path):
    server = _server(tmp_path)
    result = server.handle_initialize({"protocolVersion": "2025-06-18"})
    assert result["protocolVersion"] == "2025-06-18"
    assert "Live Mode dispatch tests" in result["instructions"]
    assert result["serverInfo"]["name"] == "dvas-live-demo-skill"


def test_initialize_falls_back_to_a_default_protocol_version_if_none_sent(tmp_path: Path):
    server = _server(tmp_path)
    result = server.handle_initialize({})
    assert result["protocolVersion"]  # non-empty, doesn't crash


def test_tools_list_returns_the_six_generic_tools(tmp_path: Path):
    server = _server(tmp_path)
    result = server.handle_tools_list({})
    names = {t["name"] for t in result["tools"]}
    assert names == {"read_file", "write_file", "execute_shell", "fetch_url", "network_send", "read_secret"}
    assert result["tools"] == TOOLS


def test_tools_call_read_file_within_declared_scope_succeeds(tmp_path: Path):
    server = _server(tmp_path)
    result = server.handle_tools_call({"name": "read_file", "arguments": {"path": "./logs/app.log"}})
    assert result["isError"] is False
    assert result["content"][0]["text"] == "hello from the sandbox"


def test_tools_call_sensitive_read_outside_scope_is_blocked_not_a_crash(tmp_path: Path):
    server = _server(tmp_path)
    result = server.handle_tools_call({"name": "read_file", "arguments": {"path": "~/.aws/credentials"}})
    assert result["isError"] is True
    assert "BLOCKED by SkillFence" in result["content"][0]["text"]
    assert "AST01" in result["content"][0]["text"] or "AST03" in result["content"][0]["text"]


def test_tools_call_write_file_reaches_the_gateway(tmp_path: Path):
    server = _server(tmp_path)
    result = server.handle_tools_call(
        {"name": "write_file", "arguments": {"path": "./logs/new.txt", "content": "written live"}}
    )
    assert result["isError"] is False
    written = (server.lab_dir / "sandbox" / "logs" / "new.txt").read_text(encoding="utf-8")
    assert written == "written live"


def test_tools_call_unknown_tool_name_is_an_error_result_not_an_exception(tmp_path: Path):
    server = _server(tmp_path)
    result = server.handle_tools_call({"name": "not_a_real_tool", "arguments": {}})
    assert result["isError"] is True
    assert "Unknown tool" in result["content"][0]["text"]


def test_handle_message_initialize_wraps_result_in_jsonrpc_envelope(tmp_path: Path):
    server = _server(tmp_path)
    response = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    assert "protocolVersion" in response["result"]


def test_handle_message_notification_gets_no_response(tmp_path: Path):
    server = _server(tmp_path)
    response = server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert response is None


def test_handle_message_unknown_method_returns_jsonrpc_error(tmp_path: Path):
    server = _server(tmp_path)
    response = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "nonexistent/method"})
    assert response["error"]["code"] == -32601


def test_handle_message_unknown_notification_method_gets_no_response(tmp_path: Path):
    server = _server(tmp_path)
    # a notification (no "id") to an unrecognized method must still not get
    # a response -- the JSON-RPC spec forbids responding to notifications
    # regardless of whether the method exists
    response = server.handle_message({"jsonrpc": "2.0", "method": "nonexistent/notification"})
    assert response is None
