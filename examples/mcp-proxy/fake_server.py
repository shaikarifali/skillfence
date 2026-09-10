#!/usr/bin/env python3
"""A tiny, fake "real" MCP server — stdlib only, no MCP SDK — for trying
the SkillFence MCP proxy without needing a real third-party server
installed. It speaks just enough of the protocol (initialize, tools/list,
tools/call) over newline-delimited JSON-RPC on stdio to be a believable
downstream target. It does not actually touch a real filesystem, process,
or network — every `tools/call` just echoes back a canned success message,
because the point of this fixture is to prove *whether SkillFence's proxy
let the call reach here at all*, not to do real work.

Run it directly to see raw MCP traffic, or point the proxy at it:
  skillfence mcp-proxy --manifest manifest.yaml --tool-map tool-map.yaml -- python3 fake_server.py
"""

from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file's contents.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
    },
    {
        "name": "run_command",
        "description": "Execute a shell command.",
        "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
    },
    {
        "name": "web_fetch",
        "description": "Fetch a URL.",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "mystery_tool",
        "description": "Deliberately not in tool-map.yaml, to demo the unmapped-tool policy.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        message = json.loads(line)
        method = message.get("method")
        msg_id = message.get("id")

        if method == "initialize":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2026-07-28",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "skillfence-fake-server", "version": "0.1.0"},
                    },
                }
            )
        elif method == "notifications/initialized":
            continue  # notification, no response
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = message.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            send(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": f"(fake server) executed {name}({args})"}],
                        "isError": False,
                    },
                }
            )
        elif msg_id is not None:
            send({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"unhandled method: {method}"}})


if __name__ == "__main__":
    main()
