"""Newline-delimited JSON-RPC framing over stdio — the MCP spec's stdio
transport (modelcontextprotocol.io/specification, "basic/transports"):
one complete JSON-RPC message per line, no embedded newlines. This module
only frames messages; it has no opinion about what's inside them.
"""

from __future__ import annotations

import json
import sys
from typing import Any, BinaryIO


def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    """Read one newline-delimited JSON-RPC message. Returns None at EOF."""
    line = stream.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return read_message(stream)  # skip stray blank lines, keep reading
    return json.loads(line.decode("utf-8"))


def write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    """Write one JSON-RPC message as a single line and flush immediately —
    stdio transports are latency-sensitive; nothing here should buffer.
    """
    stream.write((json.dumps(message) + "\n").encode("utf-8"))
    stream.flush()


def jsonrpc_error(request_id: Any, *, code: int, message: str, data: dict | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def jsonrpc_tool_result(request_id: Any, *, text: str, is_error: bool = False) -> dict[str, Any]:
    """A `tools/call` result carrying a single text content block — the
    shape SkillFence uses to tell the calling agent *why* a call was
    blocked, in-band, the same way a real tool failure would be reported
    (rather than a bare JSON-RPC error, which some clients surface less
    legibly to the model).
    """
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": is_error},
    }


# JSON-RPC reserved error codes (spec range for server errors: -32000..-32099)
BLOCKED_BY_POLICY = -32001


def stderr(message: str) -> None:
    """MCP stdio servers MUST NOT write anything but valid MCP messages to
    stdout — stderr is the only safe place for SkillFence's own logging
    while proxying.
    """
    print(f"[skillfence mcp-proxy] {message}", file=sys.stderr, flush=True)
