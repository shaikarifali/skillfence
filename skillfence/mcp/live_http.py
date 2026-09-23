"""Live Mode's HTTP transport — a stdlib-only "Streamable HTTP" MCP server
(see modelcontextprotocol.io/specification, "Streamable HTTP"), bound to
127.0.0.1 only, same posture as `skillfence.labui.server`. A single
synchronous JSON response per POST is enough for everything this server
needs to do (no server-initiated notifications, no resumable streams), so
the GET/SSE half of the transport spec is intentionally not implemented —
verified directly against the real `mcp` SDK's client
(`mcp.client.streamable_http`), which fully supports a server that only
ever responds `Content-Type: application/json` and never opens a stream.

Deliberately foreground, own-terminal: unlike `skillfence mcp-proxy`
(stdio-spawned by the real client, so its stdin is consumed by the JSON-RPC
stream — it routes the human-gate prompt to stderr instead), this server
is started by a human in their own terminal and connected *to* over the
network. Its own stdin is never touched, so `HumanGate`'s existing
interactive prompt (`skillfence/hitl/cli_gate.py`) works completely
unchanged — the same real prompt `skillfence run` already shows.
"""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from rich.console import Console

from skillfence.mcp.lab_server import LabMCPServer

_SESSION_HEADER = "mcp-session-id"
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600


def _make_handler(lab_server: LabMCPServer, session_id: str, lock: threading.Lock) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # noqa: A002 - stdlib signature
            pass  # the CLI prints its own startup line; per-request noise stays quiet

        def _send_json(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(_SESSION_HEADER, session_id)
            self.end_headers()
            self.wfile.write(body)

        def _send_empty(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header(_SESSION_HEADER, session_id)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802 - stdlib method name
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                message = json.loads(raw.decode("utf-8")) if raw else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json(
                    {"jsonrpc": "2.0", "id": None, "error": {"code": _PARSE_ERROR, "message": "Parse error"}},
                    status=400,
                )
                return

            if not isinstance(message, dict):
                self._send_json(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": _INVALID_REQUEST, "message": "Invalid Request — batched requests are not supported"},
                    },
                    status=400,
                )
                return

            # Serializes every call into the one shared RuntimeGateway --
            # this server holds exactly one gateway for its whole lifetime
            # (session-sticky flags, provenance, correlation all depend on
            # that), so concurrent requests must not interleave into it.
            with lock:
                response = lab_server.handle_message(message)

            if response is None:
                self._send_empty(202)  # no body for a notification, per spec
                return
            self._send_json(response)

        def do_GET(self) -> None:  # noqa: N802 - stdlib method name
            # This server never sends unsolicited messages, so it has
            # nothing to stream -- a bare GET (some clients probe for an
            # SSE stream here) gets a plain refusal instead of a hung
            # connection.
            self._send_json({"error": "this server does not support server-initiated streaming"}, status=405)

        def do_DELETE(self) -> None:  # noqa: N802 - stdlib method name
            # Explicit session termination (spec-optional): 405 tells a
            # real client "not supported, that's fine" rather than the
            # stdlib's default 501, which some clients log as a warning.
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

    return Handler


def build_live_server(
    lab_dir: Path,
    *,
    port: int = 0,
    decision: Optional[str] = None,
    console: Optional[Console] = None,
) -> tuple[ThreadingHTTPServer, LabMCPServer]:
    """Binds to 127.0.0.1:<port> only — `port=0` (the default) asks the OS
    for a free port, read back via `server.server_address[1]`. Returns the
    bound HTTP server *and* the `LabMCPServer` instance driving it (its
    `session_id`/`events_path` are what the CLI prints before handing off
    to `serve_forever()`).
    """
    lab_server = LabMCPServer(lab_dir, decision=decision, console=console)
    lock = threading.Lock()
    handler = _make_handler(lab_server, str(uuid.uuid4()), lock)
    http_server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    return http_server, lab_server
