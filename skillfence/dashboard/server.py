"""A local, read-only HTTP server for the SkillFence dashboard. Stdlib
only (`http.server`) -- no new dependency for something this small, and
bound to 127.0.0.1 only: this is a local evidence viewer, never a service
meant to be reachable from another machine.
"""

from __future__ import annotations

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from skillfence.dashboard.data import discover_sessions, session_detail
from skillfence.dashboard.templates import PAGE


def _make_handler(root: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:  # noqa: A002 - stdlib signature
            pass  # quiet by default; the CLI prints its own startup line

        def _send_json(self, payload, status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib method name
            parsed = urllib.parse.urlparse(self.path)
            parts = [p for p in parsed.path.split("/") if p]

            if parsed.path == "/":
                self._send_html(PAGE)
                return
            if parts == ["api", "root"]:
                self._send_json({"path": str(root)})
                return
            if parts == ["api", "sessions"]:
                self._send_json([s.to_dict() for s in discover_sessions(root)])
                return
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "session":
                session_id = urllib.parse.unquote(parts[2])
                detail = session_detail(root, session_id)
                if detail is None:
                    self._send_json({"error": "session not found"}, status=404)
                    return
                self._send_json(detail)
                return

            self._send_json({"error": "not found"}, status=404)

    return Handler


def build_server(root: Path, *, port: int = 0) -> ThreadingHTTPServer:
    """Binds to 127.0.0.1:<port>. `port=0` (the default) asks the OS for a
    free port -- read it back via `server.server_address[1]`.
    """
    handler = _make_handler(root.resolve())
    return ThreadingHTTPServer(("127.0.0.1", port), handler)
