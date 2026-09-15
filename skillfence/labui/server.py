"""A local HTTP server for the Lab Explorer — stdlib only, bound to
127.0.0.1 only, same reasoning as `skillfence.dashboard.server`. Unlike
the dashboard (read-only, past sessions only), this one can also *run* a
lab on request -- that's still safe under the same trust model: it's the
same local engine, same local files, same thing `skillfence run` already
does from a terminal, just triggered from a browser instead of a shell.
Nothing here is reachable from another machine.
"""

from __future__ import annotations

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from skillfence.labui.data import lab_detail, list_labs, run_lab_via_ui
from skillfence.labui.templates import PAGE

_LAB_PREFIX = "/api/lab/"
_RUN_SUFFIX = "/run"


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
            path = parsed.path

            if path == "/":
                self._send_html(PAGE)
                return
            if path == "/api/root":
                self._send_json({"path": str(root)})
                return
            if path == "/api/labs":
                self._send_json(list_labs(root))
                return
            if path.startswith(_LAB_PREFIX):
                name = urllib.parse.unquote(path[len(_LAB_PREFIX) :])
                if not name:
                    self._send_json({"error": "missing lab name"}, status=400)
                    return
                detail = lab_detail(root, name)
                if detail is None:
                    self._send_json({"error": "lab not found"}, status=404)
                    return
                self._send_json(detail)
                return

            self._send_json({"error": "not found"}, status=404)

        def do_POST(self) -> None:  # noqa: N802 - stdlib method name
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path.startswith(_LAB_PREFIX) and path.endswith(_RUN_SUFFIX):
                name = urllib.parse.unquote(path[len(_LAB_PREFIX) : -len(_RUN_SUFFIX)])
                if not name:
                    self._send_json({"error": "missing lab name"}, status=400)
                    return
                query = urllib.parse.parse_qs(parsed.query)
                decision = (query.get("decision") or ["reject"])[0]
                mode = (query.get("mode") or ["enforce"])[0]
                if mode not in ("enforce", "observe"):
                    self._send_json({"error": f"invalid mode: {mode!r} (must be 'enforce' or 'observe')"}, status=400)
                    return
                try:
                    result = run_lab_via_ui(root, name, decision=decision, mode=mode)
                except ValueError:
                    self._send_json({"error": f"invalid decision: {decision!r}"}, status=400)
                    return
                if result is None:
                    self._send_json({"error": "lab not found or has no script.yaml to run"}, status=404)
                    return
                self._send_json(result)
                return

            self._send_json({"error": "not found"}, status=404)

    return Handler


def build_server(root: Path, *, port: int = 0) -> ThreadingHTTPServer:
    """Binds to 127.0.0.1:<port>. `port=0` (the default) asks the OS for a
    free port -- read it back via `server.server_address[1]`.
    """
    handler = _make_handler(root.resolve())
    return ThreadingHTTPServer(("127.0.0.1", port), handler)
