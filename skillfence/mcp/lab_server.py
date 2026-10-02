"""Live Mode — a real, connectable MCP server for one SkillFence-Lab lab.

Every other SkillFence-Lab lab runs `script.yaml` through `ReferenceAgent`, a
deterministic stand-in for what a real LLM agent would do (see
`skillfence/adapters/reference_agent.py`). That's correct for
`skillfence bench` — a benchmark needs the same script to produce the
same result every time, and a real LLM would not. But it means nothing
watching a scripted run ever sees a *real* agent get manipulated.

`LabMCPServer` closes that gap without touching the deterministic path at
all: it exposes one lab's declared actions as real MCP tools, so a real
client (Claude Desktop, Cline, MCP Inspector) can connect a real LLM that
decides on its own what to call and when. Every call still executes
inside the exact same sandboxed `RuntimeGateway` every other lab uses,
built the exact same way `run_lab()` builds one
(`skillfence.lab_runner.build_lab_gateway`) — nothing here opens a real
socket, runs a real shell command, or touches a real credential. What
changes is *who's deciding to call the tool in the first place*.

This module only implements the JSON-RPC method handlers and the
tool-name -> gateway-method dispatch; it has no opinion about transport
(see `skillfence/mcp/live_http.py` for the HTTP+JSON transport that wraps
this).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

from rich.console import Console

from skillfence.lab_runner import build_lab_gateway
from skillfence.runtime.gateway import ActionBlocked, RuntimeGateway

# A widely-supported revision, not necessarily the newest -- this server's
# behavior (initialize / tools/list / tools/call, no resources, no
# sampling, no streaming) hasn't changed across recent spec revisions, so
# rather than guess which exact version a given client expects, the server
# echoes back whatever the client asked for in `initialize` params. This
# fallback is only used for a client that (unusually) sends none.
FALLBACK_PROTOCOL_VERSION = "2025-06-18"

# The six actions every SkillFence-Lab lab's script.yaml already speaks
# (skillfence/adapters/reference_agent.py's own dispatch table), exposed
# generically rather than with per-lab story-flavored names -- every lab
# that already has a compatible manifest.yaml and sandbox/ works here with
# zero new per-lab authoring.
TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": "Read a file from the skill's workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to read, relative to the workspace or ~-prefixed."}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file in the skill's workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to write, relative to the workspace or ~-prefixed."},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "execute_shell",
        "description": "Execute a shell command.",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch the contents of a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "network_send",
        "description": "Send data to an external network destination.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "payload": {"type": "string", "description": "Description of what's being sent."},
            },
            "required": ["destination", "payload"],
        },
    },
    {
        "name": "read_secret",
        "description": "Read a named secret/credential value from the process environment.",
        "inputSchema": {
            "type": "object",
            "properties": {"var_name": {"type": "string"}},
            "required": ["var_name"],
        },
    },
]

_JSONRPC_METHOD_NOT_FOUND = -32601
_JSONRPC_INTERNAL_ERROR = -32603


class LabMCPServer:
    """One live MCP session for one lab. Stateful (one `RuntimeGateway` per
    instance) — construct a fresh one per accepted connection, the same
    way `run_lab()` constructs a fresh gateway per scripted invocation.
    """

    def __init__(
        self,
        lab_dir: Path,
        *,
        decision: Optional[str] = None,
        console: Optional[Console] = None,
    ) -> None:
        self.lab_dir = lab_dir
        setup = build_lab_gateway(
            lab_dir,
            decision=decision,
            mode="enforce",
            console=console,
            agent_name="live-agent",
        )
        self.gateway: RuntimeGateway = setup.gateway
        self.session_id = setup.session_id
        self.events_path = setup.events_path
        self.gateway.start()

        skill_md_path = lab_dir / "skill" / "SKILL.md"
        self.instructions: Optional[str] = (
            skill_md_path.read_text(encoding="utf-8") if skill_md_path.exists() else None
        )

    # -- JSON-RPC method handlers ------------------------------------------

    def handle_initialize(self, params: dict) -> dict:
        return {
            "protocolVersion": params.get("protocolVersion") or FALLBACK_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": f"skillfence-lab-live-{self.gateway.skill}", "version": "0.1"},
            "instructions": self.instructions,
        }

    def handle_tools_list(self, params: dict) -> dict:
        return {"tools": TOOLS}

    def handle_tools_call(self, params: dict) -> dict:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        try:
            text = self._dispatch(name, arguments)
            return {"content": [{"type": "text", "text": text}], "isError": False}
        except ActionBlocked as exc:
            finding = exc.finding
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"BLOCKED by SkillFence — {finding.title}\n\n{finding.explain()}",
                    }
                ],
                "isError": True,
            }
        except KeyError:
            return {"content": [{"type": "text", "text": f"Unknown tool: {name!r}"}], "isError": True}
        except Exception as exc:  # noqa: BLE001 — surface to the agent, never crash the session over one bad call
            return {"content": [{"type": "text", "text": f"Error: {exc}"}], "isError": True}

    def _dispatch(self, name: Optional[str], arguments: dict) -> str:
        gw = self.gateway
        if name == "read_file":
            return gw.read_file(arguments["path"])
        if name == "write_file":
            gw.write_file(arguments["path"], arguments.get("content", ""))
            return "ok"
        if name == "execute_shell":
            return gw.execute_shell(arguments["command"])
        if name == "fetch_url":
            content, _event = gw.fetch_url(arguments["url"])
            return content
        if name == "network_send":
            gw.network_send(arguments["destination"], arguments.get("payload", ""))
            return "ok"
        if name == "read_secret":
            return gw.access_secret(arguments["var_name"])
        raise KeyError(name)

    # -- top-level JSON-RPC message dispatch --------------------------------

    def handle_message(self, message: dict) -> Optional[dict]:
        """Returns a JSON-RPC response dict for a request, or `None` for a
        notification — per spec, the server MUST NOT send a response to a
        notification (a message with no `id`).
        """
        method = message.get("method")
        msg_id = message.get("id")
        is_notification = "id" not in message

        if method == "notifications/initialized":
            return None  # client-sent notification once initialize completes; nothing to do

        handlers: dict[str, Callable[[dict], dict]] = {
            "initialize": self.handle_initialize,
            "tools/list": self.handle_tools_list,
            "tools/call": self.handle_tools_call,
        }
        handler = handlers.get(method or "")

        if handler is None:
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": _JSONRPC_METHOD_NOT_FOUND, "message": f"Method not found: {method}"},
            }

        try:
            result = handler(message.get("params") or {})
        except Exception as exc:  # noqa: BLE001 — any handler bug becomes a JSON-RPC error, not a dropped connection
            if is_notification:
                return None
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": _JSONRPC_INTERNAL_ERROR, "message": str(exc)},
            }

        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}
