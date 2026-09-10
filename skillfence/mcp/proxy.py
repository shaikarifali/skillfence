"""The MCP proxy relay + intercept loop.

Two threads: one pumps the real downstream server's stdout back to the
real client's stdout (pure passthrough — responses, notifications,
anything the server sends unprompted). The main thread pumps the real
client's stdin toward the server, intercepting only `tools/call` requests
to run them through RuntimeGateway.authorize() first.

Deployment note, and why this is safe by construction: when this proxy is
spawned by a real MCP client, its own stdin is entirely consumed by the
JSON-RPC message stream — there is no free TTY left for a human to answer
an interactive decision prompt through the same process. SkillFence's
existing HumanGate fail-safe (`sys.stdin.isatty()` -> deny) therefore does
exactly the right thing here with no extra code: any action serious enough
to need a human decision fails safe and is blocked, not silently allowed,
whenever the proxy is running headless (i.e. always, in real deployment).
Pre-authorize expected actions with `skillfence policy allow` so they
don't need to gate live; review anything that got blocked with
`skillfence findings`.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Optional

from rich.console import Console

from skillfence.events.bus import EventBus
from skillfence.findings.schema import Finding
from skillfence.hitl.cli_gate import HumanGate
from skillfence.mcp import transport
from skillfence.mcp.fingerprint import ToolFingerprintStore
from skillfence.mcp.toolmap import ToolMap
from skillfence.policy.manifest import CapabilityManifest
from skillfence.policy.store import PolicyStore, default_policy_store_path
from skillfence.runtime.gateway import ActionBlocked, RuntimeGateway
from skillfence.runtime.sandbox import Sandbox
from skillfence.storage.jsonl_store import append_jsonl

REDACTION_TEMPLATE = (
    "[REDACTED BY SKILLFENCE — {reason}. Original content withheld; "
    "see `skillfence findings {findings_path}`.]"
)


class MCPProxy:
    def __init__(
        self,
        *,
        target_command: list[str],
        manifest_path: Path,
        toolmap_path: Path,
        audit_dir: Path,
        fresh: bool = False,
    ) -> None:
        self.target_command = target_command
        self.tool_map = ToolMap.load(toolmap_path)
        self.manifest = CapabilityManifest.load(manifest_path)
        self.audit_dir = audit_dir
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.fresh = fresh
        self.session_id = f"mcp-{uuid.uuid4().hex[:8]}"
        self.findings_path = self.audit_dir / f"{self.session_id}.findings.jsonl"
        self._child: Optional[subprocess.Popen] = None
        self._gateway = self._build_gateway()
        # Stable across proxy runs (audit_dir is a fixed default,
        # `--fresh` only affects the policy store) so a description change
        # between two separate sessions against the same server is
        # detectable at all -- the per-session *.events.jsonl files are not.
        self._fingerprints = ToolFingerprintStore(self.audit_dir / f"{self.manifest.name}.tool-fingerprints.json")
        # request id -> tool name, for every tools/call actually forwarded
        # to the child. Popped off as each matching response comes back
        # through _pump_child_to_client, so this never grows unbounded.
        self._pending_tool_calls: dict[Any, str] = {}

    def _build_gateway(self) -> RuntimeGateway:
        events_path = self.audit_dir / f"{self.session_id}.events.jsonl"
        bus = EventBus(events_path)
        # stderr, deliberately: stdout is the MCP protocol channel and must
        # never carry anything but valid MCP messages.
        console = Console(stderr=True)
        human_gate = HumanGate(console=console)
        policy_store = None if self.fresh else PolicyStore(default_policy_store_path())
        # RuntimeGateway's constructor requires a Sandbox, but authorize()
        # (the only entry point this proxy calls) never touches it -- there
        # is no lab sandbox in a real deployment, the real downstream
        # server performs the real action.
        sandbox = Sandbox(root=self.audit_dir)
        gateway = RuntimeGateway(
            bus=bus,
            manifest=self.manifest,
            sandbox=sandbox,
            human_gate=human_gate,
            session_id=self.session_id,
            agent="mcp-proxy",
            skill=self.manifest.name,
            policy_store=policy_store,
        )
        gateway.start()
        return gateway

    def run(self) -> None:
        transport.stderr(f"session {self.session_id} — target: {' '.join(self.target_command)}")
        transport.stderr(f"manifest: {self.manifest.name}  audit: {self.audit_dir}")
        self._child = subprocess.Popen(
            self.target_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        relay = threading.Thread(target=self._pump_child_to_client, daemon=True)
        relay.start()
        try:
            self._pump_client_to_child()
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        finally:
            if self._child.stdin:
                try:
                    self._child.stdin.close()
                except OSError:
                    pass
            try:
                self._child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._child.kill()
            relay.join(timeout=2)
            transport.stderr(f"session {self.session_id} ended — {len(self._gateway.findings)} finding(s) recorded")

    def _pump_child_to_client(self) -> None:
        assert self._child is not None and self._child.stdout is not None
        while True:
            message = transport.read_message(self._child.stdout)
            if message is None:
                return
            tools = (message.get("result") or {}).get("tools")
            if isinstance(tools, list):
                self._scan_tool_list(tools)
            tool_name = self._pending_tool_calls.pop(message.get("id"), None)
            if tool_name is not None:
                self._scan_tool_response(tool_name, message)
            transport.write_message(sys.stdout.buffer, message)

    def _scan_tool_list(self, tools: list[dict[str, Any]]) -> None:
        """Scan a `tools/list` response's descriptions *before* it's
        relayed to the real client — MCP tool poisoning and rug-pull are
        both attacks on the description text itself, which most clients
        hand straight to the model as trusted context. A flagged tool's
        description is redacted in place; every other tool in the same
        response is relayed untouched.
        """
        for tool in tools:
            name = tool.get("name")
            description = tool.get("description")
            if not name or not isinstance(description, str) or not description:
                continue

            try:
                self._gateway.scan_mcp_tool_description(name, description)
            except ActionBlocked as exc:
                transport.stderr(f"BLOCK  tools/list[{name}].description — {exc.finding.title}")
                self._record_finding(exc.finding)
                tool["description"] = REDACTION_TEMPLATE.format(
                    reason="tool poisoning suspected", findings_path=self.findings_path
                )
                continue  # already flagged this session; skip the rug-pull check below

            if self._fingerprints.check_and_record(name, description):
                try:
                    self._gateway.flag_tool_description_changed(name)
                except ActionBlocked as exc:
                    transport.stderr(f"BLOCK  tools/list[{name}].description — {exc.finding.title}")
                    self._record_finding(exc.finding)
                    tool["description"] = REDACTION_TEMPLATE.format(
                        reason="description changed since last seen (rug-pull)", findings_path=self.findings_path
                    )
        self._fingerprints.save()

    def _scan_tool_response(self, tool_name: str, message: dict[str, Any]) -> None:
        """Scan a real tool call's response *before* relaying it — the same
        live-credential content check `read_file()` already applies to lab
        filesystem reads, applied here to whatever a real downstream MCP
        server actually returned. Bidirectional: `_scan_tool_list` covers
        what the server *describes* itself as; this covers what it
        *returns*. A flagged content block is redacted whole -- secret_scan
        deliberately never returns match positions or values, only which
        pattern fired, so there's nothing to elide surgically.
        """
        content_blocks = (message.get("result") or {}).get("content")
        if not isinstance(content_blocks, list):
            return
        for block in content_blocks:
            text = block.get("text") if isinstance(block, dict) else None
            if not isinstance(text, str) or not text:
                continue
            try:
                self._gateway.scan_tool_response_content(tool_name, text)
            except ActionBlocked as exc:
                transport.stderr(f"BLOCK  tools/call[{tool_name}] response — {exc.finding.title}")
                self._record_finding(exc.finding)
                block["text"] = REDACTION_TEMPLATE.format(
                    reason="live credential pattern found in response", findings_path=self.findings_path
                )

    def _pump_client_to_child(self) -> None:
        assert self._child is not None and self._child.stdin is not None
        while True:
            message = transport.read_message(sys.stdin.buffer)
            if message is None:
                return
            if message.get("method") == "tools/call" and "id" in message:
                self._handle_tool_call(message)
            else:
                transport.write_message(self._child.stdin, message)

    def _handle_tool_call(self, message: dict[str, Any]) -> None:
        assert self._child is not None and self._child.stdin is not None
        params = message.get("params") or {}
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}
        request_id = message.get("id")

        kind, resource = self.tool_map.resolve(tool_name, arguments)
        if kind is None:
            policy = self.tool_map.unmapped_tool_policy
            if policy == "allow":
                transport.stderr(f"ALLOW  {tool_name}  (unmapped, policy=allow)")
                self._pending_tool_calls[request_id] = tool_name
                transport.write_message(self._child.stdin, message)
                return
            if policy == "block":
                transport.stderr(f"BLOCK  {tool_name}  (unmapped, policy=block)")
                self._deny(request_id, f"Blocked by SkillFence: '{tool_name}' has no entry in this server's tool map.")
                return
            kind = "unmapped"  # policy == "gate": routes through authorize(), always human-gates

        try:
            self._gateway.authorize(kind=kind, resource=resource, tool_name=tool_name)
        except ActionBlocked as exc:
            transport.stderr(f"BLOCK  {tool_name}({resource}) — {exc.finding.title}")
            self._record_finding(exc.finding)
            self._deny(request_id, f"Blocked by SkillFence: {exc.finding.title}. See `skillfence findings` for evidence.")
            return

        transport.stderr(f"ALLOW  {tool_name}({resource})")
        self._pending_tool_calls[request_id] = tool_name
        transport.write_message(self._child.stdin, message)

    def _deny(self, request_id: Any, text: str) -> None:
        transport.write_message(sys.stdout.buffer, transport.jsonrpc_tool_result(request_id, text=text, is_error=True))

    def _record_finding(self, finding: Finding) -> None:
        append_jsonl(self.findings_path, finding.model_dump())
