#!/usr/bin/env python3
"""Worked example: SkillFence in front of real CrewAI tools.

Run: pip install 'skillfence[crewai]' && python3 examples/crewai-adapter/demo.py

Like the LangChain adapter, this runs inside your own process — CrewAI
tools are Python function calls, not a wire protocol, so there's no proxy
to stand in front of them. `wrap_tool()` returns a `CrewStructuredTool`
you pass into `Agent(tools=[...])` in place of the original tool; every
real call goes through the same `RuntimeGateway` the labs and the other
two adapters use before the tool's real function runs.
"""

from __future__ import annotations

from pathlib import Path

from crewai.tools import BaseTool
from pydantic import BaseModel

from skillfence.adapters.crewai_adapter import wrap_tool
from skillfence.events.bus import EventBus
from skillfence.hitl.cli_gate import HumanGate
from skillfence.hitl.decisions import DecisionType
from skillfence.mcp.toolmap import ToolMap
from skillfence.policy.manifest import CapabilityManifest
from skillfence.runtime.gateway import ActionBlocked, RuntimeGateway
from skillfence.runtime.sandbox import Sandbox

HERE = Path(__file__).parent


# -- two real CrewAI tools, exactly as you'd define them for a real agent --

class _ReadFileArgs(BaseModel):
    path: str


class ReadFileTool(BaseTool):
    name: str = "read_file"
    description: str = "Read a local file's contents."
    args_schema: type[BaseModel] = _ReadFileArgs

    def _run(self, path: str) -> str:
        return f"(demo) contents of {path}"


class _WebhookArgs(BaseModel):
    url: str


class SendWebhookTool(BaseTool):
    name: str = "send_webhook"
    description: str = "POST a status update to a webhook URL."
    args_schema: type[BaseModel] = _WebhookArgs

    def _run(self, url: str) -> str:
        return f"(demo) would have POSTed to {url}"


def main() -> None:
    manifest = CapabilityManifest.load(HERE / "manifest.yaml")
    tool_map = ToolMap.load(HERE / "tool-map.yaml")

    bus = EventBus(HERE / ".runs" / "demo.events.jsonl")
    # --decision reject, non-interactive, so this demo runs unattended.
    human_gate = HumanGate(auto_decider=lambda _req: DecisionType.REJECT)
    sandbox = Sandbox(root=HERE / "sandbox")
    gateway = RuntimeGateway(
        bus=bus, manifest=manifest, sandbox=sandbox, human_gate=human_gate,
        session_id="crewai-demo", agent="crewai-demo", skill=manifest.name,
    )
    gateway.start()

    read_file = wrap_tool(ReadFileTool(), gateway, tool_map)
    send_webhook = wrap_tool(SendWebhookTool(), gateway, tool_map)

    print(f"Skill: {manifest.name}  (declares filesystem.read: {manifest.capabilities.filesystem.read})\n")

    print("1) Declared read — allowed, real function runs:")
    print("   ->", read_file.invoke({"path": "./reports/q3.md"}))

    print("\n2) Undeclared, sensitive read — SkillFence blocks it before the real function runs:")
    try:
        read_file.invoke({"path": "~/.aws/credentials"})
    except ActionBlocked as exc:
        print("   -> BLOCKED:", exc.finding.title)

    print("\n3) Network tool with network.enabled: false in the manifest — also blocked:")
    try:
        send_webhook.invoke({"url": "https://exfil.test/collect"})
    except ActionBlocked as exc:
        print("   -> BLOCKED:", exc.finding.title)

    print(f"\n{len(gateway.findings)} finding(s) recorded. Full evidence: {bus.jsonl_path}")
    print("\nThese wrapped tools are ready to pass straight into a real Agent:")
    print("  Agent(role=..., tools=[read_file, send_webhook], ...)")


if __name__ == "__main__":
    main()
