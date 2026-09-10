#!/usr/bin/env python3
"""Worked example: SkillFence in front of real Google ADK tools.

Run: pip install 'skillfence[adk]' && python3 examples/adk-adapter/demo.py

Unlike LangChain/CrewAI, ADK's own `before_tool_callback` contract doesn't
use exceptions at all -- it's typed to return `Optional[dict[str, Any]]`:
`None` means "proceed with the real tool," a dict means "skip the real
tool, use this dict as its response instead." `build_before_tool_callback()`
returns a function matching that exact contract; pass it straight into
`LlmAgent(before_tool_callback=...)` and every real tool call is authorized
through the same `RuntimeGateway` the labs and the other adapters use
before ADK ever calls the tool's real `run_async()`.

This demo drives the same dispatch a real ADK agent turn uses internally
(`agent.canonical_before_tool_callbacks` then, only if every one of them
returned `None`, `tool.run_async()`) without needing a full `Runner` +
session service + live model call, so it runs standalone.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from google.adk.agents.llm_agent import LlmAgent
from google.adk.tools.function_tool import FunctionTool

from skillfence.adapters.adk_adapter import build_before_tool_callback
from skillfence.events.bus import EventBus
from skillfence.hitl.cli_gate import HumanGate
from skillfence.hitl.decisions import DecisionType
from skillfence.mcp.toolmap import ToolMap
from skillfence.policy.manifest import CapabilityManifest
from skillfence.runtime.gateway import RuntimeGateway
from skillfence.runtime.sandbox import Sandbox

HERE = Path(__file__).parent


# -- two real ADK tools, exactly as you'd define them for a real agent -----

def read_file(path: str) -> str:
    """Read a local file's contents."""
    return f"(demo) contents of {path}"


def send_webhook(url: str) -> str:
    """POST a status update to a webhook URL."""
    return f"(demo) would have POSTed to {url}"


async def call_tool(agent: LlmAgent, tool: FunctionTool, args: dict) -> object:
    """The real dispatch: every canonical before_tool_callback runs first;
    the real tool only runs if none of them returned a response.
    """
    for before_callback in agent.canonical_before_tool_callbacks:
        response = before_callback(tool=tool, args=args, tool_context=None)
        if response is not None:
            return response
    return await tool.run_async(args=args, tool_context=None)


def main() -> None:
    manifest = CapabilityManifest.load(HERE / "manifest.yaml")
    tool_map = ToolMap.load(HERE / "tool-map.yaml")

    bus = EventBus(HERE / ".runs" / "demo.events.jsonl")
    # --decision reject, non-interactive, so this demo runs unattended.
    human_gate = HumanGate(auto_decider=lambda _req: DecisionType.REJECT)
    sandbox = Sandbox(root=HERE / "sandbox")
    gateway = RuntimeGateway(
        bus=bus, manifest=manifest, sandbox=sandbox, human_gate=human_gate,
        session_id="adk-demo", agent="adk-demo", skill=manifest.name,
    )
    gateway.start()

    callback = build_before_tool_callback(gateway, tool_map)
    agent = LlmAgent(name="demo_agent", model="gemini-2.0-flash", before_tool_callback=callback)

    read_file_tool = FunctionTool(read_file)
    send_webhook_tool = FunctionTool(send_webhook)

    print(f"Skill: {manifest.name}  (declares filesystem.read: {manifest.capabilities.filesystem.read})\n")

    print("1) Declared read — allowed, real function runs:")
    result = asyncio.run(call_tool(agent, read_file_tool, {"path": "./reports/q3.md"}))
    print("   ->", result)

    print("\n2) Undeclared, sensitive read — SkillFence blocks it before the real function runs:")
    result = asyncio.run(call_tool(agent, read_file_tool, {"path": "~/.aws/credentials"}))
    print("   -> BLOCKED:", result["error"] if isinstance(result, dict) else result)

    print("\n3) Network tool with network.enabled: false in the manifest — also blocked:")
    result = asyncio.run(call_tool(agent, send_webhook_tool, {"url": "https://exfil.test/collect"}))
    print("   -> BLOCKED:", result["error"] if isinstance(result, dict) else result)

    print(f"\n{len(gateway.findings)} finding(s) recorded. Full evidence: {bus.jsonl_path}")
    print("\nThis callback is ready to pass straight into a real Agent:")
    print("  LlmAgent(name=..., model=..., before_tool_callback=callback, tools=[...])")


if __name__ == "__main__":
    main()
