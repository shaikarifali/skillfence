"""End-to-end proof that the Google ADK adapter actually blocks a real
tool's real underlying function from running -- not just that a dict gets
returned somewhere. Skips cleanly if the optional `google-adk` dependency
isn't installed (`pip install skillfence[adk]`).

The deep test below drives the real `google.adk.agents.llm_agent.LlmAgent`
(to prove our callback is accepted and resolved by `canonical_before_tool_
callbacks` the way a real Agent construction would) and the real
`google.adk.tools.function_tool.FunctionTool.run_async()` (the same method
`__call_tool_async()` calls in `google/adk/flows/llm_flows/functions.py`).
The one piece that is *not* driven through the real framework is the
surrounding `_run_with_trace()` gather/event-building machinery in that
same file, which needs a full `InvocationContext` (session service,
artifact service, memory service, ...) to construct -- disproportionate
scaffolding for what it would additionally prove. What's reproduced here
instead is the exact conditional verified directly from that source before
writing the adapter: call each of `agent.canonical_before_tool_callbacks`
in order, and only call the real tool if every one of them returned `None`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("google.adk")

from google.adk.agents.llm_agent import LlmAgent  # noqa: E402
from google.adk.tools.function_tool import FunctionTool  # noqa: E402

from skillfence.adapters.adk_adapter import build_before_tool_callback  # noqa: E402
from skillfence.events.bus import EventBus  # noqa: E402
from skillfence.hitl.cli_gate import HumanGate  # noqa: E402
from skillfence.hitl.decisions import DecisionType  # noqa: E402
from skillfence.mcp.toolmap import ToolMap  # noqa: E402
from skillfence.policy.manifest import CapabilityManifest  # noqa: E402
from skillfence.runtime.gateway import RuntimeGateway  # noqa: E402
from skillfence.runtime.sandbox import Sandbox  # noqa: E402

_execution_log: list[str] = []


def read_file(path: str) -> str:
    """Read a file's contents."""
    _execution_log.append(path)
    return f"real contents of {path}"


def mystery_action(payload: str) -> str:
    """Not in the tool map -- exercises unmapped_tool_policy."""
    _execution_log.append(f"mystery:{payload}")
    return "ran"


def _write_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(
        "name: adk-test-skill\nversion: \"0.1\"\npurpose: [test]\n"
        "capabilities:\n  filesystem:\n    read: [\"./reports/**\"]\n"
        "  process:\n    execute: []\n  network:\n    enabled: false\n    domains: []\n"
        "  secrets:\n    access: false\n",
        encoding="utf-8",
    )
    return path


def _write_toolmap(tmp_path: Path, *, unmapped_policy: str = "gate") -> Path:
    path = tmp_path / "tool-map.yaml"
    path.write_text(
        f"unmapped_tool_policy: {unmapped_policy}\ntools:\n  read_file:\n    kind: fs_read\n    resource_arg: path\n",
        encoding="utf-8",
    )
    return path


def _make_agent(tmp_path: Path, *, decision: str = "reject", unmapped_policy: str = "gate") -> LlmAgent:
    _execution_log.clear()
    manifest = CapabilityManifest.load(_write_manifest(tmp_path))
    tool_map = ToolMap.load(_write_toolmap(tmp_path, unmapped_policy=unmapped_policy))
    sandbox = Sandbox(root=tmp_path / "sandbox")
    forced = DecisionType(decision)
    human_gate = HumanGate(auto_decider=lambda _req, _forced=forced: _forced)
    bus = EventBus(tmp_path / "events.jsonl")
    gateway = RuntimeGateway(
        bus=bus,
        manifest=manifest,
        sandbox=sandbox,
        human_gate=human_gate,
        session_id="test-session",
        agent="adk-test",
        skill=manifest.name,
    )
    gateway.start()
    callback = build_before_tool_callback(gateway, tool_map)
    return LlmAgent(name="test_agent", model="gemini-2.0-flash", before_tool_callback=callback)


async def _dispatch(agent: LlmAgent, tool: FunctionTool, args: dict) -> object:
    """The exact Step 2 -> Step 3 gating from functions.py's
    `_run_with_trace()`, verified against real 2.8.0 source: run every
    canonical before_tool_callback in order, stop at the first non-None
    result, and only call the real tool if none of them produced one.
    """
    function_response = None
    for before_callback in agent.canonical_before_tool_callbacks:
        result = before_callback(tool=tool, args=args, tool_context=None)
        if asyncio.iscoroutine(result):
            result = await result
        function_response = result
        if function_response:
            break
    if function_response is None:
        return await tool.run_async(args=args, tool_context=None)
    return function_response


def test_declared_tool_call_actually_executes_the_real_function(tmp_path: Path):
    agent = _make_agent(tmp_path)
    tool = FunctionTool(read_file)
    result = asyncio.run(_dispatch(agent, tool, {"path": "./reports/q3.md"}))
    assert result == "real contents of ./reports/q3.md"
    assert _execution_log == ["./reports/q3.md"]  # the real function genuinely ran


def test_undeclared_sensitive_tool_call_never_executes_the_real_function(tmp_path: Path):
    agent = _make_agent(tmp_path, decision="reject")
    tool = FunctionTool(read_file)
    result = asyncio.run(_dispatch(agent, tool, {"path": "~/.aws/credentials"}))
    assert isinstance(result, dict) and "error" in result
    assert "Blocked by SkillFence" in result["error"]
    assert _execution_log == []  # the real tool body must never have run


def test_unmapped_tool_with_gate_policy_never_executes(tmp_path: Path):
    agent = _make_agent(tmp_path, decision="reject", unmapped_policy="gate")
    tool = FunctionTool(mystery_action)
    result = asyncio.run(_dispatch(agent, tool, {"payload": "x"}))
    assert isinstance(result, dict) and "error" in result
    assert _execution_log == []


def test_unmapped_tool_with_allow_policy_executes(tmp_path: Path):
    agent = _make_agent(tmp_path, unmapped_policy="allow")
    tool = FunctionTool(mystery_action)
    result = asyncio.run(_dispatch(agent, tool, {"payload": "x"}))
    assert result == "ran"
    assert _execution_log == ["mystery:x"]


def test_unmapped_tool_with_block_policy_never_executes_and_skips_gateway(tmp_path: Path):
    agent = _make_agent(tmp_path, unmapped_policy="block")
    tool = FunctionTool(mystery_action)
    result = asyncio.run(_dispatch(agent, tool, {"payload": "x"}))
    assert isinstance(result, dict) and "error" in result
    assert "no entry in the tool map" in result["error"]
    assert _execution_log == []


def test_callback_return_type_matches_adk_before_tool_callback_contract(tmp_path: Path):
    """Guards the exact claim this adapter is built on: ADK's own
    `BeforeToolCallback` type is `Callable[[BaseTool, dict, ToolContext],
    Optional[dict[str, Any]]]` -- returning `None` on allow, a `dict` on
    block. A future regression to raising an exception instead (the
    LangChain-shaped mistake) would fail loudly here.
    """
    agent = _make_agent(tmp_path, decision="reject")
    tool = FunctionTool(read_file)
    callback = agent.canonical_before_tool_callbacks[0]

    allowed = callback(tool=tool, args={"path": "./reports/q3.md"}, tool_context=None)
    assert allowed is None

    blocked = callback(tool=tool, args={"path": "~/.aws/credentials"}, tool_context=None)
    assert isinstance(blocked, dict)
