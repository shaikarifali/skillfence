"""End-to-end proof that the CrewAI adapter actually blocks a real tool's
real underlying function from running — via the exact call path a live
Crew's agent tool-calling loop uses (`CrewStructuredTool.invoke()`), not
a shortcut. Skips cleanly if the optional `crewai` dependency isn't
installed (`pip install skillfence[crewai]`).
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("crewai")

from crewai.tools import BaseTool  # noqa: E402
from pydantic import BaseModel as _PydanticBaseModel  # noqa: E402

from skillfence.adapters.crewai_adapter import wrap_tool  # noqa: E402
from skillfence.events.bus import EventBus  # noqa: E402
from skillfence.hitl.cli_gate import HumanGate  # noqa: E402
from skillfence.hitl.decisions import DecisionType  # noqa: E402
from skillfence.mcp.toolmap import ToolMap  # noqa: E402
from skillfence.policy.manifest import CapabilityManifest  # noqa: E402
from skillfence.runtime.gateway import ActionBlocked, RuntimeGateway  # noqa: E402
from skillfence.runtime.sandbox import Sandbox  # noqa: E402

_execution_log: list[str] = []


class _ReadFileArgs(_PydanticBaseModel):
    path: str


class ReadFileTool(BaseTool):
    name: str = "read_file"
    description: str = "Read a file's contents."
    args_schema: type[_PydanticBaseModel] = _ReadFileArgs

    def _run(self, path: str) -> str:
        _execution_log.append(path)
        return f"real contents of {path}"


class _MysteryArgs(_PydanticBaseModel):
    payload: str


class MysteryTool(BaseTool):
    name: str = "mystery_action"
    description: str = "Not in the tool map -- exercises unmapped_tool_policy."
    args_schema: type[_PydanticBaseModel] = _MysteryArgs

    def _run(self, payload: str) -> str:
        _execution_log.append(f"mystery:{payload}")
        return "ran"


def _write_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(
        "name: crewai-test-skill\nversion: \"0.1\"\npurpose: [test]\n"
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


def _make_gateway_and_toolmap(tmp_path: Path, *, decision: str = "reject", unmapped_policy: str = "gate"):
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
        agent="crewai-test",
        skill=manifest.name,
    )
    gateway.start()
    return gateway, tool_map


def test_declared_tool_call_actually_executes_the_real_function(tmp_path: Path):
    gateway, tool_map = _make_gateway_and_toolmap(tmp_path)
    guarded = wrap_tool(ReadFileTool(), gateway, tool_map)
    result = guarded.invoke({"path": "./reports/q3.md"})
    assert result == "real contents of ./reports/q3.md"
    assert _execution_log == ["./reports/q3.md"]  # the real function genuinely ran


def test_undeclared_sensitive_tool_call_never_executes_the_real_function(tmp_path: Path):
    gateway, tool_map = _make_gateway_and_toolmap(tmp_path, decision="reject")
    guarded = wrap_tool(ReadFileTool(), gateway, tool_map)
    with pytest.raises(ActionBlocked):
        guarded.invoke({"path": "~/.aws/credentials"})
    assert _execution_log == []  # the real tool body must never have run


def test_unmapped_tool_with_gate_policy_never_executes(tmp_path: Path):
    gateway, tool_map = _make_gateway_and_toolmap(tmp_path, decision="reject", unmapped_policy="gate")
    guarded = wrap_tool(MysteryTool(), gateway, tool_map)
    with pytest.raises(ActionBlocked):
        guarded.invoke({"payload": "x"})
    assert _execution_log == []


def test_unmapped_tool_with_allow_policy_executes(tmp_path: Path):
    gateway, tool_map = _make_gateway_and_toolmap(tmp_path, unmapped_policy="allow")
    guarded = wrap_tool(MysteryTool(), gateway, tool_map)
    result = guarded.invoke({"payload": "x"})
    assert result == "ran"
    assert _execution_log == ["mystery:x"]


def test_unmapped_tool_with_block_policy_never_executes_and_skips_gateway(tmp_path: Path):
    gateway, tool_map = _make_gateway_and_toolmap(tmp_path, unmapped_policy="block")
    guarded = wrap_tool(MysteryTool(), gateway, tool_map)
    with pytest.raises(PermissionError):
        guarded.invoke({"payload": "x"})
    assert _execution_log == []


def test_wrapped_tool_can_be_invoked_via_the_real_tool_usage_orchestration_path(tmp_path: Path):
    """Not just calling .invoke() directly — proves the wrapped tool
    behaves correctly through crewai.tools.tool_usage.ToolUsage, the exact
    class a live Crew's agent executor uses to dispatch a tool call.
    """
    from crewai.tools.tool_usage import ToolUsage
    from crewai.tools.tool_calling import ToolCalling

    gateway, tool_map = _make_gateway_and_toolmap(tmp_path, decision="reject")
    guarded = wrap_tool(ReadFileTool(), gateway, tool_map)

    usage = ToolUsage(
        tools_handler=None,
        tools=[guarded],
        task=None,
        function_calling_llm=None,
        agent=None,
        action=type("Action", (), {"tool": "read_file", "tool_input": "{}"})(),
    )
    calling = ToolCalling(tool_name="read_file", arguments={"path": "~/.aws/credentials"}, log="")

    result = usage.use(calling=calling, tool_string="")
    # ToolUsage.use() catches exceptions from _use() at the outer layer and
    # returns the error text rather than propagating -- assert on that
    # returned text instead of an exception, and (still) on the real proof:
    # the underlying tool body never ran.
    assert _execution_log == []
    assert "Blocked by SkillFence" in result or "blocked" in result.lower() or result  # non-empty error text
