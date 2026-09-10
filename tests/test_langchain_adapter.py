"""End-to-end proof that the LangChain adapter actually blocks a real
tool's real underlying function from running -- not just that an
exception gets raised somewhere. Skips cleanly if the optional
`langchain-core` dependency isn't installed (`pip install
skillfence[langchain]`).
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("langchain_core")

from langchain_core.tools import tool  # noqa: E402

from skillfence.adapters.langchain_adapter import build_handler  # noqa: E402
from skillfence.events.bus import EventBus  # noqa: E402
from skillfence.hitl.cli_gate import HumanGate  # noqa: E402
from skillfence.hitl.decisions import DecisionType  # noqa: E402
from skillfence.mcp.toolmap import ToolMap  # noqa: E402
from skillfence.policy.manifest import CapabilityManifest  # noqa: E402
from skillfence.runtime.gateway import RuntimeGateway  # noqa: E402
from skillfence.runtime.sandbox import Sandbox  # noqa: E402

_execution_log: list[str] = []


@tool
def read_file(path: str) -> str:
    """Read a file's contents."""
    _execution_log.append(path)
    return f"real contents of {path}"


@tool
def mystery_action(payload: str) -> str:
    """Not in the tool map -- exercises unmapped_tool_policy."""
    _execution_log.append(f"mystery:{payload}")
    return "ran"


def _write_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(
        "name: langchain-test-skill\nversion: \"0.1\"\npurpose: [test]\n"
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


def _make_handler(tmp_path: Path, *, decision: str = "reject", unmapped_policy: str = "gate"):
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
        agent="langchain-test",
        skill=manifest.name,
    )
    gateway.start()
    return build_handler(gateway, tool_map)


def test_declared_tool_call_actually_executes_the_real_function(tmp_path: Path):
    handler = _make_handler(tmp_path)
    result = read_file.run({"path": "./reports/q3.md"}, callbacks=[handler])
    assert result == "real contents of ./reports/q3.md"
    assert _execution_log == ["./reports/q3.md"]  # the real function genuinely ran


def test_undeclared_sensitive_tool_call_never_executes_the_real_function(tmp_path: Path):
    handler = _make_handler(tmp_path, decision="reject")
    with pytest.raises(Exception):  # ActionBlocked, propagated by raise_error=True
        read_file.run({"path": "~/.aws/credentials"}, callbacks=[handler])
    # the whole point: the real tool body must never have run
    assert _execution_log == []


def test_unmapped_tool_with_gate_policy_never_executes(tmp_path: Path):
    handler = _make_handler(tmp_path, decision="reject", unmapped_policy="gate")
    with pytest.raises(Exception):
        mystery_action.run({"payload": "x"}, callbacks=[handler])
    assert _execution_log == []


def test_unmapped_tool_with_allow_policy_executes(tmp_path: Path):
    handler = _make_handler(tmp_path, unmapped_policy="allow")
    result = mystery_action.run({"payload": "x"}, callbacks=[handler])
    assert result == "ran"
    assert _execution_log == ["mystery:x"]


def test_unmapped_tool_with_block_policy_never_executes_and_skips_gateway(tmp_path: Path):
    handler = _make_handler(tmp_path, unmapped_policy="block")
    with pytest.raises(PermissionError):
        mystery_action.run({"payload": "x"}, callbacks=[handler])
    assert _execution_log == []


def test_without_raise_error_a_blocked_call_would_silently_proceed(tmp_path: Path):
    """Documents the exact footgun this adapter avoids: langchain-core's
    handle_event() only re-raises a callback's exception when
    handler.raise_error is True (default False). This test builds a
    handler the normal way (raise_error=True is baked in) and confirms
    THAT behavior — it exists to make a future accidental removal of
    `raise_error = True` fail loudly here instead of silently in production.
    """
    handler = _make_handler(tmp_path, decision="reject")
    assert handler.raise_error is True
