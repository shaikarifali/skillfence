"""End-to-end protocol test for Live Mode's HTTP transport — connects the
*real* official `mcp` SDK client (`mcp.client.streamable_http`) against
the hand-rolled `build_live_server()`, over a real bound socket on
127.0.0.1. This is the test that actually matters for "does this speak
correct MCP" — the unit tests in `test_lab_server.py` only exercise the
dispatch logic directly, never the wire protocol.

`mcp` is not a runtime dependency of this package (Live Mode's HTTP layer
is deliberately stdlib-only, so nothing ships that isn't already a
dependency) — it's a dev-time-only way to verify protocol correctness
against a real client implementation. Install it to run this test:

    pip install "mcp[cli]"
    pytest tests/test_live_http.py

If it isn't installed, this test skips rather than failing — same
convention `test_labs.py` uses for an unavailable SkillFence-Lab clone.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest

mcp_client = pytest.importorskip("mcp")
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamablehttp_client  # noqa: E402

from skillfence.mcp.live_http import build_live_server  # noqa: E402


def _build_lab(tmp_path: Path) -> Path:
    lab_dir = tmp_path / "demo-lab"
    (lab_dir / "skill").mkdir(parents=True)
    (lab_dir / "sandbox" / "logs").mkdir(parents=True)
    (lab_dir / "sandbox" / "logs" / "app.log").write_text("hello from live http", encoding="utf-8")
    (lab_dir / "skill" / "manifest.yaml").write_text(
        'name: demo-skill\nversion: "0.1"\npurpose: [demo purpose]\n'
        'capabilities:\n  filesystem:\n    read: ["${workspace}/logs/**"]\n'
        "  process:\n    execute: []\n  network:\n    enabled: false\n    domains: []\n"
        "  secrets:\n    access: false\n",
        encoding="utf-8",
    )
    (lab_dir / "skill" / "SKILL.md").write_text("# demo-skill\n\nLive HTTP transport test skill.\n", encoding="utf-8")
    return lab_dir


@pytest.fixture()
def live_server(tmp_path: Path):
    lab_dir = _build_lab(tmp_path)
    http_server, lab_server = build_live_server(lab_dir, port=0, decision="reject")
    thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    thread.start()
    port = http_server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}/mcp", lab_server
    finally:
        http_server.shutdown()
        http_server.server_close()
        thread.join(timeout=2)


def test_real_mcp_client_completes_full_session(live_server):
    url, lab_server = live_server

    async def run():
        async with streamablehttp_client(url) as (read, write, get_session_id):
            async with ClientSession(read, write) as session:
                init_result = await session.initialize()
                assert init_result.serverInfo.name == "skillfence-lab-live-demo-skill"
                assert "Live HTTP transport test skill" in (init_result.instructions or "")
                assert get_session_id()  # a real session id was negotiated

                tools_result = await session.list_tools()
                names = {t.name for t in tools_result.tools}
                assert names == {
                    "read_file",
                    "write_file",
                    "execute_shell",
                    "fetch_url",
                    "network_send",
                    "read_secret",
                }

                ok = await session.call_tool("read_file", {"path": "./logs/app.log"})
                assert ok.isError is False
                assert ok.content[0].text == "hello from live http"

                blocked = await session.call_tool("read_file", {"path": "~/.aws/credentials"})
                assert blocked.isError is True
                assert "BLOCKED by SkillFence" in blocked.content[0].text

    asyncio.run(run())

    # the real gateway behind this session actually recorded the blocked
    # attempt -- same audit trail every other SkillFence-Lab lab produces
    assert len(lab_server.gateway.findings) == 1
    assert lab_server.gateway.findings[0].status == "blocked"
