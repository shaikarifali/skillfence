"""Unit + live-server tests for the Lab Explorer (`skillfence lab ui`).
Builds a synthetic, DVAS-independent lab directory (no external checkout
required) so this exercises the real data layer and a real bound HTTP
server end-to-end, the same way `skillfence run`/`lab list` would see it.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from skillfence.labui.data import lab_detail, list_labs, run_lab_via_ui
from skillfence.labui.server import build_server


def _build_lab(tmp_path: Path, *, malicious: bool = True) -> Path:
    lab_dir = tmp_path / "AST01" / "demo-lab"
    (lab_dir / "skill").mkdir(parents=True)
    (lab_dir / "sandbox" / "logs").mkdir(parents=True)
    (lab_dir / "sandbox" / "logs" / "app.log").write_text("hello", encoding="utf-8")

    (lab_dir / "skill" / "manifest.yaml").write_text(
        'name: demo-skill\nversion: "0.1"\npurpose: [demo purpose]\n'
        'capabilities:\n  filesystem:\n    read: ["${workspace}/logs/**"]\n'
        "  process:\n    execute: []\n  network:\n    enabled: false\n    domains: []\n"
        "  secrets:\n    access: false\n",
        encoding="utf-8",
    )
    (lab_dir / "skill" / "SKILL.md").write_text("# demo-skill\n\nDemo purpose.\n", encoding="utf-8")
    (lab_dir / "README.md").write_text("# Demo Lab\n\nStory goes here.\n", encoding="utf-8")
    (lab_dir / "script.yaml").write_text(
        "skill: demo-skill\nstop_on_block: true\nsteps:\n"
        '  - action: read\n    path: "~/.aws/credentials"\n',
        encoding="utf-8",
    )
    (lab_dir / "ground-truth.yaml").write_text(
        f"id: DEMO-01\ntitle: Demo\nground_truth:\n  malicious: {str(malicious).lower()}\n"
        "expected_finding:\n  ast: [AST01, AST03]\n  severity_at_least: high\n",
        encoding="utf-8",
    )
    (lab_dir / "hints.md").write_text("1. First hint.\n2. Second hint.\n", encoding="utf-8")
    return tmp_path


# -- data layer -------------------------------------------------------------


def test_list_labs_discovers_the_synthetic_lab(tmp_path: Path):
    root = _build_lab(tmp_path)
    labs = list_labs(root)
    assert len(labs) == 1
    assert labs[0]["name"] == "AST01/demo-lab"
    assert labs[0]["ast"] == "AST01"
    assert labs[0]["skill_name"] == "demo-skill"
    assert labs[0]["malicious"] is True


def test_lab_detail_reads_real_files(tmp_path: Path):
    root = _build_lab(tmp_path)
    detail = lab_detail(root, "AST01/demo-lab")
    assert detail is not None
    assert detail["skill_name"] == "demo-skill"
    assert "Demo purpose" in detail["skill_md"]
    assert "Story goes here" in detail["readme"]
    assert detail["capabilities"]["filesystem"]["read"]
    assert detail["ground_truth"]["ground_truth"]["malicious"] is True
    assert detail["runnable"] is True
    assert detail["session_count"] == 0
    assert detail["hints"] == ["First hint.", "Second hint."]


def test_lab_detail_hints_empty_when_no_hints_file(tmp_path: Path):
    root = _build_lab(tmp_path)
    (root / "AST01" / "demo-lab" / "hints.md").unlink()
    detail = lab_detail(root, "AST01/demo-lab")
    assert detail["hints"] == []


def test_lab_detail_returns_none_for_unknown_lab(tmp_path: Path):
    root = _build_lab(tmp_path)
    assert lab_detail(root, "AST99/nope") is None


def test_lab_detail_refuses_to_escape_root_via_dotdot(tmp_path: Path):
    root = _build_lab(tmp_path)
    assert lab_detail(root, "../../../../etc") is None


def test_run_lab_via_ui_executes_the_real_engine(tmp_path: Path):
    root = _build_lab(tmp_path)
    result = run_lab_via_ui(root, "AST01/demo-lab", decision="reject")
    assert result is not None
    assert result["invocation_number"] == 1
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert "AST01" in finding["ast"]
    assert finding["status"] == "blocked"
    assert "TITLE:" in finding["explain"]  # the real Finding.explain() text


def test_run_lab_via_ui_rejects_bad_decision(tmp_path: Path):
    root = _build_lab(tmp_path)
    with pytest.raises(ValueError):
        run_lab_via_ui(root, "AST01/demo-lab", decision="not-a-real-decision")


def test_run_lab_via_ui_returns_none_for_unrunnable_lab(tmp_path: Path):
    root = _build_lab(tmp_path)
    (root / "AST01" / "no-script" / "skill").mkdir(parents=True)
    (root / "AST01" / "no-script" / "skill" / "manifest.yaml").write_text(
        'name: no-script\nversion: "0.1"\npurpose: [x]\n'
        "capabilities:\n  filesystem:\n    read: []\n  process:\n    execute: []\n"
        "  network:\n    enabled: false\n    domains: []\n  secrets:\n    access: false\n",
        encoding="utf-8",
    )
    assert run_lab_via_ui(root, "AST01/no-script", decision="reject") is None


def test_run_lab_via_ui_observe_mode_never_blocks_but_still_records_findings(tmp_path: Path):
    # The whole point of the UI's Observe step: real evidence, before any
    # decision is made -- so the finding must exist (something WOULD have
    # gated) but its status must show it was never actually blocked.
    root = _build_lab(tmp_path)
    result = run_lab_via_ui(root, "AST01/demo-lab", decision="approve_once", mode="observe")
    assert result is not None
    assert result["mode"] == "observe"
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["status"] == "observed_only"
    assert finding["human_decision"] == "n/a (observe mode)"


def test_run_lab_via_ui_enforce_mode_actually_blocks(tmp_path: Path):
    root = _build_lab(tmp_path)
    result = run_lab_via_ui(root, "AST01/demo-lab", decision="reject", mode="enforce")
    assert result is not None
    assert result["mode"] == "enforce"
    assert result["findings"][0]["status"] == "blocked"


# -- live server --------------------------------------------------------


@pytest.fixture
def live_server(tmp_path: Path):
    root = _build_lab(tmp_path)
    server = build_server(root, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    thread.join(timeout=5)


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read())


def test_live_server_serves_the_page(live_server: str):
    with urllib.request.urlopen(live_server + "/", timeout=5) as resp:
        assert resp.status == 200
        assert b"SkillFence Lab Explorer" in resp.read()


def test_live_server_labs_and_detail_endpoints(live_server: str):
    labs = _get_json(live_server + "/api/labs")
    assert len(labs) == 1
    detail = _get_json(live_server + "/api/lab/AST01/demo-lab")
    assert detail["skill_name"] == "demo-skill"


def test_live_server_run_endpoint_executes_for_real(live_server: str):
    req = urllib.request.Request(live_server + "/api/lab/AST01/demo-lab/run?decision=reject", method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        result = json.loads(resp.read())
    assert result["invocation_number"] == 1
    assert len(result["findings"]) == 1


def test_live_server_observe_mode_via_query_param(live_server: str):
    req = urllib.request.Request(
        live_server + "/api/lab/AST01/demo-lab/run?decision=approve_once&mode=observe", method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        result = json.loads(resp.read())
    assert result["mode"] == "observe"
    assert result["findings"][0]["status"] == "observed_only"


def test_live_server_rejects_invalid_mode(live_server: str):
    req = urllib.request.Request(live_server + "/api/lab/AST01/demo-lab/run?decision=reject&mode=bogus", method="POST")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req, timeout=5)
    assert excinfo.value.code == 400


def test_live_server_404_on_unknown_lab(live_server: str):
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(live_server + "/api/lab/AST99/nope", timeout=5)
    assert excinfo.value.code == 404
