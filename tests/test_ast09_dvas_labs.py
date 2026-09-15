"""AST09 (No Governance) DVAS labs. Structurally different from every other
DVAS category: these are fleet directories (multiple skill/manifest.yaml
subdirectories), graded by `skillfence.governance.inventory.build_inventory`
instead of a single script.yaml's Finding outcome -- there is nothing for
the single-shot ground-truth.yaml/bench harness to score here, matching
`test_delayed_payload.py`/`test_ast07_dvas_labs.py`'s precedent for lab
shapes `test_labs.py` can't handle.

Uses `SKILLFENCE_POLICY_STORE` to point every `run_lab()` call at a
tmp-local grants file, so this test never reads or writes the real
org-wide store.

Requires the DVAS lab suite (https://github.com/shaikarifali/DVAS) cloned
alongside this repo, or DVAS_ROOT pointed at it — see test_labs.py.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from skillfence.governance.inventory import build_inventory
from skillfence.lab_runner import run_lab
from skillfence.policy.store import PolicyStore

DVAS_ROOT = Path(os.environ.get("DVAS_ROOT", str(Path(__file__).resolve().parents[1].parent / "DVAS")))

pytestmark = pytest.mark.skipif(
    not DVAS_ROOT.is_dir(),
    reason=f"DVAS lab suite not found at {DVAS_ROOT} — clone https://github.com/shaikarifali/DVAS "
    "alongside this repo, or set DVAS_ROOT, to run these tests.",
)


def _copy_fleet(tmp_path: Path, lab_name: str) -> Path:
    source = DVAS_ROOT / "AST09" / lab_name / "fleet"
    if not source.is_dir():
        pytest.skip(f"{source} not found")
    dest = tmp_path / "fleet"
    shutil.copytree(source, dest, ignore=shutil.ignore_patterns(".runs", ".skillfence"))
    return dest


def test_shadow_skill_flagged_never_reviewed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SKILLFENCE_POLICY_STORE", str(tmp_path / "policy_grants.json"))
    fleet = _copy_fleet(tmp_path, "01-beginner-shadow-skill")

    run_lab(fleet / "invoice-bot", decision="reject")
    run_lab(fleet / "report-bot", decision="reject")

    rows = {r.skill: r for r in build_inventory(fleet, policy_store=PolicyStore(tmp_path / "policy_grants.json"))}
    assert rows["invoice-bot"].clean
    assert rows["report-bot"].clean
    assert not rows["shadow-sync"].ever_reviewed
    assert "never reviewed" in rows["shadow-sync"].flags


def test_stale_approval_flagged_ungoverned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    store_path = tmp_path / "policy_grants.json"
    monkeypatch.setenv("SKILLFENCE_POLICY_STORE", str(store_path))
    fleet = _copy_fleet(tmp_path, "02-intermediate-stale-approval")

    for skill in ("payroll-sync", "ticket-bot", "metrics-collector", "doc-indexer"):
        run_lab(fleet / skill, decision="reject")
    run_lab(fleet / "legacy-exporter", decision="allow_scoped")

    rows = {r.skill: r for r in build_inventory(fleet, policy_store=PolicyStore(store_path))}
    for skill in ("payroll-sync", "ticket-bot", "metrics-collector", "doc-indexer"):
        assert rows[skill].clean
    assert rows["legacy-exporter"].active_grants == 1
    assert rows["legacy-exporter"].ungoverned_grants == 1
    assert not rows["legacy-exporter"].clean


def test_scope_creep_grant_distinguishes_reviewed_from_forgotten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    store_path = tmp_path / "policy_grants.json"
    monkeypatch.setenv("SKILLFENCE_POLICY_STORE", str(store_path))
    fleet = _copy_fleet(tmp_path, "03-advanced-scope-creep-grant")

    for skill in ("api-gateway-monitor", "cache-warmer", "webhook-dispatcher", "data-archiver"):
        run_lab(fleet / skill, decision="reject")

    # slack-notifier: approved, then reviewed again afterward -- stays governed
    run_lab(fleet / "slack-notifier", decision="allow_scoped")
    run_lab(fleet / "slack-notifier", decision="reject")

    # credential-rotator: approved, never reviewed again -- becomes ungoverned
    run_lab(fleet / "credential-rotator", decision="allow_scoped")

    rows = {r.skill: r for r in build_inventory(fleet, policy_store=PolicyStore(store_path))}
    for skill in ("api-gateway-monitor", "cache-warmer", "webhook-dispatcher", "data-archiver"):
        assert rows[skill].clean

    assert rows["slack-notifier"].active_grants == 1
    assert rows["slack-notifier"].clean, "re-reviewed after the grant -- must not be flagged"

    assert rows["credential-rotator"].active_grants == 1
    assert rows["credential-rotator"].ungoverned_grants == 1
    assert not rows["credential-rotator"].clean, "never reviewed again -- must be flagged"
