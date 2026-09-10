"""Tests for `skillfence profile` and `skillfence report --sarif`. Uses one
real DVAS lab as a fixture (same DVAS_ROOT convention as test_labs.py) since
both features are consolidations over real run history, not something
meaningfully testable against a synthetic zero-history skill alone.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from skillfence.fingerprint.behavior import record_and_diff
from skillfence.lab_runner import run_lab
from skillfence.reporting.security_report import build_report
from skillfence.reporting.skill_profile import build_profile
from skillfence.storage.jsonl_store import append_jsonl

DVAS_ROOT = Path(os.environ.get("DVAS_ROOT", str(Path(__file__).resolve().parents[1].parent / "DVAS")))
_LAB = DVAS_ROOT / "AST01" / "credential-reader"

pytestmark = pytest.mark.skipif(
    not _LAB.is_dir(),
    reason=f"DVAS lab suite not found at {DVAS_ROOT} — clone https://github.com/shaikarifali/DVAS "
    "alongside this repo, or set DVAS_ROOT, to run these tests.",
)


@pytest.fixture
def ran_lab(tmp_path: Path) -> Path:
    lab_dir = tmp_path / "credential-reader"
    shutil.copytree(_LAB, lab_dir, ignore=shutil.ignore_patterns(".runs"))

    # run_lab() alone only executes the script and returns results in
    # memory — persisting findings.jsonl and the fingerprint history is
    # done by the CLI's `run` command (skillfence/cli/main.py), not by
    # run_lab() itself. Replicate exactly what it does so this fixture
    # matches real `skillfence run` usage instead of a partial simulation.
    result = run_lab(lab_dir, decision="reject")
    findings_path = lab_dir / ".runs" / "findings.jsonl"
    for finding in result.findings:
        append_jsonl(findings_path, finding.model_dump())
    record_and_diff(
        lab_dir / ".runs",
        invocation_number=result.invocation_number,
        session_id=result.session_id,
        events_path=result.events_path,
    )
    return lab_dir


def test_profile_before_any_run_is_declared_only(tmp_path: Path):
    lab_dir = tmp_path / "credential-reader"
    shutil.copytree(_LAB, lab_dir, ignore=shutil.ignore_patterns(".runs"))
    profile = build_profile(lab_dir)
    assert profile.status == "NOT YET RUN"
    assert profile.run_count == 0
    assert profile.declared_fs_read  # still shows the declared side


def test_profile_after_blocked_run_shows_review_required(ran_lab: Path):
    profile = build_profile(ran_lab)
    assert profile.run_count == 1
    assert profile.status in ("REVIEW REQUIRED", "CRITICAL HISTORY")
    assert profile.finding_counts["high"] + profile.finding_counts["critical"] >= 1
    assert profile.latest_finding_title is not None


def test_profile_to_dict_round_trips_key_fields(ran_lab: Path):
    profile = build_profile(ran_lab)
    data = profile.to_dict()
    assert data["skill"] == profile.skill
    assert data["status"] == profile.status
    assert data["history"]["latest_finding_title"] == profile.latest_finding_title


def test_sarif_output_has_one_result_per_finding(ran_lab: Path):
    report = build_report(ran_lab)
    sarif = report.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(report.findings)
    rule_ids = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    result_rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert result_rule_ids.issubset(rule_ids)


def test_sarif_severity_maps_to_error_level(ran_lab: Path):
    report = build_report(ran_lab)
    sarif = report.to_sarif()
    for finding, result in zip(report.findings, sarif["runs"][0]["results"]):
        if finding.get("severity") in ("critical", "high"):
            assert result["level"] == "error"
