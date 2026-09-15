"""AST07 (Update Drift, behavioral-baseline variant) DVAS labs. Multi-run,
so they can't use the single-shot ground-truth.yaml harness in
test_labs.py: each one is clean on invocation 1 and gates on invocation 2,
mirroring test_delayed_payload.py's convention.

Requires the DVAS lab suite (https://github.com/shaikarifali/DVAS) cloned
alongside this repo, or DVAS_ROOT pointed at it — see test_labs.py.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from skillfence.lab_runner import run_lab

DVAS_ROOT = Path(os.environ.get("DVAS_ROOT", str(Path(__file__).resolve().parents[1].parent / "DVAS")))

pytestmark = pytest.mark.skipif(
    not DVAS_ROOT.is_dir(),
    reason=f"DVAS lab suite not found at {DVAS_ROOT} — clone https://github.com/shaikarifali/DVAS "
    "alongside this repo, or set DVAS_ROOT, to run these tests.",
)


def _run_twice(tmp_path: Path, lab_name: str):
    source_lab = DVAS_ROOT / "AST07" / lab_name
    if not source_lab.is_dir():
        pytest.skip(f"{source_lab} not found")
    lab_dir = tmp_path / lab_name
    shutil.copytree(source_lab, lab_dir, ignore=shutil.ignore_patterns(".runs"))

    run1 = run_lab(lab_dir, decision="reject")
    run2 = run_lab(lab_dir, decision="reject")
    return run1, run2


def test_silent_patch_clean_then_gates(tmp_path: Path):
    run1, run2 = _run_twice(tmp_path, "01-beginner-silent-patch")
    assert run1.invocation_number == 1
    assert run1.findings == [], "invocation 1 only touches an ordinary declared-looking file"
    assert run2.invocation_number == 2
    assert run2.findings, "invocation 2's sensitive read is a capability never seen before"
    finding = run2.findings[-1]
    assert "AST07" in finding.ast
    assert finding.severity == "critical"
    assert finding.status == "blocked"


def test_quiet_egress_clean_then_gates(tmp_path: Path):
    run1, run2 = _run_twice(tmp_path, "02-intermediate-quiet-egress")
    assert run1.findings == [], "invocation 1 only uses the first of two declared, allowed domains"
    assert run2.findings, "invocation 2 activates the second declared-but-dormant domain"
    finding = run2.findings[-1]
    assert "AST07" in finding.ast
    assert finding.severity == "high"
    assert finding.status == "blocked"


def test_open_policy_drift_clean_then_gates(tmp_path: Path):
    run1, run2 = _run_twice(tmp_path, "03-advanced-open-policy-drift")
    assert run1.findings == [], "invocation 1's destination is 'declared' under the open network policy"
    assert run2.findings, "invocation 2's new destination is equally 'declared' -- only the baseline catches it"
    finding = run2.findings[-1]
    assert "AST07" in finding.ast
    assert finding.severity == "high"
    assert finding.status == "blocked"
