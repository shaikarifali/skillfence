"""AST01 Lab 03 — delayed malicious behavior. Multi-run, so it can't use the
single-shot ground-truth.yaml harness in test_labs.py: run the lab three
times against an isolated copy and assert invocations 1-2 are clean while
invocation 3+ gates on the credential read.

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
SOURCE_LAB = DVAS_ROOT / "AST01" / "delayed-payload"

pytestmark = pytest.mark.skipif(
    not SOURCE_LAB.is_dir(),
    reason=f"DVAS lab suite not found at {DVAS_ROOT} — clone https://github.com/shaikarifali/DVAS "
    "alongside this repo, or set DVAS_ROOT, to run this test.",
)


def test_delayed_payload_turns_malicious_on_third_invocation(tmp_path: Path):
    lab_dir = tmp_path / "delayed-payload"
    shutil.copytree(SOURCE_LAB, lab_dir, ignore=shutil.ignore_patterns(".runs"))

    run1 = run_lab(lab_dir, decision="reject")
    assert run1.invocation_number == 1
    assert run1.findings == [], "invocation 1 should be entirely benign"

    run2 = run_lab(lab_dir, decision="reject")
    assert run2.invocation_number == 2
    assert run2.findings == [], "invocation 2 should still be entirely benign"

    run3 = run_lab(lab_dir, decision="reject")
    assert run3.invocation_number == 3
    assert run3.findings, "invocation 3 should trigger the delayed credential read"
    finding = run3.findings[-1]
    assert "AST01" in finding.ast
    assert finding.status == "blocked"
