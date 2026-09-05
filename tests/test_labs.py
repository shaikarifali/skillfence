"""Regression suite driven by every DVAS lab's ground-truth.yaml.

DVAS (the vulnerable lab suite this runtime is benchmarked against) lives
in its own repository: https://github.com/shaikarifali/DVAS. Clone it as a
sibling of this repo (so you have `skillfence/` and `DVAS/` side by side),
or point `DVAS_ROOT` at wherever you cloned it:

    git clone https://github.com/shaikarifali/DVAS ../DVAS
    pytest tests/test_labs.py
    # or: DVAS_ROOT=/path/to/DVAS pytest tests/test_labs.py

If DVAS isn't found, these tests are skipped rather than failing — they
exercise the tool against an external, versioned corpus, not code that
lives in this repo.

No live network calls (all labs run fully offline against local fixtures),
so this is safe to run in CI once DVAS is checked out alongside it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from skillfence.lab_runner import run_lab

DVAS_ROOT = Path(os.environ.get("DVAS_ROOT", str(Path(__file__).resolve().parents[1].parent / "DVAS")))

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _discover_labs() -> list[Path]:
    if not DVAS_ROOT.is_dir():
        return []
    return sorted(p.parent for p in DVAS_ROOT.glob("**/ground-truth.yaml"))


_LABS = _discover_labs()

pytestmark = pytest.mark.skipif(
    not _LABS,
    reason=f"DVAS lab suite not found at {DVAS_ROOT} — clone https://github.com/shaikarifali/DVAS "
    "alongside this repo, or set DVAS_ROOT, to run these tests.",
)


@pytest.mark.parametrize("lab_dir", _LABS or [Path(".")], ids=lambda p: p.relative_to(DVAS_ROOT).as_posix() if _LABS else "skipped")
def test_lab_matches_ground_truth(lab_dir: Path):
    gt = yaml.safe_load((lab_dir / "ground-truth.yaml").read_text(encoding="utf-8"))
    result = run_lab(lab_dir, decision="reject")

    if not gt["ground_truth"]["malicious"]:
        assert len(result.findings) == gt.get("expected_findings", 0), (
            f"benign lab {lab_dir} produced {len(result.findings)} finding(s) — false positive"
        )
        return

    assert result.findings, f"malicious lab {lab_dir} produced no findings — false negative"

    expected = gt["expected_finding"]
    top = result.findings[-1]  # the finding tied to the deepest/most-escalated action
    assert set(expected["ast"]).issubset(set(top.ast)), f"expected AST tags {expected['ast']}, got {top.ast}"
    min_severity = SEVERITY_ORDER[expected["severity_at_least"]]
    assert SEVERITY_ORDER[top.severity] >= min_severity, (
        f"expected severity >= {expected['severity_at_least']}, got {top.severity}"
    )

    if "expected_attack_chain" in gt:
        for expected_chain in gt["expected_attack_chain"]:
            assert any(expected_chain in f.attack_chain for f in result.findings), (
                f"expected attack chain '{expected_chain}' not found in any finding"
            )

    if gt.get("expected_decision", {}).get("human_gate"):
        assert top.human_gate is True
        assert top.status == "blocked"  # every test forces --decision reject
