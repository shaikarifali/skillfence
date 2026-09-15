"""Data layer for the Lab Explorer web UI — a live, dynamic view over the
exact same lab directories `skillfence lab list`/`run`/`bench` already
read, and the exact same `run_lab()` every one of those commands calls.
No parallel lab format, no separate "web" representation of a lab: this
module only ever reads real files and calls the real engine.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from skillfence.cli.lab_catalog import discover_labs
from skillfence.lab_runner import run_lab
from skillfence.policy.manifest import CapabilityManifest


def _ast_of(lab_dir: Path, labs_root: Path) -> str:
    try:
        rel = lab_dir.relative_to(labs_root)
        return rel.parts[0].upper() if rel.parts else "-"
    except ValueError:
        return "-"


def list_labs(root: Path) -> list[dict]:
    """One summary row per discovered `skill/manifest.yaml` under `root` --
    the same discovery `skillfence lab list` uses, so this never drifts
    from what the CLI itself would show.
    """
    return [
        {
            "name": i.name,
            "ast": i.ast,
            "skill_name": i.skill_name,
            "purpose": i.purpose,
            "malicious": i.malicious,
            "title": i.title,
        }
        for i in discover_labs(root)
    ]


def lab_detail(root: Path, name: str) -> dict | None:
    """Full detail for one lab: declared capabilities, `SKILL.md`,
    `README.md`, and its `ground-truth.yaml` expectation, if any of those
    exist -- exactly the files a human would open to review this lab
    themselves. Returns `None` if `name` doesn't resolve to a real lab
    directory under `root` (including an attempt to escape `root` via
    `..` -- resolved and checked before anything is read).
    """
    root = root.resolve()
    lab_dir = (root / name).resolve()
    if root not in lab_dir.parents and lab_dir != root:
        return None
    manifest_path = lab_dir / "skill" / "manifest.yaml"
    if not manifest_path.exists():
        return None
    try:
        manifest = CapabilityManifest.load(manifest_path)
    except Exception:  # noqa: BLE001 — a broken lab shouldn't crash the UI
        return None

    skill_md_path = lab_dir / "skill" / "SKILL.md"
    readme_path = lab_dir / "README.md"
    gt_path = lab_dir / "ground-truth.yaml"

    ground_truth: dict | None = None
    if gt_path.exists():
        try:
            ground_truth = yaml.safe_load(gt_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            ground_truth = None

    runs_dir = lab_dir / ".runs"
    session_count = len(list(runs_dir.glob("*.events.jsonl"))) if runs_dir.exists() else 0

    return {
        "name": name,
        "ast": _ast_of(lab_dir, root),
        "skill_name": manifest.name,
        "version": manifest.version,
        "purpose": manifest.purpose,
        "capabilities": manifest.capabilities.model_dump(),
        "security": manifest.security.model_dump(),
        "skill_md": skill_md_path.read_text(encoding="utf-8") if skill_md_path.exists() else None,
        "readme": readme_path.read_text(encoding="utf-8") if readme_path.exists() else None,
        "ground_truth": ground_truth,
        "runnable": (lab_dir / "script.yaml").exists(),
        "session_count": session_count,
    }


def run_lab_via_ui(root: Path, name: str, *, decision: str) -> dict | None:
    """Runs the exact same `run_lab()` the CLI's `run`/`bench` call --
    same engine, same policy store, same JSONL audit trail written to the
    lab's own `.runs/` directory. Returns `None` if `name` isn't a real,
    runnable (has a `script.yaml`) lab under `root`. Raises `ValueError`
    if `decision` isn't a real `DecisionType` value -- the caller turns
    that into an HTTP 400, same as a bad CLI `--decision` flag would exit
    non-zero.
    """
    root = root.resolve()
    lab_dir = (root / name).resolve()
    if root not in lab_dir.parents and lab_dir != root:
        return None
    if not (lab_dir / "script.yaml").exists():
        return None

    result = run_lab(lab_dir, decision=decision)
    steps = [{"action": r.step.get("action"), "status": r.status, "detail": r.detail} for r in result.report.results]
    findings = [{**f.model_dump(), "explain": f.explain()} for f in result.findings]
    return {
        "session_id": result.session_id,
        "invocation_number": result.invocation_number,
        "steps": steps,
        "findings": findings,
    }
