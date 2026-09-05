"""Lab discovery — shared by `lab list`, `learn`, and `inspect`."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from skillfence.policy.manifest import CapabilityManifest


@dataclass
class LabInfo:
    dir: Path
    ast: str
    name: str
    skill_name: str
    purpose: list[str]
    malicious: bool | None  # None if no ground-truth.yaml (learning-only lab without a scored answer)
    title: str | None


def _ast_of(lab_dir: Path, labs_root: Path) -> str:
    try:
        rel = lab_dir.relative_to(labs_root)
        return rel.parts[0].upper() if rel.parts else "-"
    except ValueError:
        return "-"


def discover_labs(labs_root: Path) -> list[LabInfo]:
    labs_root = labs_root.resolve()
    infos: list[LabInfo] = []
    for manifest_path in sorted(labs_root.glob("**/skill/manifest.yaml")):
        lab_dir = manifest_path.parent.parent
        try:
            manifest = CapabilityManifest.load(manifest_path)
        except Exception:  # noqa: BLE001 — a broken lab shouldn't crash discovery
            continue

        malicious: bool | None = None
        title: str | None = None
        gt_path = lab_dir / "ground-truth.yaml"
        if gt_path.exists():
            gt = yaml.safe_load(gt_path.read_text(encoding="utf-8")) or {}
            malicious = bool(gt.get("ground_truth", {}).get("malicious"))
            title = gt.get("title")

        infos.append(
            LabInfo(
                dir=lab_dir,
                ast=_ast_of(lab_dir, labs_root),
                name=lab_dir.relative_to(labs_root).as_posix(),
                skill_name=manifest.name,
                purpose=manifest.purpose,
                malicious=malicious,
                title=title,
            )
        )
    return infos
