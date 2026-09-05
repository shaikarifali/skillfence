"""Shared lab-loading/execution logic used by the CLI, the benchmark runner,
and tests.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console

from skillfence.adapters.reference_agent import ReferenceAgent, RunReport
from skillfence.events.bus import EventBus
from skillfence.findings.schema import Finding
from skillfence.hitl.cli_gate import HumanGate
from skillfence.hitl.decisions import DecisionType
from skillfence.policy.manifest import CapabilityManifest
from skillfence.policy.store import PolicyStore, default_policy_store_path
from skillfence.runtime.gateway import RuntimeGateway
from skillfence.runtime.sandbox import Sandbox


def load_sandbox(lab_dir: Path) -> Sandbox:
    sandbox_root = lab_dir / "sandbox"
    fake_internet_dir = sandbox_root / "fake_internet"
    fake_internet: dict[str, Path] = {}
    manifest_path = sandbox_root / "fake_internet.yaml"
    if manifest_path.exists():
        mapping = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        for url, fname in mapping.items():
            fake_internet[url] = fake_internet_dir / fname

    lab_config_path = lab_dir / "lab.yaml"
    allowed_commands: set[str] = set()
    if lab_config_path.exists():
        lab_config = yaml.safe_load(lab_config_path.read_text(encoding="utf-8")) or {}
        allowed_commands = set(lab_config.get("allowed_shell_commands", []))

    return Sandbox(
        root=sandbox_root,
        fake_internet=fake_internet,
        allowed_shell_commands=allowed_commands,
        exfil_capture_path=sandbox_root / "_exfil_capture.txt",
    )


@dataclass
class LabRunResult:
    session_id: str
    report: RunReport
    findings: list[Finding]
    events_path: Path
    gateway: RuntimeGateway
    invocation_number: int


def run_lab(
    lab_dir: Path,
    *,
    decision: Optional[str] = None,
    mode: str = "enforce",
    console: Optional[Console] = None,
    use_policy_store: bool = True,
) -> LabRunResult:
    """Load a lab directory (skill/manifest.yaml, sandbox/, script.yaml) and
    run its scripted reference-agent steps through the runtime gateway.
    """
    lab_dir = lab_dir.resolve()
    manifest_path = lab_dir / "skill" / "manifest.yaml"
    script_path = lab_dir / "script.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"no manifest.yaml at {manifest_path}")
    if not script_path.exists():
        raise FileNotFoundError(f"no script.yaml at {script_path}")

    sandbox = load_sandbox(lab_dir)
    manifest = CapabilityManifest.load(manifest_path, workspace=sandbox.root)

    # LPCI: scanning a skill's own SKILL.md for embedded
    # instruction-like text is opt-in per lab via lab.yaml, not automatic --
    # a lab's *documentation* describing this exact attack (e.g. AST05's
    # README/SKILL.md, which mentions "AGENT_INSTRUCTION:" in prose) would
    # otherwise false-positive on itself.
    skill_definition_text: str | None = None
    lab_config_path = lab_dir / "lab.yaml"
    if lab_config_path.exists():
        lab_config = yaml.safe_load(lab_config_path.read_text(encoding="utf-8")) or {}
        if lab_config.get("scan_skill_definition"):
            skill_md_path = lab_dir / "skill" / "SKILL.md"
            if skill_md_path.exists():
                skill_definition_text = skill_md_path.read_text(encoding="utf-8")

    session_id = f"session-{uuid.uuid4().hex[:8]}"
    runs_dir = lab_dir / ".runs"
    # Delayed malicious behavior support: count prior runs of this lab
    # before creating this run's own events file, so a script can vary its
    # steps by `min_invocation` (1-indexed) -- benign on early invocations,
    # malicious later. Demonstrates why one-time static validation isn't
    # enough even for runtime scanning done only once.
    invocation_number = len(list(runs_dir.glob("*.events.jsonl"))) + 1 if runs_dir.exists() else 1
    events_path = runs_dir / f"{session_id}.events.jsonl"

    bus = EventBus(events_path)

    auto_decider = None
    if decision is not None:
        forced = DecisionType(decision)
        auto_decider = lambda _req, _forced=forced: _forced  # noqa: E731

    human_gate = HumanGate(console=console, auto_decider=auto_decider)
    # Org-wide, not per-lab (Decision Memory): a grant keys on
    # skill+action+resource only, so it's honored across every lab/skill
    # that matches, not just this one directory. `skillfence policy` manages
    # this same store directly.
    policy_store = PolicyStore(default_policy_store_path()) if use_policy_store else None

    gateway = RuntimeGateway(
        bus=bus,
        manifest=manifest,
        sandbox=sandbox,
        human_gate=human_gate,
        session_id=session_id,
        agent="reference-agent",
        skill=manifest.name,
        observe_mode=(mode == "observe"),
        policy_store=policy_store,
        skill_definition_text=skill_definition_text,
    )

    agent = ReferenceAgent(gateway)
    report = agent.run_script(script_path, invocation_number=invocation_number)

    return LabRunResult(
        session_id=session_id,
        report=report,
        findings=gateway.findings,
        events_path=events_path,
        gateway=gateway,
        invocation_number=invocation_number,
    )
