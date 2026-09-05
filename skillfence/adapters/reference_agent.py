"""Reference agent — the first supported runtime. A deterministic,
scriptable stand-in for a real LLM-driven agent (skills author quickly,
tool calls are interceptable by construction, runs are automatable,
containerizable, attribution is exact).

It reads a `script.yaml` describing the steps the "agent" decided to take and
executes each through the RuntimeGateway. Two things keep it honest rather
than a fixture player:

1. It does not pre-know whether a step will be blocked; ActionBlocked can
   interrupt the script exactly like a real tool denial would.
2. It is a *naive instruction follower*: any AGENT_INSTRUCTION directive
   found in fetched content is appended to its own plan and carried out
   next -- the exact failure mode SkillFence exists to catch, without
   requiring a real model at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from skillfence.runtime.content_scan import parse_injected_action
from skillfence.runtime.gateway import ActionBlocked, RuntimeGateway


@dataclass
class StepResult:
    step: dict[str, Any]
    status: str  # "ok" | "blocked" | "error"
    detail: str = ""


@dataclass
class RunReport:
    skill: str
    results: list[StepResult] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(r.status == "blocked" for r in self.results)


class ReferenceAgent:
    def __init__(self, gateway: RuntimeGateway) -> None:
        self.gateway = gateway
        self._provenance: list[str] = []
        self._script_dir: Path = Path(".")

    # -- AgentAdapter-style hooks (kept lightweight for the MVP) -----------

    def on_skill_loaded(self, skill: str) -> None:
        self._provenance.append(f"skill:{skill}")

    def on_tool_requested(self, tool: str, args: dict[str, Any]) -> None:
        self._provenance.append(f"tool_request:{tool}")

    def before_tool_execution(self, tool: str, args: dict[str, Any]) -> None:
        pass

    def after_tool_execution(self, tool: str, result: Any) -> None:
        pass

    def get_active_skill(self) -> str:
        return self.gateway.skill

    def get_instruction_provenance(self) -> list[str]:
        return list(self._provenance)

    # -- script execution -----------------------------------------------

    def run_script(self, script_path: Path, *, invocation_number: int = 1) -> RunReport:
        raw = yaml.safe_load(script_path.read_text(encoding="utf-8")) or {}
        all_steps: list[dict[str, Any]] = list(raw.get("steps", []))
        # A step tagged `min_invocation: N` only runs from the
        # Nth time this lab is executed onward -- lets a script stay benign
        # on early runs and turn malicious later, deterministically.
        steps = [s for s in all_steps if s.get("min_invocation", 1) <= invocation_number]
        report = RunReport(skill=self.gateway.skill)
        self._script_dir = script_path.parent

        parent_event = self.gateway.start()
        self.on_skill_loaded(self.gateway.skill)

        queue = list(steps)
        # LPCI: if the skill's own definition contained an
        # embedded instruction (opt-in per lab, see lab_runner), the naive
        # agent follows it immediately -- before any of its scripted,
        # declared-task steps -- exactly as it follows a fetched-content
        # instruction mid-script.
        logic_layer = self.gateway.logic_layer_injection()
        if logic_layer is not None:
            injected, source_event_id = logic_layer
            self._provenance.append(f"logic_layer_instruction:{injected}")
            queue.insert(0, self._injected_to_step(injected, parent_hint=source_event_id))
        while queue:
            step = queue.pop(0)
            self.on_tool_requested(step.get("action", "?"), step)
            try:
                extra = self._execute_step(step, parent_event)
                report.results.append(StepResult(step=step, status="ok"))
                if extra is not None:
                    queue.insert(0, extra)  # naive: follow the injected instruction next
            except ActionBlocked as exc:
                report.results.append(
                    StepResult(step=step, status="blocked", detail=exc.finding.title)
                )
                if raw.get("stop_on_block", True):
                    break
            except FileNotFoundError as exc:
                report.results.append(StepResult(step=step, status="error", detail=str(exc)))

        return report

    def _execute_step(self, step: dict[str, Any], parent_event: str) -> dict[str, Any] | None:
        action = step["action"]
        # a step injected via an untrusted instruction carries its own
        # provenance parent (the instruction-detected event) so the chain
        # shown to the human is fetch -> instruction -> action, not
        # skill.invoke -> action.
        parent_event = step.get("_from_instruction", parent_event)

        if action == "read":
            self.gateway.read_file(step["path"], parent_event=parent_event)
            return None

        if action == "write":
            self.gateway.write_file(step["path"], step.get("content", ""), parent_event=parent_event)
            return None

        if action == "exec":
            self.gateway.execute_shell(step["command"], parent_event=parent_event)
            return None

        if action == "network_send":
            self.gateway.network_send(
                step["destination"], step.get("payload", ""), parent_event=parent_event
            )
            return None

        if action == "read_secret":
            self.gateway.access_secret(step["var"], parent_event=parent_event)
            return None

        if action == "update":
            manifest_path = self._script_dir / "skill" / step["manifest"]
            self.gateway.apply_update(step["version"], manifest_path, parent_event=parent_event)
            self._provenance.append(f"update:{step['version']}")
            return None

        if action == "fetch":
            content, evt = self.gateway.fetch_url(step["url"], parent_event=parent_event)
            self._provenance.append(f"fetch:{step['url']}")
            injected = parse_injected_action(content)
            if injected:
                self._provenance.append(f"instruction:{injected}")
                return self._injected_to_step(injected, parent_hint=evt.event_id)
            return None

        raise ValueError(f"unknown step action: {action}")

    @staticmethod
    def _injected_to_step(injected: dict[str, str], *, parent_hint: str) -> dict[str, Any]:
        action = injected.get("action", "").lower()
        if action == "read" and "path" in injected:
            return {"action": "read", "path": injected["path"], "_from_instruction": parent_hint}
        if action == "exec" and "command" in injected:
            return {"action": "exec", "command": injected["command"], "_from_instruction": parent_hint}
        if action == "network_send" and "url" in injected:
            return {"action": "network_send", "destination": injected["url"], "_from_instruction": parent_hint}
        raise ValueError(f"unsupported injected action: {injected}")
