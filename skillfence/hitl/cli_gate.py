"""Interactive CLI human decision gate.

This is the enforcement boundary: for HIGH/CRITICAL risk, execution is
genuinely blocked until this returns a DecisionRecord that grants it.
Fail-safe: if there's no interactive terminal to ask, HIGH/CRITICAL
default-denies rather than silently proceeding.
"""

from __future__ import annotations

import sys
from typing import Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from skillfence.hitl.decisions import DecisionRecord, DecisionRequest, DecisionType

# maps single-key CLI shortcuts to DecisionType
KEY_MAP = {
    "a": DecisionType.APPROVE_ONCE,
    "r": DecisionType.REJECT,
    "s": DecisionType.ALLOW_SCOPED,
    "q": DecisionType.QUARANTINE_SKILL,
    "i": DecisionType.INSPECT_CHAIN,
    "d": DecisionType.ALWAYS_DENY_RULE,
}

AutoDecider = Callable[[DecisionRequest], DecisionType]


class HumanGate:
    def __init__(
        self,
        console: Optional[Console] = None,
        *,
        auto_decider: Optional[AutoDecider] = None,
    ) -> None:
        """`auto_decider`, when set, answers decision requests without a TTY —
        used by DVAS/tests/replay so the whole pipeline stays scriptable while
        keeping a real human as the default path for a live demo.
        """
        self.console = console or Console()
        self.auto_decider = auto_decider

    def decide(self, request: DecisionRequest, *, explanation: str, provenance: str | None) -> DecisionRecord:
        if self.auto_decider is not None:
            decision = self.auto_decider(request)
            return DecisionRecord(decision=decision, actor="auto", event_id=request.event_id)

        if not sys.stdin.isatty():
            # fail-safe: no human available, HIGH/CRITICAL denies
            self.console.print(
                "[bold red]No interactive terminal available — failing safe (REJECT).[/bold red]"
            )
            return DecisionRecord(
                decision=DecisionType.REJECT,
                actor="fail-safe",
                event_id=request.event_id,
                reason="no human available; high/critical actions default-deny",
            )

        self._render(request, explanation=explanation, provenance=provenance)

        while True:
            choice = Prompt.ask(
                "[a] Approve once  [r] Reject  [s] Allow scoped  [q] Quarantine  [i] Inspect provenance",
                default="r",
            ).strip().lower()
            if choice == "i":
                self.console.print(Panel(provenance or "(no provenance available)", title="Provenance"))
                continue
            decision_type = KEY_MAP.get(choice)
            if decision_type is None:
                self.console.print("[yellow]Unrecognized option, try again.[/yellow]")
                continue
            reason = Prompt.ask("Reason (optional)", default="")
            return DecisionRecord(decision=decision_type, event_id=request.event_id, reason=reason)

    def _render(self, request: DecisionRequest, *, explanation: str, provenance: str | None) -> None:
        risk = request.risk.upper()
        color = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(
            request.risk, "red"
        )
        header = f"🚨 {risk} — HUMAN DECISION REQUIRED" if risk in ("HIGH", "CRITICAL") else risk

        body = [
            f"[bold]AST:[/bold] {' / '.join(request.ast) or '-'}",
            f"[bold]CDS:[/bold] {request.cds:.2f} ({request.cds_band})",
            f"[bold]Skill:[/bold] {request.skill}",
            f"[bold]Requested:[/bold] {request.requested_action} {request.target or ''}",
            "",
            explanation,
            "",
            f"[bold]Recommended:[/bold] {request.recommended_action.upper()}",
        ]
        self.console.print(Panel("\n".join(body), title=header, border_style=color))
