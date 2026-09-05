"""Deterministic risk scoring — explicitly NOT an LLM.

Score is additive from named, auditable factors. Every factor that fired is
kept so findings/CLI can show "why flagged" instead of a bare number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from skillfence.events.schema import Severity

# Named factors
SCORE_SENSITIVE_CREDENTIAL_READ = 40
SCORE_UNDECLARED_CAPABILITY = 20
SCORE_NETWORK_EGRESS = 20
SCORE_UNKNOWN_DESTINATION = 10
SCORE_EXTERNAL_INSTRUCTION_INVOLVED = 20
SCORE_PREVIOUSLY_APPROVED_EXACT_ACTION = -20
SCORE_WORKING_DIRECTORY_ACCESS = -20

# LPCI (AST01): an instruction-like directive embedded in the
# skill's own definition, not in fetched external content. Same weight as
# SCORE_EXTERNAL_INSTRUCTION_INVOLVED (it's an equally untrusted source of
# "why is the agent doing this"), kept as a separate named factor so
# why_flagged/report text can say which kind of instruction was involved.
SCORE_LOGIC_LAYER_INSTRUCTION_INVOLVED = 20

# AST02 (supply-chain compromise): a capability that only became
# declared/reachable after a skill update, exercised shortly after that
# update. This fires even when the (possibly compromised) new manifest
# "declares" it -- the signal is the behavior *delta* across the update,
# which policy-declared-vs-observed alone would miss.
SCORE_BEHAVIOR_CHANGED_AFTER_UPDATE = 30

THRESHOLDS = (
    (29, Severity.LOW),
    (49, Severity.MEDIUM),
    (69, Severity.HIGH),
)

# A named, quantified Capability Drift Score. Deliberately *not* a second, independently-tuned
# scoring formula — that would let CDS and RISK disagree, which is exactly
# the kind of "two sources of truth" bug this project's whole design avoids
# elsewhere (one deterministic score, several presentations of it). CDS is
# the same additive score normalized to 0.0-1.0, so a human reading "CDS:
# 0.87 (CRITICAL)" is reading the same evidence as "RISK: CRITICAL", not a
# rival opinion about it.
CDS_SCALE = 100.0
CDS_BAND_THRESHOLDS = (
    (0.2, "ALLOW"),
    (0.5, "WARN"),
    (0.8, "GATE"),
)


def cds_band(cds: float) -> str:
    for ceiling, band in CDS_BAND_THRESHOLDS:
        if cds <= ceiling:
            return band
    return "BLOCK"


@dataclass
class RiskAssessment:
    score: int
    severity: Severity
    factors: list[str] = field(default_factory=list)

    @property
    def requires_human_gate(self) -> bool:
        return self.severity in (Severity.HIGH, Severity.CRITICAL)

    @property
    def recommended_action(self) -> str:
        return "reject" if self.severity == Severity.CRITICAL else "review"

    @property
    def cds(self) -> float:
        return round(min(self.score, CDS_SCALE) / CDS_SCALE, 2)

    @property
    def cds_band(self) -> str:
        return cds_band(self.cds)


def score_to_severity(score: int) -> Severity:
    for ceiling, severity in THRESHOLDS:
        if score <= ceiling:
            return severity
    return Severity.CRITICAL


class RiskEngine:
    """Accumulates named factors into a score, then maps to severity."""

    def assess(
        self,
        *,
        sensitive_credential_read: bool = False,
        undeclared_capability: bool = False,
        network_egress: bool = False,
        unknown_destination: bool = False,
        external_instruction_involved: bool = False,
        logic_layer_instruction_involved: bool = False,
        previously_approved_exact_action: bool = False,
        working_directory_access: bool = False,
        behavior_changed_after_update: bool = False,
    ) -> RiskAssessment:
        score = 0
        factors: list[str] = []

        def add(flag: bool, points: int, label: str) -> None:
            nonlocal score
            if flag:
                score += points
                factors.append(f"{label} ({points:+d})")

        add(sensitive_credential_read, SCORE_SENSITIVE_CREDENTIAL_READ, "sensitive credential read")
        add(undeclared_capability, SCORE_UNDECLARED_CAPABILITY, "undeclared capability")
        add(network_egress, SCORE_NETWORK_EGRESS, "network egress")
        add(unknown_destination, SCORE_UNKNOWN_DESTINATION, "unknown destination")
        add(
            external_instruction_involved,
            SCORE_EXTERNAL_INSTRUCTION_INVOLVED,
            "external instruction involved",
        )
        add(
            logic_layer_instruction_involved,
            SCORE_LOGIC_LAYER_INSTRUCTION_INVOLVED,
            "logic-layer instruction involved (skill's own definition, not external content)",
        )
        add(
            previously_approved_exact_action,
            SCORE_PREVIOUSLY_APPROVED_EXACT_ACTION,
            "previously approved exact action",
        )
        add(
            working_directory_access,
            SCORE_WORKING_DIRECTORY_ACCESS,
            "working-directory access",
        )
        add(
            behavior_changed_after_update,
            SCORE_BEHAVIOR_CHANGED_AFTER_UPDATE,
            "behavior changed after skill update",
        )

        score = max(score, 0)
        severity = score_to_severity(score)
        return RiskAssessment(score=score, severity=severity, factors=factors)
