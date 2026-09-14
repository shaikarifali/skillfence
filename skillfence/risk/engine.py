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
# which policy-declared-vs-observed alone would miss. Also doubles as
# AST10 (cross-platform reuse) when the update that introduced the
# capability was itself a platform migration rather than an ordinary
# version bump -- same detection, same score, relabeled (see
# RuntimeGateway._platform_migration) since the root cause a reviewer
# should suspect differs: a compromised update pipeline vs. a porting
# tool that quietly widened a narrow declaration.
SCORE_BEHAVIOR_CHANGED_AFTER_UPDATE = 30

# AST06 (weak isolation): the resolved resource path falls outside this
# lab's own sandbox root entirely -- a path-traversal/symlink-style escape
# attempt, not merely an undeclared-but-still-sandboxed action. Scored above
# every other single factor: an isolation break threatens the host, not just
# this one skill's declared scope.
SCORE_SANDBOX_ESCAPE_ATTEMPT = 50

# AST07 (update drift): this exact capability token has never been observed
# in any prior invocation of this skill, even though it *is* within the
# manifest's declared scope right now -- the manifest never had to change
# for the skill's real behavior to drift, because the declared scope was
# already broad enough to cover it. Policy-declared-vs-observed alone is
# blind to this; only a cross-invocation behavioral baseline catches it.
SCORE_NEW_CAPABILITY_SINCE_BASELINE = 30

# MCP proxy: a real downstream server's tool name has no entry in this
# server's tool map -- there is no manifest signal at all for it, not even
# "undeclared." Scored at the same weight as a sandbox escape: not knowing
# what a live, real-world action does is exactly the situation the human
# gate exists for, deterministically, every time -- not a probabilistic
# guess about how dangerous the tool's name sounds.
SCORE_UNRESOLVABLE_TOOL_MAPPING = 50

# A live-looking credential pattern (AWS key, GitHub PAT, private key
# material, ...) was found in the actual *content* being read/returned --
# not just a sensitive-looking path. Must reach HIGH on its own: the whole
# point of this check is the case where the path is declared *and*
# innocuous-looking (`deploy-notes.txt`), so `undeclared_capability` and
# `sensitive_credential_read` never fire to carry the score there. A
# confirmed live secret in content is stronger evidence than a merely
# sensitive-looking path (Snyk's Feb 2026 ToxicSkills audit: 280+ skills
# leaking credentials exactly this way) and must gate independently.
# Fires in addition to, not instead of, path-based sensitivity.
SCORE_SECRET_PATTERN_IN_CONTENT = 50

# MCP tool poisoning: a real downstream MCP server's `tools/list` response
# contains a tool *description* with instruction-like text embedded in it --
# the "MCP Tool Poisoning" class first documented publicly in 2025, where an
# agent never even calls the malicious tool; reading its description is the
# whole attack, because most clients hand every tool description to the
# model as trusted context before any tool is invoked. Scored to gate on its
# own -- the tool is never called; the finding must fire from the list
# response alone.
SCORE_TOOL_DESCRIPTION_POISONED = 50

# MCP rug-pull: a tool this proxy has seen before now has a *different*
# description than last time, with no server-side version bump this proxy
# can observe. The classic MCP rug-pull is a server that ships a benign
# description at install/first-use time (when a human is most likely to be
# reviewing it) and silently swaps in a malicious one later. Scored high
# enough to gate independently, same as poisoning -- treat an unexplained
# description change as untrusted until a human reviews and re-approves it.
SCORE_MCP_TOOL_RUG_PULL = 50

# ASCII smuggling / zero-width evasion: the instruction that fired
# `external_instruction_involved`/`logic_layer_instruction_involved`/tool-
# poisoning was only visible after stripping invisible interleaving
# characters or decoding a Unicode Tag Block payload -- i.e. the raw text a
# naive scanner (or a human glancing at the content) would see contains no
# instruction at all. Deliberate evasion of detection is itself an
# aggravating signal, on top of whatever score the instruction itself
# already carries, not a replacement for it.
SCORE_HIDDEN_UNICODE_PAYLOAD = 30

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
        platform_migration_involved: bool = False,
        sandbox_escape_attempt: bool = False,
        new_capability_since_baseline: bool = False,
        unresolvable_tool_mapping: bool = False,
        secret_labels: list[str] | None = None,
        tool_description_poisoned: bool = False,
        tool_description_changed: bool = False,
        hidden_unicode_payload: bool = False,
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
            "behavior changed after platform migration (cross-platform reuse)"
            if platform_migration_involved
            else "behavior changed after skill update",
        )
        add(
            sandbox_escape_attempt,
            SCORE_SANDBOX_ESCAPE_ATTEMPT,
            "resolved path escapes this skill's own sandbox root",
        )
        add(
            new_capability_since_baseline,
            SCORE_NEW_CAPABILITY_SINCE_BASELINE,
            "capability token never observed in any prior invocation, despite unchanged manifest",
        )
        add(
            unresolvable_tool_mapping,
            SCORE_UNRESOLVABLE_TOOL_MAPPING,
            "real MCP tool has no entry in this server's tool map — no capability signal exists for it at all",
        )
        if secret_labels:
            add(
                True,
                SCORE_SECRET_PATTERN_IN_CONTENT,
                f"live-looking credential pattern in content: {', '.join(secret_labels)}",
            )
        add(
            tool_description_poisoned,
            SCORE_TOOL_DESCRIPTION_POISONED,
            "MCP tool description contains instruction-like content (tool poisoning)",
        )
        add(
            tool_description_changed,
            SCORE_MCP_TOOL_RUG_PULL,
            "MCP tool description changed since it was last seen (possible rug-pull)",
        )
        add(
            hidden_unicode_payload,
            SCORE_HIDDEN_UNICODE_PAYLOAD,
            "instruction was hidden via invisible Unicode (ASCII smuggling / zero-width evasion), not plainly visible",
        )

        score = max(score, 0)
        severity = score_to_severity(score)
        return RiskAssessment(score=score, severity=severity, factors=factors)
