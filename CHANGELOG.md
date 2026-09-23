# Changelog

All notable changes to SkillFence are documented here. Loosely follows
[Keep a Changelog](https://keepachangelog.com/) — newest first.

## [Unreleased]

### Added
- **`skillfence lab live`** — a real, connectable MCP server for one lab,
  so a real agent (Claude Desktop, Cline, the MCP Inspector) decides on
  its own what to call and when, instead of the deterministic scripted
  reference agent `skillfence run` always uses. Every call still executes
  inside the same sandboxed `RuntimeGateway` every other lab uses, built
  the same way `run_lab()` builds one — nothing opens a real socket, runs
  a real shell command, or touches a real credential. Stdlib-only HTTP
  transport speaking the current MCP "Streamable HTTP" wire format,
  verified end-to-end against the real `mcp` SDK's client. See
  `docs/live-mode.md` for client connection config.

### Fixed
- **AST07 (Update Drift) behavioral-baseline detection is now actually
  wired up.** `new_capability_since_baseline` existed as a defined risk
  factor but nothing ever passed it into the gateway's enforcement path —
  it was dead code. A skill's cross-invocation behavioral history (every
  capability token it's produced across every prior run, computed
  directly from raw event logs already on disk) is now loaded before each
  run and actually checked, so a capability token never seen in any prior
  invocation gets tagged AST07 and scored, even when it's within the
  current manifest's declared scope.
- **Lab Explorer: sidebar and main panel weren't scrolling independently.**
  `.shell` used `min-height` instead of `height`, and neither `#sidebar`
  nor `#main` had `min-height:0` — the classic flexbox bug where a tall
  child (the full lab list) forces the whole flex container past the
  viewport instead of scrolling internally. The whole page grew to the
  sidebar's full content height instead of the two panes scrolling on
  their own.
- **Lab Explorer: the ground-truth verdict, AST tags, and severity were
  shown before a lab was ever run**, spoiling every lab before it could be
  judged. The analysis is now collapsed behind a "Show analysis & expected
  verdict" reveal, opened only after a decision has actually been made —
  and the decision itself can no longer be picked blind: **Run** is now a
  two-step **Observe** (runs for real, blocks nothing, shows true
  behavior) then **Decide** (choose the human-gate response with the real
  evidence already in front of you, then **Enforce** it for real).

### Added
- **Progressive hints.** `skillfence lab hint <lab> [--level N]` reveals a
  lab's hints one at a time, in order, without spoiling the analysis; the
  Lab Explorer's lab pages get a matching "Stuck? Hints" section with the
  same one-at-a-time reveal. Every runnable DVAS lab ships a `hints.md`.
- **Lab Explorer: a heraldic identity per OWASP chapter** — a distinct
  shield icon and color per category, a dedicated Chapter overview page
  (the real issue, the real fix, a real-world-evidence citation, and that
  chapter's labs), reachable from the landing page, the sidebar, and every
  lab's own eyebrow. Benign controls and the multi-category capstone are
  now correctly kept out of the "ten OWASP categories" count instead of
  being miscounted as an 11th/12th category.
- **A zero-context onboarding doc**, linked at the top of this README —
  what an agentic skill actually is, why a manifest and `SKILL.md` alone
  can't be trusted, and what SkillFence does about it at runtime, for a
  reader who has never seen either project before.
- **Identity/memory persistence detection (AST01).** `write_file()` now
  recognizes writes to conventional agent identity/memory files
  (`MEMORY.md`, `AGENTS.md`, `CLAUDE.md`, `SOUL.md`, ...) as a distinct,
  high-scoring risk factor, independent of whether the manifest happens to
  declare write access to them — a future session reads these files back
  as trusted context with no re-scanning, so planting an instruction here
  compromises every session after this one, not just the current run.
- **Progressive-disclosure detection (AST05).** `fetch_url()` now keeps a
  session-level history of every fetch's content and re-scans the
  concatenation of everything fetched so far, in addition to the existing
  single-fetch scan. Catches a directive deliberately split across two or
  more individually-benign fetches — invisible to a scanner that only ever
  looks at one document at a time — and tags it with a distinct
  "progressive disclosure" risk factor separate from the base
  external-instruction signal.
- **`skillfence lab ui`** — a live local web UI over a lab suite: browse
  every discovered lab's declared capabilities, `SKILL.md`, and
  `README.md`, then run one through the real engine and see its real
  findings (including the unedited `Finding.explain()` text) directly in
  the browser. Reuses the same discovery `lab list` uses and the same
  `run_lab()` every other command calls — no mock data, no separate "web"
  representation of a lab.
- **Full OWASP Agentic Skills Top 10 coverage (AST01–AST10).**
- **AST10 (Cross-Platform Reuse) coverage** — reuses the AST02
  baseline-drift detection (a capability declared now that was absent
  from a skill's true original manifest); tagging an `update` step with
  `platform_migration: true` marks the update as a cross-platform port
  rather than an ordinary version bump, which changes a later drift
  finding's tag from AST02 to AST10 and its human-facing explanation to
  name porting-tool capability widening as the likely cause.
- **AST08 (Poor Scanning) coverage** — a manifest can declare
  `security.scanned: true` (optionally `scan_tool: "..."`), a
  self-declared claim of a prior static scan/review. SkillFence never
  trusts it; a runtime finding that fires anyway gets tagged AST08 —
  concrete evidence that a scan attestation is not a substitute for
  runtime enforcement.
- **AST09 (No Governance) coverage** — `skillfence inventory <root>`: a
  fleet-wide, read-only report of every skill under a root directory
  that's never actually been reviewed (zero sessions found anywhere) and
  every active policy grant not backed by any review at or after it was
  issued.

## [0.4.0] — 2026-09-14

### Fixed
- **AST02 (capability drift) now compares against a skill's true original
  manifest**, not just the one immediately before the most recent update.
  Closes a real gap: a capability smuggled in by an early update, never
  acted on, survived past any later unrelated update without being
  flagged — because the old check only ever remembered one update back.

### Added
- **Persistent dashboard index** (`skillfence/dashboard/index.py`, stdlib
  `sqlite3`) — caches both parsed file contents and the directory walk,
  so a dashboard restart doesn't start cold and a "whole fleet" root
  isn't walked in full on every browser poll.
- **`skillfence policy compile-apparmor`** — compiles a capability
  manifest into a real, loadable [AppArmor](https://apparmor.net/)
  profile. SkillFence stays a policy *compiler*; a real kernel LSM does
  the actual real-time enforcement, closing the gap `telemetry correlate`
  leaves as retroactive-only.
- **`auditd` SOCKADDR decoding** — `skillfence telemetry correlate` now
  decodes a `connect()` syscall's real destination (IPv4/IPv6/AF_UNIX)
  from its `SOCKADDR` audit record instead of only reporting that a
  connection happened.

## [0.3.0] — 2026-09-10

### Added
- **MCP proxy** (`skillfence mcp-proxy`) — authorizes every real
  `tools/call` through the runtime gateway before it's forwarded; scans
  `tools/list` tool descriptions and tool *responses* for poisoning,
  rug-pull, and live secrets before either reaches the agent or the client.
- **LangChain, CrewAI, and Google ADK adapters** — real agent
  integrations, each built after verifying the actual framework's
  tool-calling mechanics from source rather than assuming a uniform
  interception pattern.
- **Content-based secret scanning** (AWS/GitHub/Slack/Stripe/JWT/
  private-key patterns) — catches a live credential pasted into a
  declared, innocuous-looking file's *content*, which path-based checks
  alone can't see.
- **ASCII smuggling and zero-width-character evasion detection** —
  normalizes Unicode Tag block encoding and invisible interleaving
  characters before every instruction-content scan in the codebase.
- **Local web dashboard** (`skillfence dashboard`) — sessions, findings,
  provenance graph, Capability Drift Score, zero external dependencies.
- **OS-level telemetry correlation** (`skillfence telemetry correlate`) —
  attributes an existing `auditd` feed back to a SkillFence session to
  surface Layer-A bypasses.
- **Evidence signing, profiles, and reports** — Ed25519 evidence signing,
  Skill Security Profile, SARIF/HTML reports, a reusable GitHub Action.
- **A second, self-contained adversarial/evasion benchmark corpus**
  (`benchmarks/adversarial/`, generated by
  `scripts/build_adversarial_corpus.py`) — 12 malicious labs stress-
  testing evasion resistance, plus 5 benign near-neighbours so the
  benchmark can't turn into "detects everything."

### Fixed
- `EventBus` now patches a gated action's persisted decision after the
  human/policy verdict resolves — previously every event's `decision`
  field stayed `"pending"` in the JSONL forever, silently affecting
  `skillfence replay` since the very first release.
- `skillfence bench` now persists `findings.jsonl` the same way `run`
  always did, so a bench run leaves a real audit trail instead of only a
  console table.
- Sandbox path-traversal resolution (`str.lstrip` was stripping a
  character class, not a prefix) and MCP tool-map risk scoring bugs.

## [0.1.0] — 2026-09-05

Initial release: the core runtime — policy engine, deterministic risk
engine, correlation engine, human-in-the-loop CLI decision gate,
JSONL audit log — covering AST01–AST05 against the companion
[DVAS](https://github.com/shaikarifali/DVAS) lab suite (15/15 malicious
labs detected, 0/2 false positives).
