"""SkillFence CLI. (`skillfence demo` works even with dummy events, no lab
required.)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from skillfence.cli.lab_catalog import discover_labs
from skillfence.events.bus import EventBus
from skillfence.events.schema import DecisionState, Event, EventType
from skillfence.fingerprint.behavior import record_and_diff
from skillfence.hitl.decisions import DecisionType
from skillfence.lab_runner import run_lab
from skillfence.policy.store import GRANT_DEFAULT_TTL, PolicyStore, default_policy_store_path
from skillfence.reporting.security_report import build_report
from skillfence.storage.jsonl_store import append_jsonl, read_jsonl

QUICKSTART = """\
Quick start — the pre-built labs:
  skillfence lab list                                   # see every lab, its AST category, and what it does
  skillfence run DVAS/AST05/external-doc-injection       # run one, live (you'll get a decision prompt)
  skillfence findings DVAS/AST05/external-doc-injection  # see the recorded evidence
  skillfence bench                                       # score every lab against its known-correct answer
  skillfence learn                                       # guided menu — pick a lab, see its mission, run it
  skillfence policy list                                 # see every remembered approval (org-wide)

Quick start — checking YOUR OWN skill:
  skillfence inspect path/to/your-skill                  # static check, needs only skill/manifest.yaml
  skillfence run path/to/your-skill --decision reject     # simulate its actions against your manifest, sandboxed
  See examples/my-first-skill/ for a copy-paste starting template, and the
  top-level README's "Using SkillFence on your own skill" section for the full guide.

Quick start — protecting a REAL MCP server, live:
  skillfence mcp-proxy --manifest m.yaml --tool-map t.yaml -- node real-server.js
  See examples/mcp-proxy/ for a complete worked example.

Run `skillfence <command> --help` for that command's own examples.
"""

app = typer.Typer(
    add_completion=False,
    help="SkillFence — runtime security for Agentic Skills",
    epilog=QUICKSTART,
)
lab_app = typer.Typer(add_completion=False, help="Discover labs.")
app.add_typer(lab_app, name="lab")
policy_app = typer.Typer(add_completion=False, help="Manage org-wide policy grants (Decision Memory).")
app.add_typer(policy_app, name="policy")
audit_app = typer.Typer(add_completion=False, help="Sign and verify evidence files (tamper-evident audit trail).")
app.add_typer(audit_app, name="audit")
telemetry_app = typer.Typer(add_completion=False, help="Correlate OS-level (auditd) telemetry against a SkillFence session.")
app.add_typer(telemetry_app, name="telemetry")
console = Console()

DEFAULT_LABS_ROOT = Path("DVAS")


def _runs_dir(lab_dir: Path) -> Path:
    return lab_dir / ".runs"


def _resolve_lab(lab: Path, labs_root: Path = DEFAULT_LABS_ROOT) -> Path:
    """Accept either a real lab directory or an AST shorthand (e.g. `dvas run
    ast01`). Falls back to the literal path for `run_lab` to fail on if
    neither resolves, so error messages stay accurate.
    """
    candidate = lab.resolve()
    if candidate.exists():
        return candidate

    token = str(lab).strip().lower()
    if token.startswith("ast") or token == "benign":
        root = labs_root.resolve()
        ast_dir = root / token.upper()
        if ast_dir.is_dir():
            matches = sorted(p.parent.parent for p in ast_dir.glob("**/skill/manifest.yaml"))
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                console.print(f"[yellow]{token.upper()} has {len(matches)} labs — pick one:[/yellow]")
                for m in matches:
                    console.print(f"  - {m.relative_to(root).as_posix()}")
                raise typer.Exit(1)
    return candidate


RUN_EXAMPLES = """\
Examples:
  skillfence run DVAS/AST05/external-doc-injection                    # live — you get the decision prompt
  skillfence run DVAS/AST01/credential-reader --decision reject        # non-interactive (CI, scripting)
  skillfence run ast04                                                 # AST shorthand, if only one lab matches
  skillfence run DVAS/AST01/credential-reader --mode observe           # log everything, block nothing
  skillfence run DVAS/AST01/credential-reader --decision allow_scoped  # approve + remember this exact action
  skillfence run DVAS/AST01/credential-reader --fresh                  # ignore any remembered approvals
  skillfence run examples/my-first-skill                               # your own skill — copy that directory to start
"""


@app.command(epilog=RUN_EXAMPLES)
def run(
    lab: Path = typer.Argument(
        ...,
        help="Path to a skill directory — a DVAS lab, or your own skill "
        "(needs skill/manifest.yaml and script.yaml; see examples/my-first-skill)",
    ),
    decision: Optional[str] = typer.Option(
        None,
        "--decision",
        help="Non-interactive: auto-answer every human decision gate with this choice "
        f"({', '.join(d.value for d in DecisionType)}). Omit for a live interactive demo.",
    ),
    mode: str = typer.Option("enforce", "--mode", help="enforce (block on reject) | observe (log only, never blocks)"),
    fresh: bool = typer.Option(
        False, "--fresh", help="Ignore the shared policy store (all org-wide ALLOW_SCOPED grants) for this run."
    ),
):
    """Run a lab: load its skill, execute its scripted agent steps through the
    SkillFence runtime gateway, and pause on any HIGH/CRITICAL action for a human
    decision (unless --decision is supplied)."""
    lab = _resolve_lab(lab)
    if decision is not None:
        try:
            DecisionType(decision)
        except ValueError:
            console.print(f"[red]Unknown --decision value: {decision}[/red]")
            raise typer.Exit(1)

    try:
        result = run_lab(lab, decision=decision, mode=mode, console=console, use_policy_store=not fresh)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    console.rule(f"[bold]SkillFence Runtime[/bold] — {result.gateway.skill}  (session {result.session_id})")
    console.print(
        f"[dim]mode={mode}  invocation #{result.invocation_number}  events -> {result.events_path}[/dim]\n"
    )

    table = Table(title="Run summary")
    table.add_column("Step")
    table.add_column("Status")
    table.add_column("Detail")
    for r in result.report.results:
        color = {"ok": "green", "blocked": "red", "error": "yellow"}[r.status]
        table.add_row(str(r.step.get("action")), f"[{color}]{r.status}[/{color}]", r.detail)
    console.print(table)

    findings_path = _runs_dir(lab) / "findings.jsonl"
    for finding in result.findings:
        append_jsonl(findings_path, finding.model_dump())

    if result.findings:
        console.print(f"\n[bold]{len(result.findings)} finding(s)[/bold] written to {findings_path}")
        for f in result.findings:
            console.print(f"  - [{f.severity.upper()}] {f.title} -> {f.status}")
    else:
        console.print("\n[green]No findings — every action stayed within declared capability / low risk.[/green]")

    fp = record_and_diff(
        _runs_dir(lab), invocation_number=result.invocation_number, session_id=result.session_id,
        events_path=result.events_path,
    )
    if fp.baseline_exists and fp.changed:
        lines = [f"Fingerprint: {fp.fingerprint_id}  ({fp.label})"]
        if fp.added:
            lines += [f"  + {t}" for t in sorted(fp.added)]
        if fp.removed:
            lines += [f"  - {t}" for t in sorted(fp.removed)]
        console.print(Panel("\n".join(lines), title="[bold yellow]BEHAVIOR CHANGED vs previous run[/bold yellow]", border_style="yellow"))


@lab_app.command(
    "list",
    epilog="Examples:\n  skillfence lab list\n  skillfence lab list DVAS/AST01   # scope to one AST category\n",
)
def lab_list(
    labs_root: Path = typer.Argument(DEFAULT_LABS_ROOT, help="Root directory to scan for skill/manifest.yaml"),
):
    """List every discoverable lab with its AST category and declared purpose."""
    infos = discover_labs(labs_root)
    if not infos:
        console.print(f"[yellow]No labs found under {labs_root}[/yellow]")
        raise typer.Exit(0)

    table = Table(title="Labs")
    table.add_column("AST")
    table.add_column("Lab")
    table.add_column("Skill")
    table.add_column("Kind")
    table.add_column("Purpose")
    for info in infos:
        kind = "-" if info.malicious is None else ("[red]malicious[/red]" if info.malicious else "[green]benign[/green]")
        purpose = info.purpose[0] if info.purpose else "-"
        table.add_row(info.ast, info.name, info.skill_name, kind, purpose)
    console.print(table)
    console.print(f"\n[dim]Run one with: skillfence run <lab dir>   (or `skillfence run {infos[0].ast.lower()}` if unambiguous)[/dim]")


@app.command(
    epilog="Examples:\n  skillfence inspect DVAS/AST03/unauthorized-network\n  skillfence inspect ast03\n"
    "  skillfence inspect examples/my-first-skill   # works on any skill/manifest.yaml, not just labs\n"
)
def inspect(
    lab: Path = typer.Argument(
        ...,
        help="Path to any skill directory with a skill/manifest.yaml — a DVAS lab, an AST "
        "shorthand (e.g. ast03), or your own skill",
    ),
):
    """Static-only inspection — read the skill's declared manifest and
    purpose. Does not execute the skill or touch the sandbox. Works on any
    skill that ships a skill/manifest.yaml, not just DVAS labs — this is the
    entry point for checking a skill you did not write yourself."""
    lab = _resolve_lab(lab)
    manifest_path = lab / "skill" / "manifest.yaml"
    if not manifest_path.exists():
        console.print(f"[red]no manifest.yaml at {manifest_path}[/red]")
        raise typer.Exit(1)

    from skillfence.policy.manifest import CapabilityManifest

    manifest = CapabilityManifest.load(manifest_path)
    console.rule(f"[bold]Inspect[/bold] — {manifest.name}")
    console.print(f"version: {manifest.version}")
    console.print("purpose:")
    for p in manifest.purpose:
        console.print(f"  - {p}")
    console.print("\ndeclared capabilities:")
    console.print(f"  filesystem.read:  {manifest.capabilities.filesystem.read or '[]'}")
    console.print(f"  filesystem.write: {manifest.capabilities.filesystem.write or '[]'}")
    console.print(f"  process.execute:  {manifest.capabilities.process.execute or '[]'}")
    console.print(
        f"  network:          {'enabled -> ' + str(manifest.capabilities.network.domains) if manifest.capabilities.network.enabled else 'disabled'}"
    )
    console.print(f"  secrets.access:   {manifest.capabilities.secrets.access}")
    skill_md = lab / "skill" / "SKILL.md"
    if skill_md.exists():
        console.print("\n[dim]SKILL.md (first lines):[/dim]")
        for line in skill_md.read_text(encoding="utf-8").splitlines()[:8]:
            console.print(f"  {line}")
    console.print(
        "\n[dim]This is the declared side only — run `skillfence observe` or "
        "`skillfence run` to see what the skill actually does.[/dim]"
    )


@app.command(epilog="Examples:\n  skillfence observe DVAS/AST05/external-doc-injection\n")
def observe(
    lab: Path = typer.Argument(..., help="Path to a lab directory (or an AST shorthand, e.g. ast03)"),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore the shared, org-wide policy store for this run."),
):
    """Establish a behavior baseline — runs the skill with every action
    logged and none blocked, so its true observed capability set can be
    recorded before enforcement is turned on. Alias for
    `run --mode observe --decision approve_once`."""
    run(lab=lab, decision=DecisionType.APPROVE_ONCE.value, mode="observe", fresh=fresh)


@app.command(
    epilog="Examples:\n  skillfence protect DVAS/AST01/credential-reader\n"
    "  skillfence protect DVAS/AST01/credential-reader --decision reject   # non-interactive\n"
)
def protect(
    lab: Path = typer.Argument(..., help="Path to a lab directory (or an AST shorthand, e.g. ast03)"),
    decision: Optional[str] = typer.Option(None, "--decision", help="Non-interactive decision for every gate."),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore the shared, org-wide policy store for this run."),
):
    """Enforce — alias for `run --mode enforce`: high/critical actions are
    truly paused and, on rejection, never executed."""
    run(lab=lab, decision=decision, mode="enforce", fresh=fresh)


def _format_expiry(grant, now: datetime) -> str:
    if grant.expires_at is None:
        return "never"
    expires = datetime.fromisoformat(grant.expires_at)
    delta = expires - now
    if delta.total_seconds() <= 0:
        return "[red]expired[/red]"
    hours, remainder = divmod(int(delta.total_seconds()), 3600)
    minutes = remainder // 60
    return f"in {hours}h{minutes:02d}m" if hours else f"in {minutes}m"


@policy_app.command(
    "list",
    epilog="Examples:\n  skillfence policy list\n  skillfence policy list --all   # include expired grants\n",
)
def policy_list(
    show_all: bool = typer.Option(False, "--all", help="Include expired grants (hidden by default)."),
):
    """List every remembered approval (Decision Memory) in the shared,
    org-wide policy store — not scoped to any one lab."""
    store = PolicyStore(default_policy_store_path())
    now = datetime.now(timezone.utc)
    grants = store.grants if show_all else [g for g in store.grants if g.is_active(now)]
    if not grants:
        console.print(f"[yellow]No grants in {store.path}[/yellow]")
        raise typer.Exit(0)

    table = Table(title=f"Policy grants — {store.path}")
    table.add_column("Grant ID")
    table.add_column("Skill")
    table.add_column("Action")
    table.add_column("Resource")
    table.add_column("Expires")
    table.add_column("Reason")
    for g in grants:
        table.add_row(g.grant_id, g.skill, g.event_type, g.resource, _format_expiry(g, now), g.reason or "-")
    console.print(table)


@policy_app.command(
    "allow",
    epilog="Examples:\n"
    '  skillfence policy allow cloud-debug filesystem.read "~/.aws/credentials" --reason "approved for audit tool"\n'
    "  skillfence policy allow cloud-debug filesystem.read \"~/.aws/credentials\" --ttl 86400   # 24h instead of the 2h default\n"
    "  skillfence policy allow cloud-debug filesystem.read \"~/.aws/credentials\" --ttl 0        # never expires\n",
)
def policy_allow(
    skill: str = typer.Argument(..., help="Exact skill name, as it appears in its manifest.yaml `name:` field."),
    action: str = typer.Argument(
        ..., help=f"Event type ({', '.join(e.value for e in EventType)})."
    ),
    resource: str = typer.Argument(..., help="Exact resource string (path, command, or URL) as the skill requests it."),
    reason: str = typer.Option("", "--reason", help="Why this is approved — recorded in the grant for audit."),
    ttl: Optional[int] = typer.Option(
        None, "--ttl", help="Seconds until this grant expires. Omit for the default (2h); 0 = never expires."
    ),
):
    """Pre-approve a specific (skill, action, resource) so it stops gating
    without needing to hit a live decision prompt — the same narrowly-scoped
    grant an `[s] Allow scoped` decision creates, created ahead of time by
    whoever owns this policy (e.g. a security lead clearing a known false
    positive for the whole org)."""
    try:
        event_type = EventType(action)
    except ValueError:
        console.print(f"[red]Unknown action '{action}'. Valid actions: {', '.join(e.value for e in EventType)}[/red]")
        raise typer.Exit(1)

    store = PolicyStore(default_policy_store_path())
    delta = None if ttl == 0 else (timedelta(seconds=ttl) if ttl is not None else GRANT_DEFAULT_TTL)
    grant = store.add_grant(
        skill=skill, event_type=event_type.value, resource=resource, decision="allow_scoped", ttl=delta, reason=reason
    )
    expiry = "never" if grant.expires_at is None else grant.expires_at
    console.print(f"[green]Grant created:[/green] {grant.grant_id}  (expires: {expiry})")
    console.print(f"[dim]Stored in {store.path} — `skillfence policy list` to see it, `skillfence policy revoke {grant.grant_id}` to undo.[/dim]")


@policy_app.command("revoke", epilog="Examples:\n  skillfence policy revoke grant-abc123def456\n")
def policy_revoke(
    grant_id: str = typer.Argument(..., help="Grant ID from `skillfence policy list`."),
):
    """Remove a previously created grant — the action will gate again on its
    next occurrence."""
    store = PolicyStore(default_policy_store_path())
    if store.revoke(grant_id):
        console.print(f"[green]Revoked {grant_id}[/green]")
    else:
        console.print(f"[yellow]No grant with id {grant_id} found in {store.path}[/yellow]")
        raise typer.Exit(1)


@policy_app.command(
    "compile-apparmor",
    epilog="Examples:\n"
    "  skillfence policy compile-apparmor skill/manifest.yaml --binary /usr/bin/python3 > skill.profile\n"
    "  skillfence policy compile-apparmor skill/manifest.yaml --binary /usr/bin/python3 "
    "--workspace /opt/agent-workspace --home /home/agent -o skill.profile\n"
    "  Then, as root: apparmor_parser -r skill.profile && aa-exec -p <skill-name> -- <command>\n",
)
def policy_compile_apparmor(
    manifest_path: Path = typer.Argument(..., help="A capability manifest (skill/manifest.yaml schema)"),
    binary: str = typer.Option(..., "--binary", help="The real interpreter/executable that will run the agent, e.g. /usr/bin/python3"),
    profile_name: Optional[str] = typer.Option(None, "--name", help="AppArmor profile name (defaults to the manifest's skill name)"),
    workspace: Optional[str] = typer.Option(
        None, "--workspace", help="Absolute path to resolve ${workspace}-free relative filesystem patterns against"
    ),
    home: Optional[str] = typer.Option(None, "--home", help="Absolute path to resolve ~-prefixed filesystem patterns against"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write the profile here instead of stdout"),
):
    """Compiles a capability manifest into a real, loadable AppArmor
    profile — SkillFence as a policy compiler, not an enforcer. Layer A
    (every other command in this tool) blocks at the agent-tool boundary,
    in-process; this generates OS-level policy a real AppArmor kernel
    module enforces natively, closing the gap `telemetry correlate`
    leaves as retroactive-only. SkillFence never loads or enforces the
    profile itself — that stays the operator's job (`apparmor_parser -r`,
    then `aa-exec -p <name> -- <command>`), the same "wrap mature
    infrastructure" principle the auditd telemetry integration uses.
    Some manifest fields have no AppArmor equivalent (`network.domains`,
    `secrets.access`) and are disclosed as comments in the generated
    profile, not silently dropped. Not verified against a live
    `apparmor_parser` — validate with `apparmor_parser -Q -r` before
    trusting one in production."""
    from skillfence.policy.apparmor_compile import compile_to_apparmor
    from skillfence.policy.manifest import CapabilityManifest

    manifest = CapabilityManifest.load(manifest_path, workspace=Path(workspace) if workspace else None)
    profile = compile_to_apparmor(
        manifest, binary=binary, profile_name=profile_name, workspace=workspace, home=home
    )
    if output:
        output.write_text(profile, encoding="utf-8")
        console.print(f"[green]Wrote {output}[/green]")
    else:
        print(profile)


@app.command(
    epilog="Examples:\n  skillfence report DVAS/AST05/external-doc-injection\n"
    "  skillfence report DVAS/AST05/external-doc-injection --json\n"
    "  skillfence report DVAS/AST05/external-doc-injection --markdown\n"
    "  skillfence report DVAS/AST05/external-doc-injection --sarif > results.sarif   # for github/codeql-action/upload-sarif\n"
    "  skillfence report DVAS/AST05/external-doc-injection --html > report.html      # shareable, open in any browser\n"
)
def report(
    lab: Path = typer.Argument(..., help="Path to a lab directory previously run with `skillfence run`"),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON instead of the text report."),
    as_markdown: bool = typer.Option(False, "--markdown", help="Emit a Markdown report instead of the text report."),
    as_sarif: bool = typer.Option(False, "--sarif", help="Emit SARIF 2.1.0 for GitHub code scanning / any SARIF-consuming CI."),
    as_html: bool = typer.Option(False, "--html", help="Emit a self-contained HTML report — shareable, no server needed."),
):
    """Security assessment report — rolls up a lab's recorded findings into
    skill / risk / AST / findings / attack-chain / decision / evidence-count
    form."""
    lab = _resolve_lab(lab)
    rpt = build_report(lab)
    if as_html:
        print(rpt.to_html())
    elif as_sarif:
        import json

        print(json.dumps(rpt.to_sarif(), indent=2))
    elif as_json:
        import json

        print(json.dumps(rpt.to_dict(), indent=2))
    elif as_markdown:
        print(rpt.to_markdown())
    else:
        console.print(rpt.to_text())


@app.command(
    epilog="Examples:\n  skillfence profile DVAS/AST01/credential-reader\n"
    "  skillfence profile DVAS/AST01/credential-reader --json\n"
)
def profile(
    lab: Path = typer.Argument(..., help="Path to a lab or skill directory previously run with `skillfence run`/`observe`"),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON instead of the text profile."),
):
    """Skill Security Profile — one consolidated view of what a skill
    declares, what it's actually been observed doing, whether its behavior
    has drifted since its last run, and its finding history. Reuses the
    same fingerprint history and findings.jsonl `run` already writes; this
    doesn't add a new detector, it just stops making you reassemble the
    picture from `inspect` + a fingerprint diff + `findings` by hand."""
    lab = _resolve_lab(lab)
    from skillfence.reporting.skill_profile import build_profile

    try:
        prof = build_profile(lab)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    if as_json:
        import json

        print(json.dumps(prof.to_dict(), indent=2))
    else:
        console.print(prof.to_text())


@app.command(
    epilog="Examples:\n  skillfence dashboard DVAS\n  skillfence dashboard .skillfence/mcp --port 9000\n"
    "  skillfence dashboard . --no-browser\n"
)
def dashboard(
    root: Path = typer.Argument(
        Path("."), help="Directory to scan for sessions -- a lab dir, an MCP proxy audit dir, or a whole fleet root"
    ),
    port: int = typer.Option(0, "--port", help="Port to bind (127.0.0.1 only). 0 (default) picks a free port."),
    open_browser: bool = typer.Option(True, "--browser/--no-browser", help="Open the dashboard in a browser tab on start."),
):
    """A local, read-only web view over evidence SkillFence already wrote —
    every session found under ROOT (`.runs/*.events.jsonl` from lab runs,
    `*.events.jsonl` from an MCP proxy audit dir), its findings, its
    provenance chain, and its Capability Drift Score, in one page. No new
    storage: it re-reads the same JSONL files `findings`/`replay`/`profile`
    already read, re-scanned on every browser refresh, so leaving it open
    during a live `run`/`mcp-proxy` session shows new events as they land.
    Bound to 127.0.0.1 only — never reachable from another machine. Point
    it at one lab or one MCP audit dir for a snappy view; a "whole fleet"
    root with hundreds of accumulated sessions is a full filesystem walk
    on every refresh and will feel it, especially over a slow mount."""
    import webbrowser

    from skillfence.dashboard.server import build_server

    if not root.exists():
        console.print(f"[red]{root} does not exist[/red]")
        raise typer.Exit(1)

    server = build_server(root, port=port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    console.print(f"[bold green]SkillFence Dashboard[/bold green] — {url}")
    console.print(f"  scanning: {root.resolve()}")
    console.print("  Ctrl-C to stop\n")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


@app.command(epilog="Examples:\n  skillfence learn\n")
def learn(
    labs_root: Path = typer.Argument(DEFAULT_LABS_ROOT, help="Root directory to scan for labs"),
):
    """Guided Learn Mode — pick a vulnerable skill lab from a menu, see its
    mission, then watch/drive SkillFence catch (or let through, if you approve)
    its attack at runtime."""
    infos = [i for i in discover_labs(labs_root) if i.malicious]
    if not infos:
        console.print(f"[yellow]No malicious labs found under {labs_root}[/yellow]")
        raise typer.Exit(0)

    console.rule("[bold]Damn Vulnerable Agentic Skills[/bold]")
    for idx, info in enumerate(infos, start=1):
        console.print(f"[{idx}] {info.ast} — {info.title or info.name}")
    console.print(f"[0] quit")

    choice = Prompt.ask("Pick a lab", choices=[str(i) for i in range(0, len(infos) + 1)], default="0")
    if choice == "0":
        raise typer.Exit(0)

    info = infos[int(choice) - 1]
    readme = info.dir / "README.md"
    if readme.exists():
        console.print(Panel(readme.read_text(encoding="utf-8"), title="MISSION", border_style="cyan"))
    console.print(
        "\n[dim]ATTACK -> OBSERVE -> DETECT -> STOP -> REMEDIATE. "
        "You'll see the runtime evidence and make the human decision yourself.[/dim]\n"
    )
    run(lab=info.dir, decision=None, mode="enforce", fresh=False)


@app.command(epilog="Examples:\n  skillfence bench\n  skillfence bench DVAS/AST01   # scope to one AST category\n")
def bench(
    labs_root: Path = typer.Argument(Path("DVAS"), help="Root directory to scan for */ground-truth.yaml"),
):
    """Run every lab with an auto-reject decision and score against its
    ground-truth.yaml — detection rate on malicious labs, false-positive
    rate on benign labs, and human interruptions per run."""
    gt_files = sorted(labs_root.resolve().glob("**/ground-truth.yaml"))
    if not gt_files:
        console.print(f"[yellow]No ground-truth.yaml found under {labs_root}[/yellow]")
        raise typer.Exit(0)

    table = Table(title="DVAS-Bench")
    table.add_column("Lab")
    table.add_column("Ground truth")
    table.add_column("Findings")
    table.add_column("Human prompts")
    table.add_column("Result")

    malicious_total = malicious_detected = 0
    benign_total = benign_clean = 0

    for gt_path in gt_files:
        lab_dir = gt_path.parent
        gt = yaml.safe_load(gt_path.read_text(encoding="utf-8"))
        result = run_lab(lab_dir, decision="reject")
        n_findings = len(result.findings)

        # `run_lab` always persists events.jsonl (via EventBus) regardless
        # of caller -- findings must be just as durable, or a bench run
        # (e.g. the one CI runs on every push) leaves no audit trail at
        # all for what it detected, only a console table that scrolls away.
        findings_path = _runs_dir(lab_dir) / "findings.jsonl"
        for finding in result.findings:
            append_jsonl(findings_path, finding.model_dump())

        is_malicious = bool(gt["ground_truth"]["malicious"])
        label = lab_dir.relative_to(labs_root.resolve()).as_posix()

        if is_malicious:
            malicious_total += 1
            detected = n_findings > 0
            malicious_detected += int(detected)
            verdict = "[green]detected[/green]" if detected else "[bold red]MISSED[/bold red]"
        else:
            benign_total += 1
            clean = n_findings == 0
            benign_clean += int(clean)
            verdict = "[green]clean[/green]" if clean else "[bold red]FALSE POSITIVE[/bold red]"

        table.add_row(label, "malicious" if is_malicious else "benign", str(n_findings), str(n_findings), verdict)

    console.print(table)
    console.print()
    if malicious_total:
        console.print(f"Detection rate: {malicious_detected}/{malicious_total} malicious labs flagged")
    if benign_total:
        console.print(f"False-positive rate: {benign_total - benign_clean}/{benign_total} benign labs incorrectly flagged")
    total_prompts = malicious_detected + (benign_total - benign_clean)
    console.print(f"Human interruptions across benchmark: {total_prompts} "
                  f"(0 expected on benign labs, {malicious_total} expected on malicious labs)")


@app.command(
    epilog="Examples:\n  skillfence findings DVAS/AST05/external-doc-injection\n"
    "  skillfence findings .skillfence/mcp/mcp-a1b2c3d4.findings.jsonl   # a specific mcp-proxy session\n"
)
def findings(
    lab: Path = typer.Argument(
        ..., help="A lab directory previously run with `skillfence run`, or a *.findings.jsonl file directly (e.g. from mcp-proxy)"
    ),
):
    """Print explainable findings recorded for a lab or an mcp-proxy session."""
    resolved = lab.resolve()
    path = resolved if resolved.suffix == ".jsonl" else _runs_dir(resolved) / "findings.jsonl"
    rows = list(read_jsonl(path))
    if not rows:
        console.print(f"[yellow]No findings recorded at {path}[/yellow]")
        raise typer.Exit(0)
    for row in rows:
        console.rule(row.get("title", "finding"))
        console.print(_explain(row))


def _explain(row: dict) -> str:
    lines = [
        f"TITLE: {row.get('title')}",
        f"AST CATEGORY: {', '.join(row.get('ast', []))}",
        f"RISK: {str(row.get('severity', '')).upper()}",
        f"CDS: {row.get('cds', 0.0):.2f} ({row.get('cds_band', 'ALLOW')})",
        f"SKILL: {row.get('skill')}",
        f"ACTION: {row.get('action')}",
        f"RESOURCE: {row.get('resource')}",
        f"DECLARED CAPABILITY: {row.get('declared_capability')}",
        f"OBSERVED CAPABILITY: {row.get('observed_capability')}",
        "WHY FLAGGED:",
        *[f"  - {r}" for r in row.get("why_flagged", [])],
        f"ATTACK CHAIN: {' -> '.join(row.get('attack_chain', [])) or '-'}",
        f"RAW EVENTS: {', '.join(row.get('evidence', []))}",
        f"HUMAN DECISION: {row.get('human_decision') or 'pending'}",
    ]
    return "\n".join(lines)


@app.command(
    epilog="Examples:\n"
    "  skillfence replay DVAS/AST05/external-doc-injection/.runs/<session>.events.jsonl\n"
)
def replay(
    events_file: Path = typer.Argument(..., help="A *.events.jsonl file produced by a previous `skillfence run`"),
):
    """Replay a recorded session's event timeline. Experimental: prints the
    sequence deterministically; does not re-run the human gate."""
    rows = list(read_jsonl(events_file))
    if not rows:
        console.print(f"[yellow]No events found at {events_file}[/yellow]")
        raise typer.Exit(0)
    console.rule(f"Replay — {events_file.name}")
    for row in rows:
        ts = row.get("timestamp", "")
        etype = row.get("event_type", "")
        resource = row.get("resource") or ""
        decision = row.get("decision", "")
        console.print(f"[dim]{ts}[/dim]  {etype:<40} {resource:<40} [bold]{decision}[/bold]")


MCP_PROXY_EXAMPLES = """\
Examples:
  skillfence mcp-proxy --manifest server-manifest.yaml --tool-map tool-map.yaml -- node real-server.js
  skillfence mcp-proxy --manifest server-manifest.yaml --tool-map tool-map.yaml --fresh -- python real_server.py
  See examples/mcp-proxy/ for a complete worked example (manifest, tool map,
  and a tiny fixture "real" server to point it at).
"""


@app.command(
    name="mcp-proxy",
    epilog=MCP_PROXY_EXAMPLES,
    context_settings={"ignore_unknown_options": True},
)
def mcp_proxy_cmd(
    target: list[str] = typer.Argument(
        ..., help="The real MCP server command to launch, e.g. `-- node real-server.js --port 1234`"
    ),
    manifest: Path = typer.Option(
        ..., "--manifest", help="Capability manifest (same schema as skill/manifest.yaml) for what this server's tools may do"
    ),
    tool_map: Path = typer.Option(
        ..., "--tool-map", help="Tool map YAML: which of the server's real tool names map to which SkillFence action kind"
    ),
    audit_dir: Path = typer.Option(
        Path(".skillfence/mcp"), "--audit-dir", help="Where this session's event/finding JSONL is written"
    ),
    fresh: bool = typer.Option(False, "--fresh", help="Ignore the shared, org-wide policy store for this session."),
):
    """Put SkillFence in front of a real MCP server. To the real client
    (Claude Code, or any MCP-speaking agent) this proxy IS the MCP server;
    to the real downstream server, this proxy IS the client. Every
    `tools/call` is authorized through the same policy/risk/human-gate
    pipeline the DVAS labs use before the real request is ever forwarded —
    everything else passes through unmodified. HIGH/CRITICAL actions
    fail-safe deny by default (no interactive TTY is available on a shared
    stdio channel) — pre-authorize expected actions with
    `skillfence policy allow`, then review `skillfence findings` for
    anything that got blocked."""
    from skillfence.mcp.proxy import MCPProxy

    proxy = MCPProxy(
        target_command=target,
        manifest_path=manifest,
        toolmap_path=tool_map,
        audit_dir=audit_dir,
        fresh=fresh,
    )
    proxy.run()


@audit_app.command("keygen", epilog="Examples:\n  skillfence audit keygen\n")
def audit_keygen(
    private_key: Path = typer.Option(
        Path(".skillfence/audit_signing_key"), "--private-key", help="Where to write the new private key"
    ),
    public_key: Path = typer.Option(
        Path(".skillfence/audit_signing_key.pub"), "--public-key", help="Where to write the matching public key"
    ),
):
    """Generate a new local Ed25519 keypair for signing evidence files.
    Run once. Keep the private key; hand the public key to anyone who
    needs to independently verify your evidence — they never need the
    private key to do so."""
    from skillfence.audit.signing import generate_keypair

    try:
        generate_keypair(private_key_path=private_key, public_key_path=public_key)
    except FileExistsError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Keypair created.[/green]  private: {private_key}   public: {public_key}")
    console.print("[dim]The private key never needs to leave this machine. Share the .pub file with reviewers.[/dim]")


@audit_app.command(
    "sign",
    epilog="Examples:\n"
    "  skillfence audit sign DVAS/AST05/external-doc-injection/.runs/findings.jsonl\n"
    "  skillfence audit sign .skillfence/mcp/mcp-abc123.findings.jsonl\n",
)
def audit_sign(
    target: Path = typer.Argument(..., help="Any evidence file to sign — findings.jsonl, events.jsonl, a rendered report"),
    private_key: Path = typer.Option(Path(".skillfence/audit_signing_key"), "--private-key"),
):
    """Sign an evidence file's current contents with your local private
    key, writing a `<file>.sig.json` sidecar. Re-run after the file
    changes to re-sign it — a stale signature will fail verification."""
    from skillfence.audit.signing import sign_file

    if not target.exists():
        console.print(f"[red]{target} does not exist[/red]")
        raise typer.Exit(1)
    try:
        sig_path = sign_file(target, private_key_path=private_key)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Signed.[/green] {sig_path}")


@audit_app.command(
    "verify",
    epilog="Examples:\n"
    "  skillfence audit verify DVAS/AST05/external-doc-injection/.runs/findings.jsonl\n"
    "  skillfence audit verify findings.jsonl --public-key colleague-public-key.pub\n",
)
def audit_verify(
    target: Path = typer.Argument(..., help="The evidence file to verify"),
    public_key: Path = typer.Option(
        Path(".skillfence/audit_signing_key.pub"), "--public-key", help="The signer's public key"
    ),
):
    """Verify an evidence file hasn't changed since it was signed. Only
    needs the *public* key — this is exactly the step a reviewer who
    didn't produce the evidence runs, independently."""
    from skillfence.audit.signing import verify_file

    result = verify_file(target, public_key_path=public_key)
    if result.valid:
        console.print(f"[bold green]VALID[/bold green]  {result.reason}")
    else:
        console.print(f"[bold red]INVALID[/bold red]  {result.reason}")
        raise typer.Exit(1)


@telemetry_app.command(
    "correlate",
    epilog="Examples:\n"
    "  skillfence telemetry correlate DVAS/AST01/credential-reader/.runs/<session>.events.jsonl /var/log/audit/audit.log\n"
    "  skillfence telemetry correlate .skillfence/mcp/<session>.events.jsonl audit-window.log --pid 4821\n"
    "  ausearch -k skillfence --format raw | skillfence telemetry correlate <session>.events.jsonl -\n",
)
def telemetry_correlate(
    events_file: Path = typer.Argument(..., help="A *.events.jsonl file produced by a previous `skillfence run`/`mcp-proxy` session"),
    audit_log: Path = typer.Argument(..., help="A file of raw auditd log lines covering the session's time window. Use '-' to read from stdin."),
    pid: Optional[int] = typer.Option(
        None, "--pid", help="Restrict correlation to this PID (the real agent/proxy process) -- omit for time-window-only correlation, which is weaker evidence"
    ),
):
    """Layer A (every command in this tool) only sees actions taken
    through an instrumented tool wrapper. An agent with real shell/code-exec
    access can act entirely outside that boundary. This correlates an
    existing OS-level telemetry source (Linux `auditd` — not a bespoke
    SkillFence syscall monitor; wraps a mature, already-deployed tool the
    same way `bench` wraps DVAS) against this session's own event log, and
    reports anything auditd saw that SkillFence's instrumented layer never
    did. Matching is name/path-suffix based, not exact — a lead worth
    review, not a deterministic verdict like the rest of this tool's
    findings. Set up auditd rules first, e.g.:
      auditctl -a always,exit -F arch=b64 -S execve,execveat -k skillfence
      auditctl -a always,exit -F arch=b64 -S open,openat -k skillfence"""
    import sys

    from skillfence.storage.jsonl_store import read_jsonl
    from skillfence.telemetry.auditd import parse_audit_log
    from skillfence.telemetry.correlate import correlate

    session_events = list(read_jsonl(events_file))
    if not session_events:
        console.print(f"[yellow]No events found in {events_file}[/yellow]")
        raise typer.Exit(0)

    audit_text = sys.stdin.read() if str(audit_log) == "-" else audit_log.read_text(encoding="utf-8")
    audit_events = parse_audit_log(audit_text)

    report = correlate(session_events, audit_events, pid=pid)

    console.rule("[bold]Telemetry Correlation[/bold]")
    console.print(f"session: {events_file.name}   audit records parsed: {len(audit_events)}   pid filter: {pid or 'none'}\n")
    console.print(f"[green]matched[/green]: {len(report.matched)}  (seen by both SkillFence and auditd)")
    console.print(f"[dim]observed (network, unmatched by design)[/dim]: {len(report.observed_network)}")
    console.print(f"[bold red]untracked[/bold red]: {len(report.untracked)}  (auditd saw this; SkillFence's instrumented layer did not)\n")

    for tf in report.untracked:
        ae = tf.audit_event
        console.print(f"  [bold red][{tf.confidence.upper()}][/bold red] {tf.reason}")
        console.print(f"    pid={ae.pid} comm={ae.comm} exe={ae.exe} paths={ae.paths or '-'}")

    for ae in report.observed_network:
        destination = ae.remote_address or "(remote address not decoded — no SOCKADDR record, or an unrecognized address family)"
        console.print(f"  [dim][OBSERVED][/dim] pid={ae.pid} comm={ae.comm} -> {destination}")

    if report.bypass_suspected:
        console.print(
            "\n[bold red]Possible Layer-A bypass[/bold red]: OS-level activity with no corresponding "
            "SkillFence event exists for this session. Review the entries above."
        )
    else:
        console.print("\n[green]No untracked OS-level activity found for this session/pid.[/green]")


@app.command()
def demo():
    """Skeleton smoke test: proves the event schema, bus, and CLI wiring work
    end-to-end with dummy events, no lab required."""
    session_id = f"session-{uuid.uuid4().hex[:8]}"
    bus = EventBus(Path(".skillfence_demo") / f"{session_id}.events.jsonl")
    console.rule("[bold]SkillFence Runtime[/bold] — demo")
    console.print("[dim]skill loaded, no lab wired yet — this just proves the pipes work[/dim]\n")

    load = bus.publish(
        Event(session_id=session_id, agent="demo-agent", skill="demo-skill", event_type=EventType.SKILL_LOAD)
    )
    read = bus.publish(
        Event(
            session_id=session_id,
            agent="demo-agent",
            skill="demo-skill",
            event_type=EventType.FS_READ,
            resource="./logs/server.log",
            declared=True,
            sensitive=False,
            parent_event=load.event_id,
            decision=DecisionState.ALLOWED,
        )
    )
    console.print(f"[green]ALLOWED[/green]  READ {read.resource}")
    console.print(f"\nWrote {bus.jsonl_path}")


if __name__ == "__main__":
    app()
