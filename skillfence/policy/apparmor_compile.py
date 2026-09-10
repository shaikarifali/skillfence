"""Compiles a SkillFence `CapabilityManifest` into a real, loadable
AppArmor profile — SkillFence as a *policy compiler*, not an enforcer.

Why AppArmor and not seccomp-bpf: seccomp filters raw syscall arguments
and can block a syscall *class* entirely ("no `connect()` at all"), but
its BPF programs can't dereference a path-string argument, so it can't
express "allow reads under `${workspace}/logs/**` only" -- which is most
of what a capability manifest actually declares. AppArmor is a path-aware
MAC system built around exactly this shape of rule (`/path/** r,`,
`/usr/bin/curl ix,`, coarse network mediation), so it maps far more
directly onto `filesystem.read/write`, `process.execute`, and
`network.enabled`.

Why this stays a compiler, not a daemon: the same "wrap mature existing
infrastructure, don't reimplement it" principle as `skillfence.telemetry`
wrapping `auditd` instead of a bespoke syscall monitor. Loading the
generated profile (`apparmor_parser -r`) and confining the real process
(`aa-exec -p <profile-name> -- <command>`) stays the operator's job.
SkillFence never runs as a privileged enforcement service.

Honest translation limits (also written into the generated profile as
comments, so the artifact documents its own gaps):
  - `network.domains` (a destination allowlist) has NO AppArmor
    equivalent -- AppArmor's network mediation is address-family/socket-
    type only, not destination-based. A profile with `network.enabled:
    true` permits networking broadly, never scoped to the declared domains.
  - `secrets.access` (a bare boolean, names no path or syscall) is not
    translated at all -- there's nothing here for an OS-level rule to hook.
  - Debian/Ubuntu-only in practice: AppArmor isn't RHEL/Fedora's default
    LSM (that's SELinux, a materially different policy language).
  - `process.execute` entries that aren't already absolute paths are
    heuristically resolved to `/usr/bin/<name>` and `/bin/<name>` via
    AppArmor brace expansion -- review before trusting on a nonstandard
    layout (a custom install prefix, a venv shim, ...).
  - A `filesystem.read`/`write` pattern that's still relative (or `~`-
    prefixed) by the time it reaches this compiler -- never templated
    with `${workspace}` at `CapabilityManifest.load()` time, which some
    manifests skip entirely (the MCP proxy has no lab sandbox to resolve
    against, so its example manifests declare plain `./reports/**`
    literals) -- has no cwd or shell to resolve it against at the OS
    level. Pass `workspace=`/`home=` to resolve these; unresolved ones
    are skipped with an explicit `# SKIPPED` comment rather than emitted
    as a rule that would silently never match anything.
  - Not verified against a live `apparmor_parser` -- this was built in a
    sandbox with no root access to install `apparmor-utils`, so profiles
    are correct against the documented, stable AppArmor grammar, not
    confirmed against the real parser. Validate with
    `apparmor_parser -Q -r <profile>` before relying on one.
"""

from __future__ import annotations

from skillfence.policy.manifest import CapabilityManifest


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _maybe_quote_pattern(pattern: str) -> str:
    if any(ch.isspace() for ch in pattern) or '"' in pattern:
        return _quote(pattern)
    return pattern


def _resolve_pattern(pattern: str, *, workspace: str | None, home: str | None) -> tuple[str | None, str | None]:
    """AppArmor rules only ever match a process's *resolved absolute*
    path -- there's no shell in the loop to expand `~` or interpret a
    relative path against a cwd. A manifest pattern that reaches here
    still relative (never templated with `${workspace}` at
    `CapabilityManifest.load()` time, e.g. a bare `./reports/**` some
    manifests use directly) would silently match nothing at runtime if
    emitted as-is -- worse than not emitting a rule for it at all.
    Returns `(resolved_pattern, None)` on success, or `(None, reason)`
    when it can't be resolved without more information from the caller.
    """
    if pattern.startswith("/"):
        return pattern, None
    if pattern.startswith("~"):
        if home is None:
            return None, f"cannot resolve {pattern!r} -- no --home given to expand it against"
        rest = pattern[1:].lstrip("/")
        resolved = f"{home.rstrip('/')}/{rest}" if rest else home.rstrip("/")
        return resolved, None
    relative = pattern[2:] if pattern.startswith("./") else pattern
    if workspace is None:
        return None, f"cannot resolve relative pattern {pattern!r} -- no --workspace given to expand it against"
    return f"{workspace.rstrip('/')}/{relative}", None


def _exec_pattern(entry: str) -> str:
    """A manifest's `process.execute` entries are bare command names in
    every real-world manifest seen so far (`"curl"`, `"cat"`, ...) -- but
    AppArmor exec rules need a path, not a bare name, since AppArmor
    doesn't do PATH resolution the way a shell does. Brace-expanded to
    the two conventional locations rather than guessing one.
    """
    if entry.startswith("/"):
        return _maybe_quote_pattern(entry)
    return f"/{{usr/,}}bin/{entry}"


def compile_to_apparmor(
    manifest: CapabilityManifest,
    *,
    binary: str,
    profile_name: str | None = None,
    workspace: str | None = None,
    home: str | None = None,
) -> str:
    """Returns AppArmor profile text for `manifest`, confining `binary`
    (the real interpreter/executable that will run the agent, e.g.
    `/usr/bin/python3`) under a *named* profile -- not attached to the
    binary path alone, since several different skills may all run under
    the same interpreter and each needs its own distinct confinement.

    If `manifest` was already loaded via `CapabilityManifest.load(path,
    workspace=...)` (the way the runtime gateway always uses it), its
    `${workspace}`-templated patterns are already absolute by the time
    they reach here. `workspace`/`home` are a *second* resolution pass
    for patterns that were never templated at all -- some manifests
    declare plain relative literals like `./reports/**` directly (the MCP
    proxy has no lab sandbox to resolve against, so its example manifests
    do this) or a `~/...` path. A pattern that stays relative all the way
    to AppArmor would silently match nothing at runtime, so one that
    can't be resolved (no `workspace`/`home` given) is skipped with an
    explicit comment instead of emitted broken.
    """
    name = profile_name or manifest.name
    lines: list[str] = [
        "#include <tunables/global>",
        "",
        f"# Generated by `skillfence policy compile-apparmor` from the capability",
        f"# manifest for skill {manifest.name!r} (v{manifest.version}).",
        f"# Purpose: {'; '.join(manifest.purpose) if manifest.purpose else '(none declared)'}",
        "#",
        "# This is a real, loadable AppArmor policy. Load it with:",
        "#   apparmor_parser -r <this-file>",
        "# and confine the real agent process with:",
        f"#   aa-exec -p {name} -- <command>",
        "# SkillFence compiles policy; it does not load or enforce it itself.",
        "",
        f"profile {_quote(name)} {_quote(binary)} {{",
        "  #include <abstractions/base>",
        "",
    ]

    fs = manifest.capabilities.filesystem
    if fs.read or fs.write:
        lines.append("  # filesystem.read / filesystem.write")
        for pattern in fs.read:
            resolved, warning = _resolve_pattern(pattern, workspace=workspace, home=home)
            if resolved is None:
                lines.append(f"  # SKIPPED (read): {warning}")
            else:
                lines.append(f"  {_maybe_quote_pattern(resolved)} r,")
        for pattern in fs.write:
            resolved, warning = _resolve_pattern(pattern, workspace=workspace, home=home)
            if resolved is None:
                lines.append(f"  # SKIPPED (write): {warning}")
            else:
                lines.append(f"  {_maybe_quote_pattern(resolved)} w,")
        lines.append("")

    proc = manifest.capabilities.process
    if proc.execute:
        lines.append("  # process.execute -- bare command names are heuristically resolved to")
        lines.append("  # common bin directories; review before trusting on a nonstandard layout.")
        for entry in proc.execute:
            lines.append(f"  {_exec_pattern(entry)} ix,")
        lines.append("")

    net = manifest.capabilities.network
    lines.append("  # network.enabled")
    if net.enabled:
        lines.append("  network inet stream,")
        lines.append("  network inet dgram,")
        lines.append("  network inet6 stream,")
        lines.append("  network inet6 dgram,")
        lines.append("  network unix stream,")
        if net.domains:
            lines.append(
                f"  # NOTE: manifest declares a domain allowlist ({', '.join(net.domains)}) -- "
                "AppArmor's network mediation has no destination-based"
            )
            lines.append("  # filtering; this profile permits networking broadly, not scoped to those domains.")
    else:
        lines.append("  deny network,")
    lines.append("")

    if manifest.capabilities.secrets.access:
        lines.append(
            "  # NOTE: manifest declares secrets.access: true -- there is no AppArmor-enforceable"
        )
        lines.append("  # equivalent (it names no path or syscall); not translated.")
        lines.append("")

    lines.append("}")
    return "\n".join(lines) + "\n"
