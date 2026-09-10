"""Format-level tests for the AppArmor profile compiler. There's no live
AppArmor kernel/`apparmor_parser` available to validate against in this
sandbox (no root to install `apparmor-utils`) -- these tests check the
generated text against the documented, stable AppArmor grammar (bracket
balance, rule shapes, comment presence), the same disclosed limitation
as the auditd parser tests.
"""

from __future__ import annotations

from pathlib import Path

from skillfence.policy.apparmor_compile import compile_to_apparmor
from skillfence.policy.manifest import CapabilityManifest


def _manifest(tmp_path: Path, yaml_body: str, *, workspace: Path | None = None) -> CapabilityManifest:
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml_body, encoding="utf-8")
    return CapabilityManifest.load(path, workspace=workspace or tmp_path)


def _balanced_braces(text: str) -> bool:
    return text.count("{") == text.count("}") and text.count("{") >= 1


BASE_YAML = """\
name: log-reader
version: "0.1"
purpose:
  - read local deployment logs
capabilities:
  filesystem:
    read: ["${workspace}/logs/**"]
  process:
    execute: []
  network:
    enabled: false
    domains: []
  secrets:
    access: false
"""


def test_generated_profile_has_balanced_braces(tmp_path: Path):
    manifest = _manifest(tmp_path, BASE_YAML)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert _balanced_braces(profile)


def test_boilerplate_present(tmp_path: Path):
    manifest = _manifest(tmp_path, BASE_YAML)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "#include <tunables/global>" in profile
    assert "#include <abstractions/base>" in profile


def test_profile_header_uses_manifest_name_and_binary_by_default(tmp_path: Path):
    manifest = _manifest(tmp_path, BASE_YAML)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert 'profile "log-reader" "/usr/bin/python3" {' in profile


def test_profile_name_override(tmp_path: Path):
    manifest = _manifest(tmp_path, BASE_YAML)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3", profile_name="custom-name")
    assert 'profile "custom-name" "/usr/bin/python3" {' in profile


def test_filesystem_read_pattern_emitted_as_r_rule(tmp_path: Path):
    manifest = _manifest(tmp_path, BASE_YAML, workspace=tmp_path)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert f"{tmp_path}/logs/** r," in profile


def test_filesystem_write_pattern_emitted_as_w_rule(tmp_path: Path):
    yaml_body = BASE_YAML.replace(
        'read: ["${workspace}/logs/**"]',
        'read: ["${workspace}/logs/**"]\n    write: ["${workspace}/out/**"]',
    )
    manifest = _manifest(tmp_path, yaml_body, workspace=tmp_path)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert f"{tmp_path}/out/** w," in profile


def test_bare_command_name_is_brace_expanded(tmp_path: Path):
    yaml_body = BASE_YAML.replace("execute: []", 'execute: ["curl"]')
    manifest = _manifest(tmp_path, yaml_body)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "/{usr/,}bin/curl ix," in profile


def test_absolute_path_command_used_as_is(tmp_path: Path):
    yaml_body = BASE_YAML.replace("execute: []", 'execute: ["/opt/tools/curl"]')
    manifest = _manifest(tmp_path, yaml_body)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "/opt/tools/curl ix," in profile


def test_network_disabled_emits_deny(tmp_path: Path):
    manifest = _manifest(tmp_path, BASE_YAML)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "deny network," in profile
    assert "network inet stream," not in profile


def test_network_enabled_emits_broad_rules_and_domain_caveat(tmp_path: Path):
    yaml_body = BASE_YAML.replace("enabled: false", "enabled: true").replace(
        "domains: []", 'domains: ["api.example.test"]'
    )
    manifest = _manifest(tmp_path, yaml_body)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "network inet stream," in profile
    assert "deny network," not in profile
    assert "api.example.test" in profile
    assert "no destination-based" in profile


def test_network_enabled_without_domains_has_no_caveat_comment(tmp_path: Path):
    yaml_body = BASE_YAML.replace("enabled: false", "enabled: true")
    manifest = _manifest(tmp_path, yaml_body)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "network inet stream," in profile
    assert "no destination-based" not in profile


def test_secrets_access_true_is_disclosed_not_silently_dropped(tmp_path: Path):
    yaml_body = BASE_YAML.replace("access: false", "access: true")
    manifest = _manifest(tmp_path, yaml_body)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "secrets.access: true" in profile
    assert "not translated" in profile


def test_secrets_access_false_has_no_disclosure_comment(tmp_path: Path):
    manifest = _manifest(tmp_path, BASE_YAML)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "not translated" not in profile


def test_purpose_and_version_recorded_in_header_comment(tmp_path: Path):
    manifest = _manifest(tmp_path, BASE_YAML)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "v0.1" in profile
    assert "read local deployment logs" in profile


def test_name_containing_a_space_is_quoted_safely(tmp_path: Path):
    manifest = _manifest(tmp_path, BASE_YAML)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3", profile_name="my skill name")
    assert 'profile "my skill name" "/usr/bin/python3" {' in profile
    assert _balanced_braces(profile)


# -- relative/~ patterns: AppArmor has no cwd or shell, so these need   --
# -- an explicit resolution pass or must be skipped, never emitted      --
# -- broken (the exact bug found while building this compiler)          --


def test_never_templated_relative_pattern_without_workspace_is_skipped_not_emitted_broken(tmp_path: Path):
    yaml_body = BASE_YAML.replace('read: ["${workspace}/logs/**"]', 'read: ["./reports/**"]')
    # loaded with NO workspace at CapabilityManifest.load() time either --
    # exactly the MCP proxy example-manifest shape (a bare relative literal
    # that's never templated at all, so load-time substitution can't help).
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml_body, encoding="utf-8")
    manifest = CapabilityManifest.load(manifest_path)  # no workspace=

    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "./reports/** r," not in profile  # never emitted as an (unenforceable) rule
    assert "SKIPPED" in profile
    assert "reports/**" in profile  # the reason names the pattern that was skipped


def test_never_templated_relative_pattern_resolved_when_workspace_given(tmp_path: Path):
    yaml_body = BASE_YAML.replace('read: ["${workspace}/logs/**"]', 'read: ["./reports/**"]')
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml_body, encoding="utf-8")
    manifest = CapabilityManifest.load(manifest_path)

    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3", workspace="/opt/agent-workspace")
    assert "/opt/agent-workspace/reports/** r," in profile
    assert "SKIPPED" not in profile


def test_tilde_pattern_without_home_is_skipped(tmp_path: Path):
    yaml_body = BASE_YAML.replace('read: ["${workspace}/logs/**"]', 'read: ["~/.aws/credentials"]')
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml_body, encoding="utf-8")
    manifest = CapabilityManifest.load(manifest_path)

    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert "~/.aws/credentials r," not in profile
    assert "SKIPPED" in profile


def test_tilde_pattern_resolved_when_home_given(tmp_path: Path):
    yaml_body = BASE_YAML.replace('read: ["${workspace}/logs/**"]', 'read: ["~/.aws/credentials"]')
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml_body, encoding="utf-8")
    manifest = CapabilityManifest.load(manifest_path)

    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3", home="/home/agent")
    assert "/home/agent/.aws/credentials r," in profile


def test_already_absolute_pattern_from_workspace_templating_is_untouched(tmp_path: Path):
    # the normal path: ${workspace} was already substituted at
    # CapabilityManifest.load() time, so this compiler's own
    # workspace=/home= resolution pass should be a no-op for it.
    manifest = _manifest(tmp_path, BASE_YAML, workspace=tmp_path)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3", workspace="/should/not/be/used")
    assert f"{tmp_path}/logs/** r," in profile
    assert "/should/not/be/used" not in profile


def test_manifest_with_no_declared_capabilities_still_produces_a_valid_profile(tmp_path: Path):
    yaml_body = """\
name: empty-skill
version: "0.1"
purpose: []
capabilities:
  filesystem:
    read: []
  process:
    execute: []
  network:
    enabled: false
    domains: []
  secrets:
    access: false
"""
    manifest = _manifest(tmp_path, yaml_body)
    profile = compile_to_apparmor(manifest, binary="/usr/bin/python3")
    assert _balanced_braces(profile)
    assert "deny network," in profile
