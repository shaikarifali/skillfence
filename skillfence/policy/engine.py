"""Policy engine — compares an intended runtime action against a skill's
declared CapabilityManifest and produces structured PolicyResult evidence
(declared vs requested vs observed; AST03 capability drift; AST04
metadata-vs-runtime mismatch).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from skillfence.policy.manifest import CapabilityManifest
from skillfence.policy.sensitive import is_sensitive_env_var, is_sensitive_path


@dataclass
class PolicyResult:
    declared: bool
    sensitive: bool
    reasons: list[str] = field(default_factory=list)


class PolicyEngine:
    def __init__(self, manifest: CapabilityManifest) -> None:
        self.manifest = manifest

    def evaluate_fs_read(self, path: str) -> PolicyResult:
        declared = self.manifest.allows_fs_read(path)
        sensitive = is_sensitive_path(path)
        reasons = []
        if sensitive:
            reasons.append("sensitive resource")
        if not declared:
            reasons.append("capability not declared in manifest")
        return PolicyResult(declared=declared, sensitive=sensitive, reasons=reasons)

    def evaluate_fs_write(self, path: str) -> PolicyResult:
        declared = self.manifest.allows_fs_write(path)
        sensitive = is_sensitive_path(path)
        reasons = []
        if sensitive:
            reasons.append("sensitive resource")
        if not declared:
            reasons.append("capability not declared in manifest")
        return PolicyResult(declared=declared, sensitive=sensitive, reasons=reasons)

    def evaluate_process(self, executable: str) -> PolicyResult:
        declared = self.manifest.allows_process(executable)
        reasons = [] if declared else ["process execution not declared in manifest"]
        return PolicyResult(declared=declared, sensitive=False, reasons=reasons)

    def evaluate_network(self, domain: Optional[str]) -> PolicyResult:
        declared = self.manifest.allows_network(domain)
        reasons = []
        if not self.manifest.capabilities.network.enabled:
            reasons.append("network access not declared (network: false)")
        elif not declared:
            reasons.append(f"destination '{domain}' not in declared domain allowlist")
        return PolicyResult(declared=declared, sensitive=False, reasons=reasons)

    def evaluate_env_secret(self, var_name: str) -> PolicyResult:
        declared = self.manifest.allows_secrets()
        sensitive = is_sensitive_env_var(var_name)
        reasons = []
        if sensitive:
            reasons.append("sensitive environment variable")
        if not declared:
            reasons.append("secret access not declared in manifest (secrets.access: false)")
        return PolicyResult(declared=declared, sensitive=sensitive, reasons=reasons)
