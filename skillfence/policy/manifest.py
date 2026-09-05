"""Capability manifest — the skill's declared behavior.

A skill ships a manifest.yaml alongside its SKILL.md. SkillFence never
trusts the manifest as ground truth about what the skill *will* do — only
as a declaration to diff runtime behavior against (capability drift).
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class FilesystemCapabilities(BaseModel):
    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)


class ProcessCapabilities(BaseModel):
    execute: list[str] = Field(default_factory=list)


class NetworkCapabilities(BaseModel):
    enabled: bool = False
    domains: list[str] = Field(default_factory=list)


class SecretCapabilities(BaseModel):
    access: bool = False


class Capabilities(BaseModel):
    filesystem: FilesystemCapabilities = Field(default_factory=FilesystemCapabilities)
    process: ProcessCapabilities = Field(default_factory=ProcessCapabilities)
    network: NetworkCapabilities = Field(default_factory=NetworkCapabilities)
    secrets: SecretCapabilities = Field(default_factory=SecretCapabilities)


class CapabilityManifest(BaseModel):
    name: str
    version: str = "0.1"
    purpose: list[str] = Field(default_factory=list)
    capabilities: Capabilities = Field(default_factory=Capabilities)

    @classmethod
    def load(cls, path: Path, *, workspace: Optional[Path] = None) -> "CapabilityManifest":
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        manifest = cls.model_validate(raw)
        if workspace is not None:
            manifest = manifest.resolve(workspace)
        return manifest

    def resolve(self, workspace: Path) -> "CapabilityManifest":
        """Expand ${workspace} in declared paths."""
        ws = str(workspace)

        def expand(patterns: list[str]) -> list[str]:
            return [p.replace("${workspace}", ws) for p in patterns]

        self.capabilities.filesystem.read = expand(self.capabilities.filesystem.read)
        self.capabilities.filesystem.write = expand(self.capabilities.filesystem.write)
        return self

    # -- declared-capability checks -------------------------------------

    def allows_fs_read(self, path: str) -> bool:
        return _match_any(path, self.capabilities.filesystem.read)

    def allows_fs_write(self, path: str) -> bool:
        return _match_any(path, self.capabilities.filesystem.write)

    def allows_process(self, executable: str) -> bool:
        return executable in self.capabilities.process.execute

    def allows_network(self, domain: Optional[str]) -> bool:
        if not self.capabilities.network.enabled:
            return False
        if not self.capabilities.network.domains:
            # network enabled but no domain allowlist declared -> declared as
            # unrestricted network access, which is itself a signal handled
            # by the risk engine, not silently blocked here.
            return True
        if domain is None:
            return False
        return _match_any(domain, self.capabilities.network.domains, is_domain=True)

    def allows_secrets(self) -> bool:
        return self.capabilities.secrets.access


def _match_any(value: str, patterns: list[str], *, is_domain: bool = False) -> bool:
    if not patterns:
        return False
    for pattern in patterns:
        if is_domain:
            if value == pattern or value.endswith("." + pattern):
                return True
        else:
            if fnmatch.fnmatch(value, pattern):
                return True
    return False
