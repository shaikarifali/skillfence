"""Tool map — declares, for one specific downstream MCP server, which of
its tools correspond to which SkillFence-authorizable action kind, and
which JSON-RPC argument holds the resource string to evaluate.

This is deliberately a *second*, small config file alongside the existing
`skill/manifest.yaml` capability manifest, not a replacement for it: the
manifest still declares what's *allowed* (globs, domains, executables);
the tool map only declares how to *read* a real server's arbitrary tool
names into the same five action kinds the manifest already governs. A
real MCP server's tool names are arbitrary strings (`read_file`,
`fs.read`, `get_file_contents`, ...) — nothing in the MCP spec can tell
SkillFence what a tool *means*, so this is the one piece of information a
human has to supply once per server.

Unmapped tools fail closed by default (`unmapped_tool_policy: gate`) —
consistent with SkillFence's existing fail-safe-on-no-TTY behavior: an
unrecognized tool is exactly the situation where the runtime should not
guess.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

VALID_KINDS = {"fs_read", "fs_write", "process_exec", "network", "secret"}
VALID_UNMAPPED_POLICIES = {"gate", "allow", "block"}


class ToolBinding(BaseModel):
    kind: str
    resource_arg: str


class ToolMap(BaseModel):
    unmapped_tool_policy: str = "gate"
    tools: dict[str, ToolBinding] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "ToolMap":
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        tool_map = cls.model_validate(raw)
        if tool_map.unmapped_tool_policy not in VALID_UNMAPPED_POLICIES:
            raise ValueError(
                f"unmapped_tool_policy must be one of {sorted(VALID_UNMAPPED_POLICIES)}, "
                f"got {tool_map.unmapped_tool_policy!r}"
            )
        for name, binding in tool_map.tools.items():
            if binding.kind not in VALID_KINDS:
                raise ValueError(f"tool {name!r}: kind must be one of {sorted(VALID_KINDS)}, got {binding.kind!r}")
        return tool_map

    def resolve(self, tool_name: str, arguments: dict) -> tuple[Optional[str], str]:
        """Returns (kind, resource) for a real `tools/call`. `kind` is
        None when the tool isn't in the map — the caller applies
        `unmapped_tool_policy` in that case. `resource` falls back to a
        stringified dump of the arguments when the configured
        `resource_arg` is missing from this particular call, so an
        authorization decision (and its audit trail) always has *something*
        concrete to point at rather than silently under-scoping.
        """
        binding = self.tools.get(tool_name)
        if binding is None:
            return None, str(arguments)
        resource = arguments.get(binding.resource_arg)
        if resource is None:
            return binding.kind, str(arguments)
        return binding.kind, str(resource)
