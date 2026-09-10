"""LangChain adapter — a `BaseCallbackHandler` that authorizes every real
tool call through `RuntimeGateway` before it runs, the same way the MCP
proxy does for MCP tool calls. `langchain-core` is an optional dependency
(only imported here, not at package import time) — installing SkillFence
doesn't require it.

Verified, not assumed, against the real langchain-core source before
writing this: `BaseTool.run()` calls `callback_manager.on_tool_start(...)`
*before* the `try:` block that invokes the tool's real `_run()`, and
`handle_event()` (langchain_core.callbacks.manager) silently swallows a
callback handler's exception unless that handler's `raise_error` is
`True` — the default is `False`. Both matter: without `raise_error = True`
here, a "blocked" call would be logged and then run anyway, exactly the
kind of bug a security tool cannot afford to ship unverified.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from skillfence.mcp.toolmap import ToolMap
from skillfence.runtime.gateway import RuntimeGateway


def build_handler(gateway: RuntimeGateway, tool_map: ToolMap):
    """Returns a `BaseCallbackHandler` instance wired to `gateway`. Raises
    `ImportError` with an actionable message if `langchain-core` isn't
    installed — this adapter is optional, the rest of SkillFence isn't.
    """
    try:
        from langchain_core.callbacks.base import BaseCallbackHandler
    except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
        raise ImportError(
            "the LangChain adapter needs langchain-core: pip install 'skillfence[langchain]'"
        ) from exc

    class _Handler(BaseCallbackHandler):
        # False is the langchain-core default -- without this override, a
        # blocked ActionBlocked raised in on_tool_start is caught and only
        # logged by handle_event(), and the real tool call proceeds anyway.
        raise_error = True

        def __init__(self) -> None:
            super().__init__()
            self._gateway = gateway
            self._tool_map = tool_map

        def on_tool_start(
            self,
            serialized: dict[str, Any],
            input_str: str,
            *,
            run_id: UUID,
            inputs: dict[str, Any] | None = None,
            **kwargs: Any,
        ) -> None:
            tool_name = serialized.get("name", "")
            arguments = inputs or {}
            kind, resource = self._tool_map.resolve(tool_name, arguments)

            if kind is None:
                policy = self._tool_map.unmapped_tool_policy
                if policy == "allow":
                    return
                if policy == "block":
                    raise PermissionError(
                        f"Blocked by SkillFence: tool {tool_name!r} has no entry in the tool map."
                    )
                kind = "unmapped"  # policy == "gate": routes through authorize(), always human-gates

            self._gateway.authorize(kind=kind, resource=resource)  # raises ActionBlocked on deny

    return _Handler()
