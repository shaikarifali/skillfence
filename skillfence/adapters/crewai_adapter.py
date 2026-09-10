"""CrewAI adapter — wraps a real tool's underlying callable so it's
authorized through `RuntimeGateway` before it runs.

This is architecturally different from the LangChain adapter, and that
difference was verified against real crewai 1.15.20 source before writing
a line of this, not assumed: CrewAI *does* have an event bus
(`crewai_event_bus`, emitting `ToolUsageStartedEvent` from
`ToolUsage._use()`), but that emit is fire-and-forget — sync handlers run
in a `ThreadPoolExecutor` the caller never awaits, so a handler raising an
exception there has no effect on whether the real tool call proceeds. A
callback-handler-style adapter (like the LangChain one) would silently do
nothing here. What actually executes a real tool synchronously, on the
same call stack, every time, is `CrewStructuredTool.invoke()` calling
`self.func(**parsed_args, **kwargs)` — and `BaseTool.to_structured_tool()`
sets that `func` to nothing more than the tool's own bound `_run` method.
So instead of hooking an event, this wraps `func` itself: the one place
guaranteed to run synchronously in the real agent tool-calling path,
regardless of which event-bus semantics CrewAI ships in a given version.

`crewai` is an optional dependency (only imported inside `wrap_tool`, not
at module import time) — installing SkillFence doesn't require it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from skillfence.mcp.toolmap import ToolMap
from skillfence.runtime.gateway import RuntimeGateway

if TYPE_CHECKING:
    from crewai.tools import BaseTool
    from crewai.tools.structured_tool import CrewStructuredTool


def wrap_tool(tool: "BaseTool", gateway: RuntimeGateway, tool_map: ToolMap) -> "CrewStructuredTool":
    """Returns a `CrewStructuredTool` — pass it into `Agent(tools=[...])`
    in place of the original `tool`. Every real call is authorized through
    `gateway` first; the real underlying function only runs if authorized.
    """
    try:
        from crewai.tools.structured_tool import CrewStructuredTool  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
        raise ImportError(
            "the CrewAI adapter needs crewai: pip install 'skillfence[crewai]'"
        ) from exc

    structured = tool.to_structured_tool()
    real_func = structured.func
    tool_name = structured.name

    def guarded(**kwargs: Any) -> Any:
        kind, resource = tool_map.resolve(tool_name, kwargs)
        if kind is None:
            policy = tool_map.unmapped_tool_policy
            if policy == "allow":
                return real_func(**kwargs)
            if policy == "block":
                raise PermissionError(
                    f"Blocked by SkillFence: tool {tool_name!r} has no entry in the tool map."
                )
            kind = "unmapped"  # policy == "gate": routes through authorize(), always human-gates

        gateway.authorize(kind=kind, resource=resource)  # raises ActionBlocked on deny
        return real_func(**kwargs)

    structured.func = guarded
    return structured
