"""Google ADK adapter — a `before_tool_callback` that authorizes every real
tool call through `RuntimeGateway` before it runs, the same way the MCP
proxy does for MCP tool calls and the LangChain/CrewAI adapters do for
theirs.

Verified, not assumed, against real google-adk 2.8.0 source before writing
a line of this (`google/adk/flows/llm_flows/functions.py`,
`_run_with_trace()`): a plugin's `before_tool_callback` runs first, then --
only if that returned `None` -- each callback in
`agent.canonical_before_tool_callbacks` runs in order; the first one to
return a non-`None` dict short-circuits Step 3 (`__call_tool_async`, which
is the only thing that actually calls `tool.run_async()`) entirely, and
that dict becomes the tool's response instead. This is a genuine,
first-class blocking mechanism — unlike LangChain (silently swallows a
callback's exception unless `raise_error = True`) or CrewAI (its event bus
is fire-and-forget and cannot block anything at all), ADK's own callback
contract (`BeforeToolCallback` in `google.adk.agents.llm_agent`) is typed
to return `Optional[dict[str, Any]]` precisely because returning a dict
*is* the documented way to short-circuit the real call.

`google-adk` is an optional dependency, only checked for here, never
imported at module level. The callback itself never touches a real
`google.adk` type at runtime (only `tool.name` and a plain `args` dict), so
nothing here actually needs the package importable to *work* — the check
below exists purely to give an actionable error message if it's missing,
matching the UX of the LangChain/CrewAI adapters.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from skillfence.mcp.toolmap import ToolMap
from skillfence.runtime.gateway import ActionBlocked, RuntimeGateway

if TYPE_CHECKING:
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext


def build_before_tool_callback(gateway: RuntimeGateway, tool_map: ToolMap):
    """Returns a `before_tool_callback` — pass it straight into
    `Agent(before_tool_callback=...)` / `LlmAgent(before_tool_callback=...)`.
    Every real tool call is authorized through `gateway` first; returning a
    dict here (instead of `None`) makes ADK skip the real tool entirely and
    hand the model this dict as the tool's response instead of running it.
    """
    try:
        import google.adk  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised only without the optional dep
        raise ImportError(
            "the Google ADK adapter needs google-adk: pip install 'skillfence[adk]'"
        ) from exc

    def before_tool_callback(
        tool: "BaseTool", args: dict[str, Any], tool_context: "ToolContext"
    ) -> dict[str, Any] | None:
        kind, resource = tool_map.resolve(tool.name, args)
        if kind is None:
            policy = tool_map.unmapped_tool_policy
            if policy == "allow":
                return None  # ADK proceeds to call the real tool
            if policy == "block":
                return {"error": f"Blocked by SkillFence: tool {tool.name!r} has no entry in the tool map."}
            kind = "unmapped"  # policy == "gate": routes through authorize(), always human-gates

        try:
            gateway.authorize(kind=kind, resource=resource, tool_name=tool.name)
        except ActionBlocked as exc:
            return {"error": f"Blocked by SkillFence: {exc.finding.title}. See `skillfence findings` for evidence."}
        return None  # allow -- ADK proceeds to call the real tool

    return before_tool_callback
