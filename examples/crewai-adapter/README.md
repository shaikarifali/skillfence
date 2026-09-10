# CrewAI adapter — worked example

```bash
pip install 'skillfence[crewai]'
python3 examples/crewai-adapter/demo.py
```

## Why this adapter is built differently from the LangChain one

CrewAI *does* have an event bus (`crewai_event_bus`, emitting a
`ToolUsageStartedEvent` before each real tool call) — but verifying it
against real `crewai` 1.15.20 source turned up a real problem: that emit
is fire-and-forget. Sync handlers run in a `ThreadPoolExecutor` that
`ToolUsage._use()` never awaits, so a handler raising an exception there
has zero effect on whether the real tool call proceeds. A callback-style
adapter (the LangChain approach) would silently do nothing here.

What actually runs a real tool synchronously, on the same call stack,
every time, is `CrewStructuredTool.invoke()` calling
`self.func(**parsed_args, **kwargs)` — and `BaseTool.to_structured_tool()`
sets that `func` to nothing more than the tool's own bound `_run` method.
So `wrap_tool()` wraps `func` directly instead of hooking the event bus:
the one place guaranteed to run synchronously in the real agent
tool-calling path, regardless of a given version's event-bus semantics.

`tests/test_crewai_adapter.py` proves this two ways: calling the wrapped
tool's `.invoke()` directly, and — more importantly — dispatching through
`crewai.tools.tool_usage.ToolUsage`, the actual class a live Crew's agent
executor uses to route a tool call by name. Both confirm the real
underlying function never runs when SkillFence blocks the call (checked
via a side-effect counter, not just "an exception happened somewhere").

## Files

- `demo.py` — three real tool calls: one declared (runs for real), one
  undeclared+sensitive filesystem read (blocked), one undeclared network
  call (blocked, `manifest.yaml` declares `network.enabled: false`).
- `manifest.yaml` / `tool-map.yaml` — same schema and pattern as the other
  two adapters.

## Using this in your own crew

```python
from skillfence.adapters.crewai_adapter import wrap_tool

read_file = wrap_tool(ReadFileTool(), gateway, tool_map)
agent = Agent(role="researcher", tools=[read_file], ...)
```
