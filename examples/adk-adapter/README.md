# Google ADK adapter — worked example

```bash
pip install 'skillfence[adk]'
python3 examples/adk-adapter/demo.py
```

## Why this adapter is shaped differently from LangChain and CrewAI

Verifying against real `google-adk` 2.8.0 source before writing a line of
this turned up a genuinely different — and better — mechanism than either
of the other two frameworks offer. In
`google/adk/flows/llm_flows/functions.py`, `_run_with_trace()` runs every
callback in `agent.canonical_before_tool_callbacks` in order; the first one
to return a non-`None` dict short-circuits the real call
(`__call_tool_async`, the only thing that ever calls `tool.run_async()`)
entirely, and that dict becomes the tool's response instead. ADK's own
`BeforeToolCallback` type is declared as
`Callable[[BaseTool, dict, ToolContext], Optional[dict[str, Any]]]` —
returning a dict *is* the documented way to block a call, not a side
effect of raising an exception the framework might or might not respect.

So `build_before_tool_callback()` doesn't need `raise_error = True` (the
LangChain footgun) or to reach past an event bus into a real function
(the CrewAI workaround) — it returns `None` to allow, or an error dict to
block, exactly matching ADK's own contract.

`tests/test_adk_adapter.py` proves this by driving the real
`agent.canonical_before_tool_callbacks` (confirming a real `LlmAgent`
resolves and registers the callback correctly) and the real
`FunctionTool.run_async()` (confirming the underlying function genuinely
never runs when blocked, checked via a side-effect log — not just "a dict
came back").

## Files

- `demo.py` — three real tool calls: one declared (runs for real), one
  undeclared+sensitive filesystem read (blocked), one undeclared network
  call (blocked, `manifest.yaml` declares `network.enabled: false`).
- `manifest.yaml` / `tool-map.yaml` — same schema and pattern as the other
  two adapters.
