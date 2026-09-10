# LangChain adapter — worked example

```bash
pip install 'skillfence[langchain]'
python3 examples/langchain-adapter/demo.py
```

Unlike the [MCP proxy](../mcp-proxy/) (a separate process sitting on the
wire between a real client and server), LangChain tools run as regular
Python function calls inside your own process — there's no protocol to
proxy. Instead, `skillfence.adapters.langchain_adapter.build_handler()`
returns a `BaseCallbackHandler` you pass straight into
`tool.run(callbacks=[handler])`, or into an `AgentExecutor`/`AgentGraph`
alongside your other callbacks. Every real tool call is authorized through
the same `RuntimeGateway` the labs and the MCP proxy use, before the real
tool function runs.

## Why `raise_error = True` matters (and why this was verified, not assumed)

`langchain-core`'s `handle_event()` catches any exception a callback
handler raises and, by default, only **logs a warning** — it does not stop
the tool from running. A callback handler has to opt in with
`raise_error = True` for its exceptions to actually propagate and abort
the call. `build_handler()` sets this on your behalf; without it, a
"blocked" call would be logged and then executed anyway — the exact
failure mode a security tool cannot ship unverified. `tests/test_langchain_adapter.py`
proves this end to end: a blocked tool's real function body is asserted to
never run at all (via a side-effect counter, not just "an exception was
raised somewhere").

## Files

- `demo.py` — runs three real LangChain tool calls: one declared (allowed,
  runs for real), one undeclared+sensitive filesystem read (blocked), one
  undeclared network call (blocked, since `manifest.yaml` declares
  `network.enabled: false`).
- `manifest.yaml` / `tool-map.yaml` — the same schema and pattern as the
  MCP proxy example: a `CapabilityManifest` for what's allowed, and a
  tool-name-to-action-kind map since a real tool's name is an arbitrary
  string nothing in LangChain itself can interpret.

## Using this in your own agent

```python
from skillfence.adapters.langchain_adapter import build_handler
# ... build a RuntimeGateway and ToolMap as in demo.py ...
handler = build_handler(gateway, tool_map)

agent_executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])
```
