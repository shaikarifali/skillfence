# Live Mode — connect a real agent to a SkillFence-Lab lab

Every SkillFence-Lab lab normally runs through a deterministic, scripted
"reference agent" (`skillfence run`) — correct for `skillfence bench`,
where the same script has to produce the same result every time, but it
means nothing about the run is *actually* driven by an LLM's own
judgment. Live Mode is the alternative: a real, connectable MCP server
for one lab, so a real agent (Claude Desktop, Cline, the MCP Inspector,
or any MCP-speaking client) decides on its own what to call and when.

Every call still executes inside the exact same sandboxed
`RuntimeGateway` every other lab uses — nothing here opens a real
socket, runs a real shell command, or touches a real credential. What's
different is *who's deciding to call the tool in the first place*.

## Start a lab live

```bash
skillfence lab live SkillFence-Lab/AST05/external-doc-injection
```

This binds to `127.0.0.1` on a free port (pick one explicitly with
`--port`) and prints the URL to connect to — `http://127.0.0.1:<port>/mcp`.
**Run this in a terminal you're going to keep watching.** Unlike
`skillfence mcp-proxy` (which is spawned *by* the client, so its own
stdin is consumed by the protocol stream), Live Mode's server is never
spawned by anything — it's a normal foreground process with a normal
free terminal, so the exact same interactive human-gate prompt
`skillfence run` already shows you works completely unchanged here. Omit
`--decision` (the default) to get that real prompt; pass
`--decision reject`/`approve_once`/etc. to auto-answer every gate
non-interactively instead (useful for a hands-off demo, not for actually
watching the interesting part).

## Connect a client

### MCP Inspector (easiest way to just look at it)

```bash
npx @modelcontextprotocol/inspector
```

Opens a local web UI. Choose transport **Streamable HTTP**, paste in the
URL `skillfence lab live` printed, connect, then browse the tool list
and call one by hand to see a real request go through SkillFence.

### Cline (VS Code extension)

Cline supports a remote Streamable HTTP server directly, no bridge
needed. Add to Cline's MCP settings (`cline_mcp_settings.json`):

```json
{
  "mcpServers": {
    "skillfence-lab-live": {
      "type": "streamableHttp",
      "url": "http://127.0.0.1:<port>/mcp"
    }
  }
}
```

### Claude Desktop

Claude Desktop natively spawns local stdio servers; connecting it to an
already-running HTTP server needs the
[`mcp-remote`](https://www.npmjs.com/package/mcp-remote) bridge:

```json
{
  "mcpServers": {
    "skillfence-lab-live": {
      "command": "npx",
      "args": ["mcp-remote", "http://127.0.0.1:<port>/mcp"]
    }
  }
}
```

(Some newer Claude Desktop builds support adding a remote server
directly without a bridge — check Settings first if yours has that
option.)

## What you'll actually see

Ask the connected agent to do whatever the lab's `SKILL.md` says it's
for (Live Mode surfaces that text as the server's `instructions` at
connect time, same as a human reviewer would read). If the lab involves
untrusted content, watch the agent decide for itself whether to act on
anything embedded in what it fetches — that decision is no longer
scripted. When it calls a tool serious enough to gate, the prompt
appears in the terminal running `skillfence lab live`, exactly like
`skillfence run`; whatever you decide there is what the agent's tool
call actually returns (either the real result, or SkillFence's blocked
explanation, which the agent sees as the tool's own output).

Findings land in the lab's `.runs/` directory exactly like a scripted
run — `skillfence findings <lab>` and `skillfence replay` work
afterward without any changes.

## What Live Mode is not

- Not a replacement for `skillfence bench` — the deterministic scripted
  suite is unaffected and remains the regression oracle.
- Not real exploitation — every one of the six tools (`read_file`,
  `write_file`, `execute_shell`, `fetch_url`, `network_send`,
  `read_secret`) is simulated against the lab's own local sandbox
  fixtures, the same as every other lab in this suite.
- Not multi-session or multi-lab — one `skillfence lab live` process
  serves exactly one lab to exactly one connected client at a time.
