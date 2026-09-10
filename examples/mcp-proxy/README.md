# MCP proxy — worked example

Puts SkillFence in front of a real MCP server. To the real client, this
proxy *is* the MCP server. To `fake_server.py` (standing in for whatever
real server you'd actually run), this proxy *is* the client. Every
`tools/call` gets authorized through the same policy/risk/human-gate
pipeline the DVAS labs use, before the real request is ever forwarded.

## Files

- `fake_server.py` — a tiny stdlib-only fixture "real" MCP server. Exposes
  `read_file`, `run_command`, `web_fetch`, and one deliberately-unmapped
  `mystery_tool`. Every call it receives just echoes back a canned success
  — the point is proving whether SkillFence's proxy *let the call reach
  here at all*, not doing real work.
- `manifest.yaml` — the same `CapabilityManifest` schema every DVAS lab
  uses, declaring what this server's tools are allowed to touch: only
  `./reports/**`, no process execution, no network, no secrets.
- `tool-map.yaml` — the piece a real MCP server needs that a DVAS lab
  doesn't: since a real server's tool names are arbitrary strings nothing
  in the MCP spec can interpret, this declares which of `fake_server.py`'s
  tool names correspond to which SkillFence action kind
  (`fs_read`/`fs_write`/`process_exec`/`network`/`secret`), and which
  JSON-RPC argument holds the resource to evaluate.

## Run it

```bash
skillfence mcp-proxy \
  --manifest examples/mcp-proxy/manifest.yaml \
  --tool-map examples/mcp-proxy/tool-map.yaml \
  -- python3 examples/mcp-proxy/fake_server.py
```

Point any real MCP client at this command instead of at `fake_server.py`
directly, and it gets the exact same tool list and behavior — with every
call now passing through SkillFence first.

## What happens to each of the four tools

- **`read_file` on `./reports/q3.md`** — declared, LOW risk. Allowed;
  forwarded to `fake_server.py`; you'll see its canned response.
- **`read_file` on `~/.aws/credentials`** — undeclared *and* a recognized
  sensitive path. HIGH/CRITICAL. Since this proxy's own stdin is entirely
  consumed by the MCP message stream, there's no interactive TTY available
  for a human decision on the same channel — it **fails safe and denies**,
  exactly like every other SkillFence entry point does with no TTY
  available. `fake_server.py` never sees this call.
- **`run_command`** — undeclared but not sensitive on its own (`process.execute`
  scoring has no "sensitive" dimension by itself) — LOW risk, allowed
  through. This is intentional and matches the rest of the engine: process
  execution alone only escalates combined with another factor.
- **`web_fetch`** — `manifest.yaml` declares `network.enabled: false`
  entirely, so any call scores HIGH (undeclared + egress + unknown
  destination) and fails safe, same as the credential read above.
- **`mystery_tool`** — not in `tool-map.yaml` at all. `unmapped_tool_policy:
  gate` (the default) means SkillFence has no capability signal for it
  whatsoever, which always routes to the human gate — and fails safe here
  for the same no-TTY reason.

## Since it fails safe on anything gate-worthy, how do you actually use this live?

Two ways, same as the rest of SkillFence:

```bash
# Pre-authorize something you already know is fine, ahead of time:
skillfence policy allow example-mcp-server filesystem.read "~/.aws/credentials" \
  --reason "reviewed, approved for this integration"

# Or review afterward — each session writes its own <session-id>.findings.jsonl:
skillfence findings .skillfence/mcp/mcp-<session-id>.findings.jsonl
```

`--fresh` skips the shared policy store for one run, ignoring any grants
you've pre-authorized — useful for confirming the deny-by-default behavior
itself, like this example does.
