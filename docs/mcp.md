# MCP server (`netlens mcp`)

`netlens mcp` serves netlens' read-only tools over stdio with the
[Model Context Protocol](https://modelcontextprotocol.io), built on the official Rust
SDK ([rmcp](https://github.com/modelcontextprotocol/rust-sdk)). An MCP client such as
an IDE assistant or a desktop chat app can then review config changes with
deterministic, cited findings.

| Tool | Input | Output |
|---|---|---|
| `review` | `before` + `after` config text, or `diff`; optional `vendor` | semantic changes, rule findings with evidence lines, deterministic rollback (all redacted) |
| `lint` | `config` text; optional `vendor` | findings (redacted) |
| `redact` | `text`; optional `mask_ips` | what netlens would send to a model |
| `vet_command` | `vendor`, `command` | whether the read-only gate allows it, plus the normalized and canonical forms, or why not. Runs nothing. |

## What it deliberately can't do

- **No device access.** `troubleshoot` is not exposed over MCP in v1. Every device
  command in netlens needs a human to approve that exact command in a terminal, and
  MCP has no channel that proves a human approved anything. A client could approve its
  own proposals. `vet_command` lets a client check a command, and running it stays a
  human job in `netlens troubleshoot`.
- **No file access.** Tools take text, not paths, so a client can't make netlens read
  files on its behalf.
- **No model calls.** Results are deterministic. The client's own model does the
  explaining, and can cite the finding ids (`F1`, ...) and evidence lines.
- Inputs are limited to 4 MiB.

Each tool call is written to the audit log as `mcp.tool` (tool name, input SHA-256 and
size); disable it with `--no-audit`.

## Client configuration

Most clients take a command plus arguments:

```json
{
  "mcpServers": {
    "netlens": { "command": "netlens", "args": ["mcp"] }
  }
}
```

Use the full path to the binary if `~/.cargo/bin` isn't on the client's `PATH`.

## Quick check from a shell

```sh
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sh","version":"0"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vet_command","arguments":{"vendor":"ios","command":"conf t"}}}' \
 | netlens mcp --no-audit
```

The integration test (`crates/netlens-cli/tests/mcp.rs`) runs the real binary this
way: it lists the tools and calls each one.
