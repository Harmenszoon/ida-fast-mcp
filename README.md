# IDA Fast MCP

MCP server for IDA Pro. Built for automated reverse engineering.

[![Lint](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml/badge.svg)](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml)
![IDA Pro 9.x](https://img.shields.io/badge/IDA%20Pro-9.x-blue)
![Python 3.12+](https://img.shields.io/badge/Python-3.12+-green)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-lightgrey)](LICENSE)

## Design

Context is finite. Every token an LLM spends parsing tool names, reading descriptions, or processing bloated output is a token not spent reasoning about your binary.

- **15 tools** — no redundancy, no overlap, clear verbs (`get_`, `list_`, `find_`, `set_`, `apply_`, `define_`) plus one `run_python` escape hatch
- **Tight tool descriptions** — unambiguous inputs and outputs, so the model picks the right tool and uses it correctly the first time
- **Bounded outputs** — pagination on all lists, no context bombs
- **Direct execution** — runs on IDA's main thread; no queue or worker pool, just request in, result out
- **One declaration per tool** — each tool's parameters are declared once via typed descriptors; the JSON schema the model sees and the validation the server runs are *derived* from that single source, so they can never drift
- **Multiple IDA instances** — open several IDAs and target any of them from one client by binary name; no extra config, no per-instance ports to wire up

Every error doubles your token cost. This server is shaped to minimize them. See [DESIGN.md](DESIGN.md) for goals and architecture.

## Install

1. Copy `ida_fast_mcp.py` to your IDA plugins folder
2. Restart IDA — server starts automatically at `http://127.0.0.1:13338/mcp`
3. Point your MCP client at the URL

Most clients just need the server URL in their MCP config. Example:
```json
{
  "ida-pro": {
    "url": "http://127.0.0.1:13338/mcp"
  }
}
```
The key (`ida-pro` here) is yours to choose — it becomes the tool-name prefix the model
sees (`mcp__ida-pro__get_function`), so a short, descriptive name helps tool selection.

No dependencies. No environment setup.

## Execution model

Every tool runs on IDA's main thread via `execute_sync()`, which already serializes all callers. There's no queue, worker pool, or cache to reason about — one request in, one JSON result out. A genuinely long operation (e.g. decompiling a pathological function) blocks until it finishes — inherent to IDA's single-threaded API. `run_python` additionally enforces a best-effort time limit that interrupts runaway Python loops.

Transport is `POST /mcp` (JSON-RPC 2.0, one request per HTTP call).

## Tools

| Tool | Description |
|------|-------------|
| `get_binary_info` | Binary metadata and segment list |
| `get_function` | Decompiled pseudocode (falls back to disassembly) |
| `get_xrefs` | Inbound cross-references to an address |
| `get_pointer_table` | Read an absolute pointer table (e.g. a vtable) |
| `get_type` | Type definition by name |
| `list_functions` | Functions (filterable by name, size) |
| `list_strings` | Strings (filterable by content, length) |
| `list_imports` | Imports/exports (filterable) |
| `list_types` | Types in local type library |
| `find_pattern` | Byte pattern search |
| `set_name` | Rename symbol or local variable |
| `set_comment` | Set comment at address |
| `apply_type` | Apply type to address or local |
| `define_type` | Parse C declaration into type library |
| `run_python` | Escape hatch: run IDAPython when no dedicated tool fits |
| `list_instances` | List open IDA instances for multi-instance routing |

## Multiple IDA instances

Open as many IDA instances as you like — they coordinate automatically. The client still
connects to the single URL; nothing to configure per instance.

- Call `list_instances` to see the open binaries (`name`, `path`, `pid`).
- Pass an optional `instance` argument (a **binary name**, path, or pid) on any tool to
  choose where it runs — e.g. `get_function(instance="kernel32.dll", address=…)`.
- With one IDA open, `instance` is optional and everything works exactly as before.

Under the hood: each instance serves on a private loopback port; the one holding the main
port routes calls to the others and takes over automatically if it closes. No registry, no
broker, no extra processes.

## Config

Default: `127.0.0.1:13338`

Environment variables (optional):
```
IDA_FAST_MCP_HOST=127.0.0.1
IDA_FAST_MCP_PORT=13338
IDA_FAST_MCP_ALLOW_NONLOOPBACK=1   # opt in to a non-loopback bind (exposes RCE — see Security)
```

## Security

Built for a single local user. There is **no authentication**: `run_python` runs
arbitrary IDAPython — code execution in the IDA process — so the HTTP layer is the entire
trust boundary. Every request is validated: any `Host` header must be loopback (defeats DNS
rebinding), any `Origin` must be loopback so web pages can't drive it (legitimate
non-browser MCP clients send none), and the body must be `application/json`. No CORS is
granted.

What this stops: browser-driven requests (CSRF) and DNS-rebinding. What it does **not**
stop: any other local process that can POST JSON — it sends no `Origin` and a loopback
`Host`, so it passes every check and gets full power.

The server binds loopback and **refuses a non-loopback bind** unless you explicitly set
`IDA_FAST_MCP_ALLOW_NONLOOPBACK=1` (it falls back to `127.0.0.1` and logs why), because a
network-reachable bind would be remote code execution — and the `Host` check is no defense
there, since an attacker can simply send `Host: 127.0.0.1`. Keep the bind on loopback and
use a local, non-browser MCP client.

## License

[Unlicense](LICENSE) — Public domain
