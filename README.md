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

Every error doubles your token cost. This server is shaped to minimize them. See [DESIGN.md](DESIGN.md) for goals and architecture.

## Install

1. Copy `ida_fast_mcp.py` to your IDA plugins folder
2. Restart IDA — server starts automatically at `http://127.0.0.1:13338/mcp`
3. Point your MCP client at the URL

Most clients just need the server URL in their MCP config. Example:
```json
{
  "ida-fast-mcp": {
    "url": "http://127.0.0.1:13338/mcp"
  }
}
```

No dependencies. No environment setup.

## Execution model

Every tool runs on IDA's main thread via `execute_sync()`, which already serializes all callers. There's no queue, worker pool, or cache to reason about — one request in, one JSON result out. A genuinely long operation (e.g. decompiling a pathological function) blocks until it finishes — inherent to IDA's single-threaded API. `run_python` additionally enforces a best-effort time limit that interrupts runaway Python loops.

Transport is `POST /mcp` (JSON-RPC 2.0, one request per HTTP call).

## Tools

| Tool | Description |
|------|-------------|
| `get_binary_info` | Binary metadata and segment list |
| `get_function` | Decompiled pseudocode (falls back to disassembly) |
| `get_xrefs` | Cross-references to address |
| `get_pointer_table` | Read pointer table (vtable, jump table) |
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

## Config

Default: `127.0.0.1:13338`

Environment variables (optional):
```
IDA_FAST_MCP_HOST=127.0.0.1
IDA_FAST_MCP_PORT=13338
```

## Security

Built for a single local user. The server binds loopback only, and `run_python` runs
arbitrary IDAPython — code execution in the IDA process — so the HTTP layer is the trust
boundary. Every request is validated: the `Host` header must be loopback (defeats DNS
rebinding), any `Origin` must be loopback so web pages can't drive it (legitimate
non-browser MCP clients send none), and the body must be `application/json`. No CORS is
granted. Use a local, non-browser MCP client and keep the bind address on loopback.

## License

[Unlicense](LICENSE) — Public domain
