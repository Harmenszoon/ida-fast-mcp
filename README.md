# IDA Fast MCP

MCP server for IDA Pro. Exposes reverse-engineering tools to AI agents via HTTP.

[![Lint](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml/badge.svg)](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml)
![IDA Pro 9.x](https://img.shields.io/badge/IDA%20Pro-9.x-blue)
![Python 3.12+](https://img.shields.io/badge/Python-3.12+-green)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-lightgrey)](LICENSE)

## Features

- **Single file, zero dependencies** — stdlib + IDA modules only
- **11 tools** — decompile, xrefs, functions, strings, imports, pattern scan, rename, type, comment
- **Pseudocode first** — decompiles with address annotations; falls back to disassembly
- **Stability first** — all IDA API calls on main thread with 5s timeout

## Install

Copy `ida_fast_mcp.py` to your IDA plugins directory. Restart IDA.

## Config

Default: `127.0.0.1:13338`

```
# Environment variables
IDA_FAST_MCP_HOST=127.0.0.1
IDA_FAST_MCP_PORT=13338
```

## Tools

| Tool | Description |
|------|-------------|
| `get_binary_info` | Binary metadata + segments |
| `get_function` | Decompiled pseudocode or disassembly |
| `get_xrefs` | Cross-references to address |
| `list_functions` | List functions (filterable) |
| `list_strings` | List strings (filterable) |
| `list_imports` | List imports/exports |
| `get_pointer_table` | Read pointer table entries |
| `pattern_scan` | Search for byte patterns |
| `rename` | Rename function/variable |
| `set_type` | Set type annotation |
| `set_comment` | Set comment |

## Transport

```
POST /mcp  (JSON-RPC 2.0)
```

## License

[Unlicense](LICENSE) — Public domain
