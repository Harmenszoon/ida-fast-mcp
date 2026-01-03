# IDA Fast MCP

MCP server for IDA Pro. Lets AI agents reverse engineer binaries.

[![Lint](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml/badge.svg)](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml)
![IDA Pro 9.x](https://img.shields.io/badge/IDA%20Pro-9.x-blue)
![Python 3.12+](https://img.shields.io/badge/Python-3.12+-green)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-lightgrey)](LICENSE)

## Why

AI agents need to navigate binaries the way humans do: decompile a function, follow xrefs, rename variables, set types. This gives them that.

Every line of pseudocode includes its address. The agent sees `/* 0x140001234 */ if (a1 > 5)` and can reason about exactly where things are. It can rename that variable, set its type, add a comment — all referencing precise locations.

One file. Drop it in your plugins folder. No dependencies, no setup, no config files.

## Features

- **Address-annotated pseudocode** — every decompiled line shows its EA
- **Stable** — all IDA API calls on main thread, 5s timeout, won't hang or crash
- **Bounded outputs** — pagination on all list operations, no memory bombs
- **Single file** — stdlib + IDA modules only, nothing to install

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
