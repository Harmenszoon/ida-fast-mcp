# IDA Fast MCP

MCP server for IDA Pro. Designed for how LLMs reason.

[![Lint](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml/badge.svg)](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml)
![IDA Pro 9.x](https://img.shields.io/badge/IDA%20Pro-9.x-blue)
![Python 3.12+](https://img.shields.io/badge/Python-3.12+-green)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-lightgrey)](LICENSE)

## Design

Context is finite. Every token an LLM spends parsing tool names, reading descriptions, or processing bloated output is a token not spent reasoning about your binary.

- **11 tools** — no redundancy, no overlap, clear names like `get_function` and `list_imports`
- **Tight tool descriptions** — unambiguous inputs and outputs, so the model picks the right tool and uses it correctly the first time
- **Bounded outputs** — pagination on all lists, no context bombs

Every error doubles your token cost. This server is shaped to minimize them.

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

No dependencies. No subprocess spawning. No environment setup.

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

## Config

Default: `127.0.0.1:13338`

Environment variables (optional):
```
IDA_FAST_MCP_HOST=127.0.0.1
IDA_FAST_MCP_PORT=13338
```

## License

[Unlicense](LICENSE) — Public domain
