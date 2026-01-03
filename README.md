# IDA Fast MCP

MCP server for IDA Pro. Designed for how LLMs reason.

[![Lint](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml/badge.svg)](https://github.com/Harmenszoon/ida-fast-mcp/actions/workflows/lint.yml)
![IDA Pro 9.x](https://img.shields.io/badge/IDA%20Pro-9.x-blue)
![Python 3.12+](https://img.shields.io/badge/Python-3.12+-green)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-lightgrey)](LICENSE)

## Design

Context is finite. Every tool, every output, every description competes for the tokens an LLM uses to think. This server is built around that constraint.

- **11 tools** — no redundancy, no overlap
- **Bounded outputs** — pagination on all lists, no context bombs
- **Address-annotated pseudocode** — every line shows its EA for precise references
- **Tight descriptions** — the model knows exactly what each tool returns

## Install

1. Copy `ida_fast_mcp.py` to your IDA plugins folder
2. Restart IDA
3. Add to your MCP client config:
   ```json
   "ida-fast-mcp": {
     "url": "http://127.0.0.1:13338/mcp"
   }
   ```

No dependencies. No setup scripts. No environment configuration.

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
