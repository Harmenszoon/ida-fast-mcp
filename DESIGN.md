# IDA Fast MCP — Design

## What it is

A single-file MCP server, embedded as an IDA Pro plugin, that gives an LLM agent a
tight set of reverse-engineering tools over local HTTP. One user, one IDA instance,
no dependencies.

## Goals

- **Lean.** One file, Python stdlib + IDA modules only. Readable top to bottom in one sitting.
- **Telepathic tools.** Names, descriptions, and outputs are shaped so the model picks
  the right tool and uses it correctly the first time.
- **Bounded outputs.** Every list paginates; nothing floods the context window.
- **Honest behavior.** Do the work, return the result. No machinery pretending to do
  more than the platform allows.

## The one constraint

IDA's API is single-threaded. Every tool runs on IDA's main thread via
`ida_kernwin.execute_sync()`, which already serializes calls. So the server is a thin
wrapper: HTTP request → validate → run on the main thread → JSON result. There is no
queue, no worker pool, and no cache — none are needed, and each would only add state to
get wrong. A genuinely long operation (e.g. decompiling a pathological function) blocks
until it finishes; that is inherent to the single-thread model. `run_python` adds a
best-effort wall-clock deadline that interrupts runaway Python loops, but a single long
native call still cannot be preempted.

## Tools

15 tools, clear verbs, no overlap:

- **get_**: `get_binary_info`, `get_function`, `get_xrefs`, `get_pointer_table`, `get_type`
- **list_**: `list_functions`, `list_strings`, `list_imports`, `list_types`
- **find_**: `find_pattern`
- **set_ / apply_ / define_**: `set_name`, `set_comment`, `apply_type`, `define_type`
- **run_python**: escape hatch for IDAPython — only when no dedicated tool fits; terse, bounded output, time-limited

Each tool is declared once. A `@tool` registration carries its parameter descriptors
(`Addr`, `Int`, `Limit`, `Offset`, `Str`, `Enum`, `Names`, …), and a `ToolSpec` derives the
JSON schema the model sees, the runtime validation the server runs, and the parsed/coerced
arguments the handler receives — all from that single declaration. Schema and validation
cannot drift, and adding a tool is one localized edit. All argument parsing (including
symbol resolution, which touches the database) runs on IDA's main thread inside
`execute_sync`.

## Conventions

- Addresses are lowercase hex strings (`0x401000`); tools also accept symbol names.
- List and search tools paginate with `offset` / `limit` and return `count` plus
  `next_offset` (and `total` where it is cheap to count).
- Tool errors are plain, actionable text with `isError: true`. `run_python` also sets
  `isError: true` on failure, and additionally returns the structured snippet failure
  (syntax/runtime/timeout/oversized) in its `error` field alongside any captured stdout.
- Transport is `POST /mcp`, JSON-RPC 2.0, one request per HTTP call.

## Security

Single local user, loopback by default, and **no authentication**. `run_python` is full
IDAPython execution — arbitrary code in the IDA process — so the HTTP layer is the trust
boundary, not the snippet. Every request is checked before any work runs: the `Host` header
must name loopback (defeats DNS rebinding), any `Origin` must be loopback (legitimate
non-browser MCP clients send none, so this rejects browser-driven CSRF), and `Content-Type`
must be `application/json`. No CORS is granted.

These checks stop web pages and DNS-rebinding, **not** other local processes: a local
non-browser process sends no `Origin` and a loopback `Host`, so it clears every check and
has full power. The bind address defaults to loopback; pointing it at a non-loopback
address exposes that code execution to the network. Keep it on loopback.
