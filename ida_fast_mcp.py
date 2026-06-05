"""
IDA Fast MCP — single-file MCP server for IDA Pro (v6.1.0)

What this is
------------
A minimal MCP (Model Context Protocol) server, embedded as an IDA Pro plugin,
that exposes a tight set of reverse-engineering tools to LLM agents over
Streamable HTTP. Built for a single local user and shaped for clean,
first-try LLM tool use.

Design
------
- One constraint drives everything: IDA's API is single-threaded, so every
  tool runs on IDA's main thread via execute_sync(). That call already
  serializes work, so the server stays a thin request -> tool -> JSON wrapper.
- Single source of truth for every tool: a `@tool` declaration carries the
  param descriptors, from which the JSON schema, the runtime validation, and
  the parsed/coerced arguments are all DERIVED. Schema and validation can
  never drift, and adding a tool is one localized edit.
- All argument parsing (symbol resolution, clamping) runs INSIDE execute_sync,
  because resolving a name to an address touches the IDA database.
- Single file, zero dependencies: Python stdlib + IDA modules only.
- Bounded outputs: strict limits and deterministic pagination on every list.
- Pseudocode first: decompile with per-line addresses; fall back to disassembly.

Multiple IDA instances
----------------------
Open several IDAs at once and target any of them from one client. Each instance runs the
full server on a private loopback worker port (first free in DEFAULT_PORT+1 .. +20). The
instance that wins DEFAULT_PORT is the "router": the client connects there, calls
list_instances to see the open binaries, and passes an optional `instance` argument
(binary name, path, or pid) on any tool to choose where it runs. The router discovers peers
by scanning the worker range for /whoami (no files, no registry) and proxies each call to
the chosen instance, or runs it in-process when that instance is itself. With one IDA open
it behaves exactly as before — `instance` is optional and defaults to the only instance.

Compatibility
-------------
- IDA Pro 9.x with the Hex-Rays decompiler.

Transport
---------
POST /mcp  (JSON-RPC 2.0 request/response; no SSE/streaming, no batch requests)
GET  /whoami  (cheap instance-identity probe used for discovery)

Security
--------
For a single local user, with NO authentication: run_python is full code execution by
design, so the HTTP layer is the entire trust boundary. The server binds loopback and
refuses a non-loopback bind unless IDA_FAST_MCP_ALLOW_NONLOOPBACK is set, because a
network-reachable bind would be remote code execution. Every request is also checked: the
Host header must be loopback (defeats DNS rebinding), any browser Origin is rejected (legit
MCP clients send none), and Content-Type must be application/json. These stop web pages and
DNS-rebinding — not other local processes, which (no Origin, loopback Host) clear every
check and have full power. Keep the bind on loopback.

Install
-------
Copy this file to your IDA plugins directory and restart IDA.

Config
------
Defaults to 127.0.0.1:13338. Override via environment or plugin options:
  IDA_FAST_MCP_HOST=127.0.0.1
  IDA_FAST_MCP_PORT=13338
  IDA_FAST_MCP_ALLOW_NONLOOPBACK=1   (opt in to a non-loopback bind; exposes RCE)
  plugins.cfg:  ida_fast_mcp:host=127.0.0.1;port=13338
"""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import random
import re
import secrets
import socket
import sys
import threading
import time
import traceback
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from typing import Any

import ida_bytes
import ida_entry
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_strlist
import ida_typeinf
import ida_xref

# IDA modules (no third-party deps)
import idaapi
import idautils
import idc

# =============================================================================
# Configuration & limits
# =============================================================================

VERSION = "6.1.0"
MCP_ENDPOINT = "/mcp"
WHOAMI_ENDPOINT = "/whoami"

# A per-process random token. The router stamps the chosen instance's token on each proxied
# call and the worker rejects a mismatch, so a call can never land on a different process even
# if a worker port is recycled — a recycled port cannot forge another instance's fresh token.
INSTANCE_HEADER = "X-IDA-Fast-MCP-Instance"
INSTANCE_TOKEN = secrets.token_hex(8)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13338

# Multiple IDA instances: the client connects to the UNIFIED endpoint (DEFAULT_PORT). Every
# instance also runs the full MCP server on a private WORKER port (the first free one in the
# range [DEFAULT_PORT+1 .. +WORKER_PORT_COUNT], loopback only). The instance that wins the
# unified port is the "router": it discovers peers by scanning the worker range and routes
# each tool call to the chosen instance. See the "Multiple IDA instances" section below.
WORKER_PORT_COUNT = 20            # cap on concurrently routable instances

DISCOVERY_TIMEOUT = 0.35          # per-port connect+read budget when scanning for instances
PROXY_TIMEOUT = 120.0             # long but finite: a proxied tool (e.g. a big decompile) may
                                  # take a while, but a wedged worker must not strand a thread
RECLAIM_INTERVAL = 1.5            # base delay between attempts to take over the unified port
RECLAIM_JITTER = 1.5             # added random delay to avoid synchronized bind storms
IDENTITY_REFRESH_MS = 2000        # how often each instance re-reads its binary name on the
                                  # main thread (the DB often loads AFTER the plugin's init)

# Internal limits (named constants for maintainability)
AVAILABLE_VARS_DISPLAY_MAX = 20

# run_python wall-clock budget. The guard (sys.settrace) interrupts Python-level
# runaways (loops) only — a single long native call or hard crash cannot be stopped.
RUN_PYTHON_TIMEOUT_SECONDS = 15.0


# Output bounds (defaults + maxima)
class Limits:
    # list ops
    XREFS_DEFAULT = 20
    XREFS_MAX = 50

    FUNCTIONS_DEFAULT = 30
    FUNCTIONS_MAX = 100

    STRINGS_DEFAULT = 30
    STRINGS_MAX = 100
    STRING_VALUE_MAX = 256  # truncate each value in list_strings

    IMPORTS_DEFAULT = 30
    IMPORTS_MAX = 100

    TYPES_DEFAULT = 30
    TYPES_MAX = 100

    POINTER_TABLE_DEFAULT = 25
    POINTER_TABLE_MAX = 100

    PATTERN_SCAN_DEFAULT = 10
    PATTERN_SCAN_MAX = 50
    PATTERN_SCAN_MIN_BYTES = 2

    # code output
    CODE_LINES_MAX = 2000

    # write ops
    RENAME_BATCH_MAX = 100  # max symbols per bulk set_name call

    # HTTP safety
    HTTP_BODY_MAX = 2 * 1024 * 1024  # 2 MiB

    # run_python output limits
    PYTHON_STDOUT_MAX = 64 * 1024     # 64 KB captured stdout/stderr
    PYTHON_RESULT_MAX = 64 * 1024     # 64 KB serialized _result
    PYTHON_TRACEBACK_MAX = 4 * 1024   # 4 KB error traceback


# =============================================================================
# State
# =============================================================================

@dataclass
class _State:
    # This instance's own worker server (the full single-DB MCP, like a standalone server).
    worker_server: ThreadingHTTPServer | None = None
    worker_thread: threading.Thread | None = None
    worker_port: int | None = None
    # The unified/router server, present only on the instance that currently owns DEFAULT_PORT.
    router_server: ThreadingHTTPServer | None = None
    router_thread: threading.Thread | None = None
    # Background loop that tries to take over the unified port if this instance is not router.
    reclaim_thread: threading.Thread | None = None
    stopping: bool = False
    # Signalled on teardown so the reclaim loop wakes immediately (no stale thread across a
    # quick stop/start). Replaced with a fresh event on each start so generations never mix.
    stop_event: threading.Event = field(default_factory=threading.Event)
    # Unified endpoint host/port (where the client connects); workers are always loopback.
    unified_host: str = DEFAULT_HOST
    unified_port: int = DEFAULT_PORT
    # Cached identity for /whoami, captured on IDA's main thread (never queried live).
    identity: dict[str, Any] = field(default_factory=dict)
    identity_timer: Any = None


_state = _State()


def _capture_identity() -> dict[str, Any]:
    """Snapshot this instance's identity. Must run on IDA's main thread (touches the DB).

    /whoami serves this cache and never calls into IDA, so discovery can't block behind a
    long-running operation.
    """
    return {
        "server": "IDA Fast MCP",
        "version": VERSION,
        "pid": os.getpid(),
        "token": INSTANCE_TOKEN,
        "binary": ida_nalt.get_root_filename() or "",
        "path": ida_nalt.get_input_file_path() or "",
        "worker_port": _state.worker_port,
    }


def _refresh_identity() -> int:
    """IDA timer callback (runs on the main thread): keep the cached binary name current.

    The plugin's init() runs at IDA startup — often before a database is open — so the name
    captured then is empty. Re-reading on a timer fills it in once the DB loads (and tracks a
    later file change). Returns the next interval in ms, or -1 to stop the timer.
    """
    if _state.stopping or _state.worker_server is None:
        return -1
    if _state.identity:
        with contextlib.suppress(Exception):
            _state.identity["binary"] = ida_nalt.get_root_filename() or ""
            _state.identity["path"] = ida_nalt.get_input_file_path() or ""
    return IDENTITY_REFRESH_MS


def _build_python_namespace() -> dict[str, Any]:
    """Fresh namespace for run_python, with common IDA modules preloaded."""
    return {
        "ida_bytes": ida_bytes,
        "ida_entry": ida_entry,
        "ida_funcs": ida_funcs,
        "ida_hexrays": ida_hexrays,
        "ida_ida": ida_ida,
        "ida_kernwin": ida_kernwin,
        "ida_lines": ida_lines,
        "ida_nalt": ida_nalt,
        "ida_name": ida_name,
        "ida_segment": ida_segment,
        "ida_strlist": ida_strlist,
        "ida_typeinf": ida_typeinf,
        "ida_xref": ida_xref,
        "idaapi": idaapi,
        "idautils": idautils,
        "idc": idc,
        "_result": None,
    }


# =============================================================================
# Small helpers
# =============================================================================

def _format_ea(ea: int) -> str:
    """Format effective address as lowercase hex with 0x prefix."""
    if ea is None or ea == idaapi.BADADDR:
        raise ValueError("Invalid address")
    if ea < 0:
        ea &= (1 << 64) - 1
    return f"0x{ea:x}"


_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")


def _is_hex(s: str) -> bool:
    return bool(_HEX_RE.match(s.strip()))


def _require_param(args: dict[str, Any], key: str) -> Any:
    """Extract a required parameter, raising ValueError if missing or null.

    Used for nested objects (e.g. bulk set_name items); top-level tool params are
    handled declaratively by ToolSpec.parse_args.
    """
    if key not in args:
        raise ValueError(f"Missing required parameter: '{key}'")
    val = args[key]
    if val is None:
        raise ValueError(f"Parameter '{key}' cannot be null")
    return val


def _get_bool(value: Any) -> bool:
    """Coerce a flag to bool, treating the strings 'false'/'0'/'no'/'' as False."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def _normalize_size(size: int) -> int:
    """Convert BADSIZE to -1 for cleaner output."""
    # BADSIZE is 0xFFFFFFFFFFFFFFFF or similar large values
    if size < 0 or size > 0x7FFFFFFFFFFFFFFF:
        return -1
    return size


def _parse_address(value: Any) -> int:
    """Parse an address string (hex) or resolve a name to EA. Touches the IDA DB."""
    if isinstance(value, int):
        return value

    if value is None:
        raise ValueError("Address is required")

    s = str(value).strip()
    if not s:
        raise ValueError("Address is required")

    # 1) An explicit 0x prefix is unambiguously a hex address.
    if s[:2].lower() == "0x" and _is_hex(s):
        return int(s, 16)

    # 2) Prefer a symbol match (handles mangled names too) before treating a bare token
    #    as hex — otherwise a symbol literally named like hex (e.g. "deadbeef") would be
    #    misread as the address 0xdeadbeef.
    ea = ida_name.get_name_ea(idaapi.BADADDR, s)
    if ea != idaapi.BADADDR:
        return ea

    # 3) Fall back to bare hex (no prefix) for convenience.
    if _is_hex(s):
        return int(s, 16)

    raise ValueError(
        f"Cannot resolve '{s}' to an address. "
        f"Use list_functions or list_strings to find valid symbols."
    )


# =============================================================================
# IDA main-thread execution wrapper
# =============================================================================

def _ida_execute(fn: Callable[[], Any], *, write: bool) -> Any:
    """Run fn on IDA's main thread via execute_sync (which serializes all callers)."""
    result: Any = None
    exception: BaseException | None = None
    ran = False

    def _wrapper() -> int:
        nonlocal result, exception, ran
        ran = True
        try:
            result = fn()
        except BaseException as e:  # noqa: BLE001 - captured and re-raised to the caller
            exception = e
        return 0

    ida_kernwin.execute_sync(_wrapper, ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ)

    if not ran:
        raise RuntimeError("IDA did not run the request (execute_sync failed)")
    if exception is not None:
        raise exception
    return result


# =============================================================================
# Parameter descriptors — single source of truth per tool argument
#
# Each descriptor knows how to (a) emit its JSON-schema fragment and (b) parse/
# coerce a raw value into the typed value the handler wants (raising a clean,
# agent-readable ValueError on bad input). ToolSpec derives the inputSchema,
# the required list, and the runtime validation from the same descriptors, so
# the schema the model sees and the checks the server runs can never disagree.
# =============================================================================

_MISSING = object()


class Param:
    """Base parameter descriptor. A param is REQUIRED iff it has no default."""

    json_type = "string"

    def __init__(self, name: str, *, default: Any = _MISSING, description: str | None = None) -> None:
        self.name = name
        self.default = default
        self.description = description

    @property
    def required(self) -> bool:
        return self.default is _MISSING

    def fallback(self) -> Any:
        return None if self.default is _MISSING else self.default

    def schema(self) -> dict[str, Any]:
        s: dict[str, Any] = {"type": self.json_type}
        s.update(self._extra())
        # A None default is the "conditionally required" marker; don't advertise it.
        if self.default is not _MISSING and self.default is not None:
            s["default"] = self.default
        if self.description:
            s["description"] = self.description
        return s

    def _extra(self) -> dict[str, Any]:
        return {}

    def parse(self, raw: Any) -> Any:
        return raw


class Addr(Param):
    """A hex address or a symbol name, parsed to an int EA (touches the IDA DB)."""

    def __init__(self, name: str = "address", *, default: Any = _MISSING,
                 description: str = "Hex address (e.g. 0x401000) or symbol name") -> None:
        super().__init__(name, default=default, description=description)

    def parse(self, raw: Any) -> int:
        return _parse_address(raw)


class Str(Param):
    def __init__(self, name: str, *, default: Any = _MISSING, description: str | None = None,
                 strip: bool = False, nonempty: bool = False) -> None:
        super().__init__(name, default=default, description=description)
        self.strip = strip
        self.nonempty = nonempty

    def parse(self, raw: Any) -> str:
        s = str(raw)
        if self.strip:
            s = s.strip()
        if self.nonempty and not s.strip():
            raise ValueError(f"{self.name} must be a non-empty string")
        return s


class NonEmptyStr(Str):
    def __init__(self, name: str, *, description: str | None = None) -> None:
        super().__init__(name, description=description, strip=True, nonempty=True)


class Filter(Str):
    """A lowercased substring match key (optional, defaults to '')."""

    def __init__(self, noun: str) -> None:
        super().__init__("filter", default="", description=f"Case-insensitive substring match on {noun}")

    def parse(self, raw: Any) -> str:
        return str(raw).lower()


class Bool(Param):
    json_type = "boolean"

    def __init__(self, name: str, *, default: bool = False, description: str | None = None) -> None:
        super().__init__(name, default=default, description=description)

    def parse(self, raw: Any) -> bool:
        return _get_bool(raw)


class Int(Param):
    json_type = "integer"

    def __init__(self, name: str, *, default: int, minimum: int | None = None,
                 maximum: int | None = None, description: str | None = None) -> None:
        super().__init__(name, default=default, description=description)
        self.minimum = minimum
        self.maximum = maximum

    def _extra(self) -> dict[str, Any]:
        e: dict[str, Any] = {}
        if self.maximum is not None:
            e["maximum"] = self.maximum
        if self.minimum is not None:
            e["minimum"] = self.minimum
        return e

    def parse(self, raw: Any) -> int:
        try:
            v = int(raw)
        except (TypeError, ValueError):
            v = self.default
        if self.minimum is not None:
            v = max(self.minimum, v)
        if self.maximum is not None:
            v = min(v, self.maximum)
        return v


class Limit(Int):
    def __init__(self, default: int, maximum: int, *, description: str | None = None) -> None:
        super().__init__("limit", default=default, minimum=1, maximum=maximum, description=description)


class Offset(Int):
    def __init__(self) -> None:
        super().__init__("offset", default=0, minimum=0)


class Enum(Param):
    def __init__(self, name: str, choices: Iterable[str], *, default: str, description: str | None = None) -> None:
        super().__init__(name, default=default, description=description)
        self.choices = list(choices)

    def _extra(self) -> dict[str, Any]:
        return {"enum": self.choices}

    def parse(self, raw: Any) -> str:
        v = str(raw).lower()
        if v not in self.choices:
            raise ValueError(f"{self.name} must be one of: {', '.join(self.choices)}")
        return v


class Names(Param):
    """Bulk-rename array; kept raw so the handler can report per-item failures."""

    json_type = "array"

    def __init__(self) -> None:
        super().__init__(
            "names", default=None,
            description="Bulk global rename (globals only): [{address, new_name}, …]. "
                        "Omit address/new_name/old_name when using this.",
        )

    def _extra(self) -> dict[str, Any]:
        return {"items": {"type": "object",
                          "properties": {"address": {"type": "string"}, "new_name": {"type": "string"}},
                          "required": ["address", "new_name"],
                          "additionalProperties": False}}

    def parse(self, raw: Any) -> Any:
        return raw


# =============================================================================
# Tool registry — ToolSpec derives schema + validation + dispatch from one place
# =============================================================================

class _Args:
    """Parsed, typed arguments exposed as attributes (p.address, p.limit, …)."""

    def __init__(self, values: dict[str, Any]) -> None:
        self.__dict__.update(values)


class ToolSpec:
    def __init__(self, name: str, description: str, params: Iterable[Param],
                 handler: Callable[[_Args], dict[str, Any]], writes: bool) -> None:
        self.name = name
        self.description = description
        self.params = list(params)
        self.handler = handler
        self.writes = writes
        self._by_name = {p.name: p for p in self.params}

    def input_schema(self) -> dict[str, Any]:
        s: dict[str, Any] = {
            "type": "object",
            "properties": {p.name: p.schema() for p in self.params},
            "additionalProperties": False,
        }
        required = [p.name for p in self.params if p.required]
        if required:
            s["required"] = required
        return s

    def descriptor(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "inputSchema": self.input_schema()}

    def parse_args(self, raw: dict[str, Any]) -> _Args:
        """Validate keys and coerce values. Runs on IDA's main thread (Addr resolution)."""
        unknown = raw.keys() - self._by_name.keys()
        if unknown:
            raise ValueError(f"Unknown argument(s) for {self.name}: {', '.join(sorted(unknown))}")

        values: dict[str, Any] = {}
        for p in self.params:
            # A present JSON null is treated as "not provided" (lenient for agents).
            if p.name in raw and raw[p.name] is not None:
                values[p.name] = p.parse(raw[p.name])
            elif p.required:
                raise ValueError(f"Missing required parameter: '{p.name}'")
            else:
                values[p.name] = p.fallback()
        return _Args(values)

    def invoke(self, raw: dict[str, Any]) -> dict[str, Any]:
        return self.handler(self.parse_args(raw))


_TOOLS: dict[str, ToolSpec] = {}


def tool(name: str, description: str, *, params: Iterable[Param] = (), writes: bool = False):
    """Register a tool handler. The handler receives parsed args as a single _Args."""
    def register(fn: Callable[[_Args], dict[str, Any]]) -> Callable[[_Args], dict[str, Any]]:
        _TOOLS[name] = ToolSpec(name, description, params, fn, writes)
        return fn
    return register


def paginate(iterable: Iterable[Any], offset: int, limit: int, key: str,
             *, project: Callable[[Any], Any] | None = None, **extra: Any) -> dict[str, Any]:
    """One-pass pagination with a total count.

    Iterates once: collects the [offset, offset+limit) window (applying `project`
    to those items only — so callers can defer expensive per-item work to the page)
    and counts the total. Returns {key, count, total, next_offset, **extra}.
    """
    page: list[Any] = []
    total = 0
    for item in iterable:
        if offset <= total < offset + limit:
            page.append(project(item) if project else item)
        total += 1
    result = {
        key: page,
        "count": len(page),
        "total": total,
        "next_offset": (offset + limit) if (offset + limit) < total else None,
    }
    result.update(extra)
    return result


# =============================================================================
# Hex-Rays helpers
# =============================================================================

def _get_line_ea(cfunc: Any, line_str: str) -> int | None:
    """Extract EA for a pseudocode line via get_line_item()."""
    if not line_str:
        return None
    item = ida_hexrays.ctree_item_t()
    if not cfunc.get_line_item(line_str, 0, True, None, item, None):
        return None
    # IDA 9.x: get_ea() method, or fall back to checking item members
    if hasattr(item, 'get_ea'):
        ea = item.get_ea()
    elif item.e:  # expression item
        ea = item.e.ea
    elif item.i:  # insn item
        ea = item.i.ea
    else:
        return None
    return ea if ea != idaapi.BADADDR else None


def _get_pseudocode_with_addresses(cfunc: Any) -> str:
    """Generate pseudocode with per-line address annotations."""
    func_entry_ea = cfunc.entry_ea
    sv = cfunc.get_pseudocode()
    out_lines: list[str] = []

    for i, sl in enumerate(sv):
        if i >= Limits.CODE_LINES_MAX:
            break

        ea = func_entry_ea if i == 0 else _get_line_ea(cfunc, sl.line)
        text = ida_lines.tag_remove(sl.line).rstrip()

        if ea is not None:
            out_lines.append(f"/* {_format_ea(ea)} */ {text}")
        else:
            out_lines.append(text)

    if sv.size() > Limits.CODE_LINES_MAX:
        out_lines.append(f"/* ... truncated at {Limits.CODE_LINES_MAX} lines ... */")

    return "\n".join(out_lines)


# =============================================================================
# String, import, and export iteration
# =============================================================================

# Best-effort string type classification
_STRING_UNICODE_TYPES: set[int] = set()
_STRING_PASCAL_TYPES: set[int] = set()

for _mod in (ida_nalt, idc):
    for _attr in ("STRTYPE_C_16", "STRTYPE_C_32", "STRTYPE_UNICODE"):
        if hasattr(_mod, _attr):
            _STRING_UNICODE_TYPES.add(getattr(_mod, _attr))
    for _attr in ("STRTYPE_PASCAL", "STRTYPE_PASCAL_16", "STRTYPE_LEN2"):
        if hasattr(_mod, _attr):
            _STRING_PASCAL_TYPES.add(getattr(_mod, _attr))

# Clean up module-level namespace
del _mod, _attr


def _classify_string_type(strtype: int) -> str:
    """Classify IDA string type constant."""
    if strtype in _STRING_UNICODE_TYPES:
        return "unicode"
    if strtype in _STRING_PASCAL_TYPES:
        return "pascal"
    return "ascii"


def _iter_strings() -> Iterable[dict[str, Any]]:
    """Iterate over strings using IDA's indexed access."""
    qty = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()

    for i in range(qty):
        if not ida_strlist.get_strlist_item(si, i):
            continue
        if si.ea == idaapi.BADADDR:
            continue
        val = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
        if val is None:
            continue
        # Decode bytes to string
        val = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
        yield {
            "address": si.ea,
            "value": val,
            "length": si.length,
            "string_type": _classify_string_type(si.type),
        }


def _iter_imports() -> Iterable[dict[str, Any]]:
    """Iterate over imports by module."""
    qty = ida_nalt.get_import_module_qty()

    for i in range(qty):
        module_name = ida_nalt.get_import_module_name(i) or ""
        collected: list[dict[str, Any]] = []

        def _cb(ea: int, name: str | None, ordinal: int, *, _collected: list = collected, _module: str = module_name) -> bool:
            nm = (name or "").strip() or f"ord_{ordinal}"
            _collected.append({"address": ea, "name": nm, "module": _module})
            return True

        ida_nalt.enum_import_names(i, _cb)
        yield from collected


def _iter_exports() -> Iterable[dict[str, Any]]:
    """Iterate over exports using IDA's indexed access."""
    qty = ida_entry.get_entry_qty()

    for i in range(qty):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        if ea == idaapi.BADADDR:
            continue

        name = ida_entry.get_entry_name(ordinal) or ida_name.get_name(ea) or f"ord_{ordinal}"
        yield {"address": ea, "name": name, "ordinal": ordinal}


# =============================================================================
# Xref type categorization using IDA's xref type constants
# =============================================================================

_XREF_TYPE_MAP: dict[int, str] = {
    # Code xrefs (ordinary flow / fall-through is filtered out before categorizing)
    ida_xref.fl_CF: "call", ida_xref.fl_CN: "call",  # far/near call
    ida_xref.fl_JF: "jump", ida_xref.fl_JN: "jump",  # far/near jump
    # Data xrefs
    ida_xref.dr_O: "offset",  # offset reference
    ida_xref.dr_W: "write",   # write access
    ida_xref.dr_R: "read",    # read access
}


def _categorize_xref_type(xref_type: int) -> str:
    """Map IDA xref type to simplified category."""
    return _XREF_TYPE_MAP.get(xref_type, "data")


# =============================================================================
# Function helpers
# =============================================================================

def _func_size(start: int) -> int:
    """Total function size in bytes, summing all chunks (tails included)."""
    return sum(end - chunk_start for chunk_start, end in idautils.Chunks(start))


def _build_disassembly(func: Any) -> str:
    """Build disassembly for a function with per-instruction address annotations.

    Iterates via FuncItems so non-contiguous (chunked) functions are fully covered.
    """
    start = func.start_ea
    name = ida_name.get_name(start) or f"sub_{start:x}"

    out: list[str] = [f"/* {_format_ea(start)} */ {name} proc"]
    lines_emitted = 0
    truncated = False

    for ea in idautils.FuncItems(start):
        if lines_emitted >= Limits.CODE_LINES_MAX:
            truncated = True
            break
        dis = ida_lines.generate_disasm_line(ea, 0)
        if dis:
            dis = ida_lines.tag_remove(dis).rstrip()
            if dis:
                out.append(f"/* {_format_ea(ea)} */ {dis}")
                lines_emitted += 1

    if truncated:
        out.append(f"/* ... truncated at {Limits.CODE_LINES_MAX} lines ... */")

    return "\n".join(out)


def _get_available_local_vars(func_ea: int) -> list[str]:
    """Get list of local variable names from a decompiled function."""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return []
        return sorted({lv.name for lv in cfunc.lvars if lv.name})
    except Exception:
        return []


# =============================================================================
# Pattern scanning (uses IDA's native bin_search for speed)
# =============================================================================

def _convert_pattern_to_ida_format(pattern_str: str) -> str:
    """
    Convert "48 8B ?? 05" format to IDA's native "48 8B ? 05" format.

    IDA's bin_search uses single '?' for full byte wildcards.
    Nibble wildcards (like "4?" or "?F") are NOT supported by IDA's bin_search.

    Raises ValueError on invalid syntax.
    """
    parts = pattern_str.strip().split()
    if not parts:
        raise ValueError("Empty pattern")

    ida_parts: list[str] = []
    has_concrete = False

    for part in parts:
        part = part.strip().upper()
        if not part:
            continue
        if part == "??" or part == "?":
            # Full byte wildcard
            ida_parts.append("?")
        elif len(part) == 2 and all(c in "0123456789ABCDEF" for c in part):
            # Concrete hex byte like "48", "AB", etc.
            ida_parts.append(part)
            has_concrete = True
        elif len(part) == 2 and "?" in part:
            # Nibble wildcard like "4?" or "?F" - NOT supported by IDA bin_search
            raise ValueError(
                f"Nibble wildcards ('{part}') not supported. Use '??' for full byte wildcard"
            )
        else:
            raise ValueError(f"Invalid byte '{part}'")

    if len(ida_parts) < Limits.PATTERN_SCAN_MIN_BYTES:
        raise ValueError(
            f"Pattern too short ({len(ida_parts)} byte). Minimum {Limits.PATTERN_SCAN_MIN_BYTES} bytes required."
        )

    if not has_concrete:
        raise ValueError("Pattern has no concrete bytes. Include at least one non-wildcard byte.")

    return " ".join(ida_parts)


def _get_segment_bounds(segment_name: str | None) -> list[tuple[int, int]]:
    """
    Return list of (start, end) tuples to search, sorted by start address.
    If segment_name is None, return all segments.
    Segment matching is case-insensitive, dot-optional.
    """
    bounds: list[tuple[int, int]] = []
    available: list[str] = []
    target = segment_name.lstrip('.').lower() if segment_name else None

    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue

        name = ida_segment.get_segm_name(seg) or ""
        if name:
            available.append(name)

        if target is None:
            bounds.append((seg.start_ea, seg.end_ea))
        elif name.lstrip('.').lower() == target:
            return [(seg.start_ea, seg.end_ea)]

    if target is not None and not bounds:
        raise ValueError(
            f"Segment '{segment_name}' not found. Available: {', '.join(available)}"
        )

    # Sort by start address to ensure consistent ordering for pagination
    bounds.sort(key=lambda x: x[0])
    return bounds


def _compile_pattern(ida_pattern: str, start_ea: int) -> ida_bytes.compiled_binpat_vec_t:
    """
    Compile a pattern string into IDA's binary format for searching.

    Returns compiled pattern object, raises ValueError on failure.
    """
    compiled = ida_bytes.compiled_binpat_vec_t()
    encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)

    # Parse with hex radix (16). IDA 9.x: returns empty string on success, error message on failure.
    err = ida_bytes.parse_binpat_str(compiled, start_ea, ida_pattern, 16, encoding)

    if err:  # Non-empty string means error
        raise ValueError(f"Failed to parse pattern: {err}")

    if compiled.empty():
        raise ValueError("Pattern compiled to empty - check syntax")

    return compiled


def _bin_search_all(compiled: ida_bytes.compiled_binpat_vec_t, start_ea: int,
                    end_ea: int, max_results: int) -> list[int]:
    """
    Search for all matches of a compiled pattern in a range.

    Uses IDA's native bin_search() for speed. Returns match addresses, up to max_results.
    """
    matches: list[int] = []
    ea = start_ea

    while len(matches) < max_results:
        # IDA 9.x bin_search returns (ea, matched_pattern_idx) tuple
        result = ida_bytes.bin_search(
            ea, end_ea, compiled,
            ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK,
        )

        found_ea = result[0] if isinstance(result, tuple) else result
        if found_ea == idaapi.BADADDR:
            break

        matches.append(found_ea)
        ea = found_ea + 1  # Move past this match to find next

    return matches


# =============================================================================
# Tools — each is the single source of truth for its own contract
# =============================================================================

@tool("get_binary_info", "Binary metadata and segment list.")
def _tool_get_binary_info(_p: _Args) -> dict[str, Any]:
    # File identity
    name = ida_nalt.get_root_filename() or ""
    path = ida_nalt.get_input_file_path() or ""
    base = ida_nalt.get_imagebase()

    # Entrypoint: prefer the linear program entry (start_ea); fall back to the real-mode
    # IP (start_ip) for segmented binaries, then to the first declared entry point.
    entry = idaapi.BADADDR
    _get_start_ea = getattr(ida_ida, "inf_get_start_ea", None)
    if _get_start_ea is not None:
        entry = _get_start_ea()
    if entry == idaapi.BADADDR:
        entry = ida_ida.inf_get_start_ip()
    if entry == idaapi.BADADDR and ida_entry.get_entry_qty() > 0:
        entry = ida_entry.get_entry(ida_entry.get_entry_ordinal(0))

    # Bitness / architecture (ida_ida has inf_is_64bit/inf_is_16bit but NOT inf_is_32bit)
    bitness = 64 if ida_ida.inf_is_64bit() else (16 if ida_ida.inf_is_16bit() else 32)
    proc = ida_ida.inf_get_procname() or ""

    proc_l = proc.lower()
    if proc_l in ("metapc", "pc", "8086"):
        architecture = "x64" if bitness == 64 else ("x86" if bitness == 32 else f"x86_{bitness}")
    elif "arm" in proc_l:
        architecture = f"arm{bitness}"
    elif "mips" in proc_l:
        architecture = f"mips{bitness}"
    elif "ppc" in proc_l or "powerpc" in proc_l:
        architecture = f"ppc{bitness}"
    elif "riscv" in proc_l:
        architecture = f"riscv{bitness}"
    else:
        architecture = proc or f"cpu{bitness}"

    endianness = "big" if ida_ida.inf_is_be() else "little"

    # File type
    ft = idaapi.get_file_type_name() or ""
    ft_u = ft.upper()
    if "PORTABLE EXECUTABLE" in ft_u or ft_u.startswith("PE"):
        file_type = "PE"
    elif "ELF" in ft_u:
        file_type = "ELF"
    elif "MACH-O" in ft_u or "MACHO" in ft_u:
        file_type = "Mach-O"
    else:
        file_type = ft.strip()[:32] if ft else ""

    # Segments - using indexed access
    segments: list[dict[str, Any]] = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue

        perm = seg.perm
        perms = "".join([
            "r" if perm & ida_segment.SEGPERM_READ else "-",
            "w" if perm & ida_segment.SEGPERM_WRITE else "-",
            "x" if perm & ida_segment.SEGPERM_EXEC else "-",
        ])

        segments.append({
            "name": ida_segment.get_segm_name(seg) or "",
            "start": _format_ea(seg.start_ea),
            "end": _format_ea(seg.end_ea),
            "permissions": perms,
        })

    return {
        "name": name,
        "path": path,
        "base_address": _format_ea(base),
        "entrypoint": _format_ea(entry) if entry != idaapi.BADADDR else None,
        "architecture": architecture,
        "bitness": bitness,
        "endianness": endianness,
        "file_type": file_type,
        "segments": segments,
    }


@tool("get_function",
      "Decompiled pseudocode for function at address. Falls back to disassembly.",
      params=[Addr(), Bool("force_disassembly", default=False, description="Skip decompiler")])
def _tool_get_function(p: _Args) -> dict[str, Any]:
    ea = p.address
    func = ida_funcs.get_func(ea)
    if not func:
        raise ValueError(
            f"No function at {_format_ea(ea)}. "
            f"This address may be data or unanalyzed code. "
            f"Use list_functions to find valid function addresses."
        )

    start = func.start_ea
    name = ida_name.get_name(start) or f"sub_{start:x}"
    base = {"address": _format_ea(start), "name": name, "size": _func_size(start)}

    if p.force_disassembly:
        return {**base, "type": "disassembly", "code": _build_disassembly(func)}

    # Attempt decompilation with failure info
    cfunc = None
    failure_desc: str | None = None
    try:
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile_func(start, failure, 0)
        if not cfunc and failure.desc():
            failure_desc = failure.desc()
    except Exception as e:
        failure_desc = f"Decompilation exception: {type(e).__name__}: {e}"

    if cfunc:
        return {**base, "type": "decompiled", "code": _get_pseudocode_with_addresses(cfunc)}

    return {
        **base,
        "type": "disassembly",
        "code": _build_disassembly(func),
        "fallback_reason": failure_desc or "Decompilation failed",
    }


@tool("get_xrefs",
      "Inbound cross-references to address (callers, data refs). For a function's callees, read get_function.",
      params=[Addr(), Limit(Limits.XREFS_DEFAULT, Limits.XREFS_MAX), Offset()])
def _tool_get_xrefs(p: _Args) -> dict[str, Any]:
    rows: list[tuple[int, dict[str, Any]]] = []

    for xref in idautils.XrefsTo(p.address):
        # Skip ordinary flow (fall-through from the previous instruction): it is linear
        # execution, not a real cross-reference, and IDA's own xref view excludes it.
        if xref.type == ida_xref.fl_F:
            continue
        from_ea = xref.frm
        cat = _categorize_xref_type(xref.type)

        from_func = ida_funcs.get_func(from_ea)
        if from_func:
            fn = ida_name.get_name(from_func.start_ea) or _format_ea(from_func.start_ea)
            obj = {"from_address": _format_ea(from_ea), "from_function": fn, "type": cat}
        else:
            # Ref originates outside any function (e.g. a data/descriptor table); name the segment.
            seg = ida_segment.getseg(from_ea)
            seg_name = ida_segment.get_segm_name(seg) if seg else None
            obj = {"from_address": _format_ea(from_ea), "from_function": None,
                   "from_segment": seg_name, "type": cat}

        rows.append((from_ea, obj))

    rows.sort(key=lambda x: x[0])
    objs = [obj for _, obj in rows]
    return paginate(objs, p.offset, p.limit, "xrefs", address=_format_ea(p.address))


@tool("get_pointer_table",
      "Absolute pointer array at address (e.g. a vtable; not relative/RVA tables). Resolves each target to a symbol.",
      params=[Addr(),
              Int("count", default=Limits.POINTER_TABLE_DEFAULT, minimum=1,
                  maximum=Limits.POINTER_TABLE_MAX, description="Number of pointers to read")])
def _tool_get_pointer_table(p: _Args) -> dict[str, Any]:
    ea = p.address

    # Reject code addresses — use get_function for those
    if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
        fn = ida_funcs.get_func(ea)
        ctx = f" inside '{ida_name.get_name(fn.start_ea)}'" if fn else ""
        raise ValueError(f"Address '{_format_ea(ea)}' is code{ctx}. Use get_function for code analysis.")

    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    read_fn = ida_bytes.get_qword if ptr_size == 8 else ida_bytes.get_dword

    entries: list[dict[str, Any]] = []

    for i in range(p.count):
        slot_ea = ea + (i * ptr_size)

        # Stop if we've left mapped memory
        if not ida_segment.getseg(slot_ea):
            break

        ptr = read_fn(slot_ea)
        raw_str = "BADADDR" if ptr == idaapi.BADADDR else f"0x{ptr:x}"

        entry: dict[str, Any] = {
            "index": i,
            "offset": i * ptr_size,
            "slot": _format_ea(slot_ea),
            "raw": raw_str,
        }

        if ptr == 0 or ptr == idaapi.BADADDR:
            entry["target"] = None
            entry["name"] = None
        else:
            # target is the actual destination; name resolves it to a symbol or func+offset.
            entry["target"] = _format_ea(ptr)
            name = ida_name.get_name(ptr)
            if not name:
                target_func = ida_funcs.get_func(ptr)
                if target_func:
                    fbase = ida_name.get_name(target_func.start_ea) or _format_ea(target_func.start_ea)
                    name = fbase if ptr == target_func.start_ea else f"{fbase}+0x{ptr - target_func.start_ea:x}"
            entry["name"] = name or None

        entries.append(entry)

    if not entries:
        seg = ida_segment.getseg(ea)
        seg_ctx = f" (segment '{ida_segment.get_segm_name(seg) or 'unknown'}')" if seg else ""
        raise ValueError(
            f"No pointer data at '{_format_ea(ea)}'{seg_ctx}. "
            "Address may be unmapped, uninitialized, or an import table (use list_imports)."
        )

    return {
        "address": _format_ea(ea),
        "name": ida_name.get_name(ea),
        "pointer_size": ptr_size,
        "entries": entries,
        "count": len(entries),
    }


@tool("get_type", "Type definition by name. Returns C declaration.",
      params=[NonEmptyStr("name", description="Type name")])
def _tool_get_type(p: _Args) -> dict[str, Any]:
    name = p.name

    til = ida_typeinf.get_idati()
    ordinal = ida_typeinf.get_type_ordinal(til, name)
    if ordinal == 0:
        raise ValueError(f"Type '{name}' not found in local type library")

    # Get the C representation. PRTYPE_MULTI -> multiline; fall back to single-line.
    definition = ida_typeinf.idc_get_local_type(ordinal, ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_MULTI)
    if not definition:
        definition = ida_typeinf.idc_get_local_type(ordinal, 0) or ""

    tif = ida_typeinf.tinfo_t()
    size = -1
    if tif.get_numbered_type(til, ordinal):
        size = _normalize_size(tif.get_size())

    return {"name": name, "size": size, "ordinal": ordinal, "definition": definition}


@tool("list_functions", "Functions sorted by address. Filter by name substring and minimum byte size.",
      params=[Filter("name"),
              Int("min_size", default=0, minimum=0, description="Minimum size in bytes"),
              Limit(Limits.FUNCTIONS_DEFAULT, Limits.FUNCTIONS_MAX), Offset()])
def _tool_list_functions(p: _Args) -> dict[str, Any]:
    flt = p.filter
    min_size = p.min_size

    def gen() -> Iterable[tuple[int, str | None, int | None]]:
        for fea in idautils.Functions():
            # Only resolve the name eagerly when filtering needs it.
            if flt:
                name = ida_name.get_name(fea) or f"sub_{fea:x}"
                if flt not in name.lower():
                    continue
            else:
                name = None
            if min_size > 0:
                size = _func_size(fea)
                if size < min_size:
                    continue
                yield (fea, name, size)
            else:
                yield (fea, name, None)

    def project(row: tuple[int, str | None, int | None]) -> dict[str, Any]:
        fea, name, size = row
        if name is None:
            name = ida_name.get_name(fea) or f"sub_{fea:x}"
        # Defer the chunk-walk to the page only (huge win on large databases).
        return {"address": _format_ea(fea), "name": name, "size": size if size is not None else _func_size(fea)}

    return paginate(gen(), p.offset, p.limit, "functions", project=project)


@tool("list_strings", "String literals. Filter by content substring and minimum length.",
      params=[Filter("content"),
              Int("min_length", default=4, minimum=0, description="Minimum length"),
              Limit(Limits.STRINGS_DEFAULT, Limits.STRINGS_MAX), Offset()])
def _tool_list_strings(p: _Args) -> dict[str, Any]:
    flt = p.filter
    min_length = p.min_length

    def gen() -> Iterable[dict[str, Any]]:
        for s in _iter_strings():
            if s["length"] < min_length:
                continue
            if flt and flt not in s["value"].lower():
                continue
            yield s

    def project(s: dict[str, Any]) -> dict[str, Any]:
        val = s["value"]
        shown = val if len(val) <= Limits.STRING_VALUE_MAX else val[:Limits.STRING_VALUE_MAX] + "…"
        return {"address": _format_ea(s["address"]), "value": shown, "string_type": s["string_type"]}

    return paginate(gen(), p.offset, p.limit, "strings", project=project)


@tool("list_imports", "Imported and/or exported symbols. Set kind to choose.",
      params=[Filter("name or module"),
              Enum("kind", ["imports", "exports", "both"], default="imports", description="Which symbols to list"),
              Limit(Limits.IMPORTS_DEFAULT, Limits.IMPORTS_MAX), Offset()])
def _tool_list_imports(p: _Args) -> dict[str, Any]:
    flt = p.filter
    kind = p.kind

    def gen() -> Iterable[dict[str, Any]]:
        if kind in ("imports", "both"):
            for imp in _iter_imports():
                nm, mod = imp["name"], imp["module"]
                if flt and flt not in nm.lower() and flt not in mod.lower():
                    continue
                yield {"address": _format_ea(imp["address"]), "name": nm, "module": mod, "type": "import"}
        if kind in ("exports", "both"):
            for exp in _iter_exports():
                nm = exp["name"]
                if flt and flt not in nm.lower():
                    continue
                entry = {"address": _format_ea(exp["address"]), "name": nm, "type": "export"}
                ordinal = exp["ordinal"]
                if ordinal and ordinal != exp["address"] and ordinal < 0x10000:
                    entry["ordinal"] = ordinal
                yield entry

    return paginate(gen(), p.offset, p.limit, "symbols")


@tool("list_types", "Types in local type library.",
      params=[Filter("name"), Limit(Limits.TYPES_DEFAULT, Limits.TYPES_MAX), Offset()])
def _tool_list_types(p: _Args) -> dict[str, Any]:
    til = ida_typeinf.get_idati()
    if not til:
        return paginate(iter(()), p.offset, p.limit, "types")

    flt = p.filter

    def gen() -> Iterable[dict[str, Any]]:
        for ordinal in range(1, ida_typeinf.get_ordinal_limit(til)):
            name = ida_typeinf.get_numbered_type_name(til, ordinal)
            if not name:
                continue
            if flt and flt not in name.lower():
                continue
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                yield {"name": name, "size": _normalize_size(tif.get_size()), "ordinal": ordinal}

    # Sort by name for consistent ordering across pages.
    items = sorted(gen(), key=lambda x: x["name"].lower())
    return paginate(items, p.offset, p.limit, "types")


@tool("find_pattern",
      "Byte pattern search (all segments unless 'segment' given). Returns matches with containing function.",
      params=[Str("pattern", description="Hex bytes; ? or ?? = whole-byte wildcard (e.g. '48 8B ?? ??')"),
              Str("segment", default=None, description="Limit to segment (e.g. '.text')"),
              Limit(Limits.PATTERN_SCAN_DEFAULT, Limits.PATTERN_SCAN_MAX), Offset()])
def _tool_find_pattern(p: _Args) -> dict[str, Any]:
    # Convert pattern to IDA format (validates syntax too)
    try:
        ida_pattern = _convert_pattern_to_ida_format(p.pattern)
    except ValueError as e:
        msg = str(e).rstrip('.')
        raise ValueError(
            f"Cannot parse pattern '{p.pattern}'. {msg}. Example: '48 8B 05 ?? ?? ?? ??'"
        ) from e

    bounds = _get_segment_bounds(p.segment)
    if not bounds:
        return {"matches": [], "count": 0, "next_offset": None}

    # Compile once (first segment's start_ea satisfies the API; it doesn't affect results).
    compiled = _compile_pattern(ida_pattern, bounds[0][0])

    # Fetch offset+limit+1 so we can report next_offset without counting every match.
    max_needed = p.offset + p.limit + 1
    all_matches: list[int] = []
    for start_ea, end_ea in bounds:
        remaining = max_needed - len(all_matches)
        if remaining <= 0:
            break
        all_matches.extend(_bin_search_all(compiled, start_ea, end_ea, remaining))

    all_matches.sort()
    has_more = len(all_matches) > p.offset + p.limit
    page = all_matches[p.offset:p.offset + p.limit]

    results: list[dict[str, Any]] = []
    for ea in page:
        func = ida_funcs.get_func(ea)
        if func:
            func_field = ida_name.get_name(func.start_ea) or _format_ea(func.start_ea)
        else:
            func_field = None
        results.append({"address": _format_ea(ea), "function": func_field})

    return {
        "matches": results,
        "count": len(results),
        "next_offset": (p.offset + p.limit) if has_more else None,
    }


def _rename_batch(names: Any) -> dict[str, Any]:
    """Bulk-rename global symbols. names = [{address, new_name}, ...]; returns failures only."""
    if not isinstance(names, list) or not names:
        raise ValueError("names must be a non-empty array of {address, new_name}")
    if len(names) > Limits.RENAME_BATCH_MAX:
        raise ValueError(f"Too many names ({len(names)}); max {Limits.RENAME_BATCH_MAX} per call")

    renamed = 0
    failed: list[dict[str, Any]] = []
    for item in names:
        is_obj = isinstance(item, dict)
        addr = item.get("address") if is_obj else None
        nm_raw = item.get("new_name") if is_obj else None
        try:
            if not is_obj:
                raise ValueError("each item must be an object {address, new_name}")
            ea = _parse_address(_require_param(item, "address"))
            nm = str(_require_param(item, "new_name")).strip()
            if not nm:
                raise ValueError("new_name must be non-empty")
            if not ida_name.set_name(ea, nm, ida_name.SN_NOWARN):
                raise ValueError("rename failed (name exists, invalid chars, or auto-name pattern)")
            renamed += 1
        except ValueError as e:
            failed.append({"address": addr, "new_name": nm_raw, "error": str(e)})

    return {"renamed": renamed, "total": len(names), "failed": failed}


@tool("set_name",
      "Rename one symbol/local (locals need old_name), or many globals at once via names. "
      "Provide EITHER address+new_name, OR names — not both. Avoid IDA prefixes (sub_, loc_, etc.).",
      writes=True,
      params=[Addr("address", default=None,
                   description="Single rename: address, or function address for a local. "
                               "Pair with new_name; omit when using names."),
              Str("new_name", default=None,
                  description="Single rename: new name. Pair with address; omit when using names."),
              Str("old_name", default=None,
                  description="Single local rename only: current local name (requires address + new_name)."),
              Names()])
def _tool_set_name(p: _Args) -> dict[str, Any]:
    # Bulk global rename when 'names' is supplied; reject mixing with single-form args.
    if p.names is not None:
        if p.address is not None or p.new_name is not None or p.old_name is not None:
            raise ValueError("Provide either 'names' (bulk globals) or address/new_name (single rename), not both.")
        return _rename_batch(p.names)

    if p.address is None:
        raise ValueError("Missing required parameter: 'address'")
    if p.new_name is None:
        raise ValueError("Missing required parameter: 'new_name'")

    ea = p.address
    new_name = p.new_name.strip()
    if not new_name:
        raise ValueError("new_name must be a non-empty string")

    # Local variable rename
    if p.old_name is not None:
        old = p.old_name.strip()
        if not old:
            raise ValueError("old_name must be a non-empty string for local renames")

        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"Address '{_format_ea(ea)}' is not within a function")
        func_start = func.start_ea

        # Fast path; fallback to locate + modify if needed
        if not ida_hexrays.rename_lvar(func_start, old, new_name):
            locator = ida_hexrays.lvar_locator_t()
            if not ida_hexrays.locate_lvar(locator, func_start, old):
                available = _get_available_local_vars(func_start)
                hint = f" Available: [{', '.join(available[:AVAILABLE_VARS_DISPLAY_MAX])}]" if available else ""
                raise ValueError(f"Variable '{old}' not found.{hint}")

            info = ida_hexrays.lvar_saved_info_t()
            info.ll = locator
            info.name = new_name
            if not ida_hexrays.modify_user_lvar_info(func_start, ida_hexrays.MLI_NAME, info):
                raise ValueError(f"Failed to rename local '{old}' to '{new_name}'")

        return {"success": True, "address": _format_ea(func_start),
                "old_name": old, "new_name": new_name, "assigned_name": new_name}

    # Global/function rename
    prev = ida_name.get_name(ea) or ""
    if not ida_name.set_name(ea, new_name, ida_name.SN_NOWARN):
        raise ValueError(
            f"Failed to rename {_format_ea(ea)} to '{new_name}'. "
            "Likely causes: name already exists, invalid characters, "
            "or matches IDA auto-name pattern (e.g., sub_XXX, loc_XXX)."
        )

    assigned = ida_name.get_name(ea) or new_name
    return {"success": True, "address": _format_ea(ea),
            "old_name": prev, "new_name": new_name, "assigned_name": assigned}


@tool("set_comment",
      "Set a comment. A function-entry address gets a function (decompiler header) comment; "
      "any other address gets a line comment. Overwrites existing.",
      writes=True,
      params=[Addr(), Str("comment", description="Comment text"),
              Bool("repeatable", default=False, description="Show at xref locations")])
def _tool_set_comment(p: _Args) -> dict[str, Any]:
    ea = p.address
    comment = p.comment
    repeatable = p.repeatable

    # A comment at a function's entry is a function summary, so use a function comment
    # (visible in the decompiler header). An item comment there is NOT shown by Hex-Rays.
    func = ida_funcs.get_func(ea)
    if func is not None and func.start_ea == ea:
        ok = ida_funcs.set_func_cmt(func, comment, repeatable)
        scope = "function"
    else:
        ok = ida_bytes.set_cmt(ea, comment, repeatable)
        scope = "line"

    if not ok:
        raise ValueError(
            f"Failed to set comment at {_format_ea(ea)}. "
            "Address may not be in analyzed code or data."
        )

    return {"success": True, "address": _format_ea(ea), "scope": scope}


@tool("apply_type", "Apply type to address (data/function) or local variable.",
      writes=True,
      params=[Addr("address", description="Address, or function address for locals"),
              NonEmptyStr("type", description="C type (e.g. 'int *', 'int __fastcall f(void *)')"),
              Str("variable", default=None, description="Local variable name; if set, address is its function")])
def _tool_apply_type(p: _Args) -> dict[str, Any]:
    ea = p.address
    type_decl = p.type

    # Local variable type
    if p.variable is not None:
        var = p.variable.strip()
        if not var:
            raise ValueError("variable must be a non-empty string")

        func = ida_funcs.get_func(ea)
        if not func:
            raise ValueError(f"Address '{_format_ea(ea)}' is not within a function")
        func_start = func.start_ea

        locator = ida_hexrays.lvar_locator_t()
        if not ida_hexrays.locate_lvar(locator, func_start, var):
            available = _get_available_local_vars(func_start)
            hint = f" Available: [{', '.join(available[:AVAILABLE_VARS_DISPLAY_MAX])}]" if available else ""
            raise ValueError(f"Variable '{var}' not found.{hint}")

        lvar_info = ida_hexrays.lvar_saved_info_t()
        lvar_info.ll = locator

        # IDA 9.x: PT_TYP for abstract types (no variable name), PT_SIL to silence errors.
        parse_flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
        tif = ida_typeinf.tinfo_t()
        result = ida_typeinf.parse_decl(tif, None, type_decl, parse_flags)
        parsed = result is not None and tif.is_correct()

        # Fallback: try adding semicolon if the type doesn't have one
        if not parsed and not type_decl.rstrip().endswith(';'):
            tif = ida_typeinf.tinfo_t()
            result = ida_typeinf.parse_decl(tif, None, type_decl + ";", parse_flags)
            parsed = result is not None and tif.is_correct()

        if not parsed:
            raise ValueError(
                f"Cannot parse type '{type_decl}'. "
                f"Use standard C syntax (e.g., 'int *', 'DWORD', 'struct FOO *')."
            )

        lvar_info.type = tif
        if not ida_hexrays.modify_user_lvar_info(func_start, ida_hexrays.MLI_TYPE, lvar_info):
            raise ValueError(
                f"Failed to apply type '{type_decl}' to variable '{var}'. "
                f"The type may be incompatible with the variable's usage."
            )

        return {"success": True, "address": _format_ea(func_start), "type": type_decl}

    # Global/function type: apply to function start if inside a function
    apply_ea = ea
    func = ida_funcs.get_func(ea)
    if func:
        apply_ea = func.start_ea

    # idc.SetType often needs a trailing ';'; retry with one appended so callers can pass
    # bare declarations like 'int *'.
    ok = bool(idc.SetType(apply_ea, type_decl))
    if not ok and not type_decl.rstrip().endswith(';'):
        ok = bool(idc.SetType(apply_ea, type_decl + ';'))
    if not ok:
        raise ValueError(
            f"Failed to apply type at {_format_ea(apply_ea)}. "
            f"For function prototypes use full signature: 'int __fastcall func(int a1, char *a2)'."
        )

    return {"success": True, "address": _format_ea(apply_ea), "type": type_decl}


@tool("define_type", "Parse C declaration into type library. Overwrites existing.",
      writes=True,
      params=[NonEmptyStr("declaration", description="C declaration (e.g. 'struct X { int a; };')")])
def _tool_define_type(p: _Args) -> dict[str, Any]:
    code = p.declaration

    # idc_parse_types handles structs, enums, typedefs; returns number of errors (0 = ok).
    errors = ida_typeinf.idc_parse_types(code, 0)
    if errors != 0:
        if not code.rstrip().endswith(';'):
            errors = ida_typeinf.idc_parse_types(code + ";", 0)
        if errors != 0:
            raise ValueError(
                "Failed to parse type declaration. Check C syntax. "
                "Example: 'struct X { int a; };' or 'typedef int DWORD;'"
            )

    # Extract the defined type name for the response, across common declaration styles.
    type_name = None
    match = re.search(r'(?:struct|enum|union)\s+(\w+)\s*\{', code)  # struct/enum/union Name { ... }
    if match:
        type_name = match.group(1)
    if not type_name:
        match = re.search(r'\}\s*\*?\s*(\w+)\s*;', code)            # typedef struct { ... } Name;
        if match:
            type_name = match.group(1)
    if not type_name:
        # typedef <anything> Name;  -> the last identifier (handles multi-word base types
        # like 'unsigned int' and pointer typedefs 'struct FOO *PFOO'). Trailing ';' optional.
        match = re.search(r'(\w+)\s*;?\s*$', code.strip())
        if match:
            type_name = match.group(1)

    result: dict[str, Any] = {"success": True}
    if type_name:
        result["name"] = type_name
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, type_name)
        if ordinal:
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                result["size"] = _normalize_size(tif.get_size())
    return result


class _RunPythonTimeout(BaseException):
    """Raised by the run_python deadline guard. Subclasses BaseException so a snippet's
    own `except Exception:` cannot swallow it."""


@tool("run_python",
      "IDAPython escape hatch — only for what no other tool can do: raw reads, bulk queries/searches "
      "across the database, or writes set_/apply_/define_ can't. Otherwise call the dedicated tool. "
      f"Terse code, no comments. Avoid unbounded loops ({int(RUN_PYTHON_TIMEOUT_SECONDS)}s limit). "
      "Return one small value via _result. Example: _result = ida_bytes.get_qword(0x404000)",
      writes=True,
      params=[Str("code", nonempty=True,
                  description="Terse IDAPython, already on IDA's main thread. "
                              "Fresh namespace each call; common IDA modules preloaded.")])
def _tool_run_python(p: _Args) -> dict[str, Any]:
    """Execute an IDAPython snippet in a fresh namespace under a wall-clock deadline.

    Returns {stdout, result, error, truncated}; `error` is null on success or a dict on
    any failure (syntax, runtime, timeout, oversized _result). The deadline guard
    (sys.settrace) interrupts Python-level runaways (loops) only: a single long native
    call cannot be interrupted, partial writes are not rolled back, and a hard SDK crash
    is not catchable. The guard is a convenience limit, not a sandbox: a snippet can
    disable it (sys.settrace(None)) or spawn threads that outlive the call, so treat
    run_python as full, unsandboxed code execution.
    """
    code = p.code

    try:
        compiled = compile(code, "<run_python>", "exec")
    except SyntaxError as e:
        return {
            "stdout": "",
            "result": None,
            "error": {"type": "SyntaxError", "message": f"line {e.lineno}, column {e.offset}: {e.msg}"},
            "truncated": False,
        }

    namespace = _build_python_namespace()
    captured = StringIO()
    deadline = time.monotonic() + RUN_PYTHON_TIMEOUT_SECONDS

    def _guard(_frame: Any, _event: str, _arg: Any) -> Any:
        # Fires per Python line/call on the exec'd frame; raises once the budget is spent.
        if time.monotonic() > deadline:
            raise _RunPythonTimeout
        return _guard

    # Run under the deadline guard; only capture the outcome here. Error data is built
    # AFTER the guard is removed, so formatting it (traceback/str) can't trip the guard.
    timed_out = False
    exc: BaseException | None = None
    old_stdout, old_stderr = sys.stdout, sys.stderr
    old_trace = sys.gettrace()
    try:
        sys.stdout = captured
        sys.stderr = captured
        sys.settrace(_guard)
        try:
            exec(compiled, namespace)
        except _RunPythonTimeout:
            timed_out = True
        except BaseException as e:  # noqa: BLE001 - capture any failure (incl. SystemExit) as data
            exc = e
    finally:
        sys.settrace(old_trace)
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    error: dict[str, Any] | None = None
    if timed_out:
        error = {
            "type": "Timeout",
            "message": (
                f"Exceeded {int(RUN_PYTHON_TIMEOUT_SECONDS)}s and was interrupted between operations "
                "(any writes already made remain). Narrow the query or avoid unbounded loops."
            ),
        }
    elif exc is not None:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        if len(tb) > Limits.PYTHON_TRACEBACK_MAX:
            tb = "…(truncated)\n" + tb[-Limits.PYTHON_TRACEBACK_MAX:]
        error = {"type": type(exc).__name__, "message": str(exc)[:1000], "traceback": tb}

    stdout = captured.getvalue()
    truncated = len(stdout) > Limits.PYTHON_STDOUT_MAX
    if truncated:
        stdout = stdout[:Limits.PYTHON_STDOUT_MAX] + "\n... (truncated)"

    result = namespace.get("_result")
    if error is None and result is not None:
        try:
            encoded = json.dumps(result, allow_nan=False)
        except (TypeError, ValueError):
            result, error = None, {
                "type": "ResultNotSerializable",
                "message": f"_result ({type(result).__name__}) is not JSON. Use dict/list/str/int/float/bool/None.",
            }
        else:
            if len(encoded) > Limits.PYTHON_RESULT_MAX:
                result, error = None, {
                    "type": "ResultTooLarge",
                    "message": f"_result is {len(encoded)} bytes (max {Limits.PYTHON_RESULT_MAX // 1024} KB). "
                               "Return a bounded summary, not a full dump.",
                }

    return {"stdout": stdout, "result": result, "error": error, "truncated": truncated}


# Tool descriptors for tools/list, derived once from the registry (insertion order).
TOOL_DESCRIPTORS: list[dict[str, Any]] = [spec.descriptor() for spec in _TOOLS.values()]


# =============================================================================
# MCP result formatting
# =============================================================================

def _tool_success(data: dict[str, Any], is_error: bool = False) -> dict[str, Any]:
    # MCP: include both 'content' (text) and 'structuredContent' (machine-readable).
    return {
        "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}],
        "structuredContent": data,
        "isError": is_error,
    }


def _tool_error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _execute_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Run a tool on IDA's main thread and wrap the result for MCP.

    Argument parsing (including symbol resolution) happens inside execute_sync via
    spec.invoke, because resolving a name to an address touches the IDA database.
    execute_sync() already serializes every caller onto IDA's single main thread.
    """
    spec = _TOOLS[tool_name]
    try:
        data = _ida_execute(lambda: spec.invoke(arguments), write=spec.writes)
    except Exception as e:  # noqa: BLE001 - any tool/validation failure becomes a clean MCP error
        return _tool_error(str(e) or type(e).__name__)
    # run_python reports snippet failures in-band via data["error"]; surface those as MCP
    # tool errors (isError) while preserving the structured stdout/error payload.
    is_error = tool_name == "run_python" and isinstance(data, dict) and data.get("error") is not None
    return _tool_success(data, is_error=is_error)


# =============================================================================
# JSON-RPC handling (protocol vs tool failures)
# =============================================================================

class JsonRpcError:
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603


def _jsonrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


# Protocol versions this server speaks, newest first. We echo the client's requested
# version when we support it, otherwise we offer our newest (per MCP initialize rules)
# rather than blindly claiming support for whatever the client asked for.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


def _handle_initialize(params: dict[str, Any]) -> dict[str, Any]:
    requested = params.get("protocolVersion")
    proto = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
    return {
        "protocolVersion": proto,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "IDA Fast MCP", "version": VERSION},
    }


def _handle_tools_list(_params: dict[str, Any], *, router: bool = False) -> dict[str, Any]:
    # The router advertises the same tools with an optional `instance` selector injected,
    # plus the router-only list_instances tool. Workers advertise the plain tool set.
    return {"tools": _router_tool_descriptors() if router else TOOL_DESCRIPTORS}


def _handle_tools_call(params: dict[str, Any]) -> dict[str, Any]:
    tool_name = params.get("name") or ""
    # Missing or null arguments means {}; a present non-object (e.g. a list) is rejected.
    arguments = params.get("arguments")
    if arguments is None:
        arguments = {}

    if not tool_name:
        raise ValueError("Missing tool name")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object")
    if tool_name not in _TOOLS:
        raise ValueError(f"Unknown tool: {tool_name}")

    return _execute_tool(tool_name, arguments)


def _handle_resources_list(_params: dict[str, Any]) -> dict[str, Any]:
    return {"resources": []}


def _handle_prompts_list(_params: dict[str, Any]) -> dict[str, Any]:
    return {"prompts": []}


def _handle_jsonrpc_request(payload: Any, *, router: bool = False) -> dict[str, Any] | None:
    # A request without "id" is a notification: per JSON-RPC we send no response at all,
    # not even on error. (A non-dict payload has no id and is treated as a real error.)
    # router=True means this is the unified endpoint: tools/call is routed to the chosen
    # instance and tools/list is augmented with the `instance` selector.
    req_id = payload.get("id") if isinstance(payload, dict) else None
    is_notification = isinstance(payload, dict) and ("id" not in payload)

    def fail(code: int, message: str) -> dict[str, Any] | None:
        return None if is_notification else _jsonrpc_error(req_id, code, message)

    if not isinstance(payload, dict):
        return _jsonrpc_error(None, JsonRpcError.INVALID_REQUEST, "Invalid Request")

    if payload.get("jsonrpc") != "2.0":
        return fail(JsonRpcError.INVALID_REQUEST, "Invalid Request")

    method = payload.get("method")
    # Missing or null params means "no params" ({}); any other non-object is invalid
    # (don't let `params: []` / 0 / "" coerce silently to {}).
    params = payload.get("params")
    if params is None:
        params = {}

    if not isinstance(method, str):
        return fail(JsonRpcError.INVALID_REQUEST, "Invalid Request")

    if not isinstance(params, dict):
        return fail(JsonRpcError.INVALID_PARAMS, "Params must be an object")

    # MCP clients may send cancellations/notifications; ignore them.
    if method.startswith("notifications/"):
        return None

    try:
        if method == "initialize":
            result = _handle_initialize(params)
        elif method == "tools/list":
            result = _handle_tools_list(params, router=router)
        elif method == "tools/call":
            if router:
                # Routing may relay a worker's complete JSON-RPC response verbatim, so it
                # returns a full response object rather than a bare result to wrap.
                resp = _route_tools_call(req_id, params)
                return None if is_notification else resp
            result = _handle_tools_call(params)
        elif method == "resources/list":
            result = _handle_resources_list(params)
        elif method == "prompts/list":
            result = _handle_prompts_list(params)
        else:
            return fail(JsonRpcError.METHOD_NOT_FOUND, f"Method not found: {method}")
    except KeyError as e:
        return fail(JsonRpcError.METHOD_NOT_FOUND, str(e))
    except ValueError as e:
        return fail(JsonRpcError.INVALID_PARAMS, str(e))
    except Exception as e:
        # Never crash the server on unexpected errors
        return fail(JsonRpcError.INTERNAL_ERROR, f"Internal error: {type(e).__name__}: {e}")

    if is_notification:
        return None

    return _jsonrpc_result(req_id, result)


# =============================================================================
# Multiple IDA instances: discovery, selection, and routing
#
# Every instance runs the full MCP server on a private worker port. The instance that owns
# the unified port (DEFAULT_PORT) is the "router": it discovers peers by scanning the worker
# range for /whoami, exposes list_instances, injects an optional `instance` selector into
# every tool, and routes each tool call to the chosen instance — proxying over loopback HTTP,
# or short-circuiting in-process when the target is itself. The 15 tools are unchanged; this
# is a thin layer in front of them.
# =============================================================================

# Optional selector injected into every tool's advertised schema by the router.
_INSTANCE_PROP: dict[str, Any] = {
    "type": "string",
    "description": "Target IDA instance: binary name (when unique), file path, or pid from "
                   "list_instances. Omit when only one instance is open.",
}

_LIST_INSTANCES_DESCRIPTOR: dict[str, Any] = {
    "name": "list_instances",
    "description": "List the open IDA instances (binary name, path, pid, version). Pass an "
                   "instance's name (or pid) as the `instance` argument to target any other "
                   "tool at it. With one instance open, `instance` can be omitted.",
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
}


def _router_tool_descriptors() -> list[dict[str, Any]]:
    """The unified tool list: every tool gains an optional `instance`, plus list_instances."""
    out: list[dict[str, Any]] = []
    for d in TOOL_DESCRIPTORS:
        schema = d["inputSchema"]
        props = {**schema.get("properties", {}), "instance": _INSTANCE_PROP}
        out.append({**d, "inputSchema": {**schema, "properties": props}})
    out.append(_LIST_INSTANCES_DESCRIPTOR)
    return out


# Short-TTL cache so a burst of routed calls doesn't rescan for each one; list_instances
# always scans fresh.
_scan_lock = threading.Lock()
_scan_cache: dict[str, Any] = {"ts": 0.0, "data": []}


def _query_whoami(port: int) -> dict[str, Any] | None:
    """Probe one worker port. Returns its identity only if it is genuinely one of us."""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=DISCOVERY_TIMEOUT)
        try:
            conn.request("GET", WHOAMI_ENDPOINT)
            resp = conn.getresponse()
            if resp.status != 200:
                return None
            data = json.loads(resp.read())
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 - a dead/refused port or a non-HTTP service is just "not us"
        return None
    # Require the marker so a random local service on a range port is never mistaken for us.
    if (isinstance(data, dict) and data.get("server") == "IDA Fast MCP"
            and isinstance(data.get("pid"), int) and isinstance(data.get("worker_port"), int)
            and isinstance(data.get("token"), str)):
        return data
    return None


def _scan_instances() -> list[dict[str, Any]]:
    """Discover live instances by scanning the worker port range. The OS port table is the
    registry — no files, no stale state; a dead instance simply isn't there.

    Probes run in parallel: a dead/filtered port can cost the full DISCOVERY_TIMEOUT (some
    systems don't refuse a closed loopback port immediately), so a serial scan over the whole
    range would be slow. In parallel the scan costs ~one timeout regardless of range size.
    """
    base = _state.unified_port + 1
    ports = list(range(base, base + WORKER_PORT_COUNT))
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        results = pool.map(_query_whoami, ports)
    found = [ident for ident in results if ident is not None]
    found.sort(key=lambda i: ((i.get("binary") or "").lower(), i.get("pid", 0)))
    return found


def _scan_instances_cached() -> list[dict[str, Any]]:
    with _scan_lock:
        now = time.monotonic()
        if now - _scan_cache["ts"] < 1.0 and _scan_cache["data"]:
            return _scan_cache["data"]
        data = _scan_instances()
        _scan_cache.update(ts=now, data=data)
        return data


def _format_instances(instances: list[dict[str, Any]]) -> str:
    return ", ".join(f"{i.get('binary') or '(no binary)'} (pid {i.get('pid')})" for i in instances)


def _path_matches(path: str, selector: str) -> bool:
    if not path:
        return False
    a = os.path.normcase(os.path.normpath(path))
    b = os.path.normcase(os.path.normpath(selector))
    return a == b


def _resolve_target(selector: Any, instances: list[dict[str, Any]]) -> dict[str, Any]:
    """Resolve an `instance` selector to exactly one instance, or raise a telepathic error.

    Selector may be a binary name (or stem), a file path, or a pid. Resolution is
    collision-aware: a selector that matches different instances by different modes is
    ambiguous unless every match is the same instance.
    """
    if not instances:
        raise ValueError("No IDA instances are reachable. Rerun list_instances.")

    if selector is None or (isinstance(selector, str) and not selector.strip()):
        if len(instances) == 1:
            return instances[0]
        raise ValueError(
            f"Multiple IDA instances are open; pass instance=<binary name or pid>. "
            f"Open: {_format_instances(instances)}."
        )

    sel = str(selector).strip()
    sel_l = sel.lower()
    matched: dict[int, dict[str, Any]] = {}
    for inst in instances:
        name = inst.get("binary") or ""
        stem = name.rsplit(".", 1)[0] if "." in name else name
        by_name = bool(name) and (name.lower() == sel_l or stem.lower() == sel_l)
        by_pid = sel.isdigit() and inst.get("pid") == int(sel)
        by_path = _path_matches(inst.get("path") or "", sel)
        if by_name or by_pid or by_path:
            matched[inst.get("pid")] = inst

    if len(matched) == 1:
        return next(iter(matched.values()))
    if not matched:
        raise ValueError(f"No open instance matches '{sel}'. Open: {_format_instances(instances)}.")
    raise ValueError(
        f"'{sel}' is ambiguous across instances: {_format_instances(list(matched.values()))}. "
        f"Pass the pid to disambiguate."
    )


def _list_instances_result() -> dict[str, Any]:
    rows = [
        {"name": i.get("binary") or None, "path": i.get("path") or None,
         "pid": i.get("pid"), "version": i.get("version")}
        for i in _scan_instances()
    ]
    return _tool_success({"instances": rows, "count": len(rows)})


def _proxy_tools_call(target: dict[str, Any], req_id: Any, name: str,
                      arguments: dict[str, Any]) -> dict[str, Any]:
    """Forward a tool call to another instance's worker port and relay its JSON-RPC response.

    The instance token lets the worker reject the call if its port has since been recycled by a
    different process (a reuse race), so a call can never silently hit the wrong database.
    """
    payload = {"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
    body = json.dumps(payload).encode("utf-8")
    try:
        conn = http.client.HTTPConnection("127.0.0.1", target["worker_port"], timeout=PROXY_TIMEOUT)
        try:
            conn.request("POST", MCP_ENDPOINT, body, headers={
                "Content-Type": "application/json",
                INSTANCE_HEADER: str(target.get("token", "")),
            })
            resp = conn.getresponse()
            data = resp.read()
        finally:
            conn.close()
        return json.loads(data)
    except Exception as e:  # noqa: BLE001 - any proxy failure becomes a clean, actionable error
        with _scan_lock:
            _scan_cache["ts"] = 0.0  # this target looks gone; force a rescan next time
        return _jsonrpc_result(req_id, _tool_error(
            f"Instance '{target.get('binary') or target.get('pid')}' (pid {target.get('pid')}) "
            f"is unreachable: {type(e).__name__}. Rerun list_instances."
        ))


def _route_tools_call(req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    """Unified-endpoint tools/call: select the target instance and dispatch to it."""
    name = params.get("name") or ""
    arguments = params.get("arguments")
    if arguments is None:
        arguments = {}
    if not name:
        return _jsonrpc_error(req_id, JsonRpcError.INVALID_PARAMS, "Missing tool name")
    if not isinstance(arguments, dict):
        return _jsonrpc_error(req_id, JsonRpcError.INVALID_PARAMS, "Tool arguments must be an object")

    # Router-native, never proxied.
    if name == "list_instances":
        return _jsonrpc_result(req_id, _list_instances_result())

    if name not in _TOOLS:
        # Match the worker/single-instance path, which reports an unknown tool as INVALID_PARAMS.
        return _jsonrpc_error(req_id, JsonRpcError.INVALID_PARAMS, f"Unknown tool: {name}")

    # The selector is a routing concern; strip it before the backend (whose schema forbids it).
    selector = arguments.get("instance")
    clean_args = {k: v for k, v in arguments.items() if k != "instance"}

    try:
        target = _resolve_target(selector, _scan_instances_cached())
    except ValueError as e:
        # Selection problems are returned as tool errors so the agent sees and self-corrects.
        return _jsonrpc_result(req_id, _tool_error(str(e)))

    if target.get("pid") == os.getpid():
        return _jsonrpc_result(req_id, _execute_tool(name, clean_args))  # in-process, no hop
    return _proxy_tools_call(target, req_id, name, clean_args)


# =============================================================================
# HTTP server
# =============================================================================

class _MCPServer(ThreadingHTTPServer):
    """Threaded HTTP server with EXCLUSIVE port ownership.

    No SO_REUSEADDR (and SO_EXCLUSIVEADDRUSE on Windows) so exactly one process can hold a
    port: this makes the unified-port election unambiguous and prevents another process from
    hijacking a worker/router port. `role` is "router" (unified endpoint) or "worker".
    """

    daemon_threads = True
    allow_reuse_address = False
    role = "worker"

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            with contextlib.suppress(OSError):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class MCPRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for MCP Streamable HTTP endpoint."""

    server_version = "IDAFastMCP/" + VERSION
    sys_version = ""

    # Use HTTP/1.1 but force Connection: close to avoid persistent connections.
    protocol_version = "HTTP/1.1"

    # Hostnames we treat as "this machine" for Host/Origin validation.
    _LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

    def _request_is_allowed(self) -> bool:
        """Reject requests that could originate from another host or a web page.

        Defends a localhost server that exposes code execution against DNS-rebinding and
        browser-driven CSRF: the Host header must name loopback (or the configured bind
        host), and any Origin header — which legitimate non-browser MCP clients do not
        send — must likewise be loopback.
        """
        allowed = self._LOOPBACK_HOSTS | {str(self.server.server_address[0]).lower()}

        def _hostname(value: str) -> str:
            # Strip scheme (for Origin), then :port, then IPv6 brackets.
            if "://" in value:
                value = value.split("://", 1)[1]
            return value.rsplit(":", 1)[0].strip("[]").lower()

        host = self.headers.get("Host", "")
        if host and _hostname(host) not in allowed:
            return False

        # Legitimate non-browser MCP clients send no Origin; any present one must be loopback.
        origin = self.headers.get("Origin")
        return not (origin and _hostname(origin) not in allowed)

    def log_message(self, *_args: Any) -> None:
        # Silence default request logging (IDA output noise).
        return

    def _respond(self, status: int, *, body: bytes = b"", content_type: str | None = None,
                 extra_headers: dict[str, str] | None = None) -> None:
        """Single path for all responses. A client may give up before IDA finishes, so
        ignore a broken connection while writing."""
        self.close_connection = True
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.send_response(status)
            if content_type:
                self.send_header("Content-Type", content_type)
            # A 204 response must carry no body; per RFC it omits Content-Length entirely.
            if status != 204:
                self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if body:
                self.wfile.write(body)

    def _send_json(self, status: int, body: Any) -> None:
        data = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
        self._respond(status, body=data, content_type="application/json; charset=utf-8")

    def _send_text(self, status: int, message: str) -> None:
        self._respond(status, body=message.encode("utf-8"), content_type="text/plain; charset=utf-8")

    def do_OPTIONS(self) -> None:
        if self.path != MCP_ENDPOINT:
            self._send_text(404, "Not Found")
            return
        # Deliberately grant no CORS: this endpoint is for local, non-browser MCP clients.
        # With no Access-Control-Allow-Origin, a browser preflight fails and the cross-site
        # request never reaches do_POST.
        self._respond(204, extra_headers={"Allow": "POST, OPTIONS"})

    def do_POST(self) -> None:
        if self.path != MCP_ENDPOINT:
            self._send_text(404, "Not Found")
            return

        # Reject browser/cross-host requests before doing any work (see _request_is_allowed).
        if not self._request_is_allowed():
            self._send_text(403, "Forbidden")
            return

        # Require a JSON content type; this also blocks simple cross-site form posts, which
        # can only send text/plain, multipart/form-data, or urlencoded bodies. Compare the
        # media type exactly (so "application/jsonx" is rejected), ignoring any ;charset.
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._send_text(415, "Unsupported Media Type: expected application/json")
            return

        # Read request body (bounded)
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0

        if content_length <= 0:
            self._send_text(400, "Empty request body")
            return

        if content_length > Limits.HTTP_BODY_MAX:
            self._send_text(413, "Request body too large")
            return

        try:
            body = self.rfile.read(content_length)
        except Exception as e:
            self._send_text(400, f"Failed to read request body: {e}")
            return

        # Parse JSON
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._send_json(200, _jsonrpc_error(None, JsonRpcError.PARSE_ERROR, f"Parse error: {e}"))
            return

        # Keep wire behavior simple: one JSON-RPC request per HTTP request.
        if isinstance(payload, list):
            self._send_json(200, _jsonrpc_error(None, JsonRpcError.INVALID_REQUEST, "Batch requests not supported."))
            return

        role = getattr(self.server, "role", "worker")

        # Worker role: if the router stamped a token that isn't ours, this port was recycled
        # under a different process. Reject so a call never silently lands on the wrong DB.
        if role == "worker":
            want = self.headers.get(INSTANCE_HEADER)
            if want and want != INSTANCE_TOKEN:
                req_id = payload.get("id") if isinstance(payload, dict) else None
                self._send_json(200, _jsonrpc_result(req_id, _tool_error(
                    "This worker port now hosts a different instance (it was recycled). "
                    "Rerun list_instances.")))
                return

        response = _handle_jsonrpc_request(payload, router=(role == "router"))
        if response is None:
            # Accepted notification with no reply body (MCP Streamable HTTP: 202 Accepted).
            self._respond(202)
            return

        self._send_json(200, response)

    def do_GET(self) -> None:
        # Discovery: a cheap identity probe served from cache (never calls into IDA, so it
        # can't block behind a long operation). Loopback-guarded like every other request.
        if self.path == WHOAMI_ENDPOINT:
            if not self._request_is_allowed():
                self._send_text(403, "Forbidden")
                return
            self._send_json(200, dict(_state.identity))
            return
        if self.path != MCP_ENDPOINT:
            self._send_text(404, "Not Found")
            return
        # The endpoint exists but offers no SSE/GET stream; advertise the allowed methods.
        self._respond(405, extra_headers={"Allow": "POST, OPTIONS"})


# =============================================================================
# Server lifecycle (embedded in IDA)
# =============================================================================

def _parse_configuration() -> tuple[str, int]:
    host = os.environ.get("IDA_FAST_MCP_HOST", DEFAULT_HOST).strip() or DEFAULT_HOST
    port_str = os.environ.get("IDA_FAST_MCP_PORT", str(DEFAULT_PORT)).strip()

    # Plugin options override environment
    try:
        opts = idaapi.get_plugin_options("ida_fast_mcp") or ""
        for part in str(opts).split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "host" and v:
                host = v
            elif k == "port" and v:
                port_str = v
    except Exception:
        pass

    # Normalize localhost to IP
    if host.lower() == "localhost":
        host = "127.0.0.1"

    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            port = DEFAULT_PORT
    except ValueError:
        port = DEFAULT_PORT

    return host, port


def _is_loopback_host(host: str) -> bool:
    """True only for addresses that stay on this machine. No DNS resolution — a hostname
    that happens to resolve to a LAN address is treated as non-loopback on purpose."""
    h = host.strip().strip("[]").lower()
    return h in ("127.0.0.1", "::1", "localhost") or h.startswith("127.")


def _guarded_unified_host(host: str) -> str:
    """Secure by default: refuse a non-loopback unified bind (network-reachable RCE) unless
    explicitly opted in. Worker ports are always loopback regardless."""
    if not _is_loopback_host(host) and not _get_bool(os.environ.get("IDA_FAST_MCP_ALLOW_NONLOOPBACK", "")):
        idaapi.msg(
            f"[IDA Fast MCP] Refusing non-loopback bind host '{host}'; using {DEFAULT_HOST} instead. "
            "This endpoint runs arbitrary code with no authentication. "
            "Set IDA_FAST_MCP_ALLOW_NONLOOPBACK=1 to allow network binding.\n"
        )
        return DEFAULT_HOST
    return host


def _serve_in_thread(server: _MCPServer, name: str) -> threading.Thread:
    def _serve() -> None:
        with contextlib.suppress(Exception):
            server.serve_forever(poll_interval=0.25)

    t = threading.Thread(target=_serve, name=f"IDAFastMCP_{name}", daemon=True)
    t.start()
    return t


def _bind_worker(base: int) -> tuple[_MCPServer | None, int | None]:
    """Bind the first free worker port in the range (loopback only, exclusive)."""
    for port in range(base, base + WORKER_PORT_COUNT):
        if port > 65535:
            break
        try:
            server = _MCPServer((DEFAULT_HOST, port), MCPRequestHandler)
        except (OSError, OverflowError):
            continue  # taken by another instance, or out of range; try the next slot
        server.role = "worker"
        return server, port
    return None, None


def _try_become_router() -> bool:
    """Attempt to claim the unified port. Exactly one instance can win (exclusive bind)."""
    if _state.router_server is not None:
        return True
    try:
        server = _MCPServer((_state.unified_host, _state.unified_port), MCPRequestHandler)
    except OSError:
        return False  # another instance holds it
    server.role = "router"
    _state.router_server = server
    _state.router_thread = _serve_in_thread(server, "router")
    return True


def _start_reclaim_loop() -> None:
    """Another instance is the router; keep trying to take over so the unified endpoint
    survives that instance closing (failover). Jittered to avoid synchronized bind storms."""
    if _state.reclaim_thread is not None and _state.reclaim_thread.is_alive():
        return

    stop_event = _state.stop_event  # capture this generation's event

    def _loop() -> None:
        # wait() returns True only when stop is signalled; on timeout it returns False -> retry.
        # This wakes instantly on teardown, so stop_server can join without leaving a stale loop.
        while not stop_event.wait(RECLAIM_INTERVAL + random.uniform(0.0, RECLAIM_JITTER)):
            if _state.router_server is not None:
                break
            if _try_become_router():
                idaapi.msg("[IDA Fast MCP] Took over the unified endpoint "
                           f"http://{_state.unified_host}:{_state.unified_port}{MCP_ENDPOINT}\n")
                break

    _state.reclaim_thread = threading.Thread(target=_loop, name="IDAFastMCP_Reclaim", daemon=True)
    _state.reclaim_thread.start()


def start_server() -> bool:
    if _state.worker_server is not None:
        idaapi.msg("[IDA Fast MCP] Server already running\n")
        return True

    host, port = _parse_configuration()
    _state.unified_host = _guarded_unified_host(host)
    _state.unified_port = port
    _state.stopping = False
    _state.stop_event = threading.Event()  # fresh event for this run (old loops are joined below)

    # Every instance is reachable on its own loopback worker port (the full single-DB server).
    worker_server, worker_port = _bind_worker(port + 1)
    if worker_server is None:
        idaapi.msg(
            f"[IDA Fast MCP] No free worker port in {port + 1}-{port + WORKER_PORT_COUNT}; "
            "close an IDA instance or change IDA_FAST_MCP_PORT. This instance will not serve.\n"
        )
        return False

    _state.worker_server = worker_server
    _state.worker_port = worker_port
    _state.identity = _capture_identity()  # on IDA's main thread (init/run run there)
    # The DB is often not open yet at init; keep the binary name current on the main thread.
    with contextlib.suppress(Exception):
        _state.identity_timer = ida_kernwin.register_timer(IDENTITY_REFRESH_MS, _refresh_identity)
    _state.worker_thread = _serve_in_thread(worker_server, "worker")

    # Contend for the unified endpoint; if another instance holds it, watch for a handover.
    became_router = _try_become_router()
    if not became_router:
        _start_reclaim_loop()

    binary = _state.identity.get("binary") or "(no binary)"
    served_by = "this instance" if became_router else "another instance"
    idaapi.msg(
        f"[IDA Fast MCP] {binary}: worker on 127.0.0.1:{worker_port}; unified endpoint "
        f"http://{_state.unified_host}:{_state.unified_port}{MCP_ENDPOINT} (served by {served_by}).\n"
    )
    return True


def stop_server() -> None:
    if _state.worker_server is None and _state.router_server is None:
        return

    _state.stopping = True
    _state.stop_event.set()  # wake the reclaim loop now so its join below returns promptly

    if _state.identity_timer is not None:
        with contextlib.suppress(Exception):
            ida_kernwin.unregister_timer(_state.identity_timer)
        _state.identity_timer = None

    for attr in ("router_server", "worker_server"):
        server = getattr(_state, attr)
        setattr(_state, attr, None)
        if server is not None:
            with contextlib.suppress(Exception):
                server.shutdown()
            with contextlib.suppress(Exception):
                server.server_close()

    for attr in ("router_thread", "worker_thread", "reclaim_thread"):
        thread = getattr(_state, attr)
        setattr(_state, attr, None)
        if thread is not None:
            with contextlib.suppress(Exception):
                thread.join(timeout=1.0)

    _state.worker_port = None
    idaapi.msg("[IDA Fast MCP] Server stopped\n")


# =============================================================================
# IDA plugin entry
# =============================================================================

class IDAFastMCPPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "IDA Fast MCP Server"
    help = "MCP server embedded in IDA Pro (Streamable HTTP)"
    wanted_name = "IDA Fast MCP"
    wanted_hotkey = ""

    def init(self) -> int:
        ok = start_server()
        return idaapi.PLUGIN_KEEP if ok else idaapi.PLUGIN_SKIP

    def run(self, _arg: int) -> None:
        # Toggle server
        if _state.worker_server is None:
            start_server()
        else:
            stop_server()

    def term(self) -> None:
        stop_server()


def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return IDAFastMCPPlugin()
