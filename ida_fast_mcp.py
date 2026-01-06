"""
IDA Fast MCP — single-file MCP server for IDA Pro (v4.10.0)

Purpose
-------
Expose a minimal, stable set of reverse-engineering tools (14 tools) to
high-capability AI agents via MCP (Model Context Protocol) over Streamable HTTP.

Compatibility
-------------
- IDA Pro 9.x with Hex-Rays Decompiler (uses ida_ida, ida_hexrays, ida_lines)

Design goals (from design reference)
------------------------------------
- Stability first: all IDA API calls run on the main thread via execute_sync()
  and every tool call has a hard 5s timeout.
- Single file, zero dependencies: stdlib + IDA modules only.
- Bounded outputs: strict limits + deterministic pagination.
- Pseudocode first: decompile with address annotations; fall back to disassembly.

Transport
---------
POST /mcp  (JSON-RPC 2.0 request/response; no SSE/streaming, no batch requests)

Install
-------
Copy this file to your IDA plugins directory and restart IDA.

Config
------
Defaults to 127.0.0.1:13338

Environment variables:
  IDA_FAST_MCP_HOST=127.0.0.1
  IDA_FAST_MCP_PORT=13338

plugins.cfg (plugin options):
  ida_fast_mcp:host=127.0.0.1;port=13338

Note: This is a local, single-user tool. Host is restricted to localhost/127.0.0.1.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import re
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
# Configuration & limits (design reference)
# =============================================================================

VERSION = "4.10.0"
MCP_ENDPOINT = "/mcp"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13338

# Timeout configuration (seconds) — Stability First
# Total timeout is the max time any request can take from arrival to response.
# Lock wait timeout is how long a request will wait for its turn if another is running.
# These share a budget: if lock takes 4s, execution gets remaining 1s.
TOTAL_TIMEOUT_SECONDS = 5.0
LOCK_WAIT_TIMEOUT_SECONDS = 4.0  # Max time waiting for lock (leaves 1s minimum for execution)
MIN_EXECUTION_HEADROOM = 0.5  # Seconds reserved for execution when calculating lock wait
MIN_EXECUTION_THRESHOLD = 0.1  # Minimum remaining time required to attempt execution

# Internal limits (named constants for maintainability)
AVAILABLE_VARS_DISPLAY_MAX = 20


# Output bounds (defaults + maxima)
class Limits:
    # list ops
    XREFS_DEFAULT = 20
    XREFS_MAX = 50

    FUNCTIONS_DEFAULT = 30
    FUNCTIONS_MAX = 100

    STRINGS_DEFAULT = 30
    STRINGS_MAX = 100

    IMPORTS_DEFAULT = 30
    IMPORTS_MAX = 100

    POINTER_TABLE_DEFAULT = 25
    POINTER_TABLE_MAX = 100

    PATTERN_SCAN_DEFAULT = 10
    PATTERN_SCAN_MAX = 50
    PATTERN_SCAN_MIN_BYTES = 2

    # code output
    CODE_LINES_MAX = 2000

    # HTTP safety
    HTTP_BODY_MAX = 2 * 1024 * 1024  # 2 MiB


# =============================================================================
# State
# =============================================================================

@dataclass
class _State:
    tool_lock: threading.Lock = field(default_factory=threading.Lock)

    http_server: ThreadingHTTPServer | None = None
    server_thread: threading.Thread | None = None


_state = _State()


# =============================================================================
# Small helpers
# =============================================================================

def _now() -> float:
    return time.monotonic()


def _clamp_int(value: Any, *, default: int, min_value: int, max_value: int) -> int:
    """Parse value as int, falling back to default; clamp result to [min_value, max_value]."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = default
    # Clamp to range (also clamps default if it was used)
    return max(min_value, min(v, max_value))


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
    """Extract a required parameter, raising ValueError if missing or null."""
    if key not in args:
        raise ValueError(f"Missing required parameter: '{key}'")
    val = args[key]
    if val is None:
        raise ValueError(f"Parameter '{key}' cannot be null")
    return val


def _get_offset(args: dict[str, Any]) -> int:
    """Extract pagination offset from args."""
    return max(0, int(args.get("offset", 0) or 0))


def _normalize_size(size: int) -> int:
    """Convert BADSIZE to -1 for cleaner output."""
    # BADSIZE is 0xFFFFFFFFFFFFFFFF or similar large values
    if size < 0 or size > 0x7FFFFFFFFFFFFFFF:
        return -1
    return size


def _paginated(key: str, items: list, offset: int, limit: int, total: int, **extra) -> dict[str, Any]:
    """Build a paginated response dict."""
    result = {
        key: items,
        "count": len(items),
        "total": total,
        "next_offset": (offset + limit) if (offset + limit) < total else None,
    }
    result.update(extra)
    return result


# =============================================================================
# IDA main-thread execution wrapper
# =============================================================================

def _ida_execute(fn: Callable[[], Any], *, write: bool) -> Any:
    """Run fn on IDA's main thread via execute_sync."""
    result: Any = None
    exception: BaseException | None = None

    def _wrapper() -> None:
        nonlocal result, exception
        try:
            result = fn()
        except BaseException as e:
            exception = e

    ida_kernwin.execute_sync(_wrapper, ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ)

    if exception is not None:
        raise exception
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
# Address parsing
# =============================================================================

def _parse_address(value: Any) -> int:
    """Parse an address string (hex) or resolve a name to EA."""
    if isinstance(value, int):
        return value

    if value is None:
        raise ValueError("Address is required")

    s = str(value).strip()
    if not s:
        raise ValueError("Address is required")

    # 1) Hex parse (with or without 0x)
    if _is_hex(s):
        return int(s, 16)

    # 2) Direct name lookup (handles mangled names too)
    ea = ida_name.get_name_ea(idaapi.BADADDR, s)
    if ea != idaapi.BADADDR:
        return ea

    raise ValueError(
        f"Cannot resolve '{s}' to an address. "
        f"Use list_functions or list_strings to find valid symbols."
    )


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
    # Code xrefs
    ida_xref.fl_CF: "call", ida_xref.fl_CN: "call",  # far/near call
    ida_xref.fl_JF: "jump", ida_xref.fl_JN: "jump",  # far/near jump
    ida_xref.fl_F: "flow",                            # ordinary flow
    # Data xrefs
    ida_xref.dr_O: "offset",  # offset reference
    ida_xref.dr_W: "write",   # write access
    ida_xref.dr_R: "read",    # read access
}


def _categorize_xref_type(xref_type: int) -> str:
    """Map IDA xref type to simplified category."""
    return _XREF_TYPE_MAP.get(xref_type, "data")


# =============================================================================
# Tool implementations (11 tools)
# =============================================================================

def _tool_get_binary_info(_args: dict[str, Any]) -> dict[str, Any]:
    """Get binary metadata including file info, architecture, and segments."""
    # File identity
    name = ida_nalt.get_root_filename() or ""
    path = ida_nalt.get_input_file_path() or ""
    base = ida_nalt.get_imagebase()

    # Entrypoint - inf_get_start_ip is authoritative in IDA 9.x
    entry = ida_ida.inf_get_start_ip()
    if entry == idaapi.BADADDR and ida_entry.get_entry_qty() > 0:
        # Fallback to first entry point
        entry = ida_entry.get_entry(ida_entry.get_entry_ordinal(0))

    # Bitness / architecture
    bitness = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit() else 16)
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


def _build_disassembly(func: Any) -> str:
    """Build disassembly output for a function with per-instruction address annotations."""
    start = func.start_ea
    end = func.end_ea
    name = ida_name.get_name(start) or f"sub_{start:x}"

    out: list[str] = [f"/* {_format_ea(start)} */ {name} proc"]
    ea = start
    lines_emitted = 0

    while ea != idaapi.BADADDR and ea < end and lines_emitted < Limits.CODE_LINES_MAX:
        dis = ida_lines.generate_disasm_line(ea, 0)
        if dis:
            dis = ida_lines.tag_remove(dis).rstrip()
            if dis:
                out.append(f"/* {_format_ea(ea)} */ {dis}")
                lines_emitted += 1
        ea = ida_bytes.next_head(ea, end)

    if ea != idaapi.BADADDR and ea < end:
        out.append(f"/* ... truncated at {Limits.CODE_LINES_MAX} lines ... */")

    return "\n".join(out)


def _tool_get_function(args: dict[str, Any]) -> dict[str, Any]:
    ea = _parse_address(_require_param(args, "address"))
    force_disasm = bool(args.get("force_disassembly", False))

    func = ida_funcs.get_func(ea)
    if not func:
        raise ValueError(
            f"No function at {_format_ea(ea)}. "
            f"This address may be data or unanalyzed code. "
            f"Use list_functions to find valid function addresses."
        )

    start = func.start_ea
    name = ida_name.get_name(start) or f"sub_{start:x}"
    size = func.end_ea - func.start_ea

    base = {"address": _format_ea(start), "name": name, "size": size}

    if force_disasm:
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


def _tool_get_xrefs(args: dict[str, Any]) -> dict[str, Any]:
    ea = _parse_address(_require_param(args, "address"))
    limit = _clamp_int(args.get("limit"), default=Limits.XREFS_DEFAULT, min_value=1, max_value=Limits.XREFS_MAX)
    offset = _get_offset(args)

    # Collect all xrefs, then sort and paginate
    xrefs_list: list[tuple[int, dict[str, Any]]] = []

    for xref in idautils.XrefsTo(ea):
        from_ea = xref.frm
        cat = _categorize_xref_type(xref.type)

        from_func = ida_funcs.get_func(from_ea)
        if from_func:
            fn = ida_name.get_name(from_func.start_ea) or _format_ea(from_func.start_ea)
            obj = {"from_address": _format_ea(from_ea), "from_function": fn, "type": cat}
        else:
            obj = {"from_address": _format_ea(from_ea), "from_function": None, "type": cat}

        xrefs_list.append((from_ea, obj))

    # Sort by address
    xrefs_list.sort(key=lambda x: x[0])
    total = len(xrefs_list)

    # Paginate
    page = [obj for _, obj in xrefs_list[offset:offset + limit]]

    return {
        "address": _format_ea(ea),
        "xrefs": page,
        "count": len(page),
        "total": total,
        "next_offset": (offset + limit) if (offset + limit) < total else None,
    }


def _tool_list_functions(args: dict[str, Any]) -> dict[str, Any]:
    name_filter = str(args.get("filter", "") or "").lower()
    min_size = max(0, int(args.get("min_size", 0) or 0))
    limit = _clamp_int(args.get("limit"), default=Limits.FUNCTIONS_DEFAULT, min_value=1, max_value=Limits.FUNCTIONS_MAX)
    offset = _get_offset(args)

    # idautils.Functions() returns addresses in sorted order
    all_funcs: list[tuple[int, str, int]] = []
    for fea in idautils.Functions():
        f = ida_funcs.get_func(fea)
        if not f:
            continue
        size = f.end_ea - f.start_ea
        if size < min_size:
            continue
        name = ida_name.get_name(fea) or f"sub_{fea:x}"
        if name_filter and name_filter not in name.lower():
            continue
        all_funcs.append((fea, name, size))

    page = all_funcs[offset:offset + limit]
    return _paginated(
        "functions",
        [{"address": _format_ea(a), "name": n, "size": s} for a, n, s in page],
        offset, limit, len(all_funcs),
    )


def _tool_list_strings(args: dict[str, Any]) -> dict[str, Any]:
    content_filter = str(args.get("filter", "") or "").lower()
    min_length = max(0, int(args.get("min_length", 4) or 4))
    limit = _clamp_int(args.get("limit"), default=Limits.STRINGS_DEFAULT, min_value=1, max_value=Limits.STRINGS_MAX)
    offset = _get_offset(args)

    out: list[dict[str, Any]] = []
    total = 0
    for s in _iter_strings():
        if s["length"] < min_length:
            continue
        val = s["value"]
        if content_filter and content_filter not in val.lower():
            continue
        if total >= offset and len(out) < limit:
            out.append({"address": _format_ea(s["address"]), "value": val, "string_type": s["string_type"]})
        total += 1

    return _paginated("strings", out, offset, limit, total)


def _tool_list_imports(args: dict[str, Any]) -> dict[str, Any]:
    """List imports and/or exports with optional filtering."""
    name_filter = str(args.get("filter", "") or "").lower()
    limit = _clamp_int(args.get("limit"), default=Limits.IMPORTS_DEFAULT, min_value=1, max_value=Limits.IMPORTS_MAX)
    offset = _get_offset(args)
    include_exports = bool(args.get("exports", False))

    out: list[dict[str, Any]] = []
    total = 0

    for imp in _iter_imports():
        nm, mod = imp["name"], imp["module"]
        if name_filter and name_filter not in nm.lower() and name_filter not in mod.lower():
            continue
        if total >= offset and len(out) < limit:
            out.append({"address": _format_ea(imp["address"]), "name": nm, "module": mod, "type": "import"})
        total += 1

    if include_exports:
        for exp in _iter_exports():
            nm = exp["name"]
            if name_filter and name_filter not in nm.lower():
                continue
            if total >= offset and len(out) < limit:
                entry = {"address": _format_ea(exp["address"]), "name": nm, "type": "export"}
                ordinal = exp["ordinal"]
                if ordinal and ordinal != exp["address"] and ordinal < 0x10000:
                    entry["ordinal"] = ordinal
                out.append(entry)
            total += 1

    return _paginated("imports", out, offset, limit, total)


def _tool_get_pointer_table(args: dict[str, Any]) -> dict[str, Any]:
    """Read consecutive pointers from a data table and resolve targets."""
    ea = _parse_address(_require_param(args, "address"))
    count = _clamp_int(
        args.get("count"),
        default=Limits.POINTER_TABLE_DEFAULT,
        min_value=1,
        max_value=Limits.POINTER_TABLE_MAX,
    )

    # Reject code addresses — use get_function for those
    if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
        fn = ida_funcs.get_func(ea)
        ctx = f" inside '{ida_name.get_name(fn.start_ea)}'" if fn else ""
        raise ValueError(f"Address '{_format_ea(ea)}' is code{ctx}. Use get_function for code analysis.")

    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    read_fn = ida_bytes.get_qword if ptr_size == 8 else ida_bytes.get_dword

    entries: list[dict[str, Any]] = []

    for i in range(count):
        slot_ea = ea + (i * ptr_size)

        # Stop if we've left mapped memory
        if not ida_segment.getseg(slot_ea):
            break

        ptr = read_fn(slot_ea)

        # Format raw pointer value (get_qword/get_dword return unsigned)
        raw_str = "BADADDR" if ptr == idaapi.BADADDR else f"0x{ptr:x}"

        entry: dict[str, Any] = {
            "index": i,
            "offset": i * ptr_size,
            "slot": _format_ea(slot_ea),
            "raw": raw_str,
        }

        # Null or BADADDR pointers
        if ptr == 0 or ptr == idaapi.BADADDR:
            entry["target"] = None
            entry["name"] = None
        else:
            # Try to resolve to a function
            target_func = ida_funcs.get_func(ptr)
            if target_func:
                entry["target"] = _format_ea(target_func.start_ea)
                entry["name"] = ida_name.get_name(target_func.start_ea)
            else:
                entry["target"] = _format_ea(ptr)
                entry["name"] = ida_name.get_name(ptr)

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


def _get_available_local_vars(func_ea: int) -> list[str]:
    """Get list of local variable names from a decompiled function."""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return []
        return sorted({lv.name for lv in cfunc.lvars if lv.name})
    except Exception:
        return []


def _tool_rename(args: dict[str, Any]) -> dict[str, Any]:
    ea = _parse_address(_require_param(args, "address"))
    new_name = str(_require_param(args, "new_name")).strip()
    old_name = args.get("old_name")

    if not new_name:
        raise ValueError("new_name must be a non-empty string")

    # Local variable rename
    if old_name is not None:
        old = str(old_name).strip()
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

        return {
            "success": True,
            "address": _format_ea(func_start),
            "old_name": old,
            "new_name": new_name,
            "assigned_name": new_name,
        }

    # Global/function rename
    prev = ida_name.get_name(ea) or ""
    ok = bool(ida_name.set_name(ea, new_name, ida_name.SN_NOWARN))
    if not ok:
        raise ValueError(
            f"Failed to rename {_format_ea(ea)} to '{new_name}'. "
            "Likely causes: name already exists, invalid characters, "
            "or matches IDA auto-name pattern (e.g., sub_XXX, loc_XXX)."
        )

    assigned = ida_name.get_name(ea) or new_name

    return {
        "success": True,
        "address": _format_ea(ea),
        "old_name": prev,
        "new_name": new_name,
        "assigned_name": assigned,
    }


def _tool_set_comment(args: dict[str, Any]) -> dict[str, Any]:
    ea = _parse_address(_require_param(args, "address"))
    comment = str(_require_param(args, "comment"))
    repeatable = bool(args.get("repeatable", False))

    if not ida_bytes.set_cmt(ea, comment, repeatable):
        raise ValueError(
            f"Failed to set comment at {_format_ea(ea)}. "
            f"Address may not be in analyzed code or data."
        )

    return {"success": True, "address": _format_ea(ea)}


def _tool_set_type(args: dict[str, Any]) -> dict[str, Any]:
    ea = _parse_address(_require_param(args, "address"))
    type_decl = str(_require_param(args, "type")).strip()
    variable = args.get("variable")

    if not type_decl:
        raise ValueError("type must be a non-empty string")

    # Local variable type
    if variable is not None:
        var = str(variable).strip()
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

        # IDA 9.x: parse_decl() returns the declared name (or None/empty on failure)
        # Use PT_TYP for abstract types (no variable name), PT_SIL to silence errors
        parse_flags = ida_typeinf.PT_SIL | ida_typeinf.PT_TYP
        tif = ida_typeinf.tinfo_t()

        # Try parsing the type declaration
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

        # Assign the parsed type to lvar_info only on success
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

    ok = bool(idc.SetType(apply_ea, type_decl))
    if not ok:
        raise ValueError(
            f"Failed to apply type at {_format_ea(apply_ea)}. "
            f"For function prototypes use full signature: 'int __fastcall func(int a1, char *a2)'."
        )

    return {"success": True, "address": _format_ea(apply_ea), "type": type_decl}


def _tool_define_type(args: dict[str, Any]) -> dict[str, Any]:
    """Parse C declaration into local type library."""
    code = str(_require_param(args, "code")).strip()
    if not code:
        raise ValueError("code must be a non-empty string")

    # Try parsing with idc_parse_types (handles structs, enums, typedefs)
    # Returns number of errors (0 = success)
    errors = ida_typeinf.idc_parse_types(code, 0)
    if errors != 0:
        # Fallback: try adding semicolon if missing
        if not code.rstrip().endswith(';'):
            errors = ida_typeinf.idc_parse_types(code + ";", 0)
        if errors != 0:
            raise ValueError(
                "Failed to parse type declaration. Check C syntax. "
                "Example: 'struct X { int a; };' or 'typedef int DWORD;'"
            )

    # Extract the defined type name for response
    # Try multiple patterns to handle different C declaration styles
    type_name = None

    # Pattern 1: struct/enum/union Name { ... }
    match = re.search(r'(?:struct|enum|union)\s+(\w+)\s*\{', code)
    if match:
        type_name = match.group(1)

    # Pattern 2: typedef struct { ... } Name;
    if not type_name:
        match = re.search(r'\}\s*(\w+)\s*;', code)
        if match:
            type_name = match.group(1)

    # Pattern 3: typedef Type Name;
    if not type_name:
        match = re.search(r'typedef\s+\S+\s+(\w+)\s*;', code)
        if match:
            type_name = match.group(1)

    result: dict[str, Any] = {"success": True}
    if type_name:
        result["name"] = type_name
        # Get size via ordinal lookup (more reliable)
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, type_name)
        if ordinal:
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                result["size"] = _normalize_size(tif.get_size())
    return result


def _tool_get_type(args: dict[str, Any]) -> dict[str, Any]:
    """Get type definition by name."""
    name = str(_require_param(args, "name")).strip()
    if not name:
        raise ValueError("name must be a non-empty string")

    til = ida_typeinf.get_idati()
    ordinal = ida_typeinf.get_type_ordinal(til, name)
    if ordinal == 0:
        raise ValueError(f"Type '{name}' not found in local type library")

    # Get the C representation using idc_get_local_type
    # Flags: 0 = just type, PRTYPE_MULTI for multiline
    definition = ida_typeinf.idc_get_local_type(ordinal, ida_typeinf.PRTYPE_DEF | ida_typeinf.PRTYPE_MULTI)
    if not definition:
        definition = ida_typeinf.idc_get_local_type(ordinal, 0) or ""

    # Get size via tinfo
    tif = ida_typeinf.tinfo_t()
    size = -1
    if tif.get_numbered_type(til, ordinal):
        size = _normalize_size(tif.get_size())

    return {
        "name": name,
        "size": size,
        "ordinal": ordinal,
        "definition": definition,
    }


def _tool_list_types(args: dict[str, Any]) -> dict[str, Any]:
    """List types in local type library."""
    filter_str = str(args.get("filter", "") or "").lower()
    limit = _clamp_int(args.get("limit"), default=30, min_value=1, max_value=100)
    offset = _get_offset(args)

    til = ida_typeinf.get_idati()
    if not til:
        return _paginated("types", [], offset, limit, 0)

    # Collect matching types by iterating ordinals
    all_types: list[dict[str, Any]] = []
    ordinal_limit = ida_typeinf.get_ordinal_limit(til)

    for ordinal in range(1, ordinal_limit):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if not name:
            continue
        if filter_str and filter_str not in name.lower():
            continue
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(til, ordinal):
            all_types.append({
                "name": name,
                "size": _normalize_size(tif.get_size()),
                "ordinal": ordinal,
            })

    # Sort by name for consistency
    all_types.sort(key=lambda x: x["name"].lower())

    page = all_types[offset:offset + limit]
    return _paginated("types", page, offset, limit, len(all_types))


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

    # Parse with hex radix (16)
    # IDA 9.x: returns empty string on success, error message on failure
    err = ida_bytes.parse_binpat_str(
        compiled,
        start_ea,
        ida_pattern,
        16,  # hex radix
        encoding
    )

    if err:  # Non-empty string means error
        raise ValueError(f"Failed to parse pattern: {err}")

    if compiled.empty():
        raise ValueError("Pattern compiled to empty - check syntax")

    return compiled


def _bin_search_all(
    compiled: ida_bytes.compiled_binpat_vec_t,
    start_ea: int,
    end_ea: int,
    max_results: int,
) -> list[int]:
    """
    Search for all matches of a compiled pattern in a range.

    Uses IDA's native bin_search() for speed.
    Returns list of match addresses, up to max_results.
    """
    matches: list[int] = []
    ea = start_ea

    while len(matches) < max_results:
        # IDA 9.x bin_search returns (ea, matched_pattern_idx) tuple
        result = ida_bytes.bin_search(
            ea,
            end_ea,
            compiled,
            ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
        )

        # Handle tuple return (IDA 9.x): (found_ea, pattern_index)
        found_ea = result[0] if isinstance(result, tuple) else result

        if found_ea == idaapi.BADADDR:
            break

        matches.append(found_ea)
        ea = found_ea + 1  # Move past this match to find next

    return matches


def _tool_pattern_scan(args: dict[str, Any]) -> dict[str, Any]:
    """Search for byte pattern in binary using IDA's native bin_search."""
    pattern_str = str(_require_param(args, "pattern"))
    segment = args.get("segment")
    limit = _clamp_int(args.get("limit"), default=Limits.PATTERN_SCAN_DEFAULT, min_value=1, max_value=Limits.PATTERN_SCAN_MAX)
    offset = _get_offset(args)

    # Convert pattern to IDA format (validates syntax too)
    try:
        ida_pattern = _convert_pattern_to_ida_format(pattern_str)
    except ValueError as e:
        msg = str(e).rstrip('.')
        raise ValueError(
            f"Cannot parse pattern '{pattern_str}'. {msg}. "
            f"Example: '48 8B 05 ?? ?? ?? ??'"
        ) from e

    # Resolve segment bounds
    bounds = _get_segment_bounds(segment)
    if not bounds:
        return {
            "matches": [],
            "count": 0,
            "total": 0,
            "next_offset": None,
        }

    # Compile pattern once, reuse for all segments
    # Use first segment's start_ea for compilation (required by API but doesn't affect results)
    compiled = _compile_pattern(ida_pattern, bounds[0][0])

    # We fetch offset + limit + 1 results to know if there are more
    # The +1 lets us detect if there are additional results beyond this page
    max_needed = offset + limit + 1

    all_matches: list[int] = []

    # Search all segments, collecting results
    for start_ea, end_ea in bounds:
        # Calculate how many more we need from this segment
        remaining = max_needed - len(all_matches)
        if remaining <= 0:
            break

        segment_matches = _bin_search_all(compiled, start_ea, end_ea, remaining)
        all_matches.extend(segment_matches)

    # Sort by address (segments may not be in address order)
    all_matches.sort()

    # Determine if there are more results beyond this page
    has_more = len(all_matches) > offset + limit

    # Get the page slice
    page = all_matches[offset:offset + limit]

    # Resolve function names for matches in page
    results: list[dict[str, Any]] = []
    for ea in page:
        func = ida_funcs.get_func(ea)
        if func:
            func_start = int(func.start_ea)
            func_name = ida_name.get_name(func_start)
            # Name if available, otherwise address (consolidation rule)
            func_field = func_name if func_name else _format_ea(func_start)
        else:
            func_field = None

        results.append({
            "address": _format_ea(ea),
            "function": func_field,
        })

    # Calculate next_offset if there are more results
    next_offset = (offset + limit) if has_more else None

    return {
        "matches": results,
        "count": len(results),
        "has_more": has_more,
        "next_offset": next_offset,
    }


# =============================================================================
# Tool registry (schemas + dispatch)
# =============================================================================

_TOOL_DISPATCH: dict[str, tuple[Callable[[dict[str, Any]], dict[str, Any]], bool]] = {
    # Read operations
    "get_binary_info": (_tool_get_binary_info, False),
    "get_function": (_tool_get_function, False),
    "get_xrefs": (_tool_get_xrefs, False),
    "get_pointer_table": (_tool_get_pointer_table, False),
    "get_type": (_tool_get_type, False),
    # List operations
    "list_functions": (_tool_list_functions, False),
    "list_strings": (_tool_list_strings, False),
    "list_imports": (_tool_list_imports, False),
    "list_types": (_tool_list_types, False),
    # Search operations
    "find_pattern": (_tool_pattern_scan, False),
    # Mutation operations
    "set_name": (_tool_rename, True),
    "set_comment": (_tool_set_comment, True),
    "apply_type": (_tool_set_type, True),
    "define_type": (_tool_define_type, True),
}

# =============================================================================
# Tool schemas (MCP tools/list)
# =============================================================================

# Schema property templates
_P_ADDR = {"type": "string", "description": "Address or symbol name"}
_P_OFFSET = {"type": "integer", "default": 0, "minimum": 0}


def _p_filter(noun: str) -> dict[str, Any]:
    return {"type": "string", "default": "", "description": f"Substring match on {noun}"}


def _p_limit(d: int, m: int) -> dict[str, Any]:
    return {"type": "integer", "default": d, "maximum": m, "minimum": 1}


def _schema(props: dict[str, Any], required: list[str] = None) -> dict[str, Any]:
    """Build an inputSchema dict with additionalProperties: false."""
    s: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": False}
    if required:
        s["required"] = required
    return s


TOOL_SCHEMAS: list[dict[str, Any]] = [
    # Read operations
    {"name": "get_binary_info",
     "description": "Binary metadata and segment list.",
     "inputSchema": _schema({})},

    {"name": "get_function",
     "description": "Decompiled pseudocode for function at address. Falls back to disassembly.",
     "inputSchema": _schema({"address": _P_ADDR,
                              "force_disassembly": {"type": "boolean", "default": False, "description": "Skip decompiler"}}, ["address"])},

    {"name": "get_xrefs",
     "description": "Cross-references to address (callers, data refs).",
     "inputSchema": _schema({"address": _P_ADDR,
                              "limit": _p_limit(Limits.XREFS_DEFAULT, Limits.XREFS_MAX),
                              "offset": _P_OFFSET}, ["address"])},

    {"name": "get_pointer_table",
     "description": "Read pointer table (vtable, jump table). Resolves to symbols.",
     "inputSchema": _schema({"address": _P_ADDR,
                              "count": _p_limit(Limits.POINTER_TABLE_DEFAULT, Limits.POINTER_TABLE_MAX)}, ["address"])},

    {"name": "get_type",
     "description": "Type definition by name. Returns C declaration.",
     "inputSchema": _schema({"name": {"type": "string", "description": "Type name"}}, ["name"])},

    # List operations
    {"name": "list_functions",
     "description": "Functions by address. Filterable by name, size.",
     "inputSchema": _schema({"filter": _p_filter("name"),
                              "min_size": {"type": "integer", "default": 0, "minimum": 0},
                              "limit": _p_limit(Limits.FUNCTIONS_DEFAULT, Limits.FUNCTIONS_MAX),
                              "offset": _P_OFFSET})},

    {"name": "list_strings",
     "description": "Strings by address. Filterable by content, length.",
     "inputSchema": _schema({"filter": _p_filter("content"),
                              "min_length": {"type": "integer", "default": 4, "minimum": 0},
                              "limit": _p_limit(Limits.STRINGS_DEFAULT, Limits.STRINGS_MAX),
                              "offset": _P_OFFSET})},

    {"name": "list_imports",
     "description": "Imports by address. Use 'exports' param for exports.",
     "inputSchema": _schema({"filter": _p_filter("name or module"),
                              "exports": {"type": "boolean", "default": False, "description": "Include exports"},
                              "limit": _p_limit(Limits.IMPORTS_DEFAULT, Limits.IMPORTS_MAX),
                              "offset": _P_OFFSET})},

    {"name": "list_types",
     "description": "Types in local type library.",
     "inputSchema": _schema({"filter": _p_filter("name"),
                              "limit": _p_limit(30, 100),
                              "offset": _P_OFFSET})},

    # Search operations
    {"name": "find_pattern",
     "description": "Byte pattern search. Returns matches with containing function.",
     "inputSchema": _schema({"pattern": {"type": "string", "description": "Hex bytes, ?? wildcards (e.g., '48 8B ?? ??')"},
                              "segment": {"type": "string", "description": "Limit to segment (e.g., '.text')"},
                              "limit": _p_limit(Limits.PATTERN_SCAN_DEFAULT, Limits.PATTERN_SCAN_MAX),
                              "offset": _P_OFFSET}, ["pattern"])},

    # Mutation operations
    {"name": "set_name",
     "description": "Rename symbol or local variable. Locals need 'old_name'. Avoid IDA prefixes (sub_, loc_, etc.).",
     "inputSchema": _schema({"address": {"type": "string", "description": "Address, or function address for locals"},
                              "new_name": {"type": "string", "description": "New name (no IDA prefixes like sub_XXXX)"},
                              "old_name": {"type": "string", "description": "Current name (required for locals)"}}, ["address", "new_name"])},

    {"name": "set_comment",
     "description": "Set comment at address. Overwrites existing.",
     "inputSchema": _schema({"address": _P_ADDR,
                              "comment": {"type": "string", "description": "Comment text"},
                              "repeatable": {"type": "boolean", "default": False, "description": "Show at xref locations"}}, ["address", "comment"])},

    {"name": "apply_type",
     "description": "Apply type to address (data/function) or local variable.",
     "inputSchema": _schema({"address": {"type": "string", "description": "Address, or function address for locals"},
                              "type": {"type": "string", "description": "C type (e.g., 'int *', 'int __fastcall f(void *)')"},
                              "variable": {"type": "string", "description": "Local variable name"}}, ["address", "type"])},

    {"name": "define_type",
     "description": "Parse C declaration into type library. Overwrites existing.",
     "inputSchema": _schema({"code": {"type": "string", "description": "C declaration (e.g., 'struct X { int a; };')"}}, ["code"])},
]

# Pre-computed schema lookup for O(1) access
_TOOL_SCHEMA_MAP: dict[str, dict[str, Any]] = {s["name"]: s["inputSchema"] for s in TOOL_SCHEMAS}


# =============================================================================
# MCP result formatting
# =============================================================================

def _tool_success(data: dict[str, Any]) -> dict[str, Any]:
    # MCP: include both 'content' (text) and 'structuredContent' (machine-readable)
    return {
        "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}],
        "structuredContent": data,
        "isError": False,
    }


def _tool_error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


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


def _validate_tool_args(tool_name: str, arguments: dict[str, Any]) -> None:
    """Enforce 'additionalProperties: false' and validate required params at runtime."""
    schema = _TOOL_SCHEMA_MAP.get(tool_name)
    if not schema:
        return

    props = schema.get("properties", {})
    required = schema.get("required", [])

    # Check for unknown arguments
    extra = arguments.keys() - props.keys()
    if extra:
        raise ValueError(f"Unknown argument(s) for {tool_name}: {', '.join(sorted(extra))}")

    # Check for missing required arguments
    missing = set(required) - arguments.keys()
    if missing:
        raise ValueError(f"Missing required argument(s) for {tool_name}: {', '.join(sorted(missing))}")


def _handle_initialize(params: dict[str, Any]) -> dict[str, Any]:
    # MCP 2025 streamable HTTP: initialize handshake
    proto = params.get("protocolVersion") or "2025-03-26"
    return {
        "protocolVersion": proto,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "IDA Fast MCP", "version": VERSION},
    }


def _handle_tools_list(_params: dict[str, Any]) -> dict[str, Any]:
    return {"tools": TOOL_SCHEMAS}


def _handle_tools_call(params: dict[str, Any]) -> dict[str, Any]:
    tool_name = params.get("name") or ""
    arguments = params.get("arguments") or {}

    if not tool_name:
        raise ValueError("Missing tool name")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be an object")
    if tool_name not in _TOOL_DISPATCH:
        raise ValueError(f"Unknown tool: {tool_name}")

    _validate_tool_args(tool_name, arguments)
    return _execute_tool(tool_name, arguments)


def _handle_resources_list(_params: dict[str, Any]) -> dict[str, Any]:
    # Out of scope for v1
    return {"resources": []}


def _handle_prompts_list(_params: dict[str, Any]) -> dict[str, Any]:
    # Out of scope
    return {"prompts": []}


def _handle_jsonrpc_request(payload: Any) -> dict[str, Any] | None:
    # Notifications: id absent => no response
    req_id = payload.get("id") if isinstance(payload, dict) else None
    is_notification = isinstance(payload, dict) and ("id" not in payload)

    if not isinstance(payload, dict):
        return _jsonrpc_error(None, JsonRpcError.INVALID_REQUEST, "Invalid Request")

    if payload.get("jsonrpc") != "2.0":
        return _jsonrpc_error(req_id, JsonRpcError.INVALID_REQUEST, "Invalid Request")

    method = payload.get("method")
    params = payload.get("params") or {}

    if not isinstance(method, str):
        return _jsonrpc_error(req_id, JsonRpcError.INVALID_REQUEST, "Invalid Request")

    if not isinstance(params, dict):
        return _jsonrpc_error(req_id, JsonRpcError.INVALID_PARAMS, "Params must be an object")

    # MCP clients may send cancellations/notifications; ignore them.
    if method.startswith("notifications/"):
        return None

    try:
        if method == "initialize":
            result = _handle_initialize(params)
        elif method == "tools/list":
            result = _handle_tools_list(params)
        elif method == "tools/call":
            result = _handle_tools_call(params)
        elif method == "resources/list":
            result = _handle_resources_list(params)
        elif method == "prompts/list":
            result = _handle_prompts_list(params)
        else:
            return _jsonrpc_error(req_id, JsonRpcError.METHOD_NOT_FOUND, f"Method not found: {method}")
    except KeyError as e:
        return _jsonrpc_error(req_id, JsonRpcError.METHOD_NOT_FOUND, str(e))
    except ValueError as e:
        return _jsonrpc_error(req_id, JsonRpcError.INVALID_PARAMS, str(e))
    except Exception as e:
        # Never crash the server on unexpected errors
        return _jsonrpc_error(req_id, JsonRpcError.INTERNAL_ERROR, f"Internal error: {type(e).__name__}: {e}")

    if is_notification:
        return None

    return _jsonrpc_result(req_id, result)


# =============================================================================
# Tool execution wrapper (queued execution with timeout budget)
# =============================================================================

def _execute_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a tool with proper queuing for parallel requests.

    Parallel requests are queued via a blocking lock with timeout. The total
    time budget (TOTAL_TIMEOUT_SECONDS) is shared between waiting for the lock
    and actual execution. This ensures:
    - Parallel requests are handled in order (no immediate rejection)
    - No single request takes longer than the total timeout
    - IDA API calls remain serialized for stability
    """
    tool_fn, requires_write = _TOOL_DISPATCH[tool_name]

    # Track total time budget
    start_time = _now()
    deadline = start_time + TOTAL_TIMEOUT_SECONDS

    # Try to acquire lock, waiting up to LOCK_WAIT_TIMEOUT_SECONDS
    # This queues parallel requests instead of rejecting them immediately
    lock_wait = min(LOCK_WAIT_TIMEOUT_SECONDS, TOTAL_TIMEOUT_SECONDS - MIN_EXECUTION_HEADROOM)
    lock_acquired = _state.tool_lock.acquire(blocking=True, timeout=lock_wait)

    if not lock_acquired:
        elapsed = _now() - start_time
        return _tool_error(
            f"Server busy — waited {elapsed:.1f}s for lock. "
            "Another operation is taking too long. Retry shortly."
        )

    # Calculate remaining time for execution
    remaining = deadline - _now()
    if remaining <= MIN_EXECUTION_THRESHOLD:  # Not enough time left
        _state.tool_lock.release()
        return _tool_error("Request timed out waiting for lock — no time left for execution.")

    result_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            res = _ida_execute(lambda: tool_fn(arguments), write=requires_write)
            result_queue.put((True, res))
        except Exception as e:
            result_queue.put((False, str(e)))
        finally:
            _state.tool_lock.release()

    thread = threading.Thread(
        target=worker,
        name=f"IDAFastMCP_{tool_name}",
        daemon=True,
    )
    try:
        thread.start()
    except RuntimeError as e:
        _state.tool_lock.release()
        return _tool_error(f"Failed to start worker thread: {e}")

    try:
        ok, payload = result_queue.get(timeout=remaining)
    except queue.Empty:
        # Cannot reliably interrupt IDA work; lock will be released when worker finishes
        total_elapsed = _now() - start_time
        return _tool_error(
            f"Operation timed out after {total_elapsed:.1f}s. "
            "The server will remain busy until the operation completes."
        )

    if ok:
        return _tool_success(payload)
    return _tool_error(payload)


# =============================================================================
# HTTP server
# =============================================================================

class MCPRequestHandler(BaseHTTPRequestHandler):
    """HTTP handler for MCP Streamable HTTP endpoint."""

    server_version = "IDAFastMCP/" + VERSION
    sys_version = ""

    # Use HTTP/1.1 but force Connection: close to avoid persistent connections.
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: Any) -> None:
        # Silence default request logging (IDA output noise).
        return

    def _send_json(self, status: int, body: Any) -> None:
        self.close_connection = True
        data = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, status: int, message: str) -> None:
        self.close_connection = True
        data = message.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self.close_connection = True
        if self.path != MCP_ENDPOINT:
            self._send_text(404, "Not Found")
            return

        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_POST(self) -> None:
        self.close_connection = True
        if self.path != MCP_ENDPOINT:
            self._send_text(404, "Not Found")
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

        # Reject batch requests (N tools × 5s timeout = stalls)
        if isinstance(payload, list):
            self._send_json(200, _jsonrpc_error(None, JsonRpcError.INVALID_REQUEST, "Batch requests not supported."))
            return

        response = _handle_jsonrpc_request(payload)
        if response is None:
            self.send_response(204)
            self.send_header("Connection", "close")
            self.end_headers()
            return

        self._send_json(200, response)

    def do_GET(self) -> None:
        self.close_connection = True
        # Spec: only POST /mcp. Keep surface area tiny.
        self._send_text(404, "Not Found")


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


def start_server() -> bool:
    if _state.http_server is not None:
        idaapi.msg("[IDA Fast MCP] Server already running\n")
        return True

    host, port = _parse_configuration()

    try:
        ThreadingHTTPServer.allow_reuse_address = True
        server = ThreadingHTTPServer((host, port), MCPRequestHandler)
        server.daemon_threads = True
    except OSError as e:
        idaapi.msg(f"[IDA Fast MCP] Failed to bind {host}:{port}: {e}\n")
        return False
    except Exception as e:
        idaapi.msg(f"[IDA Fast MCP] Server init failed: {type(e).__name__}: {e}\n")
        return False

    _state.http_server = server

    def _serve() -> None:
        with contextlib.suppress(Exception):
            server.serve_forever(poll_interval=0.25)

    t = threading.Thread(target=_serve, name="IDAFastMCP_HTTPServer", daemon=True)
    _state.server_thread = t
    t.start()

    idaapi.msg(f"[IDA Fast MCP] Listening on http://{host}:{port}{MCP_ENDPOINT} (timeout {TOTAL_TIMEOUT_SECONDS:.0f}s)\n")
    return True


def stop_server() -> None:
    server = _state.http_server
    if not server:
        return

    _state.http_server = None

    with contextlib.suppress(Exception):
        server.shutdown()
    with contextlib.suppress(Exception):
        server.server_close()

    t = _state.server_thread
    _state.server_thread = None
    if t:
        with contextlib.suppress(Exception):
            t.join(timeout=1.0)

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
        if _state.http_server is None:
            start_server()
        else:
            stop_server()

    def term(self) -> None:
        stop_server()


def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return IDAFastMCPPlugin()
