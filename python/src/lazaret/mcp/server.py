#!/usr/bin/env python3
"""Lazaret MCP server — exposes the Lazaret scanner as MCP tools.

Stdio transport, no dependencies (stock python3). Run as `lazaret-mcp`
or `python -m lazaret.mcp`.

Tools:
    scan_directory  — full project scan with quality gate
    scan_files      — scan specific files (e.g. just the ones you changed)
    scan_snippet    — scan a code string before writing it to disk
    quality_gate    — pass/fail gate only, for quick change verification
"""
import json
import re
import os
import sys

from lazaret.scanner import core as lazaret  # noqa: E402
try:
    from lazaret.registry import repo as lazaret_repo  # registry scanning (optional)
except Exception:  # pragma: no cover
    lazaret_repo = None

REGISTRY_DB = os.environ.get("LAZARET_DB", "lazaret-registry.db")
# L1 (artifact hygiene): the MCP server scans ARBITRARY upstream packages
# into the shared registry DB — the credential-bearing flagged lines of a
# hostile or merely sloppy package must not be persisted. mk_issue in
# lazaret.scanner.core redacts SECRET-rule flagged lines into the placeholder, so
# the Store blob only ever sees the placeholder; the slim() issue copies
# the tools return carry no snippet fields at all. Registry scanning is
# the reason redaction is default-ON there.
if os.environ.get("LAZARET_NO_REDACT") == "1":
    lazaret.REDACT_SECRETS = False

PROTOCOL_VERSION = "2024-11-05"
MAX_ISSUES = 200

TOOLS = [
    {
        "name": "scan_directory",
        "description": ("Recursively scan a project directory for security vulnerabilities "
                        "and code-quality issues in Python/JavaScript files. Returns quality-gate "
                        "result, metrics, ratings, and the issue list."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to the project directory"},
                "exclude": {"type": "array", "items": {"type": "string"},
                            "description": "Extra directory names to skip (node_modules, .git etc. are always skipped)"},
                "include_deps": {"type": "boolean",
                                 "description": "Also scan dependency dirs (node_modules, venv, vendor) for supply-chain indicators: obfuscated code, secrets, suspicious install hooks"},
                "max_issues": {"type": "integer", "description": f"Cap on issues returned (default {MAX_ISSUES})"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_files",
        "description": ("Scan specific Python/JavaScript files (e.g. only the files changed in a "
                        "diff). Returns issues per file. Use after editing code to verify the "
                        "changes introduce no new problems."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "paths": {"type": "array", "items": {"type": "string"},
                          "description": "Absolute paths of files to scan"},
            },
            "required": ["paths"],
        },
    },
    {
        "name": "scan_snippet",
        "description": ("Scan a code snippet (string) for security and quality issues before "
                        "writing it to disk. language: 'py' or 'js'."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code to scan"},
                "language": {"type": "string", "enum": ["py", "js"]},
            },
            "required": ["code", "language"],
        },
    },
    {
        "name": "scan_package",
        "description": ("Fetch and scan a public npm or PyPI package for supply-chain "
                        "compromise (obfuscation, install hooks, secrets) and vulnerabilities. "
                        "The archive is scanned in memory. Result is recorded in the registry "
                        "state DB. spec examples: 'npm:left-pad@1.3.0', 'pypi:requests', "
                        "'npm:@babel/core'."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "spec": {"type": "string",
                         "description": "npm:<name>[@version] or pypi:<name>[@version]"},
                "full": {"type": "boolean",
                         "description": "Run the full ruleset (default: supply-chain/secret rules only)"},
            },
            "required": ["spec"],
        },
    },
    {
        "name": "registry_status",
        "description": ("List tracked npm/PyPI packages and the verdict of their most recent "
                        "scan (OK / WARN / SUSPICIOUS) from the registry state DB."),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "discover_packages",
        "description": ("Find npm/PyPI packages newly published or updated within a recent time "
                        "window (supply-chain threat hunting). Optionally scans them. PyPI uses "
                        "timestamped RSS feeds; npm uses the replication changes feed (best-effort)."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "string", "description": "Time window: 7d, 2w, 24h, or an ISO date (default 7d)"},
                "ecosystem": {"type": "array", "items": {"type": "string", "enum": ["pypi", "npm"]},
                              "description": "Restrict to pypi and/or npm (default both)"},
                "limit": {"type": "integer", "description": "Max packages to return (default 25, cap 50)"},
                "scan": {"type": "boolean", "description": "Also scan the discovered packages (bounded to 15)"},
            },
        },
    },
    {
        "name": "quality_gate",
        "description": ("Run the project quality gate on a directory. Returns PASSED/FAILED with "
                        "the individual conditions — a compact check for CI-style verification "
                        "after making changes."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to the project directory"},
            },
            "required": ["path"],
        },
    },
]


def slim(issue):
    return {k: issue[k] for k in ("rule", "type", "sev", "msg", "fix", "file", "line")}


def result_summary(res, max_issues):
    return {
        "qualityGate": "PASSED" if res["pass"] else "FAILED",
        "conditions": res["conditions"],
        "metrics": res["metrics"],
        "counts": res["counts"],
        "ratings": res["ratings"],
        "issueTotal": len(res["issues"]),
        "issues": [slim(i) for i in res["issues"][:max_issues]],
    }


def run_project_scan(path, exclude=None, include_deps=False):
    files, manifests, binary_issues = lazaret.collect_files(
        path, exclude or [], include_deps=include_deps)
    issues = list(binary_issues)
    for f in files:
        issues.extend(lazaret.scan_file(f["path"], f["content"], f["lang"],
                                          dep=f.get("dep", False)))
    for mf in manifests:
        issues.extend(lazaret.scan_manifest(mf["path"], mf["content"]))
    if getattr(lazaret, "lazaret_flow", None) is not None:
        issues.extend(lazaret.lazaret_flow.analyze(files))
    return lazaret.build_result(path, files, issues)


def tool_scan_directory(args):
    path = args["path"]
    if not os.path.isdir(path):
        raise ValueError(f"Not a directory: {path}")
    res = run_project_scan(path, args.get("exclude"), bool(args.get("include_deps")))
    out = result_summary(res, int(args.get("max_issues") or MAX_ISSUES))
    out["supplyChainIndicators"] = res.get("supplyChain", 0)
    return out


# audit M6/G7 (this card): scan_files read whole files with open().read() —
# a sparse/huge file (e.g. /proc/kcore-style) allocates unboundedly and
# kills the single-threaded server (verified: a 512MB sparse file hung it).
# Same 2,000,000-byte cap as lazaret.collect_files, and the same
# verdict-integrity rule: a file that was not scanned must leave a signal
# (SC-TRUNCATED, CRITICAL), never a silent skip.
MAX_SCAN_FILE_BYTES = 2_000_000


def tool_scan_files(args):
    out, all_issues, files = {}, [], []
    for p in args["paths"]:
        ext = os.path.splitext(p)[1].lower()
        lang = lazaret.EXTS.get(ext)
        if lang is None:
            out[p] = {"error": f"Unsupported extension {ext} (need .py/.js/.ts/.jsx/.tsx)"}
            continue
        if not os.path.isfile(p):
            out[p] = {"error": "File not found"}
            continue
        try:
            size = os.path.getsize(p)
        except OSError as exc:
            out[p] = {"error": f"Cannot stat file: {exc}"}
            continue
        if size > MAX_SCAN_FILE_BYTES:
            ti = lazaret.truncated_issue(
                p, f"{size:,} bytes exceeds the {MAX_SCAN_FILE_BYTES:,}-byte file limit")
            all_issues.append(ti)
            out[p] = {"error": ti["msg"], "rule": ti["rule"], "sev": ti["sev"]}
            continue
        # bounded read: read cap+1 so a file that GREW between stat and read
        # (TOCTOU) is still caught, then falls into the truncation path.
        with open(p, encoding="utf-8", errors="replace") as fh:
            content = fh.read(MAX_SCAN_FILE_BYTES + 1)
        if len(content) > MAX_SCAN_FILE_BYTES:
            ti = lazaret.truncated_issue(
                p, f"read exceeded the {MAX_SCAN_FILE_BYTES:,}-byte file limit")
            all_issues.append(ti)
            out[p] = {"error": ti["msg"], "rule": ti["rule"], "sev": ti["sev"]}
            continue
        issues = lazaret.scan_file(p, content, lang)
        files.append({"path": p, "content": content, "lang": lang})
        all_issues.extend(issues)
        out[p] = {"issueCount": len(issues), "issues": [slim(i) for i in issues]}
    summary = {
        "files": out,
        "totalIssues": len(all_issues),
        "worstSeverity": min((i["sev"] for i in all_issues),
                             key=lambda s: lazaret.SEV_ORDER[s], default=None),
    }
    return summary


def tool_scan_snippet(args):
    lang = args["language"]
    name = "snippet.py" if lang == "py" else "snippet.js"
    issues = lazaret.scan_file(name, args["code"], lang)
    issues.sort(key=lambda i: (lazaret.SEV_ORDER[i["sev"]], i["line"]))
    return {"issueCount": len(issues), "issues": [slim(i) for i in issues]}


def tool_quality_gate(args):
    path = args["path"]
    if not os.path.isdir(path):
        raise ValueError(f"Not a directory: {path}")
    res = run_project_scan(path)
    return {"qualityGate": "PASSED" if res["pass"] else "FAILED",
            "conditions": res["conditions"], "counts": res["counts"],
            "ratings": res["ratings"],
            "supplyChainIndicators": res.get("supplyChain", 0)}


def tool_scan_package(args):
    if lazaret_repo is None:
        raise ValueError("Registry scanning unavailable (lazaret.registry not importable).")
    eco, name, ver = lazaret_repo.parse_spec(args["spec"])
    res = lazaret_repo.scan_package(eco, name, ver, full=bool(args.get("full")))
    store = lazaret_repo.Store(REGISTRY_DB)
    pid, _ = store.add_package(eco, name)
    store.save_scan(pid, res)
    return {"package": f"{eco}:{name}@{res['version']}", "artifact": res.get("artifact"),
            "verdict": res["verdict"], "profile": res["profile"],
            "filesScanned": res["filesScanned"], "binaryArtifacts": res.get("binaryArtifacts", 0),
            "supplyChainIndicators": res["supplyChain"], "severityCounts": res["sevCounts"],
            "issueTotal": len(res["issues"]), "issues": [slim(i) for i in res["issues"][:MAX_ISSUES]]}


def tool_registry_status(args):
    if lazaret_repo is None:
        raise ValueError("Registry scanning unavailable (lazaret.registry not importable).")
    store = lazaret_repo.Store(REGISTRY_DB)
    rows = []
    for eco, name, ver, profile, at, verdict, n, supply in store.status():
        rows.append({"package": f"{eco}:{name}", "lastVersion": ver, "lastScan": at,
                     "verdict": verdict, "issues": n, "supplyChain": supply})
    return {"tracked": len(rows), "packages": rows}


def tool_discover_packages(args):
    if lazaret_repo is None:
        raise ValueError("Registry scanning unavailable (lazaret.registry not importable).")
    since = args.get("since") or "7d"
    cutoff = lazaret_repo.parse_since(since)
    ecos = args.get("ecosystem") or ["pypi", "npm"]
    limit = min(int(args.get("limit") or 25), 50)
    discovered = []
    if "pypi" in ecos:
        discovered += lazaret_repo.discover_pypi(cutoff, limit)
    if "npm" in ecos:
        discovered += lazaret_repo.discover_npm(cutoff, limit)
    discovered.sort(key=lambda x: x[3], reverse=True)
    discovered = discovered[:limit]
    out = {"since": cutoff.isoformat(), "count": len(discovered),
           "packages": [{"ecosystem": e, "name": n, "version": v, "when": w.isoformat()}
                        for e, n, v, w in discovered]}
    if args.get("scan"):
        store = lazaret_repo.Store(REGISTRY_DB)
        results = []
        for e, n, v, _w in discovered[:15]:
            try:
                res = lazaret_repo.scan_package(e, n, v)
                pid, _ = store.add_package(e, n)
                store.save_scan(pid, res)
                results.append({"package": f"{e}:{n}@{res['version']}", "verdict": res["verdict"],
                                "supplyChainIndicators": res["supplyChain"],
                                "binaryArtifacts": res.get("binaryArtifacts", 0)})
            except Exception as exc:                       # noqa: BLE001
                results.append({"package": f"{e}:{n}", "error": str(exc)})
        out["scanned"] = results
        out["flagged"] = [r for r in results if r.get("verdict") in ("WARN", "SUSPICIOUS")]
    return out


HANDLERS = {
    "scan_directory": tool_scan_directory,
    "scan_files": tool_scan_files,
    "scan_snippet": tool_scan_snippet,
    "scan_package": tool_scan_package,
    "registry_status": tool_registry_status,
    "discover_packages": tool_discover_packages,
    "quality_gate": tool_quality_gate,
}


# Deepest JSON nesting accepted in a request. Real MCP traffic is a handful of
# levels deep; anything past this is treated as hostile (see _loads_frame).
MAX_FRAME_DEPTH = 512
_JSON_STRUCTURE = re.compile(r'"(?:\\.|[^"\\])*"|[\[\]{}]')   # string literals, or brackets
_DEPTH_ERROR = {"code": -32700, "message": (
    f"Parse error: request JSON exceeds the maximum nesting depth of "
    f"{MAX_FRAME_DEPTH} (treated as hostile input, not a crash; re-send the "
    f"request with bounded depth)")}


def _frame_depth_exceeds(line, limit=MAX_FRAME_DEPTH):
    """True if the frame nests arrays/objects deeper than `limit`. Brackets
    inside string literals don't count."""
    if line.count("[") + line.count("{") <= limit:
        return False          # can't be that deep; skip the scan
    depth = 0
    for match in _JSON_STRUCTURE.finditer(line):
        token = match.group()
        if token == "[" or token == "{":
            depth += 1
            if depth > limit:
                return True
        elif token == "]" or token == "}":
            depth -= 1
    return False


def _loads_frame(line):
    """Parse one JSON-RPC frame with the deep-nesting guard (card 1149e3e5).

    Hostile-repo chain: a scanned package stores findings/scan results
    (user-supplied repo content) in the registry DB; every later
    registry_status / scan_package / discover_packages reply embeds those
    blobs in its JSON-RPC result. When the poisoned frame comes back as the
    NEXT request line (a client that pipes its transcript back, a
    transcript-driven runner, or a hostile repo planting a
    .lazaret/transcript line), json.loads(line) at 60k nesting depth blows
    CPython's recursion limit and takes the whole server down — every other
    tool call after it is lost. JSON-RPC says a server MUST NOT die on a bad
    frame: report -32700 and keep serving. Same contract for the reversed
    chain, where a hostile repo's transcripts are consumed as client input.
    A merely-bad frame (syntax) is still dropped as before; only
    parse failures caused by depth get a structured error response.

    Depth is measured explicitly (MAX_FRAME_DEPTH) before parsing, because
    whether json.loads overflows depends on the interpreter: Python 3.14's
    parser accepts depths that older versions reject, so a RecursionError
    alone is not a reliable signal. The RecursionError handler stays as a
    fallback."""
    if _frame_depth_exceeds(line):
        return None, _DEPTH_ERROR
    try:
        return json.loads(line), None
    except json.JSONDecodeError:
        return None, None
    except RecursionError:
        return None, _DEPTH_ERROR


def reply(msg_id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


# audit H3/G5/G6 (this card): a single line frame may itself be enormous —
# a client (or a transcript-replay harness) can send tens of megabytes on
# one line. json.loads on such a line is the same unbounded allocation the
# scan_files cap protects against; cap the frame instead: -32600 and keep
# serving the next line.
MAX_FRAME_BYTES = 16 * 1024 * 1024


def _validated_request(req):
    """Frame validation (audit H3 = F4/G5/G6).

    Returns (method, msg_id, params, err) where err is a JSON-RPC error dict
    when the frame does not conform to JSON-RPC 2.0 / MCP shape:
      * non-object frame ("hello", 42, [1,2])           → -32600 Invalid Request
      * jsonrpc != "2.0" or method not a string         → -32600 Invalid Request
      * params present, non-null and not an object      → -32602 Invalid params
    A missing or null params is coerced to {} (the spec allows it and clients
    really do send `"params": null` — the initialize handshake of every
    minimal client) so the tool/handler layer never sees a non-dict.
    """
    if not isinstance(req, dict):
        return None, None, None, {"code": -32600, "message": (
            "Invalid Request: frame must be a JSON object "
            f"(got {type(req).__name__})")}
    method, msg_id = req.get("method"), req.get("id")
    if req.get("jsonrpc") != "2.0" or not isinstance(method, str):
        return None, msg_id, None, {"code": -32600, "message": (
            "Invalid Request: needs jsonrpc==\"2.0\" and a string method")}
    params = req.get("params")
    if params is None:
        params = {}
    elif not isinstance(params, dict):
        return None, msg_id, None, {"code": -32602, "message": (
            f"Invalid params: 'params' must be an object (got {type(params).__name__})")}
    return method, msg_id, params, None


def _dispatch(method, msg_id, params):
    """Route one validated request. Raises nothing that escapes main()'s
    (Exception, SystemExit) safety net; KeyboardInterrupt is re-raised by
    the caller. Tool-level failures come back as isError content (the
    existing contract), so this returns None on every handled path."""
    if method == "initialize":
        # params is a validated dict here — the `{"method":"initialize",
        # "params":null}` frame of the G5 PoC used to crash on
        # params.get(...) BEFORE any try block, killing the server on the
        # very first message a client sends.
        reply(msg_id, {
            "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "lazaret", "version": "1.0.0"},
        })
    elif method == "notifications/initialized":
        pass
    elif method == "ping":
        reply(msg_id, {})
    elif method == "tools/list":
        reply(msg_id, {"tools": TOOLS})
    elif method == "tools/call":
        name = params.get("name")
        handler = HANDLERS.get(name)
        if handler is None:
            reply(msg_id, error={"code": -32602, "message": f"Unknown tool: {name}"})
            return
        args = params.get("arguments")
        if args is None:
            args = {}
        elif not isinstance(args, dict):
            reply(msg_id, error={"code": -32602, "message": (
                f"Invalid params: 'arguments' must be an object (got {type(args).__name__})")})
            return
        try:
            result = handler(args)
            reply(msg_id, {"content": [{"type": "text",
                                        "text": json.dumps(result, indent=2)}]})
        except SystemExit as exc:
            # audit H2 (=F3/F4): tool code (e.g. lazaret_repo) used to be
            # able to raise SystemExit — `except Exception` missed it and the
            # whole server died. Tool failure is reported, server stays up.
            reply(msg_id, {"content": [{"type": "text", "text": f"Error: {exc}"}],
                           "isError": True})
        except Exception as exc:  # report tool failure, keep server alive
            reply(msg_id, {"content": [{"type": "text", "text": f"Error: {exc}"}],
                           "isError": True})
    elif msg_id is not None:
        reply(msg_id, error={"code": -32601, "message": f"Method not found: {method}"})


def main():
    # MCP messages are UTF-8 by definition. On Windows, stdin/stdout would
    # otherwise use the ANSI code page: a client's non-ASCII text (a code
    # snippet with an accented character) would be misread, or crash the loop.
    for stream in (sys.stdin, sys.stdout):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
    lazaret.configure_stdio()   # stderr: never crash on a diagnostic
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if len(line) > MAX_FRAME_BYTES:
            # oversized frame: reject with -32600 and keep serving
            reply(None, error={"code": -32600, "message": (
                f"Invalid Request: frame exceeds {MAX_FRAME_BYTES} byte limit")})
            continue
        req, frame_error = _loads_frame(line)
        if frame_error is not None:
            # deep-nested frame: structured error, server keeps serving
            # (id is unknown — the frame never parsed; null is the JSON-RPC
            # convention for errors detected before the id is readable)
            reply(None, error=frame_error)
            continue
        if req is None:
            # merely-bad frame (syntax error): dropped silently as before
            continue
        method, msg_id, params, err = _validated_request(req)
        if err is not None:
            # frame validation: -32600 / -32602 per JSON-RPC 2.0 (MCP spec).
            # msg_id is None when the id itself was unreadable (non-object
            # frame) — the JSON-RPC convention for pre-id errors.
            reply(msg_id, error=err)
            continue
        try:
            _dispatch(method, msg_id, params)
        except KeyboardInterrupt:
            raise                    # operator interrupt is never swallowed
        except (Exception, SystemExit) as exc:
            # audit H2: the dispatch safety net. One try around the WHOLE
            # dispatch, catching BaseException classes that mean "library
            # code tried to die" (SystemExit) and every ordinary failure.
            # The server replies -32603 and keeps serving — a tool crash
            # must never take down every other connection/request.
            detail = f"{type(exc).__name__}: {exc}" if not isinstance(exc, SystemExit) else f"{exc}"
            try:
                reply(msg_id, error={"code": -32603, "message": f"Internal error: {detail}"})
            except Exception:
                pass                 # never let the error reply itself kill us


if __name__ == "__main__":
    main()
