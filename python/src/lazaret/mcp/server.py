#!/usr/bin/env python3
"""Lazaret MCP server — exposes the Lazaret scanner as MCP tools.

Stdio transport, no dependencies (stock python3). Run as `lazaret-mcp`
or `python -m lazaret.mcp`.

Tools:
    scan_directory  — full project scan with quality gate
    scan_files      — scan specific files (e.g. just the ones you changed)
    scan_snippet    — scan a code string before writing it to disk
    quality_gate    — pass/fail gate only, for quick change verification
    scan_package / registry_status / discover_packages — npm / PyPI registry

Tool calls run one at a time on a worker thread, so the server keeps
answering ping and honors notifications/cancelled while a scan runs.

Environment:
    LAZARET_DB                registry state DB (see lazaret-registry --db)
    LAZARET_MCP_ROOTS         os.pathsep-separated directories; when set, a
                              path outside them is a tool error
    LAZARET_MCP_MAX_FILES     files one tool call may scan   (default 20000)
    LAZARET_MCP_MAX_BYTES     source bytes one call may read (default 200000000)
    LAZARET_MCP_MAX_SECONDS   wall-clock budget per call     (default 300)
    A call that hits a cap returns what it scanned, marked "incomplete", with
    an SC-TRUNCATED finding for what was left out (scan_files: one per
    unscanned file) or, for packages, an INCOMPLETE entry — never clean.
"""
import json
import os
import queue
import re
import sys
import threading
import time

import lazaret as _lazaret_package
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

# Protocol revisions this server speaks, newest first. A client asking for
# one of them gets it back; any other request is answered with the newest
# (the client then decides whether it can continue). A client that names
# none gets the revision the server was first written against.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2024-11-05")
PROTOCOL_VERSION = "2024-11-05"
MAX_ISSUES = 200
# discover_packages(scan=true): packages scanned per call; the rest are
# listed as INCOMPLETE ("not scanned") and the call is marked incomplete.
MAX_DISCOVER_SCANS = 15

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
                        "scan (OK / WARN / INCOMPLETE / SUSPICIOUS) from the registry state DB."),
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
                "scan": {"type": "boolean", "description": (
                    f"Also scan the discovered packages (at most {MAX_DISCOVER_SCANS}; the "
                    f"rest are listed as INCOMPLETE, not scanned)")},
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


# ---------------- Per-call context: cancellation, caps, allowed roots ----------------
class ToolCancelled(Exception):
    """The client cancelled the running call (notifications/cancelled)."""


def _env_number(name, default, kind=int):
    try:
        value = kind(os.environ.get(name, default))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def allowed_roots():
    """Real paths of LAZARET_MCP_ROOTS entries ([] = no restriction)."""
    raw = os.environ.get("LAZARET_MCP_ROOTS", "")
    return [os.path.normcase(os.path.realpath(os.path.expanduser(p.strip())))
            for p in raw.split(os.pathsep) if p.strip()]


class ToolContext:
    """What one tool call may use. Handlers call check() between files."""

    def __init__(self, cancel_event=None):
        self.cancel_event = cancel_event if cancel_event is not None else threading.Event()
        self.max_files = _env_number("LAZARET_MCP_MAX_FILES", 20_000)
        self.max_bytes = _env_number("LAZARET_MCP_MAX_BYTES", 200_000_000)
        self.max_seconds = _env_number("LAZARET_MCP_MAX_SECONDS", 300.0, float)
        self.deadline = time.monotonic() + self.max_seconds
        self.roots = allowed_roots()

    def cancelled(self):
        return self.cancel_event.is_set()

    def check(self):
        if self.cancel_event.is_set():
            raise ToolCancelled("cancelled by the client")

    def expired(self):
        return time.monotonic() > self.deadline

    def check_path(self, path):
        """Tool error for a path outside LAZARET_MCP_ROOTS (symlinks resolved)."""
        if not isinstance(path, str) or not path or "\x00" in path:
            raise ValueError("path must be a non-empty string")
        if not self.roots:
            return
        real = os.path.normcase(os.path.realpath(path))
        for root in self.roots:
            try:
                if os.path.commonpath([real, root]) == root:
                    return
            except ValueError:            # different drives
                continue
        raise ValueError(f"path is outside the allowed roots (LAZARET_MCP_ROOTS): {path}")


_LOCAL = threading.local()


def _ctx():
    """The running call's context (a fresh default one outside the server)."""
    ctx = getattr(_LOCAL, "ctx", None)
    return ctx if ctx is not None else ToolContext()


def slim(issue):
    return {k: issue[k] for k in ("rule", "type", "sev", "msg", "fix", "file", "line")}


def result_summary(res, max_issues):
    out = {
        "qualityGate": "PASSED" if res["pass"] else "FAILED",
        "conditions": res["conditions"],
        "metrics": res["metrics"],
        "counts": res["counts"],
        "ratings": res["ratings"],
        "issueTotal": len(res["issues"]),
        "issues": [slim(i) for i in res["issues"][:max_issues]],
    }
    for key in ("incomplete", "incompleteReason", "notes"):
        if res.get(key):
            out[key] = res[key]
    return out


# ---------------- Project scan (mirrors the CLI pipeline) ----------------
_MANIFEST_NAMES = ("package.json", "binding.gyp")
_SOURCE_CAP = 2_000_000          # collect_files' per-file limit


def _preflight(root, exclude, include_deps, ctx):
    """Count what collect_files would read before it reads it; stops at the
    caps (and on cancel / deadline) so a huge tree costs a bounded walk.
    -> None when within budget, else the reason."""
    skip = set(lazaret.SKIP_DIRS) | set(exclude)
    deps = set(lazaret.DEP_MARKERS)
    if include_deps:
        skip -= deps
    n_files = n_bytes = 0
    stack = [root]
    while stack:
        ctx.check()
        if ctx.expired():
            return f"time budget of {ctx.max_seconds:g} s spent while listing files"
        try:
            with os.scandir(stack.pop()) as it:
                entries = list(it)
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    if e.name not in skip and (include_deps or e.name not in deps):
                        stack.append(e.path)
                    continue
                if not e.is_file(follow_symlinks=False):
                    continue
                ext = os.path.splitext(e.name)[1].lower()
                source = ext in lazaret.EXTS or e.name in _MANIFEST_NAMES
                if not source and ext not in lazaret.COMPILED_EXTS:
                    continue
                n_files += 1
                if source:
                    size = e.stat(follow_symlinks=False).st_size
                    n_bytes += size if size <= _SOURCE_CAP else 0
            except OSError:
                continue
            if n_files > ctx.max_files:
                return f"more than {ctx.max_files:,} files to scan (LAZARET_MCP_MAX_FILES)"
            if n_bytes > ctx.max_bytes:
                return f"more than {ctx.max_bytes:,} bytes of source (LAZARET_MCP_MAX_BYTES)"
    return None


def run_project_scan(path, exclude=None, include_deps=False, ctx=None):
    """The CLI's project pipeline for the MCP tools: core.scan_project(), the
    same function `lazaret <dir>` runs (collection, scan_file per file,
    package.json / binding.gyp, skipped-tree notes, the guarded cross-file
    pass, gate, redaction), so the two can never drift apart again.

    MCP budget (ctx): caps on files / bytes are enforced before anything is
    read; cancellation and the deadline are checked between files. A call
    that stops early returns what it scanned with "incomplete": true and an
    SC-TRUNCATED finding, so it can never pass the gate."""
    ctx = ctx or _ctx()
    exclude = list(exclude or [])
    over = _preflight(path, exclude, include_deps, ctx)
    if over:
        res = lazaret.build_result(path, [], [lazaret.truncated_issue(
            ".", f"directory not scanned: {over}; narrow the path or raise the MCP caps")])
        res.update(incomplete=True, incompleteReason=over, notes=[])
        return res

    def should_stop():
        ctx.check()                      # raises when the call was cancelled
        if ctx.expired():
            return f"time budget of {ctx.max_seconds:g} s (LAZARET_MCP_MAX_SECONDS) exceeded"
        return None

    try:
        res = lazaret.scan_project(path, exclude, include_deps=include_deps,
                                   should_stop=should_stop)
    except lazaret.ScanTargetError:
        # an empty directory is a clean (if pointless) scan for a tool caller
        res = lazaret.build_result(path, [], [])
        res["warnings"] = []
    res["notes"] = res.pop("warnings", [])
    return res


def tool_scan_directory(args):
    ctx = _ctx()
    path = args.get("path")
    ctx.check_path(path)
    if not os.path.isdir(path):
        raise ValueError(f"Not a directory: {path}")
    exclude = args.get("exclude") or []
    if not isinstance(exclude, list) or not all(isinstance(x, str) for x in exclude):
        raise ValueError("exclude must be an array of directory names")
    res = run_project_scan(path, exclude, bool(args.get("include_deps")), ctx=ctx)
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
    ctx = _ctx()
    paths = args.get("paths")
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        raise ValueError("paths must be an array of strings")
    for p in paths:                      # every path is checked before any is read
        ctx.check_path(p)
    out, all_issues, files = {}, [], []
    read_bytes, stopped = 0, None
    for idx, p in enumerate(paths):
        ctx.check()
        if idx >= ctx.max_files:
            stopped = f"file cap of {ctx.max_files:,} (LAZARET_MCP_MAX_FILES) reached"
        elif read_bytes > ctx.max_bytes:
            stopped = f"byte cap of {ctx.max_bytes:,} (LAZARET_MCP_MAX_BYTES) reached"
        elif ctx.expired():
            stopped = f"time budget of {ctx.max_seconds:g} s (LAZARET_MCP_MAX_SECONDS) exceeded"
        if stopped:
            # verdict integrity: every file the cap left out carries an
            # SC-TRUNCATED finding (same shape as an oversized file's), so a
            # capped call can never look clean
            for q in paths[idx:]:
                if q in out:
                    continue
                ti = lazaret.truncated_issue(q, f"{stopped}; the file was not read")
                all_issues.append(ti)
                out[q] = {"error": f"not scanned: {stopped}", "rule": ti["rule"], "sev": ti["sev"]}
            break
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
        try:
            with open(p, "rb") as fh:
                data = fh.read(MAX_SCAN_FILE_BYTES + 1)
        except OSError as exc:
            out[p] = {"error": f"Cannot read file: {exc}"}
            continue
        if len(data) > MAX_SCAN_FILE_BYTES:
            ti = lazaret.truncated_issue(
                p, f"read exceeded the {MAX_SCAN_FILE_BYTES:,}-byte file limit")
            all_issues.append(ti)
            out[p] = {"error": ti["msg"], "rule": ti["rule"], "sev": ti["sev"]}
            continue
        read_bytes += len(data)
        # BOM / UTF-16 / PEP 263 coding cookie (UTF-7 → SC-UTF7), like the
        # registry: scan what the interpreter will read.
        content, extra = lazaret.decode_member(p, data)
        issues = extra + lazaret.scan_file(p, content, lang)
        files.append({"path": p, "content": content, "lang": lang})
        all_issues.extend(issues)
        out[p] = {"issueCount": len(issues), "issues": [slim(i) for i in issues]}
    summary = {
        "files": out,
        "totalIssues": len(all_issues),
        "worstSeverity": min((i["sev"] for i in all_issues),
                             key=lambda s: lazaret.SEV_ORDER[s], default=None),
    }
    if stopped:
        summary["incomplete"] = True
        summary["incompleteReason"] = stopped
    return summary


def tool_scan_snippet(args):
    lang = args.get("language")
    code = args.get("code")
    if lang not in ("py", "js") or not isinstance(code, str):
        raise ValueError("scan_snippet needs code (string) and language 'py' or 'js'")
    name = "snippet.py" if lang == "py" else "snippet.js"
    issues = lazaret.scan_file(name, code, lang)
    issues.sort(key=lambda i: (lazaret.SEV_ORDER[i["sev"]], i["line"]))
    return {"issueCount": len(issues), "issues": [slim(i) for i in issues]}


def tool_quality_gate(args):
    ctx = _ctx()
    path = args.get("path")
    ctx.check_path(path)
    if not os.path.isdir(path):
        raise ValueError(f"Not a directory: {path}")
    res = run_project_scan(path, ctx=ctx)
    out = {"qualityGate": "PASSED" if res["pass"] else "FAILED",
           "conditions": res["conditions"], "counts": res["counts"],
           "ratings": res["ratings"],
           "supplyChainIndicators": res.get("supplyChain", 0)}
    for key in ("incomplete", "incompleteReason", "notes"):
        if res.get(key):
            out[key] = res[key]
    return out


def _store_result(store, eco, name, res):
    """Persist; a DB failure is reported next to the verdict, never instead of it."""
    try:
        pid, _ = store.add_package(eco, name)
        store.save_scan(pid, res)
        return None
    except Exception as exc:                                       # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"


def tool_scan_package(args):
    if lazaret_repo is None:
        raise ValueError("Registry scanning unavailable (lazaret.registry not importable).")
    spec = args.get("spec")
    if not isinstance(spec, str):
        raise ValueError("spec must be a string like npm:left-pad@1.3.0")
    ctx = _ctx()
    eco, name, ver = lazaret_repo.parse_spec(spec)
    # open the state DB first: an unreachable DB is a tool error before any download
    store = lazaret_repo.Store(REGISTRY_DB)
    res = lazaret_repo.scan_package(eco, name, ver, full=bool(args.get("full")),
                                    deadline=ctx.deadline, cancel=ctx.cancelled)
    store_error = _store_result(store, eco, name, res)
    out = {"package": f"{eco}:{name}@{res['version']}", "artifact": res.get("artifact"),
           "verdict": res["verdict"], "verdictReason": res.get("verdictReason"),
           "profile": res["profile"],
           "filesScanned": res["filesScanned"], "binaryArtifacts": res.get("binaryArtifacts", 0),
           "supplyChainIndicators": res["supplyChain"], "severityCounts": res["sevCounts"],
           "issueTotal": len(res["issues"]), "issues": [slim(i) for i in res["issues"][:MAX_ISSUES]]}
    if len(res.get("artifacts") or []) > 1:
        out["artifacts"] = [{k: a.get(k) for k in ("filename", "kind", "verdict", "verdictReason")}
                            for a in res["artifacts"]]
    if store_error:
        out["storeError"] = store_error
    return out


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
    ctx = _ctx()
    since = args.get("since") or "7d"
    if not isinstance(since, str):
        raise ValueError("since must be a string like 7d, 2w, 24h or an ISO date")
    cutoff = lazaret_repo.parse_since(since)
    ecos = args.get("ecosystem") or ["pypi", "npm"]
    try:
        limit = min(int(args.get("limit") or 25), 50)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer") from None
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
        results, reasons = [], []
        for i, (e, n, v, _w) in enumerate(discovered):
            ctx.check()
            spec = f"{e}:{n}" + (f"@{v}" if v else "")
            # A discovered package that is not scanned cannot be cleared: it
            # is listed as INCOMPLETE (so it shows up in `flagged`) and the
            # call is marked incomplete, never silently dropped.
            if i >= MAX_DISCOVER_SCANS:
                why = f"discover_packages scans at most {MAX_DISCOVER_SCANS} packages per call"
            elif ctx.expired():
                why = f"time budget of {ctx.max_seconds:g} s (LAZARET_MCP_MAX_SECONDS) exceeded"
            else:
                why = None
            if why:
                results.append({"package": spec, "verdict": "INCOMPLETE",
                                "error": f"not scanned: {why}"})
                if why not in reasons:
                    reasons.append(why)
                continue
            try:
                # tracked even when the scan fails, so the next sweep retries it
                store.add_package(e, n)
            except Exception:                              # noqa: BLE001
                pass
            try:
                res = lazaret_repo.scan_package(e, n, v, deadline=ctx.deadline,
                                                cancel=ctx.cancelled)
            except lazaret_repo.ScanCancelled:
                raise
            except Exception as exc:                       # noqa: BLE001
                # a package that could not be scanned cannot be cleared
                results.append({"package": spec, "verdict": "INCOMPLETE", "error": str(exc)})
                continue
            entry = {"package": f"{e}:{n}@{res['version']}", "verdict": res["verdict"],
                     "verdictReason": res.get("verdictReason"),
                     "supplyChainIndicators": res["supplyChain"],
                     "binaryArtifacts": res.get("binaryArtifacts", 0)}
            store_error = _store_result(store, e, n, res)
            if store_error:
                entry["storeError"] = store_error
            results.append(entry)
        out["scanned"] = results
        out["flagged"] = [r for r in results
                          if r.get("verdict") in ("WARN", "INCOMPLETE", "SUSPICIOUS")]
        if reasons:
            out["incomplete"] = True
            out["incompleteReason"] = "; ".join(reasons)
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


# ---------------- JSON-RPC framing ----------------
# Deepest JSON nesting accepted in a request. Real MCP traffic is a handful of
# levels deep; anything past this is treated as hostile (see _loads_frame).
MAX_FRAME_DEPTH = 512
_DEPTH_ERROR = {"code": -32700, "message": (
    f"Parse error: request JSON exceeds the maximum nesting depth of "
    f"{MAX_FRAME_DEPTH} (treated as hostile input, not a crash; re-send the "
    f"request with bounded depth)")}
_PARSE_ERROR = {"code": -32700, "message": "Parse error: the frame is not valid JSON"}
_STRUCTURE_RE = re.compile(r'["\[\]{}]')


def _frame_depth_exceeds(line, limit=MAX_FRAME_DEPTH):
    """True if the frame nests arrays/objects deeper than `limit`. Brackets
    inside string literals don't count. One linear pass with string/escape
    state (the old regex backtracked quadratically on an unterminated
    string: 41 KB took 6 s)."""
    if line.count("[") + line.count("{") <= limit:
        return False          # can't be that deep; skip the scan
    n = len(line)
    depth, in_string, i = 0, False, 0
    backslash = -1            # position of the next backslash at or after i
    while i < n:
        if in_string:
            quote = line.find('"', i)
            if quote == -1:
                return False                  # unterminated string: nothing more counts
            if backslash < i:
                backslash = line.find("\\", i)
                if backslash == -1:
                    backslash = n
            if backslash < quote:
                i = backslash + 2             # skip the escaped character
                continue
            in_string, i = False, quote + 1
            continue
        m = _STRUCTURE_RE.search(line, i)
        if m is None:
            return False
        ch, i = m.group(), m.end()
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        else:
            depth -= 1
    return False


def _loads_frame(line):
    """Parse one JSON-RPC frame with the deep-nesting guard (card 1149e3e5).
    -> (request, error): error is a -32700 JSON-RPC error for a frame that is
    not JSON (a client must get an answer, never silence) or that nests
    deeper than MAX_FRAME_DEPTH (measured explicitly: whether json.loads
    overflows depends on the interpreter)."""
    if _frame_depth_exceeds(line):
        return None, _DEPTH_ERROR
    try:
        return json.loads(line), None
    except RecursionError:
        return None, _DEPTH_ERROR
    except ValueError:                        # JSONDecodeError, int digit limit
        return None, _PARSE_ERROR


# The stream protocol frames go to. main() points sys.stdout at stderr so a
# stray print() in library code can never corrupt the protocol stream.
_OUT = None
_WRITE_LOCK = threading.Lock()


def reply(msg_id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    stream = _OUT if _OUT is not None else sys.stdout
    with _WRITE_LOCK:
        stream.write(json.dumps(msg) + "\n")
        stream.flush()


# audit H3/G5/G6 (this card): a single line frame may itself be enormous —
# a client (or a transcript-replay harness) can send tens of megabytes on
# one line. json.loads on such a line is the same unbounded allocation the
# scan_files cap protects against; cap the frame instead: -32600 and keep
# serving the next line.
MAX_FRAME_BYTES = 16 * 1024 * 1024


def _validated_request(req):
    """Frame validation (audit H3 = F4/G5/G6).

    Returns (method, msg_id, params, err, is_notification). err is a JSON-RPC
    error dict when the frame does not conform to JSON-RPC 2.0 / MCP shape
    (always answered, with the id when it is readable):
      * non-object frame ("hello", 42, [1,2] — batches are not supported)
                                                         → -32600, id null
      * jsonrpc != "2.0" or method not a string         → -32600
      * id present but not a string/integer (MCP forbids null) → -32600, id null
      * params present, non-null and not an object      → -32602
    A frame without "id" is a notification: never answered.
    A missing or null params is coerced to {}."""
    if not isinstance(req, dict):
        return None, None, None, {"code": -32600, "message": (
            "Invalid Request: frame must be a JSON object "
            f"(got {type(req).__name__})")}, False
    has_id = "id" in req
    msg_id = req.get("id")
    if has_id and (isinstance(msg_id, bool) or not isinstance(msg_id, (str, int))):
        return None, None, None, {"code": -32600, "message": (
            "Invalid Request: id must be a string or an integer")}, False
    method = req.get("method")
    if req.get("jsonrpc") != "2.0" or not isinstance(method, str):
        return None, msg_id, None, {"code": -32600, "message": (
            "Invalid Request: needs jsonrpc==\"2.0\" and a string method")}, False
    params = req.get("params")
    if params is None:
        params = {}
    elif not isinstance(params, dict):
        return None, msg_id, None, {"code": -32602, "message": (
            f"Invalid params: 'params' must be an object (got {type(params).__name__})")}, False
    return method, msg_id, params, None, not has_id


def negotiate_protocol(requested):
    if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    if requested is None:
        return PROTOCOL_VERSION
    return SUPPORTED_PROTOCOL_VERSIONS[0]


LAZARET_VERSION = _lazaret_package.__version__


def _id_key(msg_id):
    return json.dumps(msg_id)


class Server:
    """Reader loop on the main thread, tool calls on one worker thread.

    The reader answers initialize / ping / tools/list itself and queues
    tools/call, so a long scan never blocks ping, and notifications/cancelled
    reaches the running call (its cancel flag is checked between files). Per
    MCP, a cancelled request gets no response."""

    def __init__(self):
        self.jobs = queue.Queue()
        self.lock = threading.Lock()
        self.pending = {}                       # id key -> cancel Event
        self.worker = threading.Thread(target=self._work, name="lazaret-mcp-tools",
                                       daemon=True)
        self.worker.start()

    # ---- worker ----
    def _work(self):
        while True:
            job = self.jobs.get()
            if job is None:
                return
            msg_id, handler, args, event = job
            try:
                if event.is_set():
                    continue                    # cancelled while queued: no reply
                _LOCAL.ctx = ToolContext(event)
                try:
                    result = handler(args)
                except ToolCancelled:
                    continue
                except Exception as exc:        # noqa: BLE001  (tool failure → isError)
                    if lazaret_repo is not None and isinstance(exc, lazaret_repo.ScanCancelled):
                        continue
                    if not event.is_set():
                        reply(msg_id, {"content": [{"type": "text", "text": f"Error: {exc}"}],
                                       "isError": True})
                    continue
                except SystemExit as exc:
                    # audit H2 (=F3/F4): tool code must never take the server down.
                    reply(msg_id, {"content": [{"type": "text", "text": f"Error: {exc}"}],
                                   "isError": True})
                    continue
                if event.is_set():
                    continue                    # cancelled as it finished: no reply
                try:
                    text = json.dumps(result, indent=2)
                except (TypeError, ValueError) as exc:
                    reply(msg_id, error={"code": -32603, "message": f"Internal error: {exc}"})
                    continue
                reply(msg_id, {"content": [{"type": "text", "text": text}]})
            except Exception as exc:            # noqa: BLE001  never let the worker die
                try:
                    reply(msg_id, error={"code": -32603,
                                         "message": f"Internal error: {type(exc).__name__}: {exc}"})
                except Exception:               # noqa: BLE001
                    pass
            finally:
                _LOCAL.ctx = None
                with self.lock:
                    if self.pending.get(_id_key(msg_id)) is event:
                        del self.pending[_id_key(msg_id)]

    def submit(self, msg_id, handler, args):
        event = threading.Event()
        with self.lock:
            self.pending[_id_key(msg_id)] = event
        self.jobs.put((msg_id, handler, args, event))

    def cancel(self, request_id):
        with self.lock:
            event = self.pending.get(_id_key(request_id))
        if event is not None:
            event.set()

    def cancel_all(self):
        with self.lock:
            for event in self.pending.values():
                event.set()

    def close(self, timeout=None):
        self.jobs.put(None)
        self.worker.join(timeout)

    # ---- reader ----
    def handle_line(self, line):
        line = line.strip()
        if not line:
            return
        if len(line) > MAX_FRAME_BYTES:
            # oversized frame: reject with -32600 and keep serving
            reply(None, error={"code": -32600, "message": (
                f"Invalid Request: frame exceeds {MAX_FRAME_BYTES} byte limit")})
            return
        req, frame_error = _loads_frame(line)
        if frame_error is not None:
            # not JSON / too deep: -32700 with id null (the id is unreadable)
            reply(None, error=frame_error)
            return
        method, msg_id, params, err, is_notification = _validated_request(req)
        if err is not None:
            reply(msg_id, error=err)
            return
        if is_notification:
            self.notification(method, params)
            return
        try:
            self.request(method, msg_id, params)
        except Exception as exc:                        # noqa: BLE001
            # audit H2: the dispatch safety net — reply -32603, keep serving.
            try:
                reply(msg_id, error={"code": -32603,
                                     "message": f"Internal error: {type(exc).__name__}: {exc}"})
            except Exception:                           # noqa: BLE001
                pass

    def notification(self, method, params):
        """Notifications are never answered; unknown ones are ignored, and an
        id-less tools/call is not executed."""
        if method == "notifications/cancelled":
            request_id = params.get("requestId")
            if isinstance(request_id, (str, int)) and not isinstance(request_id, bool):
                self.cancel(request_id)

    def request(self, method, msg_id, params):
        if method == "initialize":
            # params is a validated dict here — the `{"method":"initialize",
            # "params":null}` frame of the G5 PoC used to crash on
            # params.get(...) BEFORE any try block.
            reply(msg_id, {
                "protocolVersion": negotiate_protocol(params.get("protocolVersion")),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "lazaret", "version": LAZARET_VERSION},
            })
        elif method == "ping":
            reply(msg_id, {})
        elif method == "tools/list":
            reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            name = params.get("name")
            handler = HANDLERS.get(name) if isinstance(name, str) else None
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
            self.submit(msg_id, handler, args)
        else:
            reply(msg_id, error={"code": -32601, "message": f"Method not found: {method}"})


def main():
    global _OUT
    # MCP messages are UTF-8 by definition. On Windows, stdin/stdout would
    # otherwise use the ANSI code page: a client's non-ASCII text (a code
    # snippet with an accented character) would be misread, or crash the loop.
    for stream in (sys.stdin, sys.stdout):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
    lazaret.configure_stdio()   # stderr: never crash on a diagnostic
    # stdout carries protocol frames only: anything library code prints
    # goes to stderr instead.
    _OUT = sys.stdout
    sys.stdout = sys.stderr
    server = Server()
    try:
        for line in sys.stdin:
            server.handle_line(line)
    except KeyboardInterrupt:
        server.cancel_all()      # operator interrupt is never swallowed
        server.close(timeout=5)
        raise
    # end of input: finish the queued calls, then exit
    server.close()


if __name__ == "__main__":
    main()
