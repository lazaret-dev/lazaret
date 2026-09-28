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
    LAZARET_MCP_ROOTS         os.pathsep-separated directories the path tools
                              (scan_directory, scan_files, quality_gate) may
                              read; a path outside them is a tool error. Unset:
                              the roots the MCP client shares (roots/list), and
                              if it shares none, every path is refused. Set but
                              empty: every tool call is refused.
    LAZARET_MCP_MAX_FILES     files one tool call may scan   (default 20000)
    LAZARET_MCP_MAX_BYTES     source bytes one call may read (default 200000000)
    LAZARET_MCP_MAX_SECONDS   wall-clock budget per call     (default 300)
    LAZARET_MAX_SOURCE_BYTES  largest source file read       (default 16000000,
                              shared with the lazaret CLI and the registry)
    A call that hits a cap returns what it scanned, marked "incomplete", with
    an SC-TRUNCATED finding for what was left out (scan_files: one per
    unscanned file) or, for packages, an INCOMPLETE entry — never clean.
    The same goes for a directory with nothing Lazaret can scan and for a
    file named to scan_files that can't be read; a directory that is missing
    or can't be listed is a tool error.
"""
import json
import os
import queue
import re
import stat
import sys
import threading
import time
import urllib.parse
import urllib.request

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
# the tools return carry no snippet fields at all.
# LAZARET_NO_REDACT=1 turns redaction off for the PROJECT tools only
# (scan_directory, scan_files, scan_snippet, quality_gate: the user's own
# code). Registry scans ignore it (review P2): repo.scan_package always
# redacts, so scan_package / discover_packages never store or return a raw
# credential line.
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
                        "timestamped RSS feeds; npm uses the replication changes feed plus one "
                        "registry lookup per package. A registry that could not be checked makes "
                        "the result incomplete (incomplete / incompleteReason), so an empty list "
                        "never stands in for one that was not checked."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "string", "description": "Time window: 7d, 2w, 24h, or an ISO date (default 7d)"},
                "ecosystem": {"type": "array", "items": {"type": "string", "enum": ["pypi", "npm"]},
                              "description": "Restrict to pypi and/or npm (default both)"},
                "limit": {"type": "integer", "minimum": 1,
                          "description": "Max packages to return (default 25, cap 50)"},
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
    """Real paths of the LAZARET_MCP_ROOTS entries; [] when the variable is
    not set (no restriction for a direct, in-process call: the MCP server
    itself never runs a path tool unrestricted, see Server.resolve_roots).
    A variable that is set but names no directory ("", ":", " ") raises
    ValueError: whoever set it meant to restrict the server, and an empty
    list must never mean "every path"."""
    raw = os.environ.get("LAZARET_MCP_ROOTS")
    if raw is None:
        return []
    roots = [os.path.normcase(os.path.realpath(os.path.expanduser(p.strip())))
             for p in raw.split(os.pathsep) if p.strip()]
    if not roots:
        raise ValueError(f"LAZARET_MCP_ROOTS is set but names no directory ({raw!r}); "
                         "refusing to run tools. List the allowed directories, or unset "
                         "it to use the roots your MCP client shares.")
    return roots


class RootsRefused:
    """The server has no roots to allow: every path is refused, with a
    reason that says how to fix it. Tools that take no path still run."""

    def __init__(self, reason):
        self.reason = reason


ROOTS_HELP = ("Set LAZARET_MCP_ROOTS to the directories Lazaret may scan (separated by "
              f"'{os.pathsep}'), or use an MCP client that shares its workspace roots.")


def root_path_of_uri(uri):
    """Real path of an MCP root's file: URI; None for any other URI, a
    relative path, or one too long to be a directory name."""
    if not isinstance(uri, str) or len(uri) > 8192:
        return None
    try:
        parts = urllib.parse.urlsplit(uri)
        if parts.scheme.lower() != "file":
            return None
        if parts.netloc.lower() in ("", "localhost"):
            path = urllib.request.url2pathname(parts.path)
        elif os.name == "nt":                     # file://server/share -> \\server\share
            path = "\\\\" + parts.netloc + urllib.request.url2pathname(parts.path)
        else:
            return None
    except (OSError, ValueError):                 # an unclosed [ in the host, a bad drive
        return None
    if not path or "\x00" in path or not os.path.isabs(path):
        return None
    return os.path.normcase(os.path.realpath(path))


class ToolContext:
    """What one tool call may use. Handlers call check() between files.
    Raises ValueError when LAZARET_MCP_ROOTS is misconfigured (see
    allowed_roots), so no tool runs without the restriction it asked for.

    `roots_resolver` (the server passes one) decides the allowed roots the
    first time a path is checked, so a tool that takes no path never waits
    on it; it returns a list of real paths or a RootsRefused. Without one
    (a direct, in-process call), LAZARET_MCP_ROOTS applies as before and an
    unset variable means no restriction."""

    def __init__(self, cancel_event=None, roots_resolver=None):
        self.cancel_event = cancel_event if cancel_event is not None else threading.Event()
        self.max_files = _env_number("LAZARET_MCP_MAX_FILES", 20_000)
        self.max_bytes = _env_number("LAZARET_MCP_MAX_BYTES", 200_000_000)
        self.max_seconds = _env_number("LAZARET_MCP_MAX_SECONDS", 300.0, float)
        self.deadline = time.monotonic() + self.max_seconds
        self.roots = allowed_roots()
        self.roots_source = "LAZARET_MCP_ROOTS"
        self._resolver = None
        if roots_resolver is not None and os.environ.get("LAZARET_MCP_ROOTS") is None:
            self._resolver = roots_resolver
            self.roots = None

    def cancelled(self):
        return self.cancel_event.is_set()

    def check(self):
        if self.cancel_event.is_set():
            raise ToolCancelled("cancelled by the client")

    def expired(self):
        return time.monotonic() > self.deadline

    def allowed(self):
        """The roots this call may use: a list of real paths ([] = no
        restriction, direct calls only) or a RootsRefused."""
        if self._resolver is not None:
            resolver, self._resolver = self._resolver, None
            self.roots = resolver(self)
            self.roots_source = "the roots your MCP client shared"
        return self.roots

    def check_path(self, path):
        """Tool error for a path outside the allowed roots (symlinks resolved)."""
        if not isinstance(path, str) or not path or "\x00" in path:
            raise ValueError("path must be a non-empty string")
        roots = self.allowed()
        if isinstance(roots, RootsRefused):
            raise ValueError(f"no directory may be scanned: {roots.reason} {ROOTS_HELP}")
        if not roots:
            return
        real = os.path.normcase(os.path.realpath(path))
        for root in roots:
            try:
                if os.path.commonpath([real, root]) == root:
                    return
            except ValueError:            # different drives
                continue
        raise ValueError(f"path is outside the allowed roots ({self.roots_source}): {path}")


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
_MANIFEST_NAMES = lazaret.MANIFEST_NAMES


def _preflight(root, exclude, include_deps, ctx):
    """Count what scan_project will read before it reads it; stops at the
    caps (and on cancel / deadline) so a huge tree costs a bounded walk.
    -> None when within budget, else the reason.

    The walk takes the same decisions as core._collect, or the budget counts
    a different tree from the one that is read: .git and `exclude` names are
    pruned, __pycache__ only has its .pyc headers read, symlinks are never
    followed, and a dependency tree is recognised by core._dep_tree_kind —
    node_modules / bower_components / site-packages always, vendor / venv /
    .venv / env only with a marker inside (a vendor/ without one is
    first-party code, and collect reads it). Sources, manifests and .pth
    files are read whole, so they count toward the byte budget; compiled
    artifacts count as files."""
    prune = set(lazaret.ALWAYS_PRUNE_DIRS) | set(exclude) | {lazaret.PYCACHE_DIR}
    n_files = n_bytes = 0
    seen = set()
    try:
        st = os.stat(root)
        if st.st_ino:
            seen.add((st.st_dev, st.st_ino))
    except OSError:
        pass
    stack = [(root, False)]
    while stack:
        ctx.check()
        if ctx.expired():
            return f"time budget of {ctx.max_seconds:g} s spent while listing files"
        path, in_dep = stack.pop()
        try:
            with os.scandir(path) as it:
                entries = list(it)
        except OSError:
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode) or (stat.S_ISDIR(mode) and lazaret._is_reparse_point(st)):
                continue                                  # never followed
            if stat.S_ISDIR(mode):
                if e.name in prune:
                    continue
                if st.st_ino:
                    if (st.st_dev, st.st_ino) in seen:
                        continue                          # filesystem loop
                    seen.add((st.st_dev, st.st_ino))
                dep = in_dep or lazaret._dep_tree_kind(e.name, e.path)
                if dep and not in_dep and not include_deps:
                    continue                              # pruned dependency tree
                stack.append((e.path, dep))
                continue
            if not stat.S_ISREG(mode):
                continue
            ext = os.path.splitext(e.name)[1].lower()
            whole = e.name in _MANIFEST_NAMES or ext == lazaret.PTH_EXT or ext in lazaret.EXTS
            if not whole and ext not in lazaret.COMPILED_EXTS:
                continue
            n_files += 1
            if whole and st.st_size <= lazaret.SOURCE_SIZE_CAP:   # collect's per-file limit
                n_bytes += st.st_size
            if n_files > ctx.max_files:
                return f"more than {ctx.max_files:,} files to scan (LAZARET_MCP_MAX_FILES)"
            if n_bytes > ctx.max_bytes:
                return f"more than {ctx.max_bytes:,} bytes of source (LAZARET_MCP_MAX_BYTES)"
    return None


def _check_scan_target(path):
    """Tool error (ValueError) unless `path` is a directory this process can
    list. The CLI exits 2 for such a target; a tool caller must never get an
    empty clean result for it."""
    try:
        with os.scandir(path):
            pass
    except FileNotFoundError:
        raise ValueError(f"Not a directory: {path} (it does not exist)") from None
    except NotADirectoryError:
        raise ValueError(f"Not a directory: {path}") from None
    except OSError as exc:
        raise ValueError(f"Cannot read directory {path}: "
                         f"{exc.strerror or type(exc).__name__}") from None


def run_project_scan(path, exclude=None, include_deps=False, ctx=None):
    """The CLI's project pipeline for the MCP tools: core.scan_project(), the
    same function `lazaret <dir>` runs (collection, scan_file per file,
    package.json / binding.gyp, skipped-tree notes, the guarded cross-file
    pass, gate, redaction), so the two can never drift apart again.

    MCP budget (ctx): caps on files / bytes are enforced before anything is
    read; cancellation and the deadline are checked between files. A call
    that stops early returns what it scanned with "incomplete": true and an
    SC-TRUNCATED finding, so it can never pass the gate.

    A target that is missing or can't be listed is a tool error (ValueError);
    one with nothing Lazaret can scan (only Go or Markdown files, or none) is
    "incomplete" with an SC-TRUNCATED finding — never a clean pass."""
    ctx = ctx or _ctx()
    exclude = list(exclude or [])
    _check_scan_target(path)
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
    except lazaret.ScanTargetError as exc:
        _check_scan_target(path)         # it vanished or became unreadable meanwhile
        # Nothing to scan: the CLI exits 2 ("usage error"). For a tool caller
        # "no findings" would read as "checked and clean", so the result is
        # incomplete and fails the gate.
        reason = str(exc)
        res = lazaret.build_result(path, [], [lazaret.truncated_issue(
            ".", f"directory not scanned: {reason}")])
        res.update(incomplete=True, incompleteReason=reason, warnings=[])
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
# The same cap as lazaret.collect_files (core.SOURCE_SIZE_CAP, read when a
# call runs), and the same verdict-integrity rule: a file that was not scanned
# must leave a signal (SC-TRUNCATED, CRITICAL), never a silent skip.


def _not_a_regular_file(mode):
    if stat.S_ISDIR(mode):
        return "it is a directory, not a regular file"
    kind = lazaret._special_kind(mode)
    return "it is not a regular file" if kind == "not a regular file" else \
        f"it is {kind}, not a regular file"


def tool_scan_files(args):
    ctx = _ctx()
    paths = args.get("paths")
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        raise ValueError("paths must be an array of strings")
    for p in paths:                      # every path is checked before any is read
        ctx.check_path(p)
    out, all_issues, files = {}, [], []
    read_bytes, stopped, unread = 0, None, 0

    def not_read(p, detail):
        # a file that is there but could not be read was not scanned: an
        # SC-TRUNCATED finding (like an oversized file's), and the call is
        # incomplete — "0 issues" must not stand in for "not looked at"
        nonlocal unread
        unread += 1
        ti = lazaret.truncated_issue(p, detail)
        all_issues.append(ti)
        out[p] = {"error": ti["msg"], "rule": ti["rule"], "sev": ti["sev"]}

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
        try:
            st = os.stat(p)
        except (FileNotFoundError, NotADirectoryError):
            out[p] = {"error": "File not found"}
            continue
        except OSError as exc:
            not_read(p, f"cannot stat the file ({exc.strerror or type(exc).__name__})")
            continue
        if not stat.S_ISREG(st.st_mode):
            not_read(p, _not_a_regular_file(st.st_mode))
            continue
        size = st.st_size
        cap = lazaret.SOURCE_SIZE_CAP
        if size > cap:
            ti = lazaret.truncated_issue(p, f"{size:,} bytes exceeds the {cap:,}-byte file limit")
            all_issues.append(ti)
            out[p] = {"error": ti["msg"], "rule": ti["rule"], "sev": ti["sev"]}
            continue
        # bounded read: read cap+1 so a file that GREW between stat and read
        # (TOCTOU) is still caught, then falls into the truncation path. The
        # symlinks were resolved (and checked against the roots) already;
        # _read_prefix opens with O_NONBLOCK and refuses anything but a
        # regular file, so a FIFO swapped in after the stat can't hang the call.
        try:
            data = lazaret._read_prefix(os.path.realpath(p), cap + 1)
        except OSError as exc:
            reason = (str(exc) if isinstance(exc, lazaret._NotRegularFile)
                      else exc.strerror or type(exc).__name__)
            not_read(p, f"cannot read the file ({reason})")
            continue
        if len(data) > cap:
            ti = lazaret.truncated_issue(p, f"read exceeded the {cap:,}-byte file limit")
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
    reasons = ([f"{unread} of {len(paths)} file(s) could not be read"] if unread else []) \
        + ([stopped] if stopped else [])
    if reasons:
        summary["incomplete"] = True
        summary["incompleteReason"] = "; ".join(reasons)
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
    with lazaret_repo.Store(REGISTRY_DB) as store:
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
    with lazaret_repo.Store(REGISTRY_DB) as store:
        status = store.status()
    rows = []
    for eco, name, ver, profile, at, verdict, n, supply in status:
        rows.append({"package": f"{eco}:{name}", "lastVersion": ver, "lastScan": at,
                     "verdict": verdict, "issues": n, "supplyChain": supply})
    return {"tracked": len(rows), "packages": rows}


DISCOVER_ECOSYSTEMS = ("pypi", "npm")


def _discover_ecosystems(value):
    """The registries a discover_packages call asked for, validated: a list
    drawn from DISCOVER_ECOSYSTEMS (missing or [] = both). Anything else is
    a tool error — ["PyPI"] used to query nothing and answer "0 packages",
    and a plain "npm" was iterated character by character."""
    if value is None or value == []:
        return list(DISCOVER_ECOSYSTEMS)
    if not isinstance(value, list) or not all(isinstance(e, str) for e in value) \
            or not set(value) <= set(DISCOVER_ECOSYSTEMS):
        raise ValueError("ecosystem must be an array drawn from "
                         + ", ".join(f'"{e}"' for e in DISCOVER_ECOSYSTEMS)
                         + f" (got {json.dumps(value)[:80]})")
    return [e for e in DISCOVER_ECOSYSTEMS if e in value]


def _discover_limit(value):
    if value is None:
        return 25
    try:
        if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
            raise ValueError
        limit = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("limit must be an integer") from None
    if limit < 1:
        raise ValueError("limit must be at least 1")
    return min(limit, 50)


def tool_discover_packages(args):
    if lazaret_repo is None:
        raise ValueError("Registry scanning unavailable (lazaret.registry not importable).")
    ctx = _ctx()
    since = args.get("since") or "7d"
    if not isinstance(since, str):
        raise ValueError("since must be a string like 7d, 2w, 24h or an ISO date")
    cutoff = lazaret_repo.parse_since(since)
    ecos = _discover_ecosystems(args.get("ecosystem"))
    limit = _discover_limit(args.get("limit"))
    discovered, notes = [], {}
    # The registry walks themselves can't be interrupted from here; the call's
    # cancel flag and deadline are honoured before each one.
    for eco in ecos:
        ctx.check()
        if ctx.expired():
            notes[eco] = (f"not checked: time budget of {ctx.max_seconds:g} s "
                          f"(LAZARET_MCP_MAX_SECONDS) exceeded")
            continue
        find = lazaret_repo.discover_pypi if eco == "pypi" else lazaret_repo.discover_npm
        discovered += find(cutoff, limit, notes)
    ctx.check()
    discovered.sort(key=lambda x: x[3], reverse=True)
    discovered = discovered[:limit]
    out = {"since": cutoff.isoformat(), "count": len(discovered),
           "packages": [{"ecosystem": e, "name": n, "version": v, "when": w.isoformat()}
                        for e, n, v, w in discovered]}
    # a registry that could not be (fully) checked makes the call incomplete:
    # "0 packages" must not read as "nothing new was published"
    gaps = [f"{e} {notes[e]}" for e in ecos if e in notes]
    if gaps:
        out["incomplete"] = True
        out["incompleteReason"] = "; ".join(gaps)
    if args.get("scan"):
        with lazaret_repo.Store(REGISTRY_DB) as store:
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
            out["incompleteReason"] = "; ".join(gaps + reasons)
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


# How long a path tool waits for the client's answer to roots/list.
ROOTS_WAIT_SECONDS = 10.0
# Most roots one roots/list answer may name.
MAX_CLIENT_ROOTS = 1000


class Server:
    """Reader loop on the main thread, tool calls on one worker thread.

    The reader answers initialize / ping / tools/list itself and queues
    tools/call, so a long scan never blocks ping, and notifications/cancelled
    reaches the running call (its cancel flag is checked between files). Per
    MCP, a cancelled request gets no response.

    Allowed roots (audit I1). A tool that takes a path (scan_directory,
    scan_files, quality_gate) may read only inside:
      1. LAZARET_MCP_ROOTS, when it is set;
      2. otherwise the roots the client shares, when it declares the MCP
         `roots` capability: the server asks with roots/list after
         notifications/initialized (or at the first path it checks), asks
         again on notifications/roots/list_changed, and a call waits up to
         ROOTS_WAIT_SECONDS for the answer;
      3. otherwise nothing: the call is a tool error that says how to allow
         a directory.
    The server never reads an unrestricted filesystem on an agent's behalf.
    Roots is deprecated as of MCP 2026-07-28 (SEP-2577, kept for at least
    12 months) in favour of server configuration, i.e. LAZARET_MCP_ROOTS;
    this server negotiates 2025-11-25 and earlier, where it is current."""

    def __init__(self):
        self.jobs = queue.Queue()
        self.lock = threading.Lock()
        self.pending = {}                       # id key -> cancel Event
        # the client's roots (all guarded by roots_lock)
        self.roots_lock = threading.Lock()
        self.client_roots_supported = False     # declared `roots` at initialize
        self.client_roots = None                # latest answer: real paths; None = none yet
        self.client_roots_error = None          # why the latest answer allows nothing
        self.roots_request_id = None            # roots/list awaiting its answer
        self.roots_ready = threading.Event()    # set once the latest request is answered
        self.roots_overdue = False              # a call already waited the full time for it
        self.roots_seq = 0
        self.worker = threading.Thread(target=self._work, name="lazaret-mcp-tools",
                                       daemon=True)
        self.worker.start()

    # ---- the client's roots ----
    def client_initialized(self, params):
        """initialize: note whether the client shares roots (a fresh
        handshake forgets any earlier answer)."""
        caps = params.get("capabilities")
        with self.roots_lock:
            self.client_roots_supported = isinstance(caps, dict) and \
                isinstance(caps.get("roots"), dict)
            self.client_roots = self.client_roots_error = self.roots_request_id = None
            self.roots_ready.clear()
            self.roots_overdue = False

    def roots_wanted(self):
        """True when the answer to roots/list would decide anything."""
        return self.client_roots_supported and os.environ.get("LAZARET_MCP_ROOTS") is None

    def request_roots(self):
        """Ask the client for its roots (roots/list). The answer arrives on
        the reader thread (response()); until then a path tool waits."""
        with self.roots_lock:
            self.roots_seq += 1
            self.roots_request_id = f"lazaret-roots-{self.roots_seq}"
            self.roots_ready.clear()
            self.roots_overdue = False
            msg = {"jsonrpc": "2.0", "id": self.roots_request_id, "method": "roots/list"}
        stream = _OUT if _OUT is not None else sys.stdout
        try:
            with _WRITE_LOCK:
                stream.write(json.dumps(msg) + "\n")
                stream.flush()
        except (OSError, ValueError):           # the client has gone: calls time out
            pass

    def response(self, frame):
        """A response to a request this server sent. Only the answer to the
        latest roots/list counts; anything else is ignored. A response is
        never answered."""
        with self.roots_lock:
            if self.roots_request_id is None or frame.get("id") != self.roots_request_id:
                return
            self.roots_request_id = None
            result = frame.get("result")
            roots = result.get("roots") if isinstance(result, dict) else None
            if "error" in frame or not isinstance(roots, list):
                self.client_roots = []
                self.client_roots_error = ("LAZARET_MCP_ROOTS is not set and the MCP client "
                                           "answered roots/list with an error.")
            else:
                paths = []
                for root in roots[:MAX_CLIENT_ROOTS]:
                    path = root_path_of_uri(root.get("uri") if isinstance(root, dict) else None)
                    if path is not None and path not in paths:
                        paths.append(path)
                self.client_roots = paths
                self.client_roots_error = None if paths else (
                    "LAZARET_MCP_ROOTS is not set and the MCP client shared no file: roots.")
            self.roots_ready.set()

    def resolve_roots(self, ctx):
        """The roots one tool call may use when LAZARET_MCP_ROOTS is unset (the
        ToolContext resolver): the client's latest answer, or a RootsRefused.
        Waits for an answer that is on its way; once one call has waited the
        full time in vain, later calls stop waiting until the client answers
        or its roots change."""
        with self.roots_lock:
            if not self.client_roots_supported:
                return RootsRefused("LAZARET_MCP_ROOTS is not set and the MCP client does not "
                                    "share its workspace roots.")
            ask = self.client_roots is None and self.roots_request_id is None
            wait = not self.roots_overdue
        if ask:                                  # no notifications/initialized came
            self.request_roots()
        if wait:
            deadline = time.monotonic() + ROOTS_WAIT_SECONDS
            while not self.roots_ready.wait(0.05):
                ctx.check()                      # a cancelled call stops waiting
                if time.monotonic() >= deadline:
                    break
        with self.roots_lock:
            if not self.roots_ready.is_set():
                self.roots_overdue = True
                return RootsRefused("LAZARET_MCP_ROOTS is not set and the MCP client did not "
                                    f"answer roots/list within {ROOTS_WAIT_SECONDS:g} s.")
            if not self.client_roots:
                return RootsRefused(self.client_roots_error)
            return list(self.client_roots)

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
                try:
                    # a misconfigured LAZARET_MCP_ROOTS is a tool error for every
                    # tool (ToolContext raises), never an unrestricted call
                    _LOCAL.ctx = ToolContext(event, roots_resolver=self.resolve_roots)
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
        if isinstance(req, dict) and "method" not in req and ("result" in req or "error" in req):
            self.response(req)          # the client answering roots/list: never replied to
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
        elif method in ("notifications/initialized", "notifications/roots/list_changed"):
            if self.roots_wanted():
                self.request_roots()

    def request(self, method, msg_id, params):
        if method == "initialize":
            # params is a validated dict here — the `{"method":"initialize",
            # "params":null}` frame of the G5 PoC used to crash on
            # params.get(...) BEFORE any try block.
            self.client_initialized(params)
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
    try:
        allowed_roots()
    except ValueError as exc:   # every tool call will be refused; say so up front
        print(f"lazaret-mcp: {exc}", file=sys.stderr)
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
