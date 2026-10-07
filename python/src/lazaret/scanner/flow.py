#!/usr/bin/env python3
"""Lazaret interprocedural taint analysis (cross-function, cross-file).

The per-file scanner (the engine's intra-file taint, core.taint_scan) tracks
taint within a single function. This module adds *whole-program* analysis: it follows untrusted data
through function calls and across files, so a source in one module that flows
into a sink in another is caught.

Approach — function summaries + a worklist fixpoint (the standard scalable
technique):

  1. Parse every file (a file the parser rejects is skipped with an INFO
     note; it never costs the rest of the pass). Every function, method,
     nested def and each module's top-level code (as a pseudo-function, so
     scripts and `if __name__ == "__main__":` blocks count) gets a summary:
        param_to_sink   : parameter -> {sink category: sink location}
        param_to_return : parameter -> categories it is sanitized for when
                          it flows into the return value
        ret_source      : a taint source the function returns (and its origin)
  2. Calls are resolved through imports, classes and self (see "Resolution
     model" below) and arguments are bound like inspect.signature. Summaries
     are iterated to a fixpoint callee-first, re-analyzing a function only
     when something it depends on changed (a generous cap reports itself).
  3. On the final pass, wherever a concrete taint *source* reaches a sink —
     by being passed into a function whose parameter reaches a sink, or by
     being returned from another function straight into a sink — emit an
     X-* finding naming the source and sink locations (possibly different
     files).

Both languages' passes are the engine's, on its own parsers' trees, within
work budgets per syntax tree node (docs/RUST_ENGINE.md): Python's
(rust/crates/lazaret-engine/src/pyflow/, the `py_flow` call; until phase 3
of the Rust-first refactor it was this module's own pass on Python's ast,
which the port was held to output for output) and JavaScript's and
TypeScript's (jsflow/, the `js_flow` call: the same approach with scopes
and bindings, the functions a call can reach, route handlers and the
values variables and objects hold). This module hands them the files and
the configured part of the model and builds the findings; the npm package
runs the same passes and builds the same findings (js/src/scanner/flow.js).

Public entry point: analyze(files) -> list[issue dict] (never raises)
  files: iterable of {"path": str, "content": str, "lang": "py"|"js"}
"""
import re
import sys

from lazaret.scanner import engine
from lazaret.scanner import taintspec

# ---------------- terminal-control neutralizer (audit H1) ----------------
# lazaret.sanitize_term is the canonical copy; lazaret_flow is imported
# BY lazaret, so it keeps a byte-identical local duplicate rather than
# importing it (no import cycle). test_terminal_sanitize.py asserts the two
# agree on a hostile matrix. Mapped set: every C0 control byte except TAB
# (0x09) and LF (0x0a), plus CR (0x0d), DEL (0x7f), the C1 controls
# U+0080–U+009F and the bidi controls U+202A–U+202E, U+2066–U+2069 — ESC/BEL,
# the two bytes of the audit PoC, are inside these ranges.
_SANITIZE_TERM_CHARS = (
    "".join(chr(n) for n in range(0x00, 0x09))      # NUL … BS
    + "".join(chr(n) for n in (0x0b, 0x0c))         # VT, FF
    + "".join(chr(n) for n in range(0x0d, 0x20))    # CR, SO … US (incl. ESC)
    + "".join(chr(n) for n in range(0x7f, 0xa0))    # DEL, C1 controls (incl. CSI)
    + "".join(chr(n) for n in range(0x202a, 0x202f))  # bidi LRE RLE PDF LRO RLO
    + "".join(chr(n) for n in range(0x2066, 0x206a))  # bidi LRI RLI FSI PDI
)
_SANITIZE_TERM_TAB = str.maketrans(
    {ch: "·" for ch in _SANITIZE_TERM_CHARS})


def sanitize_term(s):
    """Local twin of lazaret.sanitize_term — see the note above."""
    return str(s).translate(_SANITIZE_TERM_TAB)

# ---------------- sink / source models (shared vocabulary) ----------------
# category -> (severity, cwe, fix)
SINK_META = {
    "SQL injection": ("BLOCKER", "CWE-89", "Use parameterized queries with placeholders."),
    "command injection": ("CRITICAL", "CWE-78", "Pass args as a list with shell=False / use execFile."),
    "code injection": ("CRITICAL", "CWE-95", "Never execute untrusted strings; use safe parsing."),
    "template injection": ("CRITICAL", "CWE-1336", "Pass data as template parameters, not template source."),
    "path traversal": ("MAJOR", "CWE-22", "Resolve and confine the path to an allowed base directory."),
    "server-side request forgery": ("MAJOR", "CWE-918", "Allowlist hosts/schemes; block internal addresses."),
    "open redirect": ("MAJOR", "CWE-601", "Allowlist redirect targets or use relative paths."),
    "cross-site scripting": ("MAJOR", "CWE-79", "Escape/sanitize before rendering; prefer textContent."),
}
CAT_SUFFIX = {
    "SQL injection": "SQL", "command injection": "CMD", "code injection": "CODE",
    "template injection": "SSTI", "path traversal": "PATH",
    "server-side request forgery": "SSRF", "open redirect": "REDIR",
    "cross-site scripting": "XSS",
}
ALL_CATS = frozenset(SINK_META)   # every sink category

# ---------------- Sanitizer model (SonarQube / Semgrep style) ----------------
# A sanitizer neutralizes taint. "full" sanitizers (numeric coercion, strict
# validation) make a value safe for every sink category; "partial" sanitizers
# clear specific categories (html.escape → XSS only, shlex.quote → command only).
# This is what stops parameterized/validated values being reported — the primary
# false-positive source in taint analysis. The built-in models are the
# engine's (pyflow/mod.rs, jsflow/); these hold the Python model's full
# sanitizers (the built-in ones, and those configure() adds) and its
# configured partial ones.
FULL_SANITIZERS_PY = {"int", "float", "bool", "complex", "uuid.UUID", "UUID",
                      "ipaddress.ip_address", "ip_address"}
_EXTRA_PARTIAL_PY = {}        # configured partial sanitizers: call name -> set(categories)


def _issue(cat, caller_file, line, lines, source_loc, sink_loc, chain):
    sev, cwe, fix = SINK_META[cat]
    start = max(0, line - 3)
    cross = source_loc.split(":")[0] != sink_loc.split(":")[0]
    scope = "cross-file" if cross else "interprocedural"
    return {
        "rule": f"X-{CAT_SUFFIX[cat]}", "name": f"{scope.capitalize()} tainted flow → {cat}",
        "type": "VULN", "sev": sev,
        "msg": f"Possible {cat}: untrusted data from {source_loc} reaches a sink at "
               f"{sink_loc} ({scope}).",
        "why": "Whole-program taint tracking followed user-controlled input from its "
               "source through " + (chain or "a function call") + " into a dangerous "
               "operation, without visible sanitization along the way.",
        "fix": fix, "ref": f"{cwe} · Interprocedural taint",
        "file": caller_file, "line": line,
        "snippet": lines[start:min(len(lines), line + 2)], "snipStart": start + 1,
    }


# ======================================================================
# Python — the engine's pass (rust/crates/lazaret-engine/src/pyflow/)
# ======================================================================
#
# Resolution model (review finding 10): a call is matched only against the
# function it can actually name —
#   f()           a module-level function defined in, or imported into, the
#                 calling module (`from m import f as g`, `import m; m.f()`,
#                 relative imports, re-exports, star imports), a nested def,
#                 or a class constructor (its __init__); a bare name that is
#                 neither defined, imported nor a builtin falls back to the
#                 project's only module-level function of that name;
#   self.m()      methods of the enclosing class and its project bases;
#   C().m(), x.m() with x = C(...), C.m(), super().m()   methods of C;
#   obj.m()       unknown receiver: the project's methods named m, only when
#                 there are at most 4 of them (pyflow's MAX_DUCK) and m is
#                 not a builtin/dict/str/file-like name (get, open, run, …).
# Anything else is an external call: it propagates taint from its arguments
# (and receiver) to its return value, unless it is a sanitizer or returns a
# non-string value (len, isinstance, …).
#
# Sources, sinks and sanitizers are the engine's built-in model (pyflow/
# mod.rs) and its configured part, handed to the engine at each analysis.

MAX_ITERS = 50                 # re-analyses of one function before cutoff
FLOW_MAX_FILES = 20_000        # Python files analyzed per run
FLOW_MAX_BYTES = 64_000_000    # Python source characters analyzed per run
_BUILTIN_FULL_PY = frozenset(FULL_SANITIZERS_PY)   # before any configure()
_PY_SOURCE_EXTRA = []          # configured sources: guarded patterns (taintspec)
_EXTRA_PY_SINKS = []           # configured sinks: (guarded pattern, category)
_PY_WORK_LIMIT = None          # (base, steps per node): a lower budget for the fixpoint


def _flow_note(rule, name, fname, line, msg, why, fix):
    return {"rule": rule, "name": name, "type": "SMELL", "sev": "INFO",
            "msg": msg, "why": why, "fix": fix,
            "ref": "CWE-400 (uncontrolled resource consumption)" if rule == "Q-FLOW-RECURSION"
                   else "Analysis coverage",
            "file": fname, "line": line, "snippet": [], "snipStart": 1}


def _analyze_python(files, findings, work_limit=None):
    """The engine's pass over the Python files of `files`. The limits above
    reach it as lower ones (a test can lower MAX_ITERS, FLOW_MAX_FILES or
    FLOW_MAX_BYTES), and `work_limit` (or _PY_WORK_LIMIT), (base, steps per
    node), lowers the fixpoint's budget."""
    py_files = [f for f in files if f.get("lang") == "py"]
    if not py_files:
        return
    outs = engine.py_flow(py_files, _PY_SOURCE_EXTRA, _EXTRA_PY_SINKS, FULL_SANITIZERS_PY - _BUILTIN_FULL_PY,
                          _EXTRA_PARTIAL_PY, max_iters=MAX_ITERS, max_files=FLOW_MAX_FILES,
                          max_bytes=FLOW_MAX_BYTES, work_limit=work_limit or _PY_WORK_LIMIT)
    lines = {}                        # a file's lines (by its index), for the snippets
    for out in outs:
        if out[0] == "issue":
            _, cat, path, line, source, sink, chain, k = out
            if k not in lines:
                lines[k] = py_files[k]["content"].split("\n")
            findings.append(_issue(cat, path, line, lines[k], source, sink, chain))
        else:
            findings.append(_flow_note(*out[1:]))


# ======================================================================
# JavaScript — the engine's pass (rust/crates/lazaret-engine/src/jsflow/)
# ======================================================================
# The configured part of the JavaScript model (configure()), handed to the
# engine at each analysis.
_JS_SOURCES = []                      # configured sources: guarded patterns (taintspec)
_JS_SINKS = []                        # configured sinks: (guarded pattern, category)
_JS_FULL_SAN = set()                  # configured full sanitizers (call names)
_JS_PARTIAL_SAN = {}                  # configured partial sanitizers: call name -> set(categories)
_JS_RUN_LIMIT = None                  # (base, steps per node): a lower limit for one function's reading
_JS_LINES_RE = re.compile(r"\r\n|[\n\r\u2028\u2029]")    # JavaScript's line terminators


def _skipped_size(path, n, limit):
    """X-FLOW-SKIPPED: a file over the pass's size limit (code points)."""
    return {"rule": "X-FLOW-SKIPPED", "name": "JS flow analysis skipped (size)",
            "type": "HOTSPOT", "sev": "INFO",
            "msg": f"{path} is {n} characters; interprocedural JS taint analysis is skipped above {limit} "
                   f"characters.",
            "why": "Reading a file this large (usually minified or machine-generated) would cost the "
                   "cross-file pass more time and memory than a scan should spend on one file.",
            "fix": "Split or deminify the file, or exclude it from the scan explicitly if the code is generated.",
            "ref": "Scalability", "file": path, "line": 1, "snippet": [], "snipStart": 1}


def _analyze_js(files, findings):
    js_files = [f for f in files if f.get("lang") == "js"]
    if not js_files:
        return
    outs = engine.js_flow(js_files, _JS_SOURCES, _JS_SINKS, _JS_FULL_SAN, _JS_PARTIAL_SAN, _JS_RUN_LIMIT)
    lines = {}                        # a file's lines (by its index), for the snippets
    for out in outs:
        if out[0] == "skipped_size":
            findings.append(_skipped_size(out[1], out[2], out[3]))
        elif out[0] == "issue":
            _, cat, path, line, source, sink, chain, k = out
            if k not in lines:
                lines[k] = _JS_LINES_RE.split(js_files[k]["content"])
            findings.append(_issue(cat, path, line, lines[k], source, sink, chain))
        else:
            findings.append(_flow_note(*out[1:]))


# ======================================================================
# Configurable taint spec (Semgrep-style): add custom sources / sinks /
# sanitizers without editing the engine. See load_config() for the file format.
# ======================================================================
def configure(cfg, on_warn=None, allow_sanitizers=True):
    """Extend the taint model from a config: a parsed config dict (validated
    here) or a taintspec.TaintSpec the caller already validated. Sections
    'python' and 'javascript', each with optional 'sources' (regex list),
    'sinks' ([{pattern, category}]) and 'sanitizers' ({full: [...],
    partial: {name: [cats]}}).

    Validation is shared with the intra-file engine (lazaret.scanner.
    taintspec): every field is type-checked, user regexes are guarded
    (length cap, static backtracking check, bounded match text), and every
    rejection is reported through on_warn(msg) — a custom sink cannot quietly
    become inert while the scan still reports PASSED. allow_sanitizers=False
    (a config from the scanned repository) ignores its sanitizers with a
    note. Never raises on config content."""
    spec = (cfg if isinstance(cfg, taintspec.TaintSpec)
            else taintspec.validate(cfg, allow_sanitizers=allow_sanitizers))
    if callable(on_warn):
        for msg in spec.warnings + spec.notes:
            on_warn(msg)
    py = spec.python
    _PY_SOURCE_EXTRA.extend(py.sources)
    _EXTRA_PY_SINKS.extend(py.sinks)
    FULL_SANITIZERS_PY.update(py.full)
    for name, cats in py.partial.items():
        _EXTRA_PARTIAL_PY[name] = set(_EXTRA_PARTIAL_PY.get(name, ())) | set(cats)
    js = spec.javascript
    _JS_SOURCES.extend(js.sources)
    _JS_SINKS.extend(js.sinks)
    _JS_FULL_SAN.update(js.full)
    for name, cats in js.partial.items():
        _JS_PARTIAL_SAN[name] = set(_JS_PARTIAL_SAN.get(name, ())) | set(cats)


def load_config(path, allow_sanitizers=True):
    """Load a JSON taint-config file and apply it. Returns True if applied.
    Rejected rules are reported to stderr (see configure())."""
    warnings = []
    applied = load_config_quietly(path, warnings, allow_sanitizers=allow_sanitizers)
    for msg in warnings:
        # audit H1: `path` may be repository content; `msg` embeds
        # rejected-rule names/patterns from it. Sanitized via the local twin.
        print(f"warning: {sanitize_term(path)}: {sanitize_term(msg)}",
              file=sys.stderr)
    return applied


_CONFIG_MAX_BYTES = 1_000_000


def load_config_quietly(path, warnings_out=None, allow_sanitizers=True):
    """Load a JSON taint-config file and apply it, collecting validation
    warnings in warnings_out (list) instead of printing them. Returns True if
    applied. A failed read/parse (unreadable, too large, bad UTF-8, invalid
    JSON, deep nesting) returns False with a single message."""
    # the explicit depth limit shared with the CLI's loader (imported here:
    # core imports this module at load time)
    from lazaret.scanner.core import json_loads_bounded
    if warnings_out is None:
        warnings_out = []
    try:
        with open(path, "rb") as fh:
            data = fh.read(_CONFIG_MAX_BYTES + 1)
        if len(data) > _CONFIG_MAX_BYTES:
            raise ValueError(f"file exceeds {_CONFIG_MAX_BYTES} bytes")
        cfg = json_loads_bounded(data.decode("utf-8"))
    except (OSError, ValueError, MemoryError) as exc:
        # 1149e3e5: a deep-nested config (~60KB of '[') is JsonTooDeep, a
        # ValueError like bad UTF-8, invalid JSON and the int-digit limit.
        # Same warn-and-skip contract as an unreadable file.
        warnings_out.append(f"could not load taint config {path}: {exc}")
        return False
    configure(cfg, on_warn=warnings_out.append, allow_sanitizers=allow_sanitizers)
    return True


# ======================================================================
def analyze(files):
    """Return interprocedural/cross-file taint findings for the file set.

    Never raises (finding 6): a file the parser rejects costs only that file
    (a Q-FLOW-SKIPPED / Q-FLOW-RECURSION INFO note names it), and an
    unexpected internal error ends the pass with a Q-FLOW-INCOMPLETE note
    instead of an exception — the CLI, MCP run_project_scan and registry
    --full callers all get results plus notes."""
    findings = []
    try:
        files = [f for f in files if isinstance(f, dict)
                 and f.get("lang") in ("py", "js") and not f.get("dep")
                 and isinstance(f.get("path"), str)]
    except Exception:                              # not even iterable
        files = []
    for run, lang in ((_analyze_python, "py"), (_analyze_js, "js")):
        try:
            run(files, findings)
        except Exception as exc:                   # never drop the whole scan
            first = next((f["path"] for f in files if f.get("lang") == lang), "?")
            findings.append(_flow_note(
                "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (internal error)",
                first, 1,
                f"The {'Python' if lang == 'py' else 'JavaScript'} cross-file taint "
                f"pass stopped on an internal error ({type(exc).__name__}); "
                f"findings it had already produced are kept.",
                "An unexpected input made the interprocedural engine fail; the "
                "rest of the scan is unaffected.",
                "Please report the file that triggers this to the Lazaret "
                "maintainers."))
    # dedupe by (rule, file, line, message)
    seen, unique = set(), []
    for i in sorted(findings, key=lambda x: (str(x["file"]), x["line"])):
        key = (i["rule"], i["file"], i["line"], i["msg"])
        if key not in seen:
            seen.add(key)
            unique.append(i)
    return unique
