#!/usr/bin/env python3
"""Lazaret interprocedural taint analysis (cross-function, cross-file).

The per-file scanner (lazaret.taint_scan) tracks taint within a single
function. This module adds *whole-program* analysis: it follows untrusted data
through function calls and across files, so a source in one module that flows
into a sink in another is caught.

Approach — function summaries + a bounded fixpoint (the standard scalable
technique):

  1. Parse every file. For each user-defined function compute a summary:
        param_to_sink   : parameter -> the dangerous sink its value reaches
        param_to_return : parameters whose value flows into the return value
        returns_source  : the function returns data derived from a taint source
  2. Iterate to a fixpoint so summaries compose transitively (f calls g calls
     a sink; g returns tainted data that f then passes to a sink; etc.).
  3. On the final pass, wherever a concrete taint *source* reaches a sink —
     directly, through a returned-tainted call, or by being passed into a
     function whose parameter reaches a sink — emit an X-FLOW finding naming
     the source and sink locations (which may be in different files).

Python analysis is AST-based (accurate, stdlib only). JavaScript uses a
bounded regex/brace heuristic (no JS parser available without dependencies),
so JS results are best-effort and intentionally conservative.

Public entry point: analyze(files) -> list[issue dict]
  files: iterable of {"path": str, "content": str, "lang": "py"|"js"}
"""
import ast
import bisect
import json
import os
import re
import sys

MAX_ITERS = 6  # fixpoint safety bound

# ---------------- terminal-control neutralizer (audit H1) ----------------
# lazaret.sanitize_term is the canonical copy; lazaret_flow is imported
# BY lazaret, so it keeps a byte-identical local duplicate rather than
# importing it (no import cycle). test_terminal_sanitize.py asserts the two
# agree on a hostile matrix. Mapped set: every C0 control byte except TAB
# (0x09) and LF (0x0a), plus CR (0x0d) and DEL (0x7f) — ESC/BEL, the two
# bytes of the audit PoC, are inside these ranges.
_SANITIZE_TERM_CHARS = (
    "".join(chr(n) for n in range(0x00, 0x09))      # NUL … BS
    + "".join(chr(n) for n in (0x0b, 0x0c))         # VT, FF
    + "".join(chr(n) for n in range(0x0d, 0x20))    # CR, SO … US (incl. ESC)
    + chr(0x7f)                                     # DEL
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
# false-positive source in taint analysis.
FULL_SANITIZERS_PY = {"int", "float", "bool", "complex", "uuid.UUID", "UUID",
                      "ipaddress.ip_address", "ip_address"}
PARTIAL_SANITIZERS_PY = {
    "shlex.quote": {"command injection"},
    "pipes.quote": {"command injection"},
    "html.escape": {"cross-site scripting"},
    "cgi.escape": {"cross-site scripting"},
    "markupsafe.escape": {"cross-site scripting"},
    "escape": {"cross-site scripting"},              # from markupsafe/html import escape
    "bleach.clean": {"cross-site scripting"},
    "os.path.basename": {"path traversal"},
    "basename": {"path traversal"},
    "secure_filename": {"path traversal"},           # werkzeug
}
# Runtime-extensible via load config (see configure()).
_EXTRA_PARTIAL_PY = {}

def _py_sanitizer(callee):
    """Return 'full', a set of neutralized categories, or None."""
    last = callee.split(".")[-1]
    if callee in FULL_SANITIZERS_PY or last in FULL_SANITIZERS_PY:
        return "full"
    for table in (PARTIAL_SANITIZERS_PY, _EXTRA_PARTIAL_PY):
        if callee in table:
            return table[callee]
        if last in table:
            return table[last]
    return None


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
# Python — AST based
# ======================================================================
def _dotted(node):
    """Best-effort dotted string for a Name/Attribute/Call/Subscript expr."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted(node.value) + "." + node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    return ""


_PY_SOURCE_RE = re.compile(
    r"\brequest\.(args|form|values|json|data|cookies|headers|files)\b"
    r"|\brequest\.get_json\b|\bsys\.argv\b|\bflask\.request\b")
_PY_SOURCE_EXTRA = []    # extra compiled source patterns (from config)
_EXTRA_PY_SINKS = []     # (compiled_pattern, category) from config

def _is_py_source(s):
    return bool(_PY_SOURCE_RE.search(s)) or any(p.search(s) for p in _PY_SOURCE_EXTRA)


def _py_sink(callee):
    for pat, cat in _EXTRA_PY_SINKS:      # configured sinks take precedence
        if pat.search(callee):
            return cat
    last = callee.split(".")[-1]
    if last in ("execute", "executemany"):
        return "SQL injection"
    if callee in ("os.system", "os.popen"):
        return "command injection"
    if callee.startswith("subprocess.") and last in (
            "run", "call", "check_output", "check_call", "Popen"):
        return "command injection"
    if callee in ("eval", "exec"):
        return "code injection"
    if last == "render_template_string":
        return "template injection"
    if callee == "open" or last in ("send_file", "send_from_directory"):
        return "path traversal"
    if last == "urlopen" or (callee.startswith("requests.") and last in (
            "get", "post", "put", "delete", "head", "request")):
        return "server-side request forgery"
    if last == "redirect":
        return "open redirect"
    return None


class _Taint:
    __slots__ = ("source", "params", "clean")

    def __init__(self, source=False, params=None, clean=()):
        self.source = source
        self.params = set(params or ())
        self.clean = frozenset(clean)   # sink categories this value is safe for

    def union(self, other):
        # concatenation is safe for a category only if BOTH parts are safe for it
        return _Taint(self.source or other.source, self.params | other.params,
                      self.clean & other.clean)

    def tainted(self):
        return self.source or bool(self.params)

    def effective(self, cat):
        """Is this value still dangerous for sink category cat (not sanitized)?"""
        return self.tainted() and cat not in self.clean

    def sanitize(self, cats):
        return _Taint(self.source, self.params, self.clean | set(cats))


EMPTY = _Taint(clean=ALL_CATS)   # not tainted, safe for everything


class _PyFunc:
    def __init__(self, name, file, node, lines):
        self.name = name
        self.file = file
        self.node = node
        self.lines = lines
        self.params = [a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs]
        if node.args.vararg:
            self.params.append(node.args.vararg.arg)
        # summaries
        self.param_to_sink = {}      # param -> category
        self.param_to_return = set()
        self.returns_source = False


def _collect_py(files, overflow=None):
    funcs = {}   # name -> list[_PyFunc]
    for f in files:
        if f["lang"] != "py":
            continue
        try:
            tree = ast.parse(f["content"])
        except SyntaxError:
            continue
        except RecursionError:
            # A deep operator chain can overflow the *parser* itself: on
            # Python 3.11, and on Windows (smaller C stack) even on later
            # versions. Skip the file and report it like an analysis overflow,
            # instead of letting one file abort the whole flow pass.
            if overflow is not None:
                overflow[f["path"]] = 1
            continue
        lines = f["content"].split("\n")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.setdefault(node.name, []).append(_PyFunc(node.name, f["path"], node, lines))
    return funcs


def _py_expr_taint(expr, env, funcs):
    """Taint of an expression given the current variable env."""
    if expr is None:
        return EMPTY
    if isinstance(expr, ast.Name):
        return env.get(expr.id, EMPTY)
    # M16/F12: ast.Num/ast.Str (and ast.Bytes/ast.NameConstant) were removed in
    # Python 3.12 — referencing them raises AttributeError, which crashed the
    # scanner on the first non-ast.Name expression in any function body on
    # 3.12+. All literals are ast.Constant since 3.8 (PEP 612/628); the
    # deprecated aliases were equivalent to Constant, so this drops nothing.
    # (Full ast.X inventory re-checked: this was the only occurrence.)
    if isinstance(expr, ast.Constant):
        return EMPTY
    if isinstance(expr, (ast.BinOp, ast.BoolOp)):
        vals = expr.values if isinstance(expr, ast.BoolOp) else [expr.left, expr.right]
        t = EMPTY
        for v in vals:
            t = t.union(_py_expr_taint(v, env, funcs))
        return t
    if isinstance(expr, ast.JoinedStr):  # f-string
        t = EMPTY
        for v in expr.values:
            if isinstance(v, ast.FormattedValue):
                t = t.union(_py_expr_taint(v.value, env, funcs))
        return t
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        t = EMPTY
        for e in expr.elts:
            t = t.union(_py_expr_taint(e, env, funcs))
        return t
    if isinstance(expr, ast.Subscript):
        s = _dotted(expr)
        if _is_py_source(s):
            return _Taint(source=True)
        return _py_expr_taint(expr.value, env, funcs)
    if isinstance(expr, ast.Attribute):
        s = _dotted(expr)
        if _is_py_source(s):
            return _Taint(source=True)
        return _py_expr_taint(expr.value, env, funcs)
    if isinstance(expr, ast.Call):
        callee = _dotted(expr.func)
        # source calls: request.args.get(...), input(), etc.
        if _is_py_source(callee) or callee == "input" or callee.endswith(".get_json"):
            return _Taint(source=True)
        args = list(expr.args) + [k.value for k in expr.keywords if k.arg]
        arg_taints = [_py_expr_taint(a, env, funcs) for a in args]
        # sanitizers: int(x) fully cleanses; html.escape(x) clears XSS; etc.
        san = _py_sanitizer(callee)
        if san == "full":
            return EMPTY
        if san is not None:                       # partial sanitizer
            inner = EMPTY
            for at in arg_taints:
                inner = inner.union(at)
            return inner.sanitize(san)
        # propagation through a user function's summary
        t = EMPTY
        for cand in funcs.get(callee.split(".")[-1], []):
            if cand.returns_source:
                t = t.union(_Taint(source=True))
            for idx, pname in enumerate(cand.params):
                if pname in cand.param_to_return and idx < len(arg_taints):
                    t = t.union(arg_taints[idx])
        # unknown callee: propagate taint of args conservatively only for common
        # taint-preserving builtins
        if callee.split(".")[-1] in ("str", "bytes", "format", "join", "strip",
                                     "decode", "encode", "replace", "lower", "upper"):
            for at in arg_taints:
                t = t.union(at)
        # taint of the object a method is called on (e.g. tainted.strip())
        if isinstance(expr.func, ast.Attribute):
            t = t.union(_py_expr_taint(expr.func.value, env, funcs))
        return t
    return EMPTY


def _py_analyze_fn(fn, funcs, emit, findings):
    """Run one function; update its summary. If emit, record findings."""
    env = {p: _Taint(params={p}) for p in fn.params}
    changed = False

    def set_env(name, taint):
        prev = env.get(name)
        env[name] = taint

    def visit_stmts(stmts):
        nonlocal changed
        for st in stmts:
            _visit(st)

    def check_call(node):
        """Check a Call node for sinks; return its taint (for nested use)."""
        nonlocal changed
        callee = _dotted(node.func)
        args = list(node.args) + [k.value for k in node.keywords if k.arg]
        arg_taints = [_py_expr_taint(a, env, funcs) for a in args]
        obj_taint = (_py_expr_taint(node.func.value, env, funcs)
                     if isinstance(node.func, ast.Attribute) else EMPTY)
        involved = arg_taints + [obj_taint]

        # 1) direct dangerous sink. Only the primary data argument (arg 0) is a
        # sink position — this keeps parameterized queries, e.g.
        # execute("… %s", (x,)), from being flagged (x is arg 1, safe).
        # We do NOT emit here: a source and sink in the *same* function is
        # intra-procedural and already reported by lazaret.taint_scan. This
        # pass only records the param→sink summary, which powers the
        # interprocedural detection in section 2.
        cat = _py_sink(callee)
        if cat:
            merged = arg_taints[0] if arg_taints else EMPTY
            if cat not in merged.clean:            # not sanitized for this sink
                for p in merged.params:
                    if fn.param_to_sink.get(p) != cat:
                        fn.param_to_sink[p] = cat
                        changed = True

        # 2) call into a user function whose parameter reaches a sink
        for cand in funcs.get(callee.split(".")[-1], []):
            for idx, pname in enumerate(cand.params):
                sink_cat = cand.param_to_sink.get(pname)
                if not sink_cat or idx >= len(arg_taints):
                    continue
                at = arg_taints[idx]
                if sink_cat in at.clean:            # argument sanitized for this sink
                    continue
                if at.source and emit:
                    line = getattr(node, "lineno", 1)
                    sink_line = getattr(cand.node, "lineno", 1)
                    findings.append(_issue(
                        sink_cat, fn.file, line, fn.lines,
                        source_loc=f"{fn.file}:{line}",
                        sink_loc=f"{cand.file}:{sink_line} (in {cand.name}())",
                        chain=f"the call to {cand.name}()"))
                for p in at.params:  # transitivity: our param reaches sink via cand
                    if fn.param_to_sink.get(p) != sink_cat:
                        fn.param_to_sink[p] = sink_cat
                        changed = True

    def check_calls_in(expr):
        """Run sink checks for every Call node within an expression subtree."""
        if expr is None:
            return
        for child in ast.walk(expr):
            if isinstance(child, ast.Call):
                check_call(child)

    def _visit(node):
        nonlocal changed
        # nested function definitions are analyzed on their own as top-level funcs
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return
        if isinstance(node, ast.Assign):
            check_calls_in(node.value)
            t = _py_expr_taint(node.value, env, funcs)
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    set_env(tgt.id, t)
                elif isinstance(tgt, (ast.Tuple, ast.List)):
                    for e in tgt.elts:
                        if isinstance(e, ast.Name):
                            set_env(e.id, t)
        elif isinstance(node, ast.AugAssign):
            check_calls_in(node.value)
            if isinstance(node.target, ast.Name):
                cur = env.get(node.target.id, EMPTY)
                set_env(node.target.id, cur.union(_py_expr_taint(node.value, env, funcs)))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            check_calls_in(node.value)
            if isinstance(node.target, ast.Name):
                set_env(node.target.id, _py_expr_taint(node.value, env, funcs))
        elif isinstance(node, ast.Return):
            check_calls_in(node.value)
            t = _py_expr_taint(node.value, env, funcs) if node.value else EMPTY
            if t.source and not fn.returns_source:
                fn.returns_source = True
                changed = True
            for p in t.params:
                if p not in fn.param_to_return:
                    fn.param_to_return.add(p)
                    changed = True
        elif isinstance(node, ast.Expr):
            check_calls_in(node.value)
        else:
            # compound statement: check calls in its guard/iterable, then recurse
            for guard in ("test", "iter"):
                check_calls_in(getattr(node, guard, None))
            for item in getattr(node, "items", []) or []:
                check_calls_in(getattr(item, "context_expr", None))
            for field in ("body", "orelse", "finalbody"):
                visit_stmts(getattr(node, field, []) or [])
            for handler in getattr(node, "handlers", []) or []:
                visit_stmts(handler.body)

    for st in fn.node.body:
        _visit(st)
    return changed


def _analyze_python(files, findings):
    overflow = {}  # file -> lowest function line that hit the limit (1: the parser did)
    funcs = _collect_py(files, overflow)
    flat = [fn for lst in funcs.values() for fn in lst]
    # M16/F12 (C1 follow-up): _py_analyze_fn → _visit/visit_stmts are mutually
    # recursive with no bound, and _py_expr_taint recurses on operand trees.
    # CPython's parser rejects >100 *nested parentheses* (SyntaxError), but an
    # operator chain ("1+1+…" / "- - -1") still parses and builds a left-deep
    # AST, so hostile/generated code CAN overflow the ~1000-frame limit while
    # being valid Python. The CLI/MCP/registry drivers have no per-file
    # isolation, so one RecursionError would otherwise abort the whole report
    # with zero findings. Guard per function, in both passes: a pathological
    # function is skipped (its findings lost, an INFO note emitted — Q- class,
    # like Q-SKIPPED-TREE) while every other function keeps its results.

    def _safe_analyze(fn, emit):
        try:
            return _py_analyze_fn(fn, funcs, emit=emit, findings=findings)
        except RecursionError:
            overflow[fn.file] = min(overflow.get(fn.file, 1 << 30),
                                    fn.node.lineno)
            return False

    # fixpoint on summaries (no emission)
    for _ in range(MAX_ITERS):
        changed = False
        for fn in flat:
            if _safe_analyze(fn, emit=False):
                changed = True
        if not changed:
            break
    # final emission pass
    for fn in flat:
        _safe_analyze(fn, emit=True)
    for fname in sorted(overflow):
        findings.append({
            "rule": "Q-FLOW-RECURSION",
            "name": "Flow analysis incomplete (recursion cutoff)",
            "type": "SMELL", "sev": "INFO",
            "msg": f"Lazaret's flow pass hit Python's recursion limit while "
                   f"analyzing {fname!r} — findings for the affected function(s) "
                   f"may be missing; every other function was still analyzed.",
            "why": "A pathologically deep expression (e.g. a long operator "
                   "chain in generated code) can overflow Python's parser or "
                   "the analysis stack even though it is valid Python. Lazaret "
                   "skips only the affected function(s), or the file if the "
                   "parser overflowed, instead of crashing the whole scan.",
            "fix": "Split or format the flagged file to keep expressions "
                   "shallow, then re-run Lazaret.",
            "ref": "CWE-400 (uncontrolled resource consumption)",
            "file": fname,
            "line": overflow[fname],
        })


# ======================================================================
# JavaScript — bounded heuristic (no JS parser available)
# ======================================================================
_JS_FUNC_RE = re.compile(
    r"(?:function\s+(?P<n1>\w+)\s*\((?P<p1>[^)]*)\)"
    r"|(?:const|let|var)\s+(?P<n2>\w+)\s*=\s*(?:async\s*)?\((?P<p2>[^)]*)\)\s*=>"
    r"|(?:const|let|var)\s+(?P<n3>\w+)\s*=\s*(?:async\s*)?function\s*\((?P<p3>[^)]*)\))")
_JS_SOURCE_RE = re.compile(
    r"req\.(query|body|params|headers|cookies)|process\.argv|location\.(search|hash|href)")
_JS_SINKS = [
    (re.compile(r"\.(query|execute)\s*\("), "SQL injection"),
    (re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\("), "command injection"),
    (re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\("), "code injection"),
    (re.compile(r"\.innerHTML\s*=|document\.write\s*\("), "cross-site scripting"),
    (re.compile(r"\bfetch\s*\(|axios(\.\w+)?\s*\("), "server-side request forgery"),
    (re.compile(r"\.redirect\s*\("), "open redirect"),
]


def _js_functions(content):
    """Yield (name, params[list], body_span, start_line).

    body_span is (start_offset, end_offset) into content — the slice the old
    version returned as a copied string. G3 fix: the old version brace-matched
    every _JS_FUNC_RE match by scanning content character by character to EOF
    and copying the whole body, which is O(matches × size) time and transient
    memory (audit G3: ~27 s and ~GB of copies for a 1.5 MB file of
    unterminated functions; an unterminated final brace scanned to EOF for
    every match). One linear brace pass now computes the spans; nothing is
    copied and no per-match scan runs.
    """
    matches = list(_JS_FUNC_RE.finditer(content))
    if not matches:
        return []
    # matching '}' for every '{', plus all '{' offsets — one stack pass
    opens, match_close, stack = [], {}, []
    for bm in re.finditer(r"[{}]", content):
        if bm.group() == "{":
            opens.append(bm.start())
            stack.append(bm.start())
        elif stack:
            match_close[stack.pop()] = bm.start()
    # newline offsets once, for start_line
    nl = [i for i, ch in enumerate(content) if ch == "\n"]
    from bisect import bisect_left
    out = []
    for m in matches:
        name = m.group("n1") or m.group("n2") or m.group("n3")
        params_s = m.group("p1") or m.group("p2") or m.group("p3") or ""
        params = [p.strip().split("=")[0].strip() for p in params_s.split(",") if p.strip()]
        # first '{' at/after m.end()-1 — exactly what the old content.find()
        # located (a match may claim a brace inside its own header, or a
        # later brace for brace-less arrow bodies)
        k = bisect_left(opens, m.end() - 1)
        if k == len(opens):
            continue
        brace = opens[k]
        close = match_close.get(brace, len(content))  # EOF if never closed
        start_line = bisect_left(nl, m.start()) + 1
        out.append((name, params, (brace, close + 1), start_line))
    return out


# JS sanitizers: full (numeric coercion) neutralize everything; partial clear a category.
_JS_FULL_SAN_RE = re.compile(r"(?:parseInt|parseFloat|Number)\s*\([^()]*\)")
_JS_PARTIAL_SAN = {
    "cross-site scripting": re.compile(
        r"(?:DOMPurify\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml)\s*\([^()]*\)"),
    "SQL injection": re.compile(r"(?:mysql2?|pool|connection|conn|db)\.escape\s*\([^()]*\)"),
    "path traversal": re.compile(r"path\.basename\s*\([^()]*\)"),
    "command injection": re.compile(r"(?:shellQuote|shell_quote|quote)\s*\([^()]*\)"),
}

def _js_neutralize(text, cats):
    """Strip sanitizer call expressions so their sanitized content stops counting
    as tainted. Full sanitizers always; partial ones only for the given categories."""
    text = _JS_FULL_SAN_RE.sub(" ", text)
    for c in cats:
        if c in _JS_PARTIAL_SAN:
            text = _JS_PARTIAL_SAN[c].sub(" ", text)
    return text


def _js_param_dangerous(seg, p, cat):
    """Does parameter p reach the sink in a dangerous way within seg?"""
    pe = re.escape(p)
    if cat == "SQL injection":
        # safe if p only appears inside a placeholder array, e.g. query(sql, [p]);
        # dangerous only when concatenated or interpolated into the query string
        return bool(re.search(r"\+\s*%s\b|\b%s\s*\+|`[^`]*\$\{[^}]*\b%s\b" % (pe, pe, pe), seg))
    return re.search(r"\b%s\b" % pe, seg) is not None


def _analyze_js(files, findings):
    # summary: fname -> set of param names reaching a sink (with category)
    summaries = {}   # name -> (params, dict(param -> category))
    fn_defs = {}     # name -> (file, start_line)
    js_files = [f for f in files if f["lang"] == "js"]
    # G3 fix: the old version was quadratic/memory-explosive on adversarial
    # input — per-match char-by-char brace scans to EOF, whole-body string
    # copies, per-sink-match×param regex passes over each body, and a
    # re.search over the ENTIRE file content per already-tainted var per
    # assignment (O(vars × size²)). This version is linear in file size:
    # one brace pass in _js_functions (spans, no copies), ONE whole-file
    # scan per sink whose matches are attributed to the function spans
    # containing them via a start/end sweep (each span is added once and
    # retired once as sink positions advance), and token-set tainted-var
    # propagation. Files above _JS_MAX_FILE are skipped with an INFO
    # finding so the blind spot is visible rather than silent (audit G3).
    for f in js_files:
        content = f["content"]
        if len(content) > _JS_MAX_FILE:
            findings.append({
                "rule": "X-FLOW-SKIPPED", "name": "JS flow analysis skipped (size)",
                "type": "HOTSPOT", "sev": "INFO",
                "msg": f"{f['path']} is {len(content)} bytes; interprocedural JS "
                       f"taint analysis is skipped above {_JS_MAX_FILE} bytes.",
                "why": "The heuristic JS engine scales poorly on minified or "
                       "machine-generated files of this size; a full analysis "
                       "would risk a multi-minute scan.",
                "fix": "Split or deminify the file, or exclude it from the scan "
                       "explicitly if the code is generated.",
                "ref": "Scalability",
                "file": f["path"], "line": 1,
                "snippet": [], "snipStart": 1})
            continue
        funcs = _js_functions(content)
        if not funcs:
            continue
        fn_defs.update({name: (f["path"], start) for name, _, _, start in funcs})
        # Sink attribution, identical in effect to the old per-body
        # finditer (which found exactly the matches inside each copied
        # body — spans give the same set, including sinks inside nested
        # closures). Each sink gets its OWN sweep: spans are walked in
        # start order, become active when their start precedes the sink
        # position and are retired when their end precedes it; sink
        # positions advance monotonically within one sink's scan, so each
        # span is appended once and removed once — linear per sink, six
        # sinks total (the old code scanned every body six times too).
        spans = [(s, e, fi) for fi, (_, _, (s, e), _) in enumerate(funcs)]
        span_reach = [dict() for _ in funcs]   # fi -> {param: category}
        for sink_re, cat in _JS_SINKS:
            spans_by_start = sorted(spans)
            active = []
            add_idx = 0
            for sm in sink_re.finditer(content):
                pos = sm.start()
                while add_idx < len(spans_by_start) and spans_by_start[add_idx][0] <= pos:
                    active.append(spans_by_start[add_idx])
                    add_idx += 1
                active[:] = [sp for sp in active if sp[1] > pos]
                if not active:
                    continue
                seg = content[pos:pos + 200]
                for s, e, fi in active:
                    params = funcs[fi][1]
                    for p in params:
                        if p and _js_param_dangerous(seg, p, cat):
                            span_reach[fi][p] = cat
        # Build summaries in MATCH order with old last-non-empty-wins
        # semantics for duplicate names (summaries[name] = ... per match).
        for fi, (name, params, _, _) in enumerate(funcs):
            if span_reach[fi]:
                summaries[name] = (params, span_reach[fi])
    if not summaries:
        return
    # scan call sites: a source-derived variable passed into a summarized function
    call_re = re.compile(r"\b(\w+)\s*\(([^;()]*)\)")
    for f in js_files:
        if len(f["content"]) > _JS_MAX_FILE:
            continue   # already reported above
        lines = f["content"].split("\n")
        # per-file tainted-var set. Find variable declarations/assignments
        # anywhere (not just at line start) so `foo(){ const q=req.query.q; ... }`
        # is handled. Processed in source order for simple forward transitivity.
        # G3: the old code ran re.search over the whole file content for every
        # already-tainted var on every assignment — O(vars × size²) on
        # adversarial input. One regex pass now extracts the RHS's identifier
        # tokens; propagation checks the RHS's own tokens (a variable became
        # tainted via a RHS that *named* it, which is exactly what
        # \b<var>\b over that RHS matched).
        tainted = set()
        assign_re = re.compile(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)"
            r"|(?:^|[;{]\s*)([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([^;\n]+)")
        word_re = re.compile(r"[A-Za-z_$][\w$]*")
        for am in assign_re.finditer(f["content"]):
            name = am.group(1) or am.group(3)
            rhs = am.group(2) or am.group(4) or ""
            rhs = _js_neutralize(rhs, ())   # a value wrapped in parseInt/Number is clean
            if _JS_SOURCE_RE.search(rhs) or (tainted & set(word_re.findall(rhs))):
                tainted.add(name)
        for i, ln in enumerate(lines):
            for cm in call_re.finditer(ln):
                fname, argstr = cm.group(1), cm.group(2)
                if fname not in summaries:
                    continue
                params, reach = summaries[fname]
                call_args = [a.strip() for a in argstr.split(",")]
                for idx, pname in enumerate(params):
                    if pname not in reach or idx >= len(call_args):
                        continue
                    a = _js_neutralize(call_args[idx], {reach[pname]})  # sink-category sanitizers
                    if _JS_SOURCE_RE.search(a) or (tainted & set(word_re.findall(a))):
                        dfile, dline = fn_defs.get(fname, (f["path"], 1))
                        findings.append(_issue(
                            reach[pname], f["path"], i + 1, lines,
                            source_loc=f"{f['path']}:{i + 1}",
                            sink_loc=f"{dfile}:{dline} (in {fname}())",
                            chain=f"the call to {fname}()"))
                        break


_JS_MAX_FILE = 2_000_000      # skip interprocedural JS flow above 2 MB


# ======================================================================
# Configurable taint spec (Semgrep-style): add custom sources / sinks /
# sanitizers without editing the engine. See load_config() for the file format.
# ======================================================================
_JS_SOURCE_BASE = _JS_SOURCE_RE.pattern

def configure(cfg, on_warn=None):
    """Extend the taint model from a parsed config dict. Sections 'python' and
    'javascript', each with optional 'sources' (regex list), 'sinks'
    ({pattern, category}), and 'sanitizers' ({full: [...], partial: {name:[cats]}}).

    Invalid rules are never silently dropped: every rejection is reported
    through on_warn(msg) (file/rule/reason + the valid category list), so a
    custom sink cannot quietly become inert while the scan still reports
    PASSED."""
    global _JS_SOURCE_RE
    warn = on_warn if callable(on_warn) else None
    if not isinstance(cfg, dict):
        if warn:
            warn(f"top level is {type(cfg).__name__}, not an object — nothing applied")
        return
    for key in cfg:
        if key not in ("python", "javascript") and not str(key).startswith("_"):
            if warn:
                warn(f"unknown top-level section {key!r} — expected 'python' or "
                     f"'javascript'; rule skipped")
    py = cfg.get("python", {}) or {}
    if not isinstance(py, dict):
        if warn:
            warn(f"section 'python' is {type(py).__name__}, not an object — "
                 f"section ignored")
        py = {}
    for pat in py.get("sources", []):
        # 48033f94: invalid regex in an auto-loaded config crashed the whole
        # scan — reject the rule with a warning (same shape as the other
        # rejections) and keep scanning.
        try:
            src_re = re.compile(pat)
        except re.error as exc:
            if warn:
                warn(f"python source pattern {pat!r} is not a valid regex "
                     f"({exc}) — rule skipped")
            continue
        _PY_SOURCE_EXTRA.append(src_re)
    py_sinks = py.get("sinks", [])
    if not isinstance(py_sinks, list):
        if warn:
            warn(f"python.sinks is {type(py_sinks).__name__}, not a list — "
                 f"section ignored")
        py_sinks = []
    for idx, sk in enumerate(py_sinks, 1):
        if not isinstance(sk, dict):
            if warn:
                warn(f"python sink #{idx} is not an object — rule skipped")
            continue
        cat, pattern = sk.get("category"), sk.get("pattern")
        if not cat:
            if warn:
                warn(f"python sink #{idx} (pattern {pattern!r}) has no "
                     f"'category' — rule skipped; valid categories: "
                     f"{', '.join(sorted(SINK_META))}")
            continue
        if cat not in SINK_META:
            if warn:
                warn(f"python sink #{idx} (pattern {pattern!r}) has unknown "
                     f"category {cat!r} — rule skipped; valid categories: "
                     f"{', '.join(sorted(SINK_META))}")
            continue
        if not pattern:
            if warn:
                warn(f"python sink #{idx} (category {cat!r}) has an empty "
                     f"'pattern' — rule skipped")
            continue
        # 48033f94: invalid sink regex — reject the rule instead of crashing.
        try:
            sink_re = re.compile(pattern)
        except re.error as exc:
            if warn:
                warn(f"python sink #{idx} (category {cat!r}) pattern "
                     f"{pattern!r} is not a valid regex ({exc}) — rule skipped")
            continue
        _EXTRA_PY_SINKS.append((sink_re, cat))
    py_san = py.get("sanitizers", {}) or {}
    if not isinstance(py_san, dict):
        if warn:
            warn(f"python.sanitizers is {type(py_san).__name__}, not an "
                 f"object — section ignored")
        py_san = {}
    for name in py_san.get("full", []):
        FULL_SANITIZERS_PY.add(name)
    py_partial = py_san.get("partial", {}) or {}
    if not isinstance(py_partial, dict):
        if warn:
            warn(f"python.sanitizers.partial is {type(py_partial).__name__}, "
                 f"not an object — section ignored")
        py_partial = {}
    for name, cats in py_partial.items():
        if not isinstance(cats, (list, tuple)):
            if warn:
                warn(f"python sanitizer {name!r} has {type(cats).__name__} "
                     f"categories, not a list — rule skipped")
            continue
        for c in cats:
            if c not in SINK_META and warn:
                warn(f"python sanitizer {name!r} lists unknown category {c!r} — "
                     f"category ignored; valid categories: "
                     f"{', '.join(sorted(SINK_META))}")
        _EXTRA_PARTIAL_PY[name] = {c for c in cats if c in SINK_META}

    js = cfg.get("javascript", {}) or {}
    if not isinstance(js, dict):
        if warn:
            warn(f"section 'javascript' is {type(js).__name__}, not an object — "
                 f"section ignored")
        js = {}
    js_src = js.get("sources", [])
    if js_src:
        # 48033f94: any invalid pattern in the joined expression (or a non-str
        # entry, where "|".join raised TypeError) is rejected with a warning
        # per entry; the valid ones still apply.
        joined = []
        for pat in js_src:
            try:
                re.compile(pat)
            except (re.error, TypeError) as exc:
                if warn:
                    warn(f"javascript source pattern {pat!r} is not a valid "
                         f"regex ({exc}) — rule skipped")
                continue
            joined.append(pat)
        if joined:
            _JS_SOURCE_RE = re.compile(_JS_SOURCE_BASE + "|" + "|".join(joined))
    js_sinks = js.get("sinks", [])
    if not isinstance(js_sinks, list):
        if warn:
            warn(f"javascript.sinks is {type(js_sinks).__name__}, not a list — "
                 f"section ignored")
        js_sinks = []
    for idx, sk in enumerate(js_sinks, 1):
        if not isinstance(sk, dict):
            if warn:
                warn(f"javascript sink #{idx} is not an object — rule skipped")
            continue
        cat, pattern = sk.get("category"), sk.get("pattern")
        if not cat:
            if warn:
                warn(f"javascript sink #{idx} (pattern {pattern!r}) has no "
                     f"'category' — rule skipped; valid categories: "
                     f"{', '.join(sorted(SINK_META))}")
            continue
        if cat not in SINK_META:
            if warn:
                warn(f"javascript sink #{idx} (pattern {pattern!r}) has unknown "
                     f"category {cat!r} — rule skipped; valid categories: "
                     f"{', '.join(sorted(SINK_META))}")
            continue
        if not pattern:
            if warn:
                warn(f"javascript sink #{idx} (category {cat!r}) has an empty "
                     f"'pattern' — rule skipped")
            continue
        # 48033f94: invalid sink regex — reject the rule instead of crashing.
        try:
            sink_re = re.compile(pattern)
        except re.error as exc:
            if warn:
                warn(f"javascript sink #{idx} (category {cat!r}) pattern "
                     f"{pattern!r} is not a valid regex ({exc}) — rule skipped")
            continue
        _JS_SINKS.append((sink_re, cat))
    js_san = js.get("sanitizers", {}) or {}
    if not isinstance(js_san, dict):
        if warn:
            warn(f"javascript.sanitizers is {type(js_san).__name__}, not an "
                 f"object — section ignored")
        js_san = {}
    for name in js_san.get("full", []):
        # 48033f94: a non-str entry made re.escape raise TypeError; the
        # compound pattern could also fail to compile — warn + skip either way.
        try:
            globals()["_JS_FULL_SAN_RE"] = re.compile(
                _JS_FULL_SAN_RE.pattern + "|" + re.escape(name)
                + r"\s*\([^()]*\)")
        except (re.error, TypeError) as exc:
            if warn:
                warn(f"javascript.sanitizers.full entry {name!r} is not a valid "
                     f"sanitizer name ({exc}) — rule skipped")
            continue
    js_partial = js_san.get("partial", {}) or {}
    if not isinstance(js_partial, dict):
        if warn:
            warn(f"javascript.sanitizers.partial is {type(js_partial).__name__}, "
                 f"not an object — section ignored")
        js_partial = {}
    for name, cats in js_partial.items():
        if not isinstance(cats, (list, tuple)):
            if warn:
                warn(f"javascript sanitizer {name!r} has {type(cats).__name__} "
                     f"categories, not a list — rule skipped")
            continue
        for c in cats:
            if c not in SINK_META:
                if warn:
                    warn(f"javascript sanitizer {name!r} lists unknown category "
                         f"{c!r} — category ignored; valid categories: "
                         f"{', '.join(sorted(SINK_META))}")
                continue
            base = _JS_PARTIAL_SAN.get(c)
            # 48033f94: re.escape() of a non-str name raised TypeError before
            # this guard existed — build the pattern and compile it inside
            # try/except so a bad rule is warned about and skipped.
            try:
                add = re.escape(name) + r"\s*\([^()]*\)"
                _JS_PARTIAL_SAN[c] = re.compile(
                    (base.pattern + "|" + add) if base else add)
            except (re.error, TypeError) as exc:
                if warn:
                    warn(f"javascript sanitizer {name!r} (category {c!r}) "
                         f"could not be compiled ({exc}) — rule skipped")
                continue


def load_config(path):
    """Load a JSON taint-config file and apply it. Returns True if applied.
    Rejected rules are reported to stderr (see configure())."""
    warnings = []
    applied = load_config_quietly(path, warnings)
    for msg in warnings:
        # audit H1: `path` is the auto-loaded <scan-root>/.lazaret-taint.json
        # (untrusted repo); `msg` embeds rejected-rule names/patterns from its
        # content. Sanitized via the local twin (see module top).
        print(f"warning: {sanitize_term(path)}: {sanitize_term(msg)}",
              file=sys.stderr)
    return applied


def load_config_quietly(path, warnings_out=None):
    """Load a JSON taint-config file and apply it, collecting validation
    warnings in warnings_out (list) instead of printing them. Returns True if
    applied. A failed read/parse returns False with a single message in
    warnings_out."""
    if warnings_out is None:
        warnings_out = []
    try:
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, json.JSONDecodeError, RecursionError) as exc:
        # 1149e3e5: RecursionError from a deep-nested config (~60KB of '[')
        # is not a JSONDecodeError — without the guard the RecursionError
        # escaped and killed the caller. Same warn-and-skip contract as an
        # unreadable file.
        warnings_out.append(f"could not load taint config {path}: {exc}")
        return False
    configure(cfg, on_warn=lambda msg: warnings_out.append(msg))
    return True


# ======================================================================
def analyze(files):
    """Return interprocedural/cross-file taint findings for the file set."""
    files = [f for f in files if f.get("lang") in ("py", "js") and not f.get("dep")]
    findings = []
    _analyze_python(files, findings)
    _analyze_js(files, findings)
    # dedupe by (rule, file, line, sink text)
    seen, unique = set(), []
    for i in sorted(findings, key=lambda x: (x["file"], x["line"])):
        key = (i["rule"], i["file"], i["line"], i["msg"])
        if key not in seen:
            seen.add(key)
            unique.append(i)
    return unique
