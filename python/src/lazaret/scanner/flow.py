#!/usr/bin/env python3
"""Lazaret interprocedural taint analysis (cross-function, cross-file).

The per-file scanner (lazaret.taint_scan) tracks taint within a single
function. This module adds *whole-program* analysis: it follows untrusted data
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

Python analysis is AST-based (stdlib only). JavaScript uses a bounded
lexer/regex heuristic (no JS parser available without dependencies), so JS
results are best-effort: a call binds to the function its file names through
relative require()/import, a call it cannot resolve may reach any function
of that name, functions are summarized by the parameters that reach a sink
(directly or through the locals that hold them) and by what they return,
and each file's work is bounded (see "modules, calls and returned values"
and "values through local variables"). The npm engine carries a twin of the
JavaScript half (js/src/scanner/flow.js).

Public entry point: analyze(files) -> list[issue dict] (never raises)
  files: iterable of {"path": str, "content": str, "lang": "py"|"js"}
"""
import ast
import bisect
import builtins as _builtins
import collections
import json
import os
import posixpath
import re
import sys
import time

from lazaret.scanner import frameworks
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
    "safe_join": {"path traversal"},                 # werkzeug / flask
    "conditional_escape": {"cross-site scripting"},  # django
    "format_html": {"cross-site scripting"},         # django
    "render_template": {"cross-site scripting"},     # an autoescaping template
    "render_to_string": {"cross-site scripting"},    # django: an autoescaping template
    "TemplateResponse": {"cross-site scripting"},    # starlette / fastapi: an autoescaping template
    "jsonify": {"cross-site scripting"},             # a JSON response
    "url_for": {"cross-site scripting", "open redirect"},  # a URL on this site
    "reverse": {"open redirect"},                    # django: a URL on this site
    "reverse_lazy": {"open redirect"},
}
# what a call returns that is not request data though its arguments may be:
# a record looked up by a value (the ORM binds it), a file's content
FULL_RESULT_PY = {"get_object_or_404", "get_list_or_404", "open", "builtins.open", "io.open", "codecs.open"}
# … and a query's result: Django's Model.objects…, Flask-SQLAlchemy's
# Model.query…, SQLAlchemy's session.query / get / scalar(s) / execute
_ORM_RESULT_RE = re.compile(r"\.objects\.|\.query\.|\bsession\.(?:query|get|scalars?|execute)\b")
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
#                 there are at most MAX_DUCK_CANDIDATES of them and m is not a
#                 builtin/dict/str/file-like name (get, open, run, …).
# Anything else is an external call: it propagates taint from its arguments
# (and receiver) to its return value, unless it is a sanitizer or returns a
# non-string value (len, isinstance, …).

MAX_ITERS = 50                 # re-analyses of one function before cutoff
FLOW_MAX_FILES = 20_000        # Python files analyzed per run
FLOW_MAX_BYTES = 64_000_000    # Python source characters analyzed per run
FLOW_TIME_BUDGET = 120.0       # seconds for the Python summary fixpoint
MAX_DUCK_CANDIDATES = 4        # obj.m() with an unknown receiver
_MAX_IMPORT_HOPS = 5
_BUILTIN_NAMES = frozenset(dir(_builtins))
_BUILTIN_FULL_PY = frozenset(FULL_SANITIZERS_PY)   # before any configure()

# Method names never resolved by duck typing when the receiver is unknown:
# builtin container/str/file/db-API/logging names that almost always belong
# to library objects (a project `def get(self, name)` must not turn every
# dict.get / os.environ.get into a source).
_COMMON_METHODS = frozenset("""
get set setdefault pop popitem update keys values items copy clear append
extend insert remove index count sort reverse add discard union intersection
difference issubset issuperset open close read readline readlines write
writelines seek tell flush truncate fileno run start stop join split rsplit
strip lstrip rstrip replace format format_map encode decode lower upper title
capitalize casefold startswith endswith find rfind partition rpartition
splitlines expandtabs zfill center ljust rjust send recv sendall sendto
connect bind listen accept execute executemany fetchone fetchall fetchmany
commit rollback cursor call apply map filter reduce next iter throw match
search sub subn fullmatch findall finditer group groups groupdict compile
load loads dump dumps parse render process handle dispatch emit log debug
info warning warn error exception critical submit result cancel wait put
get_nowait put_nowait acquire release lock notify notify_all is_set
setattr getattr delattr register unregister exists makedirs mkdir unlink
delete create save merge destroy upsert get_one get_all get_by_id get_many
find find_one find_all first last bulk_create bulk_update refresh
""".split())
# The query builders of an ORM (SQLAlchemy's select() / insert() / update() /
# delete() and their .where / .filter / .filter_by / .values … , Django's
# QuerySet methods): the value they build binds what it is given as a
# parameter, so it carries no SQL injection. Raw SQL — text(q), a formatted
# string — is still read.
_SQL_BUILDER_FUNCS = frozenset(("select", "insert", "update", "delete", "sqlalchemy.select", "sqlalchemy.insert",
                                "sqlalchemy.update", "sqlalchemy.delete"))
_SQL_BUILDER_METHODS = frozenset((
    "where", "filter", "filter_by", "values", "order_by", "group_by", "having", "join", "outerjoin", "options",
    "limit", "offset", "returning", "on_conflict_do_update", "on_conflict_do_nothing", "exclude", "annotate",
    "select_related", "prefetch_related", "values_list", "distinct"))

# External calls whose result carries no attacker-controlled text.
_CLEAN_RESULT = frozenset("""
len bool isinstance issubclass hasattr callable id hash type ord abs round sum
any all divmod exists isfile isdir islink ismount isabs getsize getmtime
getatime getctime startswith endswith isdigit isalpha isalnum isspace
isnumeric isdecimal isidentifier islower isupper istitle isascii isprintable
count find rfind index rindex hexdigest digest compare_digest time monotonic
perf_counter
""".split())


def _dotted(node):
    """Best-effort dotted string for a Name/Attribute/Call/Subscript expr."""
    parts = []
    while True:
        if isinstance(node, ast.Name):
            parts.append(node.id)
            break
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Name) and node.func.id == "__import__"
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                parts.append(node.args[0].value)   # __import__('shlex').quote
                break
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:
            parts.append("")
            break
    return ".".join(reversed(parts))


_PY_SOURCE_RE = re.compile(
    r"\brequest\.(args|form|values|json|data|cookies|headers|files|query_string|stream|full_path"
    r"|GET|POST|COOKIES|META|FILES|body|query_params|path_params)\b"
    r"|\brequest\.(?:get_json|get_data)\b|\bsys\.argv\b|\bflask\.request\b"
    r"|\b(?:websocket|ws)\.receive_(?:text|json|bytes)\b")
_PY_SOURCE_EXTRA = []    # guarded source patterns (from config)
_EXTRA_PY_SINKS = []     # (guarded pattern, category) from config


def _is_py_source(*names):
    for s in names:
        if s and (_PY_SOURCE_RE.search(s) or any(p.search(s) for p in _PY_SOURCE_EXTRA)):
            return True
    return False


def _py_config_sink(*names):
    for pat, cat in _EXTRA_PY_SINKS:      # configured sinks take precedence
        for s in names:
            if s and pat.search(s):
                return cat
    return None


def _py_builtin_sink(callee):
    last = callee.split(".")[-1]
    if last in ("execute", "executemany", "executescript") or last == "RawSQL" or (
            last in ("raw", "extra") and ".objects." in f".{callee}"):
        return "SQL injection"
    if callee in ("os.system", "os.popen", "asyncio.create_subprocess_shell"):
        return "command injection"
    if callee.startswith("subprocess.") and last in (
            "run", "call", "check_output", "check_call", "Popen"):
        return "command injection"
    if callee in ("eval", "exec", "builtins.eval", "builtins.exec"):
        return "code injection"
    if last == "render_template_string" or callee in (
            "jinja2.Template", "mako.template.Template", "django.template.Template") or (
            last == "from_string" and ("env" in callee.lower() or callee.startswith("jinja2."))):
        return "template injection"
    if (callee in ("open", "builtins.open", "codecs.open", "io.open", "os.open")
            or last in ("send_file", "send_from_directory", "FileResponse")
            or (callee.startswith("shutil.") and last in (
                "copy", "copy2", "copyfile", "copytree", "move", "rmtree"))
            or callee in ("os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.rename",
                          "os.replace", "os.listdir", "os.scandir")):
        return "path traversal"
    if last == "urlopen" or (callee.startswith("requests.") and last in (
            "get", "post", "put", "delete", "head", "request")) or (callee.startswith("httpx.") and last in (
            "get", "post", "put", "patch", "delete", "head", "request", "stream")):
        return "server-side request forgery"
    if last in ("redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "RedirectResponse"):
        return "open redirect"
    # a response body built from the value (Flask / Werkzeug, Django,
    # Starlette / FastAPI), or the value marked as safe HTML
    if last in ("make_response", "Response", "HttpResponse", "HTMLResponse", "Markup", "mark_safe", "SafeString"):
        return "cross-site scripting"
    return None


def _py_sink(callee):
    """Sink category of a callee name (configured patterns first)."""
    return _py_config_sink(callee) or _py_builtin_sink(callee)


def _py_config_sanitizer(*names):
    """'full', a set of categories, or None — from a taint config only."""
    for callee in names:
        if not callee:
            continue
        if callee in FULL_SANITIZERS_PY and callee not in _BUILTIN_FULL_PY:
            return "full"
        if callee in _EXTRA_PARTIAL_PY:
            return _EXTRA_PARTIAL_PY[callee]
    return None


def _py_builtin_sanitizer(*names):
    for callee in names:
        if not callee:
            continue
        last = callee.split(".")[-1]
        if callee in FULL_SANITIZERS_PY or last in FULL_SANITIZERS_PY:
            return "full"
        for table in (PARTIAL_SANITIZERS_PY, _EXTRA_PARTIAL_PY):
            if callee in table:
                return table[callee]
            if last in table:
                return table[last]
        if last.startswith("escape"):                # escape_html(), escapejs(), …
            return {"cross-site scripting"}
    return None


class _Taint:
    """Abstract value: tainted by a concrete source and/or by parameters of
    the function being analyzed; `clean` = sink categories it is sanitized
    for. origin = file:line of the concrete source; via = the function whose
    return value delivered it (None if read in the current function)."""
    __slots__ = ("source", "params", "clean", "origin", "via")

    def __init__(self, source=False, params=(), clean=(), origin=None, via=None):
        self.source = bool(source)
        self.params = frozenset(params)
        self.clean = frozenset(clean)
        self.origin = origin if source else None
        self.via = via if source else None

    def union(self, other):
        # concatenation is safe for a category only if BOTH parts are safe
        if other is EMPTY or other is None:
            return self
        if self is EMPTY:
            return other
        src = self if self.source else other
        return _Taint(self.source or other.source, self.params | other.params,
                      self.clean & other.clean, src.origin, src.via)

    def tainted(self):
        return self.source or bool(self.params)

    def effective(self, cat):
        """Is this value still dangerous for sink category cat?"""
        return self.tainted() and cat not in self.clean

    def sanitize(self, cats):
        if not self.tainted():
            return EMPTY
        return _Taint(self.source, self.params, self.clean | set(cats),
                      self.origin, self.via)


EMPTY = _Taint(clean=ALL_CATS)   # not tainted, safe for everything


def _union_all(vals):
    t = EMPTY
    for v in vals:
        if v is not None:
            t = t.union(v)
    return t


class _PyModule:
    def __init__(self, path, content, tree):
        self.path = path
        self.lines = content.split("\n")
        self.tree = tree
        norm = path.replace("\\", "/")
        while norm.startswith("./"):
            norm = norm[2:]
        stem = norm[:-3] if norm.endswith(".py") else norm
        if posixpath.basename(stem) == "__init__":
            stem = posixpath.dirname(stem)
        self.key = stem
        self.dir = posixpath.dirname(norm)
        self.funcs = {}       # module-level def name -> _PyFunc
        self.classes = {}     # class name -> _PyClass
        self.nested = {}      # nested def name -> [_PyFunc]
        self.imports = {}     # bound name -> import record
        self.stars = []       # (module, level) of `from m import *`
        self.all_funcs = []
        self.globals = {}     # module variable -> source taint
        self.body_fn = None


class _PyClass:
    def __init__(self, name, mod, node):
        self.name = name
        self.mod = mod
        self.node = node
        self.methods = {}
        self.attr_taint = {}  # self.<attr> -> source taint (any method)
        self.bases = None     # resolved lazily: [_PyClass]
        self.subclasses = []


class _PyFunc:
    def __init__(self, name, mod, node, cls=None, pseudo=False):
        self.name = name
        self.mod = mod
        self.file = mod.path
        self.lines = mod.lines
        self.node = node
        self.cls = cls
        self.pseudo = pseudo
        self.qualname = "<module>" if pseudo else (f"{cls.name}.{name}" if cls else name)
        self.line = 1 if pseudo else getattr(node, "lineno", 1)
        self.kind = "function"
        if pseudo:
            self.posonly, self.args, self.kwonly = [], [], []
            self.vararg = self.kwarg = None
        else:
            a = node.args
            self.posonly = [x.arg for x in getattr(a, "posonlyargs", [])]
            self.args = [x.arg for x in a.args]
            self.kwonly = [x.arg for x in a.kwonlyargs]
            self.vararg = a.vararg.arg if a.vararg else None
            self.kwarg = a.kwarg.arg if a.kwarg else None
            if cls is not None:
                self.kind = "method"
                for d in node.decorator_list:
                    dn = _dotted(d)
                    if dn in ("staticmethod", "builtins.staticmethod"):
                        self.kind = "static"
                    elif dn in ("classmethod", "builtins.classmethod"):
                        self.kind = "class"
        positional = self.posonly + self.args
        # the implicit receiver of a bound method carries no caller data
        self.receiver = (positional[0] if self.kind in ("method", "class")
                         and positional else None)
        self.params = [p for p in positional + ([self.vararg] if self.vararg else [])
                       + self.kwonly + ([self.kwarg] if self.kwarg else [])
                       if p != self.receiver]
        # summaries
        self.param_to_sink = {}      # param -> {category: sink location}
        self.param_to_return = {}    # param -> frozenset(categories clean on return)
        self.ret_source = None       # _Taint of a concrete source it returns
        # pre-pass results
        self.local_names = set()
        self.types = {}              # local var -> _PyClass (x = C(...))
        self.callees = set()
        self.callers = set()
        self.runs = 0

    def body(self):
        return self.node.body


def _bind(fn, pos, starred, kws, dstar, skip_first):
    """Bind call-site argument taints to fn's parameters like
    inspect.signature: positional-only + regular params in order (the
    receiver skipped for bound calls), extra positionals into *args,
    keywords by name (never positional-only), unknown keywords into
    **kwargs; a *iterable / **mapping argument may fill any remaining
    parameter."""
    positional = fn.posonly + fn.args
    if skip_first and positional:
        positional = positional[1:]
    out = {}

    def put(name, t):
        out[name] = out[name].union(t) if name in out else t

    i = 0
    for t in pos:
        if i < len(positional):
            put(positional[i], t)
            i += 1
        elif fn.vararg:
            put(fn.vararg, t)
    if starred is not None:
        for p in positional[i:]:
            put(p, starred)
        if fn.vararg:
            put(fn.vararg, starred)
    by_name = set(fn.args) | set(fn.kwonly)
    if skip_first and fn.posonly + fn.args:
        by_name.discard((fn.posonly + fn.args)[0])
    for name, t in kws:
        if name in by_name:
            put(name, t)
        elif fn.kwarg:
            put(fn.kwarg, t)
    if dstar is not None:
        for p in by_name:
            if p not in out:
                put(p, dstar)
        if fn.kwarg:
            put(fn.kwarg, dstar)
    return out


class _CallRes:
    __slots__ = ("targets", "ctor", "canon", "precise")

    def __init__(self, targets, ctor, canon, precise):
        self.targets = targets      # [(_PyFunc, skip_first)]
        self.ctor = ctor            # _PyClass when the call constructs one
        self.canon = canon          # import-canonical dotted callee name
        self.precise = precise      # resolved through names, not duck typing


def _own_nodes(stmts):
    """Every AST node of these statements, without descending into nested
    function/class bodies or lambdas (those are analyzed on their own)."""
    stack = list(reversed(stmts))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # decorators, defaults and bases belong to the enclosing scope
            stack.extend(getattr(node, "decorator_list", []))
            stack.extend(getattr(node, "bases", []))
            args = getattr(node, "args", None)
            if args is not None:
                stack.extend(d for d in args.defaults + args.kw_defaults if d is not None)
            continue
        if isinstance(node, ast.Lambda):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


class _PyProject:
    def __init__(self):
        self.modules = []
        self.by_key = {}          # path key (no .py / __init__) -> module
        self.by_dotted = {}       # dotted suffix -> [modules]
        self.funcs_by_name = {}   # module-level def name -> [_PyFunc]
        self.methods_by_name = {} # method name -> [_PyFunc]
        self.classes = []
        self.funcs = []           # every analyzable function incl. <module>
        self._name_cache = {}
        self._call_cache = {}

    # ---------- collection ----------
    def add_module(self, mod):
        self.modules.append(mod)
        self.by_key[mod.key] = mod
        parts = [p for p in mod.key.split("/") if p and p != "."]
        for k in range(1, min(len(parts), 8) + 1):
            self.by_dotted.setdefault(".".join(parts[-k:]), []).append(mod)
        self._collect(mod.tree.body, mod, None, False)
        mod.body_fn = _PyFunc("<module>", mod, mod.tree, pseudo=True)
        mod.all_funcs.append(mod.body_fn)
        for node in _own_nodes(mod.tree.body):
            self._record_import(mod, node)

    def _record_import(self, mod, node):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    mod.imports[a.asname] = ("import", a.name)
                else:
                    head = a.name.split(".")[0]
                    mod.imports.setdefault(head, ("import", head))
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            for a in node.names:
                if a.name == "*":
                    mod.stars.append((base, node.level or 0))
                else:
                    mod.imports[a.asname or a.name] = ("from", base, a.name, node.level or 0)

    def _collect(self, body, mod, cls, in_func):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = _PyFunc(node.name, mod, node, cls=cls if not in_func else None)
                mod.all_funcs.append(fn)
                if in_func:
                    mod.nested.setdefault(node.name, []).append(fn)
                elif cls is not None:
                    cls.methods[node.name] = fn
                    self.methods_by_name.setdefault(node.name, []).append(fn)
                else:
                    mod.funcs[node.name] = fn
                    self.funcs_by_name.setdefault(node.name, []).append(fn)
                self._collect(node.body, mod, None, True)
                for n in _own_nodes(node.body):     # imports inside functions
                    self._record_import(mod, n)
            elif isinstance(node, ast.ClassDef):
                c = _PyClass(node.name, mod, node)
                self.classes.append(c)
                if not in_func and cls is None:
                    mod.classes[node.name] = c
                self._collect(node.body, mod, c, False)
            else:
                for field in ("body", "orelse", "finalbody", "handlers", "cases"):
                    sub = getattr(node, field, None)
                    if isinstance(sub, list):
                        stmts = []
                        for s in sub:
                            if isinstance(s, (ast.excepthandler,)) or type(s).__name__ == "match_case":
                                stmts.extend(s.body)
                            elif isinstance(s, ast.stmt):
                                stmts.append(s)
                        self._collect(stmts, mod, cls, in_func)

    # ---------- name resolution ----------
    def resolve_module(self, dotted, frm, level=0):
        if level:
            base = frm.dir
            for _ in range(level - 1):
                base = posixpath.dirname(base)
            key = posixpath.join(base, *dotted.split(".")) if dotted else base
            m = self.by_key.get(key)
            return [m] if m is not None else []
        cands = self.by_dotted.get(dotted, [])
        if len(cands) <= 1:
            return list(cands)
        fparts = frm.dir.split("/")

        def score(m):
            n = 0
            for a, b in zip(m.dir.split("/"), fparts):
                if a != b:
                    break
                n += 1
            return n
        best = max(score(m) for m in cands)
        return [m for m in cands if score(m) == best]

    def resolve_name(self, mod, name, hops=0):
        """[(kind, target)] — kind 'func' | 'class' | 'module' | 'ext'."""
        key = (id(mod), name)
        hit = self._name_cache.get(key)
        if hit is not None:
            return hit
        self._name_cache[key] = []            # cycle guard (re-export loops)
        out = self._resolve_name(mod, name, hops)
        self._name_cache[key] = out
        return out

    def _resolve_name(self, mod, name, hops):
        if name in mod.funcs:
            return [("func", mod.funcs[name])]
        if name in mod.classes:
            return [("class", mod.classes[name])]
        imp = mod.imports.get(name)
        if imp is not None:
            if imp[0] == "import":
                ms = self.resolve_module(imp[1], mod)
                return [("module", m) for m in ms] or [("ext", imp[1])]
            _, base, attr, level = imp
            sub = self.resolve_module(f"{base}.{attr}" if base else attr, mod, level)
            if sub:
                return [("module", m) for m in sub]
            out = []
            if hops < _MAX_IMPORT_HOPS and (base or level):
                for m in self.resolve_module(base, mod, level):
                    out.extend(self.resolve_name(m, attr, hops + 1))
            internal = [t for t in out if t[0] != "ext"]
            if internal:
                return internal
            if out:
                return out
            return [("ext", f"{base}.{attr}" if base and not level else attr)]
        if name in mod.nested:
            return [("func", f) for f in mod.nested[name]]
        if hops < _MAX_IMPORT_HOPS:
            for base, level in mod.stars:
                for m in self.resolve_module(base, mod, level):
                    r = [t for t in self.resolve_name(m, name, hops + 1) if t[0] != "ext"]
                    if r:
                        return r
        return []

    def canonical(self, mod, dotted):
        """Replace an import alias at the head of a dotted name with what it
        imports: `sp.run` -> `subprocess.run`, `check_output` (from
        subprocess) -> `subprocess.check_output`."""
        head, sep, rest = dotted.partition(".")
        imp = mod.imports.get(head)
        if imp is None:
            return dotted
        if imp[0] == "import":
            base = imp[1]
        else:
            base = f"{imp[1]}.{imp[2]}" if imp[1] and not imp[3] else imp[2]
        return base + (sep + rest if rest else "")

    def bases(self, cls):
        if cls.bases is None:
            cls.bases = []
            for b in cls.node.bases:
                for kind, t in self._expr_targets(cls.mod, b):
                    if kind == "class" and t is not cls and t not in cls.bases:
                        cls.bases.append(t)
                        t.subclasses.append(cls)
        return cls.bases

    def _expr_targets(self, mod, node):
        if isinstance(node, ast.Name):
            return self.resolve_name(mod, node.id)
        if isinstance(node, ast.Attribute):
            out = []
            for kind, t in self._expr_targets(mod, node.value):
                if kind == "module":
                    out.extend(self.resolve_name(t, node.attr))
            return out
        return []

    def lookup_method(self, cls, name):
        seen, stack = set(), [cls]
        while stack:
            c = stack.pop(0)
            if id(c) in seen:
                continue
            seen.add(id(c))
            if name in c.methods:
                return [c.methods[name]]
            stack.extend(self.bases(c))
        return []

    def mro_attr_taint(self, cls, attr):
        seen, stack, t = set(), [cls], None
        while stack:
            c = stack.pop()
            if id(c) in seen:
                continue
            seen.add(id(c))
            v = c.attr_taint.get(attr)
            if v is not None:
                t = v if t is None else t.union(v)
            stack.extend(self.bases(c))
        return t

    # ---------- call resolution ----------
    def _receiver(self, fn, val):
        if isinstance(val, ast.Name):
            if fn.cls is not None and fn.receiver and val.id == fn.receiver:
                return ("instance", fn.cls)
            if val.id in fn.types:
                return ("instance", fn.types[val.id])
            if val.id in fn.local_names:
                return None
            tl = self.resolve_name(fn.mod, val.id)
            mods = [t for k, t in tl if k == "module"]
            if mods:
                return ("module", mods)
            classes = [t for k, t in tl if k == "class"]
            if classes:
                return ("classref", classes[0])
            ext = [t for k, t in tl if k == "ext"]
            if ext:
                return ("ext", ext[0])
            return None
        if isinstance(val, ast.Call):
            if isinstance(val.func, ast.Name) and val.func.id == "super" and fn.cls is not None:
                return ("super", fn.cls)
            classes = [t for k, t in self._expr_targets(fn.mod, val.func) if k == "class"]
            if classes:
                return ("instance", classes[0])
            return None
        if isinstance(val, ast.Attribute):
            tl = self._expr_targets(fn.mod, val)
            mods = [t for k, t in tl if k == "module"]
            if mods:
                return ("module", mods)
            classes = [t for k, t in tl if k == "class"]
            if classes:
                return ("classref", classes[0])
            root = val
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id not in fn.local_names and not (
                    fn.receiver and root.id == fn.receiver):
                if any(k == "ext" for k, _ in self.resolve_name(fn.mod, root.id)):
                    return ("ext", None)
        return None

    def resolve_call(self, fn, call):
        key = (id(call), id(fn))
        res = self._call_cache.get(key)
        if res is None:
            res = self._resolve_call(fn, call)
            self._call_cache[key] = res
        return res

    def _resolve_call(self, fn, call):
        func = call.func
        canon = self.canonical(fn.mod, _dotted(func))
        targets, ctor, precise = [], None, True

        def add_class(c):
            nonlocal ctor
            ctor = c
            for m in self.lookup_method(c, "__init__"):
                targets.append((m, True))

        if isinstance(func, ast.Name):
            tl = self.resolve_name(fn.mod, func.id)
            if not tl and func.id not in _BUILTIN_NAMES and func.id not in fn.local_names:
                cands = self.funcs_by_name.get(func.id, [])
                if len(cands) == 1:           # unique project-wide fallback
                    tl = [("func", cands[0])]
            for kind, t in tl:
                if kind == "func":
                    targets.append((t, False))
                elif kind == "class":
                    add_class(t)
        elif isinstance(func, ast.Attribute):
            attr = func.attr
            recv = self._receiver(fn, func.value)
            if recv is None:
                if not attr.startswith("__") and attr not in _COMMON_METHODS:
                    cands = self.methods_by_name.get(attr, [])
                    if 0 < len(cands) <= MAX_DUCK_CANDIDATES:
                        precise = False
                        targets = [(m, m.kind != "static") for m in cands]
            elif recv[0] == "instance":
                targets = [(m, m.kind != "static") for m in self.lookup_method(recv[1], attr)]
            elif recv[0] == "super":
                for b in self.bases(recv[1]):
                    targets.extend((m, m.kind != "static") for m in self.lookup_method(b, attr))
            elif recv[0] == "classref":
                targets = [(m, m.kind == "class") for m in self.lookup_method(recv[1], attr)]
            elif recv[0] == "module":
                for m in recv[1]:
                    for kind, t in self.resolve_name(m, attr):
                        if kind == "func":
                            targets.append((t, False))
                        elif kind == "class":
                            add_class(t)
        return _CallRes(targets, ctor, canon, precise and bool(targets or ctor))

    # ---------- pre-pass ----------
    def prepass(self, fn):
        nodes = list(_own_nodes(fn.body()))
        names = set(fn.posonly + fn.args + fn.kwonly)
        names.update(x for x in (fn.vararg, fn.kwarg) if x)
        for n in nodes:
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                names.add(n.id)
        if not fn.pseudo:
            fn.local_names = names
        for n in nodes:
            if (isinstance(n, ast.Assign) and len(n.targets) == 1
                    and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Call)):
                classes = [t for k, t in self._expr_targets(fn.mod, n.value.func) if k == "class"]
                if classes:
                    fn.types[n.targets[0].id] = classes[0]
        for n in nodes:
            if isinstance(n, ast.Call):
                for f, _ in self.resolve_call(fn, n).targets:
                    fn.callees.add(f)
                    f.callers.add(fn)


# Route handlers (0.1.7): the parameters a web framework fills from the
# request are concrete sources in the handler (lazaret.scanner.frameworks
# decides which, for both engines). A flow from one into another function's
# sink is an X-* finding; one into a sink of the handler itself is the
# intra-file engine's (T-*).
_FRAMEWORK_MODULES = {"flask": "flask", "quart": "flask", "fastapi": "fastapi", "django": "django"}


def _frameworks_of(mod):
    """The frameworks module `mod` imports ({'flask', 'fastapi', 'django'})."""
    got = getattr(mod, "_frameworks", None)
    if got is None:
        got = set()
        for rec in mod.imports.values():
            base = rec[1] if rec[0] == "import" else (rec[1] if not rec[3] else "")
            head = (base or "").split(".")[0]
            if head in _FRAMEWORK_MODULES:
                got.add(_FRAMEWORK_MODULES[head])
        mod._frameworks = got
    return got


def _text(node):
    """The source text of an annotation or default node ('' for None)."""
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:                          # a node unparse cannot render
        return ""


def _request_params(fn):
    """The parameters of `fn` a web framework fills from the request, if it
    is a route handler (see above)."""
    got = getattr(fn, "_request_params", None)
    if got is not None:
        return got
    got = []
    if not fn.pseudo:
        fws = _frameworks_of(fn.mod)
        a = fn.node.args
        positional = list(getattr(a, "posonlyargs", [])) + list(a.args)
        defaults = [None] * (len(positional) - len(a.defaults)) + list(a.defaults)
        params = ([(x.arg, _text(x.annotation), _text(d)) for x, d in zip(positional, defaults)]
                  + [(x.arg, _text(x.annotation), _text(d)) for x, d in zip(a.kwonlyargs, a.kw_defaults)])
        routed = False
        for d in fn.node.decorator_list:
            if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)):
                continue
            method = d.func.attr
            if method == "route" or ("flask" in fws and method in frameworks.FLASK_ROUTE_METHODS):
                routed = True
                rule = next((x.value for x in d.args[:1] if isinstance(x, ast.Constant) and isinstance(x.value, str)),
                            next((k.value.value for k in d.keywords if k.arg == "rule"
                                  and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str)), ""))
                free = frameworks.flask_free_vars(rule)
                got.extend(name for name, _, _ in params if name in free)
            elif "fastapi" in fws and method in frameworks.FASTAPI_ROUTE_METHODS:
                routed = True
                aliases = getattr(fn.mod, "_dep_aliases", None)
                if aliases is None:
                    aliases = fn.mod._dep_aliases = frameworks.dep_aliases("\n".join(fn.mod.lines))
                got.extend(name for name, ann, dflt in params if frameworks.fastapi_param(name, ann, dflt, aliases))
        if not routed and "django" in fws:
            names = [name for name, _, _ in params]
            first = 2 if names[:2] == ["self", "request"] else 1 if names[:1] == ["request"] else 0
            if first:
                got.extend(name for name, ann, _ in params[first:] if frameworks.django_param(name, ann))
            if first and a.vararg is not None:
                got.append(a.vararg.arg)
            if first and a.kwarg is not None:
                got.append(a.kwarg.arg)
        got = list(dict.fromkeys(got))
    fn._request_params = got
    return got


# Guards (0.1.7), the intra-file engine's in AST form: a path check —
# `x.is_relative_to(base)`, `x.startswith(base)`, `os.path.realpath(x)
# .startswith(base)`, `".." not in x` — or an allowlist check — `x in
# ALLOWED` against a collection that holds no request data — clears the value
# in the branch where it passed: inside the body of a positive test, and past
# an `if` whose body leaves (return, raise, continue, break, abort(),
# sys.exit()) on a negative one. A path check clears path traversal, an
# allowlist every category.
_PATH_CHECKS = frozenset(("is_relative_to", "startswith"))
_EXIT_CALLS = frozenset(("abort", "flask.abort", "sys.exit", "exit"))


def _guard_of(test):
    """(name, categories, positive, collection node or None) of a guard
    `test` (see above), else None."""
    positive = True
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        positive, test = False, test.operand
    if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and test.func.attr in _PATH_CHECKS \
            and test.args:
        target = test.func.value
        if isinstance(target, ast.Call) and _dotted(target.func).rsplit(".", 1)[-1] in (
                "realpath", "abspath", "normpath", "resolve") and (target.args or isinstance(target.func, ast.Attribute)):
            target = target.args[0] if target.args else target.func.value
        if isinstance(target, ast.Name):
            return target.id, {"path traversal"}, positive, None
        return None
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], (ast.In, ast.NotIn)):
        left, right = test.left, test.comparators[0]
        negated = isinstance(test.ops[0], ast.NotIn) != (not positive)
        if isinstance(left, ast.Constant) and isinstance(left.value, str) and left.value.startswith("..") \
                and isinstance(right, ast.Name):
            # `".." in x` fails the check; `".." not in x` passes it
            return right.id, {"path traversal"}, negated, None
        if isinstance(left, ast.Name) and not (isinstance(right, ast.Constant) and isinstance(right.value, str)):
            return left.id, set(ALL_CATS), not negated, right
    return None


def _leaves(body):
    """Does a block always leave its function or loop at its end?"""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    return (isinstance(last, ast.Expr) and isinstance(last.value, ast.Call)
            and _dotted(last.value.func) in _EXIT_CALLS)


class _Analyzer:
    """One pass over one function: computes its summary contributions and,
    when emit is set, the findings at its call sites and sinks."""

    def __init__(self, proj, fn, emit, findings):
        self.p = proj
        self.fn = fn
        self.emit = emit
        self.findings = findings
        self.env = {p: _Taint(params={p}) for p in fn.params}
        for p in _request_params(fn):          # a route handler's: request data
            self.env[p] = _Taint(source=True, params={p}, origin=self.here(fn.line))
        if fn.receiver:
            self.env[fn.receiver] = EMPTY
        self.sink_adds = []
        self.ret_params = {}
        self.ret_source = None
        self.attr_writes = {}

    # ---------- reporting / summaries ----------
    def here(self, line):
        return f"{self.fn.file}:{line}"

    def sink_loc(self, line):
        if self.fn.pseudo:
            return f"{self.fn.file}:{line} (module level)"
        return f"{self.fn.file}:{line} (in {self.fn.qualname}())"

    def report(self, cat, line, source_loc, sink_loc, chain):
        self.findings.append(_issue(cat, self.fn.file, line, self.fn.lines,
                                    source_loc=source_loc, sink_loc=sink_loc,
                                    chain=chain))

    def ret(self, t):
        if t.source:
            self.ret_source = t if self.ret_source is None else self.ret_source.union(t)
        for p in t.params:
            self.ret_params[p] = (t.clean if p not in self.ret_params
                                  else self.ret_params[p] & t.clean)

    def sink(self, cat, t, line):
        if t is None or not t.tainted() or cat in t.clean:
            return
        for p in t.params:
            self.sink_adds.append((p, cat, self.sink_loc(line)))
        if t.source and t.via and self.emit:
            # a source returned by another function reaches a sink here —
            # the intra-file engine cannot see this one (finding 7)
            self.report(cat, line, t.origin, self.here(line),
                        f"the value returned by {t.via}()")

    # ---------- statements ----------
    def run(self):
        self.stmts(self.fn.body())

    def stmts(self, body):
        for st in body:
            self.stmt(st)

    def _fork(self):
        return dict(self.env)

    @staticmethod
    def _merge(a, b):
        out = dict(a)
        for k, v in b.items():
            out[k] = out[k].union(v) if k in out else v
        return out

    def stmt(self, st):
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for d in st.decorator_list:
                self.expr(d)
            return
        if isinstance(st, ast.Assign):
            v = self.expr(st.value)
            for tgt in st.targets:
                self.assign(tgt, v)
        elif isinstance(st, ast.AugAssign):
            v = self.expr(st.value)
            self.assign(st.target, self.expr(st.target).union(v))
        elif isinstance(st, ast.AnnAssign):
            if st.value is not None:
                self.assign(st.target, self.expr(st.value))
        elif isinstance(st, ast.Return):
            self.ret(self.expr(st.value) if st.value is not None else EMPTY)
        elif isinstance(st, ast.Expr):
            self.expr(st.value)
        elif isinstance(st, ast.If):
            self.expr(st.test)
            guard = self.guard(st.test)
            before = self._fork()
            if guard is not None and guard[2]:            # the value passed the check in the body
                self.env[guard[0]] = self.name_taint(guard[0]).sanitize(guard[1])
            self.stmts(st.body)
            after_body = self.env
            self.env = before
            if guard is not None and not guard[2] and _leaves(st.body):
                # the body leaves when the value fails the check: past the if it passed
                self.env[guard[0]] = self.name_taint(guard[0]).sanitize(guard[1])
                self.stmts(st.orelse)
            else:
                self.stmts(st.orelse)
                self.env = self._merge(after_body, self.env)
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            it = self.expr(st.iter)
            before = self._fork()
            for _ in range(2):                 # second round: loop-carried taint
                self.assign(st.target, it)
                self.stmts(st.body)
            self.env = self._merge(before, self.env)
            self.stmts(st.orelse)
        elif isinstance(st, ast.While):
            before = self._fork()
            for _ in range(2):
                self.expr(st.test)
                self.stmts(st.body)
            self.env = self._merge(before, self.env)
            self.stmts(st.orelse)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                v = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, v)
            self.stmts(st.body)
        elif isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
            before = self._fork()
            self.stmts(st.body)
            after = self.env
            merged = self._merge(before, after)
            outs = [after]
            for h in st.handlers:
                self.env = dict(merged)
                if h.type is not None:
                    self.expr(h.type)
                if h.name:
                    self.env[h.name] = EMPTY
                self.stmts(h.body)
                outs.append(self.env)
            self.env = after
            self.stmts(st.orelse)
            outs[0] = self.env
            acc = outs[0]
            for o in outs[1:]:
                acc = self._merge(acc, o)
            self.env = acc
            self.stmts(st.finalbody)
        elif type(st).__name__ == "Match":
            subj = self.expr(st.subject)
            before = self._fork()
            acc = before
            for case in st.cases:
                self.env = dict(before)
                self.bind_pattern(case.pattern, subj)
                if case.guard is not None:
                    self.expr(case.guard)
                self.stmts(case.body)
                acc = self._merge(acc, self.env)
            self.env = acc
        elif isinstance(st, ast.Raise):
            self.expr(st.exc)
            self.expr(st.cause)
        elif isinstance(st, ast.Assert):
            self.expr(st.test)
            self.expr(st.msg)
        elif isinstance(st, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
                             ast.Pass, ast.Break, ast.Continue, ast.Delete)):
            return
        else:
            for child in ast.iter_child_nodes(st):
                if isinstance(child, ast.expr):
                    self.expr(child)
                elif isinstance(child, ast.stmt):
                    self.stmt(child)

    def guard(self, test):
        """(name, categories, positive) when `test` checks a local name's
        value (see _guard_of), and the collection an allowlist is checked
        against holds no request data."""
        g = _guard_of(test)
        if g is None:
            return None
        name, cats, positive, coll = g
        if coll is not None and self.expr(coll).tainted():
            return None
        return name, cats, positive

    def bind_pattern(self, pat, t):
        stack = [pat]
        while stack:
            p = stack.pop()
            if p is None:
                continue
            name = getattr(p, "name", None) or getattr(p, "rest", None)
            if isinstance(name, str):
                self.env[name] = t
            for field in ("pattern", "patterns", "kwd_patterns"):
                sub = getattr(p, field, None)
                if isinstance(sub, list):
                    stack.extend(sub)
                elif sub is not None:
                    stack.append(sub)

    def assign(self, tgt, t):
        if isinstance(tgt, ast.Name):
            self.env[tgt.id] = t
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            for e in tgt.elts:
                self.assign(e, t)
        elif isinstance(tgt, ast.Starred):
            self.assign(tgt.value, t)
        elif isinstance(tgt, ast.Attribute):
            if isinstance(tgt.value, ast.Name):
                self.env[f"{tgt.value.id}.{tgt.attr}"] = t
                fn = self.fn
                if fn.cls is not None and fn.receiver == tgt.value.id and t.source:
                    prev = self.attr_writes.get(tgt.attr)
                    self.attr_writes[tgt.attr] = t if prev is None else prev.union(t)
            else:
                self.expr(tgt.value)
        elif isinstance(tgt, ast.Subscript):
            self.expr(tgt.slice)
            base = tgt.value
            if isinstance(base, ast.Name):
                self.env[base.id] = self.name_taint(base.id).union(t)
            else:
                self.expr(base)

    # ---------- expressions ----------
    def name_taint(self, name):
        v = self.env.get(name)
        if v is None:
            v = self.fn.mod.globals.get(name, EMPTY)
        return v

    def source(self, line):
        return _Taint(source=True, origin=self.here(line))

    def expr(self, e):
        if e is None:
            return EMPTY
        if isinstance(e, ast.Name):
            return self.name_taint(e.id)
        if isinstance(e, ast.Constant):
            return EMPTY
        if isinstance(e, ast.Call):
            return self.call(e)
        if isinstance(e, ast.Attribute):
            s = _dotted(e)
            if _is_py_source(s, self.p.canonical(self.fn.mod, s)):
                return self.source(e.lineno)
            if isinstance(e.value, ast.Name):
                k = f"{e.value.id}.{e.attr}"
                if k in self.env:
                    return self.env[k]
                fn = self.fn
                if fn.cls is not None and fn.receiver == e.value.id:
                    t = self.p.mro_attr_taint(fn.cls, e.attr)
                    if t is not None:
                        return t
            return self.expr(e.value)
        if isinstance(e, ast.Subscript):
            s = _dotted(e)
            if _is_py_source(s, self.p.canonical(self.fn.mod, s)):
                self.expr(e.slice)
                return self.source(e.lineno)
            v = self.expr(e.value)
            self.expr(e.slice)
            return v
        if isinstance(e, ast.BinOp):
            return self.expr(e.left).union(self.expr(e.right))
        if isinstance(e, ast.BoolOp):
            return _union_all([self.expr(v) for v in e.values])
        if isinstance(e, ast.UnaryOp):
            v = self.expr(e.operand)
            return EMPTY if isinstance(e.op, ast.Not) else v
        if isinstance(e, ast.Compare):
            self.expr(e.left)
            for c in e.comparators:
                self.expr(c)
            return EMPTY
        if isinstance(e, ast.IfExp):
            self.expr(e.test)
            return self.expr(e.body).union(self.expr(e.orelse))
        if isinstance(e, ast.JoinedStr):
            return _union_all([self.expr(v) for v in e.values])
        if isinstance(e, ast.FormattedValue):
            self.expr(e.format_spec)
            return self.expr(e.value)
        if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
            return _union_all([self.expr(x) for x in e.elts])
        if isinstance(e, ast.Dict):
            return _union_all([self.expr(x) for x in e.keys if x is not None]
                              + [self.expr(x) for x in e.values])
        if isinstance(e, (ast.Starred, ast.Await)):
            return self.expr(e.value)
        if isinstance(e, (ast.Yield, ast.YieldFrom)):
            self.ret(self.expr(e.value))       # generators "return" what they yield
            return EMPTY
        if isinstance(e, ast.NamedExpr):
            v = self.expr(e.value)
            self.assign(e.target, v)
            return v
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self.comprehension(e.generators, [e.elt])
        if isinstance(e, ast.DictComp):
            return self.comprehension(e.generators, [e.key, e.value])
        if isinstance(e, ast.Lambda):
            return EMPTY
        for child in ast.iter_child_nodes(e):
            if isinstance(child, ast.expr):
                self.expr(child)
        return EMPTY

    def comprehension(self, generators, elts):
        saved = self.env
        self.env = dict(saved)
        for gen in generators:
            self.assign(gen.target, self.expr(gen.iter))
            for cond in gen.ifs:
                self.expr(cond)
        out = _union_all([self.expr(x) for x in elts])
        self.env = saved
        return out

    def call(self, e):
        fn, p = self.fn, self.p
        raw = _dotted(e.func)
        res = p.resolve_call(fn, e)
        canon = res.canon
        recv = self.expr(e.func.value) if isinstance(e.func, ast.Attribute) else EMPTY
        pos, starred, kws, dstar = [], None, [], None
        body = None      # a response's body, when its first argument is a (body, status/headers) tuple
        for a in e.args:
            if not pos and starred is None and isinstance(a, ast.Tuple) and a.elts:
                elts = [self.expr(x) for x in a.elts]      # as self.expr(a), keeping the first
                body = elts[0]
                pos.append(_union_all(elts))
            elif isinstance(a, ast.Starred):
                v = self.expr(a.value)
                starred = v if starred is None else starred.union(v)
            elif starred is not None:          # positional after *x: position unknown
                starred = starred.union(self.expr(a))
            else:
                pos.append(self.expr(a))
        for k in e.keywords:
            v = self.expr(k.value)
            if k.arg is None:
                dstar = v if dstar is None else dstar.union(v)
            else:
                kws.append((k.arg, v))
        all_args = _union_all(pos + [starred, dstar] + [v for _, v in kws])
        line = getattr(e, "lineno", 1)

        # 1) sources: request.args.get(...), input(), sys.argv, …
        if (_is_py_source(raw, canon) or raw == "input"
                or raw.endswith(".get_json")):
            return self.source(line)

        # 2) direct sink. Only the primary data argument is a sink position
        # (execute("… %s", (x,)) stays clean). Not emitted when the source is
        # read in this same function — that flow is intra-procedural and the
        # intra-file engine reports it; this records the param→sink summary
        # and reports sources that arrived through another function's return.
        cat = _py_config_sink(raw, canon)
        if cat is None and not res.precise:
            cat = _py_builtin_sink(canon) or _py_builtin_sink(raw)
        if cat:
            first = (body if body is not None and cat == "cross-site scripting"
                     else pos[0] if pos else starred if starred is not None
                     else kws[0][1] if kws else dstar)
            self.sink(cat, first, line)

        # 3) calls into project functions whose parameters reach sinks
        bound_all = []
        for f, skip in res.targets:
            bound = _bind(f, pos, starred, kws, dstar, skip)
            bound_all.append((f, bound))
            for pname, cats in f.param_to_sink.items():
                t = bound.get(pname)
                if t is None or not t.tainted():
                    continue
                for c, loc in cats.items():
                    if c in t.clean:                 # sanitized for this sink
                        continue
                    if t.source and self.emit:
                        self.report(c, line, t.origin, loc,
                                    f"the call to {f.qualname}()")
                    for q in t.params:                # transitivity
                        self.sink_adds.append((q, c, loc))

        # 4) the call's own value
        san = _py_config_sanitizer(raw, canon)
        if san == "full":
            return EMPTY
        if san is not None:
            return all_args.sanitize(san)
        if bound_all or res.ctor is not None:
            t = EMPTY
            for f, bound in bound_all:
                if f.ret_source is not None:
                    rs = f.ret_source
                    t = t.union(_Taint(True, (), rs.clean, rs.origin, f.qualname))
                for pname, clean in f.param_to_return.items():
                    b = bound.get(pname)
                    if b is not None and b.tainted():
                        t = t.union(b.sanitize(clean))
            if res.ctor is not None or not res.precise:
                t = t.union(all_args)          # objects carry their data
            return t
        san = _py_builtin_sanitizer(canon, raw)
        if san == "full":
            return EMPTY
        if canon in FULL_RESULT_PY or raw in FULL_RESULT_PY or _ORM_RESULT_RE.search(f".{raw}"):
            return EMPTY                       # a looked-up record, a file's content
        if canon in _SQL_BUILDER_FUNCS or raw in _SQL_BUILDER_FUNCS or (
                isinstance(e.func, ast.Attribute) and e.func.attr in _SQL_BUILDER_METHODS):
            return all_args.union(recv).sanitize({"SQL injection"})     # a parameterized query
        if san is not None:
            return all_args.sanitize(san)
        if raw.rsplit(".", 1)[-1] in _CLEAN_RESULT:
            return EMPTY
        return all_args.union(recv)            # unknown call: taint propagates

    # ---------- commit ----------
    def commit(self):
        """Merge this pass into the function's summary (monotone: sinks and
        returned params only grow, clean sets only shrink). Returns
        (summary_changed, class_attrs_changed, globals_changed)."""
        f = self.fn
        changed = cls_changed = glob_changed = False
        for pname, cat, loc in self.sink_adds:
            d = f.param_to_sink.setdefault(pname, {})
            if cat not in d:
                d[cat] = loc
                changed = True
        for pname, clean in self.ret_params.items():
            old = f.param_to_return.get(pname)
            new = clean if old is None else (old & clean)
            if new != old:
                f.param_to_return[pname] = new
                changed = True
        rs = self.ret_source
        if rs is not None:
            old = f.ret_source
            if old is None:
                f.ret_source = _Taint(True, (), rs.clean, rs.origin, rs.via)
                changed = True
            elif (old.clean & rs.clean) != old.clean:
                f.ret_source = _Taint(True, (), old.clean & rs.clean, old.origin, old.via)
                changed = True
        if f.cls is not None:
            for attr, t in self.attr_writes.items():
                old = f.cls.attr_taint.get(attr)
                new = _Taint(True, (), t.clean if old is None else old.clean & t.clean,
                             t.origin if old is None else old.origin,
                             t.via if old is None else old.via)
                if old is None or new.clean != old.clean:
                    f.cls.attr_taint[attr] = new
                    cls_changed = True
        if f.pseudo:
            g = f.mod.globals
            for name, t in self.env.items():
                if "." in name or not t.source:
                    continue
                old = g.get(name)
                if old is None or (old.clean & t.clean) != old.clean:
                    g[name] = _Taint(True, (), t.clean if old is None else old.clean & t.clean,
                                     t.origin if old is None else old.origin,
                                     t.via if old is None else old.via)
                    glob_changed = True
        return changed, cls_changed, glob_changed


def _flow_note(rule, name, fname, line, msg, why, fix):
    return {"rule": rule, "name": name, "type": "SMELL", "sev": "INFO",
            "msg": msg, "why": why, "fix": fix,
            "ref": "CWE-400 (uncontrolled resource consumption)" if rule == "Q-FLOW-RECURSION"
                   else "Analysis coverage",
            "file": fname, "line": line, "snippet": [], "snipStart": 1}


def _parse_py(f):
    """(tree, None) or (None, (kind, detail)); kind is 'overflow' or 'skip'.
    Never raises: one unparseable file costs only that file (finding 6)."""
    content = f.get("content")
    if not isinstance(content, str):
        return None, ("skip", "content is not text")
    try:
        return ast.parse(content), None
    except (RecursionError, MemoryError):
        # a deep operator chain can overflow the *parser* itself (Python
        # 3.11 / Windows: RecursionError; "Parser stack overflowed":
        # MemoryError)
        return None, ("overflow", None)
    except SyntaxError as exc:
        text = str(getattr(exc, "msg", "") or exc)
        if "null bytes" in text.lower():
            return None, ("skip", "it contains NUL bytes")
        if ("Missing parentheses in call to 'print'" in text
                or "Missing parentheses in call to 'exec'" in text
                or re.search(r"^\s*print\s+[\"'\w]", content, re.M)):
            return None, ("skip", "it looks like Python 2 source")
        return None, ("skip", f"syntax error at line {getattr(exc, 'lineno', '?')}")
    except ValueError as exc:                  # NUL bytes on Python 3.10/3.11
        if "null bytes" in str(exc).lower():
            return None, ("skip", "it contains NUL bytes")
        return None, ("skip", f"it could not be parsed ({type(exc).__name__})")
    except Exception as exc:                   # never drop the whole pass
        return None, ("skip", f"it could not be parsed ({type(exc).__name__})")


def _analyze_python(files, findings, time_budget=None):
    budget = FLOW_TIME_BUDGET if time_budget is None else time_budget
    started = time.monotonic()
    overflow = {}   # file -> lowest line that hit a stack limit (1: the parser)
    skipped = {}    # file -> reason the parser rejected it
    notes = []
    proj = _PyProject()
    py_files = [f for f in files if f.get("lang") == "py"]
    total, over_budget = 0, []
    for f in py_files:
        size = len(f.get("content") or "")
        if len(proj.modules) >= FLOW_MAX_FILES or total + size > FLOW_MAX_BYTES:
            over_budget.append(f.get("path", "?"))
            continue
        tree, err = _parse_py(f)
        if err is not None:
            if err[0] == "overflow":
                overflow[f["path"]] = 1
            else:
                skipped[f["path"]] = err[1]
            continue
        total += size
        try:
            proj.add_module(_PyModule(f["path"], f["content"], tree))
        except RecursionError:
            overflow[f["path"]] = 1
    if over_budget:
        notes.append(_flow_note(
            "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)",
            over_budget[0], 1,
            f"Cross-file taint analysis skipped {len(over_budget)} Python file(s) "
            f"beyond its budget ({FLOW_MAX_FILES} files / {FLOW_MAX_BYTES:,} "
            f"characters), starting with {over_budget[0]!r}.",
            "Very large code bases are analyzed up to a fixed budget so a scan "
            "cannot run unbounded; flows through the skipped files are not seen.",
            "Scan sub-trees separately, or exclude generated code."))

    funcs = [fn for m in proj.modules for fn in m.all_funcs]

    def guarded(fn, emit):
        try:
            a = _Analyzer(proj, fn, emit, findings)
            a.run()
            return a.commit()
        except RecursionError:
            overflow[fn.file] = min(overflow.get(fn.file, 1 << 30), fn.line)
            return (False, False, False)

    for fn in funcs:
        try:
            proj.prepass(fn)
        except RecursionError:
            overflow[fn.file] = min(overflow.get(fn.file, 1 << 30), fn.line)

    # callee-first order (iterative DFS post-order), then a worklist: a
    # function is re-analyzed only when a summary it depends on changed.
    order, seen = [], set()
    for root in funcs:
        if id(root) in seen:
            continue
        seen.add(id(root))
        stack = [(root, iter(root.callees))]
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                order.append(node)
            elif id(nxt) not in seen:
                seen.add(id(nxt))
                stack.append((nxt, iter(nxt.callees)))
    queue = collections.deque(order)
    queued = {id(f) for f in order}
    cutoff, timed_out = [], False
    while queue:
        if time.monotonic() - started > budget:
            timed_out = True
            break
        fn = queue.popleft()
        queued.discard(id(fn))
        fn.runs += 1
        changed, cls_changed, glob_changed = guarded(fn, emit=False)
        deps = set()
        if changed:
            deps.update(fn.callers)
        if cls_changed:
            stack, seen_c = [fn.cls], set()
            while stack:
                c = stack.pop()
                if id(c) in seen_c:
                    continue
                seen_c.add(id(c))
                deps.update(c.methods.values())
                stack.extend(c.subclasses)
        if glob_changed:
            deps.update(fn.mod.all_funcs)
        for d in deps:
            if id(d) in queued:
                continue
            if d.runs >= MAX_ITERS:
                cutoff.append(d)
                continue
            queue.append(d)
            queued.add(id(d))
    if cutoff:
        first = min(cutoff, key=lambda f: (f.file, f.line))
        notes.append(_flow_note(
            "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (iteration cap)",
            first.file, first.line,
            f"Interprocedural summaries for {len(cutoff)} function(s) did not "
            f"converge within {MAX_ITERS} re-analyses (first: "
            f"{first.qualname}() in {first.file!r}); flows through them may be "
            f"missing.",
            "Summaries are iterated to a fixpoint with a generous safety cap; "
            "hitting it means an unusually long or cyclic call chain.",
            "Report the pattern to the Lazaret maintainers; split the chain if "
            "possible."))
    if timed_out:
        first = funcs[0].file if funcs else "?"
        notes.append(_flow_note(
            "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (time budget)",
            first, 1,
            f"Cross-file taint analysis stopped after {budget:.0f} s before its "
            f"summaries converged; findings may be missing.",
            "The interprocedural pass has a time budget so a scan cannot run "
            "unbounded on very large code bases.",
            "Scan sub-trees separately, or exclude generated code."))
    # final emission pass
    for fn in order:
        guarded(fn, emit=True)
        if time.monotonic() - started > 2 * budget:
            break
    for fname in sorted(overflow):
        notes.append(_flow_note(
            "Q-FLOW-RECURSION", "Flow analysis incomplete (recursion cutoff)",
            fname, overflow[fname],
            f"Lazaret's flow pass hit Python's parser/recursion limit while "
            f"analyzing {fname!r} — findings for the affected function(s) may "
            f"be missing; every other function was still analyzed.",
            "A pathologically deep expression (e.g. a long operator chain in "
            "generated code) can overflow Python's parser or the analysis "
            "stack even though it is valid Python. Lazaret skips only the "
            "affected function(s), or the file if the parser overflowed, "
            "instead of crashing the whole scan.",
            "Split or format the flagged file to keep expressions shallow, "
            "then re-run Lazaret."))
    for fname in sorted(skipped):
        notes.append(_flow_note(
            "Q-FLOW-SKIPPED", "File skipped by flow analysis",
            fname, 1,
            f"Cross-file taint analysis skipped {fname!r}: {skipped[fname]}.",
            "Only files Python 3 can parse take part in the interprocedural "
            "pass; flows into or out of this file are not seen (the "
            "per-file rules still ran).",
            "Fix the syntax error (or port the file to Python 3), then re-run."))
    findings.extend(notes)


# ======================================================================
# JavaScript — bounded heuristic (no JS parser available)
# ======================================================================
_JS_FUNC_RE = re.compile(
    r"(?:function\s+(?P<n1>\w+)\s*\((?P<p1>[^)]*)\)"
    r"|(?:const|let|var)\s+(?P<n2>\w+)\s*=\s*(?:async\s*)?\((?P<p2>[^)]*)\)\s*=>"
    r"|(?:const|let|var)\s+(?P<n3>\w+)\s*=\s*(?:async\s*)?function\s*\((?P<p3>[^)]*)\))")
_JS_SOURCE_RE = re.compile(
    r"req\.(query|body|params|headers|cookies)|process\.argv|location\.(search|hash|href)")
_JS_CMD_SINK_RE = re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\(")   # not on a RegExp (_js_regexp_calls)
_JS_SINKS = [
    (re.compile(r"\.(query|execute)\s*\("), "SQL injection"),
    (_JS_CMD_SINK_RE, "command injection"),
    (re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\("), "code injection"),
    (re.compile(r"\.innerHTML\s*=|document\.write\s*\("), "cross-site scripting"),
    (re.compile(r"\bfetch\s*\(|axios(\.\w+)?\s*\("), "server-side request forgery"),
    (re.compile(r"\.redirect\s*\("), "open redirect"),
]


# ---- a small linear lexer (review finding 12) ----
# The brace pass used to count braces inside strings, comments, regex and
# template literals: `const b = "}"; exec(cmd);` closed the function early
# (missed sink) and `console.log("{" + cmd)` made one function swallow the
# next (false positive). _js_mask() returns a same-length copy of the source
# in which the CONTENT of '…', "…", `…` template text, comments and regex
# literals is blanked (delimiters, ${…} code and newlines are kept), so every
# later regex/brace pass only sees code. Regex literals are recognized
# heuristically: a '/' where an expression may start (after an operator,
# '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';' or a keyword
# like return/typeof), never after an identifier, number, ')' or ']'.
_JS_TOKEN_RE = re.compile(
    r"(?P<ws>\s+)"
    r"|(?P<lc>//[^\n  ]*)"
    r"|(?P<bc>/\*.*?(?:\*/|\Z))"
    r"|(?P<sq>'(?:[^'\\\n]|\\.)*'?)"
    r"|(?P<dq>\"(?:[^\"\\\n]|\\.)*\"?)"
    r"|(?P<bt>`)"
    r"|(?P<id>[A-Za-z_$\u0080-￿][\w$\u0080-￿]*)"
    r"|(?P<num>\d[\w.]*)"
    r"|(?P<p>.)", re.S)
_JS_TPL_TEXT_RE = re.compile(r"(?:[^`\\$]|\\.|\$(?!\{))*", re.S)
_JS_REGEX_LIT_RE = re.compile(r"/(?:[^/\\\[\n]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[A-Za-z]*")
_JS_NOT_NL_RE = re.compile(r"[^\n  ]")
_JS_REGEX_AFTER = set("(,=:[!&|?{};+-*%<>~^")
_JS_REGEX_KEYWORDS = frozenset((
    "return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
    "void", "throw", "instanceof", "yield", "await"))


def _js_mask(src, literals=None):
    """Same-length copy of src with string/template-text/comment/regex
    CONTENT replaced by spaces (newlines kept, ${…} code kept). Linear.
    literals (a dict), when given, receives the text of every closed '…' /
    "…" literal by the offset of its opening quote (module specifiers)."""
    out = []
    last_copy = 0
    n = len(src)

    def blank(a, b):
        nonlocal last_copy
        if b > a:
            out.append(src[last_copy:a])
            out.append(_JS_NOT_NL_RE.sub(" ", src[a:b]))
            last_copy = b

    def template_text(i):
        """Scan template text from i; returns (next index, opened ${)."""
        m = _JS_TPL_TEXT_RE.match(src, i)
        j = m.end()
        blank(i, j)
        if j >= n:
            return n, False
        if src[j] == "`":
            return j + 1, False
        return j + 2, True                      # at "${"

    stack = []            # brace depth inside each open ${ … }
    last_sig, last_word = "", ""
    i = 0
    while i < n:
        m = _JS_TOKEN_RE.match(src, i)
        kind = m.lastgroup
        j = m.end()
        if kind == "ws":
            i = j
            continue
        if kind in ("lc", "bc"):
            blank(i, j)
            i = j
            continue
        if kind in ("sq", "dq"):
            closed = j - i >= 2 and src[j - 1] == src[i]
            if literals is not None and closed:
                literals[i] = src[i + 1:j - 1]
            blank(i + 1, j - 1 if closed else j)
            last_sig, last_word = '"', ""
            i = j
            continue
        if kind == "bt":
            k, opened = template_text(i + 1)
            if opened:
                stack.append(0)
            last_sig, last_word = "`" if not opened else "{", ""
            i = k
            continue
        if kind == "id":
            last_sig, last_word = "a", m.group()
            i = j
            continue
        if kind == "num":
            last_sig, last_word = "0", ""
            i = j
            continue
        ch = m.group()
        if ch == "/" and (last_sig == "" or last_sig in _JS_REGEX_AFTER and last_sig != "}"
                          or (last_sig == "a" and last_word in _JS_REGEX_KEYWORDS)):
            rm = _JS_REGEX_LIT_RE.match(src, i)
            if rm is not None:
                end = rm.end()
                close = src.rindex("/", i + 1, end)
                blank(i + 1, close)
                last_sig, last_word = ")", ""     # a value: '/' after it divides
                i = end
                continue
        if ch == "{" and stack:
            stack[-1] += 1
        elif ch == "}" and stack:
            if stack[-1] == 0:
                stack.pop()
                k, opened = template_text(i + 1)
                if opened:
                    stack.append(0)
                last_sig, last_word = "`" if not opened else "{", ""
                i = k
                continue
            stack[-1] -= 1
        last_sig, last_word = ch, ""
        i = j
    out.append(src[last_copy:])
    return "".join(out)


def _js_braces(code):
    """(offsets of every '{', {offset of a '{': offset of its '}'}) of masked
    code — one stack pass; a '{' never closed has no entry."""
    opens, match_close, stack = [], {}, []
    for bm in re.finditer(r"[{}]", code):
        if bm.group() == "{":
            opens.append(bm.start())
            stack.append(bm.start())
        elif stack:
            match_close[stack.pop()] = bm.start()
    return opens, match_close


def _js_param_name(p):
    """A parameter as its uses spell it: without a default (`a = 1`), a
    TypeScript annotation (`a: string`, `a?: T`) or a rest marker (`...a`)."""
    name = p.strip().split("=")[0].strip().split(":")[0].strip()
    if name.endswith("?"):
        name = name[:-1].strip()
    if name.startswith("..."):
        name = name[3:].strip()
    return name


def _js_functions(content, code=None, braces=None, pairs=None, heads=None):
    """Yield (name, params[list], body_span, start_line).

    body_span is (start_offset, end_offset) into content — the slice the old
    version returned as a copied string. G3 fix: the old version brace-matched
    every _JS_FUNC_RE match by scanning content character by character to EOF
    and copying the whole body, which is O(matches × size) time and transient
    memory (audit G3: ~27 s and ~GB of copies for a 1.5 MB file of
    unterminated functions; an unterminated final brace scanned to EOF for
    every match). One linear brace pass now computes the spans; nothing is
    copied and no per-match scan runs. Headers and braces are read from the
    masked code (_js_mask), so braces in strings/comments/regex/template
    text no longer count.

    An arrow function whose body is an expression (`const f = (x) => g(x);`)
    spans that expression, to the end of its statement; it used to take the
    next '{' in the file, often another function's body. Parameter names drop
    TypeScript annotations and rest markers (_js_param_name). heads (a
    list), when given, receives the (start, stop) of each function's header.
    """
    if code is None:
        code = _js_mask(content)
    matches = list(_JS_FUNC_RE.finditer(code))
    if not matches:
        return []
    opens, match_close = braces if braces is not None else _js_braces(code)
    # newline offsets once, for start_line
    nl = [m.start() for m in re.finditer("\n", code)]
    from bisect import bisect_left
    out = []
    for m in matches:
        name = m.group("n1") or m.group("n2") or m.group("n3")
        params_s = m.group("p1") or m.group("p2") or m.group("p3") or ""
        params = [_js_param_name(p) for p in params_s.split(",") if p.strip()]
        if m.group("n2") is not None:
            b = m.end()
            while b < len(code) and code[b] in _JS_BLANK:
                b += 1
            if b >= len(code) or code[b] != "{":        # an expression body
                end = _js_arg_end(code, b, True) if pairs is None else _js_arg_end_at(code, b, True, pairs)
                out.append((name, params, (b, end), bisect_left(nl, m.start()) + 1))
                if heads is not None:
                    heads.append(m.span())
                continue
        # first '{' at/after m.end()-1 (a match may claim a brace inside its
        # own header)
        k = bisect_left(opens, m.end() - 1)
        if k == len(opens):
            continue
        brace = opens[k]
        close = match_close.get(brace, len(code))  # EOF if never closed
        start_line = bisect_left(nl, m.start()) + 1
        out.append((name, params, (brace, close + 1), start_line))
        if heads is not None:
            heads.append(m.span())
    return out


_JS_ARG_SCAN = 4000   # max characters scanned for a sink's argument list


_JS_ARG_STOP_RE = re.compile(r"[()\[\]{}]")
_JS_STATEMENT_STOP_RE = re.compile(r"[()\[\]{};\n]")


def _js_arg_end(code, k, statement):
    """Where an argument list (statement=False) or the rest of a statement
    (statement=True) that starts at k ends: at the first closing bracket
    without an opening one after k, or, for a statement, a ';' or newline
    outside brackets; else _JS_ARG_SCAN characters on."""
    stop = min(len(code), k + _JS_ARG_SCAN)
    depth = 0
    for m in (_JS_STATEMENT_STOP_RE if statement else _JS_ARG_STOP_RE).finditer(code, k, stop):
        ch = m.group()
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return m.start()
            depth -= 1
        elif depth == 0:                     # ';' or a newline ends a statement
            return m.start()
    return stop


def _js_sink_args(code, start, end):
    """The text a sink match can consume: the balanced argument list of a
    call sink (`exec(` … `)`), else the rest of the statement (`x.innerHTML
    = …;`). Computed on masked code, so parentheses in strings don't count.
    The old 200-character window after the sink also matched a parameter
    used in a LATER statement (`exec("uptime"); console.log(msg)`)."""
    k = end
    if not (end > start and code[end - 1] == "("):
        k2 = end
        while k2 < len(code) and code[k2] in " \t":
            k2 += 1
        if k2 < len(code) and code[k2] == "(":
            k = k2 + 1
        else:
            return code[end:_js_arg_end(code, end, True)]
    return code[k:_js_arg_end(code, k, False)]


def _js_sink_matches(pattern, code):
    """(start, end) of every sink match in code. Built-in sinks are compiled
    regexes; configured ones are taintspec.GuardedPattern (per-line, each
    line capped) — both expose finditer()."""
    for m in pattern.finditer(code):
        yield m.start(), m.end()


# JS sanitizers: full (numeric coercion) neutralize everything; partial clear a category.
_JS_FULL_SAN_RE = re.compile(r"(?:parseInt|parseFloat|Number)\s*\([^()]*\)")
_JS_PARTIAL_SAN = {
    "cross-site scripting": re.compile(
        r"(?:DOMPurify\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml)\s*\([^()]*\)"),
    "SQL injection": re.compile(r"(?:mysql2?|pool|connection|conn|db)\.escape\s*\([^()]*\)"),
    "path traversal": re.compile(r"path\.basename\s*\([^()]*\)"),
    "command injection": re.compile(r"(?:shellQuote|shell_quote|quote)\s*\([^()]*\)"),
}

# the built-in tables as they are before a taint config extends them
_JS_FULL_SAN_RE0 = _JS_FULL_SAN_RE
_JS_PARTIAL_SAN0 = dict(_JS_PARTIAL_SAN)


def _js_neutralize(text, cats):
    """Strip sanitizer call expressions so their sanitized content stops counting
    as tainted. Full sanitizers always; partial ones only for the given categories."""
    text = _JS_FULL_SAN_RE.sub(" ", text)
    for c in cats:
        if c in _JS_PARTIAL_SAN:
            text = _JS_PARTIAL_SAN[c].sub(" ", text)
    return text


_JS_PARAM_RES = {}      # (name, sql) -> its compiled pattern (re's own cache holds 512)


def _js_param_dangerous(seg, p, cat):
    """Does parameter p reach the sink in a dangerous way within seg?"""
    sql = cat == "SQL injection"
    rx = _JS_PARAM_RES.get((p, sql))
    if rx is None:
        pe = re.escape(p)
        # SQL: safe if p only appears inside a placeholder array, e.g.
        # query(sql, [p]); dangerous only when concatenated or interpolated
        # into the query string
        rx = re.compile(r"\+\s*%s\b|\b%s\s*\+|`[^`]*\$\{[^}]*\b%s\b" % (pe, pe, pe) if sql else r"\b%s\b" % pe)
        if len(_JS_PARAM_RES) > 4096:
            _JS_PARAM_RES.clear()
        _JS_PARAM_RES[(p, sql)] = rx
    return rx.search(seg) is not None


def _js_text(content):
    """JS source as the pattern engine numbers its lines (core.source_lines,
    shared semantics 1): U+2028 / U+2029 are ECMAScript line terminators, so
    they end a line like LF. Same length as content (one character for one),
    so offsets, the size cap and the masked code stay aligned; X-* line
    numbers and snippets then match core's findings on the same file."""
    if "\u2028" in content or "\u2029" in content:
        return content.replace("\u2028", "\n").replace("\u2029", "\n")
    return content


# ---- modules, calls and returned values (review follow-ups) ----
# The call-site pass used to bind a call to the last function of that name
# in the whole project, read a function's own header as a call, see only
# calls whose arguments held no parentheses, and know nothing of what
# functions return. It now reads modules, calls and returned values — and
# where it cannot tell what a call reaches, it assumes the call may reach
# any function of that name, never that it reaches nothing:
#   * binding. A call binds to the function its file names: a definition
#     visible from the call (in its own scope or an enclosing one), else
#     what a relative require() / import brings in (named, default and
#     namespace imports, `require('./x').f()`, a module or export copied to
#     another const, module.exports / exports.x / ESM exports, `export …
#     from` and `export *` through up to _JS_EXPORT_HOPS modules). Those
#     bindings are definite. Anything else is open — a package, a path
#     alias (`@/lib/x`), a workspace package, an export the pass does not
#     follow, `this.f()`, `obj.f()`, a name the file neither defines nor
#     imports, a binding assigned more than once: the call may reach any of
#     the project's functions of that name, and code outside the scan. Only
#     positive evidence binds nothing: a Node built-in module (`fs`,
#     `node:child_process`), or a member of a JavaScript global object
#     (`JSON.parse`, `Math.max`);
#   * a call's value. A definite call reads as what its function returns:
#     the request data the function reads and returns, and the call's
#     arguments — unless no return of the function can hold anything it is
#     given (literals, full sanitizers, calls to such functions: `isValid(q)`
#     returning true or false), or every return is sanitized for a category
#     (`return escapeHtml(s)`). A constructor call (`new f(x)`) keeps its
#     arguments. An open call keeps its arguments and receiver and adds the
#     request data any function it may reach returns. A sanitizer is trusted
#     by name only when no project function has that name (a sanitizer from
#     the operator's taint config always is): a project's own `escapeHtml`
#     is read like any other function;
#   * a function passed as an argument counts through what it returns;
#   * reports. The call-site pass reports request data passed into a
#     function whose parameter reaches a sink, for each function the call
#     may reach; the returned-value pass reports a sink fed by request data
#     another function read and returned. Request data read in the sink's
#     own function is the intra-file engine's (T-*) finding, not repeated;
#   * bounds. Nested code makes the expressions read overlap, so returned
#     values, returned-value sinks and calls with nested calls or several
#     statements in their arguments read at most _JS_READ_BUDGET times a
#     file's size (+64 KiB). Past that, those stop for the file (a
#     Q-FLOW-INCOMPLETE note), while every call whose arguments hold no
#     nested call is still checked — all that the name-based pass read.
_JS_BLANK = " \t\n\r"
_JS_EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
_JS_TS_SOURCES = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
_JS_EXPORT_HOPS = 8      # modules followed through `export … from` / `export *` / module.exports = require()
_JS_EVAL_DEPTH = 4       # calls nested in arguments read as their return values
_JS_RET_ROUNDS = 16      # rounds of the returned-value fixpoint (a note if they don't settle)
_JS_READ_BUDGET = 4      # nested expression text read per file, in multiples of its size (+64 KiB)
_JS_MAX_OPEN = 4         # an open call's functions checked at a call site (more: the last one defined)
_JS_MAX_OPEN_EDGES = 8   # an open call orders the fixpoint after its functions when there are this few
_JS_SCOPE_WALK = 64      # enclosing scopes searched for the declaration of an assigned name
_JS_MAX_ALIAS = 16       # names assigned to one name that a call through it follows
_JS_MAX_CARRY = 64       # parameters one value is followed for (the first ones found)
_JS_ALL = "*"            # in a set of clean categories: no argument reaches the value at all
_JS_UNIVERSE = frozenset(SINK_META) | {_JS_ALL}
_JS_EMPTY_NODE = ((), False, (), False)
_JS_NO_PARAMS = ({}, {})                    # param_map() of the module: no parameters (never written)
_JS_OPAQUE_NODE = ((), False, (), True)     # an expression not read: never free of data
_JS_LITERAL_WORDS = frozenset(("true", "false", "null", "undefined", "NaN", "Infinity", "void"))
_JS_NOT_ALIAS = _JS_LITERAL_WORDS | {"this", "super", "arguments"}
# a member of one of these is the language's or the runtime's, not the project's
_JS_GLOBAL_OBJECTS = frozenset((
    "JSON", "Math", "Object", "Array", "Number", "String", "Boolean", "Symbol", "BigInt",
    "Date", "RegExp", "Error", "Promise", "Reflect", "Proxy", "Intl", "Atomics", "WebAssembly",
    "console", "Buffer", "process"))
_JS_NODE_BUILTINS = frozenset((
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2",
    "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode",
    "querystring", "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib"))
# methods of JavaScript's built-in objects and everyday runtime objects: on a
# receiver the pass cannot identify, `x.replace(…)` is String's, not a
# project function named replace (the Python engine's _COMMON_METHODS)
_JS_COMMON_METHODS = frozenset("""
at charAt charCodeAt codePointAt concat endsWith includes indexOf lastIndexOf
localeCompare match matchAll normalize padEnd padStart repeat replace
replaceAll search slice split startsWith substr substring toLowerCase
toUpperCase toLocaleLowerCase toLocaleUpperCase toString toLocaleString trim
trimStart trimEnd trimLeft trimRight valueOf copyWithin entries every fill
filter find findIndex findLast findLastIndex flat flatMap forEach join keys
map pop push reduce reduceRight reverse shift some sort splice unshift values
hasOwnProperty isPrototypeOf propertyIsEnumerable apply bind call then catch
finally get set has delete clear add exec test getTime toISOString toJSON
parse stringify on once off emit addListener removeListener
removeAllListeners addEventListener removeEventListener dispatchEvent pipe
write end read destroy resume pause log debug info warn error trace send json
status render sendFile sendStatus cookie header type
""".split())
_JS_CONTROL_WORDS = frozenset(("if", "for", "while", "switch", "catch", "with", "await"))
_JS_IDCHAR_RE = re.compile(r"[\w$]")
_JS_BRACKET_RE = re.compile(r"[()\[\]{}]")
_JS_HARD_RE = re.compile(r"[();\n]")
_JS_CALL_RE = re.compile(r"(?<![\w$])(\w[\w$]*)\s*\(")
_JS_RETURN_RE = re.compile(r"return(?<![\w$.]return)(?![\w$])")
# the head of a function value: `function name` before its '(' (group 1
# unset), or the parameters and `=>` of an arrow function (group 1)
_JS_FUNCTION_HEAD_RE = re.compile(
    r"(?:async\s*)?(?:function(?![\w$])\s*\*?\s*(?:[A-Za-z_$][\w$]*\s*)?(?=\()"
    r"|(\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>)")
_JS_ASSIGN_OP = r"(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?="
# `const a = …`, and `a = …` / `a += …` starting a statement (after ; { or a
# newline, or a body without braces: `if (c) a += …`, `else a = …`, `=> a = …`)
_JS_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)"
    r"|(?:^|[;{\n]\s*|\)[ \t]*|=>[ \t]*|(?<![\w$.])else\s+)([A-Za-z_$][\w$]*)\s*"
    + _JS_ASSIGN_OP + r"(?![=>])\s*([^;\n]+)")
# any assignment to a name, anywhere (declarations with a value included)
_JS_WRITE_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*" + _JS_ASSIGN_OP + r"(?![=>])")
_JS_WORD_RE = re.compile(r"[A-Za-z_$][\w$]*")
# The patterns start with their keyword and check what precedes it after it
# (`return(?<![\w$.]return)` rather than `(?<![\w$.])return`): the same
# matches, but the regex engine can skip ahead to the keyword.
_JS_NOT_AFTER = r"(?<![\w$.]const)(?<![\w$.]let)(?<![\w$.]var)"
_JS_DECL_RE = re.compile(r"(?:const|let|var)" + _JS_NOT_AFTER + r"(?![\w$])")
# imports: const m = require('x') / const f = require('x').g / import m = require('x')
_JS_REQUIRE_BIND_RE = re.compile(
    r"(?:const|let|var|import)" + _JS_NOT_AFTER + r"(?<![\w$.]import)"
    r"\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*(['\"]) *\2\s*\)"
    r"(?:\s*\.\s*([A-Za-z_$][\w$]*))?[ \t]*(?![^;,}\n])")
# const { a, b: c } = require('x')
_JS_REQUIRE_DESTRUCTURE_RE = re.compile(
    r"(?:const|let|var)" + _JS_NOT_AFTER + r"\s*\{([^{}]*)\}\s*=\s*require\s*\(\s*(['\"]) *\2\s*\)[ \t]*(?![^;,}\n])")
# require('x') anywhere else (`require('./x').f()`, `require('./x')(…)`)
_JS_INLINE_REQUIRE_RE = re.compile(r"require(?<![\w$.]require)\s*\(\s*(['\"]) *\1\s*\)")
# a module copied: the value of `const o = lib` / `const f = lib.g`, and `const { g } = lib`
_JS_ALIAS_RE = re.compile(r"([A-Za-z_$][\w$]*)(?:\s*\.\s*([A-Za-z_$][\w$]*))?")
_JS_DESTRUCTURE_RE = re.compile(
    r"(?:const|let|var)" + _JS_NOT_AFTER + r"\s*\{([^{}]*)\}\s*=\s*([A-Za-z_$][\w$]*)[ \t]*(?![^;,}\n])")
# import d, { a, b as c } from 'x' / import * as m from 'x'
_JS_IMPORT_RE = re.compile(
    r"import(?<![\w$.]import)(?![\w$])\s*(?:([A-Za-z_$][\w$]*)\s*,?\s*)?"
    r"(?:\{([^{}]*)\}|\*\s*as\s+([A-Za-z_$][\w$]*))?\s*from\s*(['\"]) *\4")
# exports
_JS_EXPORT_LIST_RE = re.compile(r"export(?<![\w$.]export)(?![\w$])\s*\{([^{}]*)\}(?:\s*from\s*(['\"]) *\2)?")
_JS_EXPORT_STAR_RE = re.compile(r"export(?<![\w$.]export)(?![\w$])\s*\*\s*from\s*(['\"]) *\1")
_JS_EXPORT_DEFAULT_RE = re.compile(
    r"export(?<![\w$.]export)\s+default\s+(?:async\s+)?(?:function(?![\w$])\s*\*?\s*)?([A-Za-z_$][\w$]*)")
_JS_MODULE_EXPORTS_RE = re.compile(
    r"module(?<![\w$.]module)\s*\.\s*exports\s*=(?!=)\s*(?:"
    r"require\s*\(\s*(['\"]) *\1\s*\)[ \t]*(?![^;,}\n])"
    r"|(?:async\s+)?function(?![\w$])\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("
    r"|\{([^{}]*)\}"
    r"|([A-Za-z_$][\w$]*)[ \t]*(?![^;,}\n]))")
_JS_EXPORTS_PROP_RE = re.compile(
    r"(?:module(?<![\w$.]module)\s*\.\s*exports|exports(?<![\w$.]exports))"
    r"\s*\.\s*([A-Za-z_$][\w$]*)\s*=(?!=)\s*(?:"
    r"(?:async\s+)?function(?![\w$])\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("
    r"|([A-Za-z_$][\w$]*)[ \t]*(?![^;,}\n]))")
# names bound other than by `name = …` (_js_other_bindings): `const { a, b: c } = v`
# / `let [x] = v`, `for (const x of v)` / `for (let [k, w] of v)` / `for (var k in v)`,
# and `list.push(v)` / `list.unshift(v)`
_JS_PATTERN_DECL_RE = re.compile(r"(?:const|let|var)" + _JS_NOT_AFTER + r"(?![\w$])\s*([\[{])")
_JS_PATTERN_VALUE_RE = re.compile(r"\s*=(?![=>])\s*([^;\n]+)")
_JS_FOR_HEAD_RE = re.compile(
    r"for(?<![\w$.]for)\s*(\()\s*(?:const|let|var)(?![\w$])\s*(?:([A-Za-z_$][\w$]*)(?![\w$])|([\[{]))")
_JS_OF_RE = re.compile(r"\s*(?:of|in)(?![\w$])\s*")
_JS_PUSH_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:push|unshift)\s*\(")
# joining strings (_js_joins): a `+`, a `${` (in a template literal no tag reads), .join( / .concat(
_JS_JOIN_RE = re.compile(r"\+(?![+=])|\$\{|\.\s*(?:join|concat)\s*\(")
# one item of `{ a, b: c = 1 }` (destructuring, an object literal) or `{ a, b as c }`
_JS_BIND_ITEM_RE = re.compile(r"\A([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?(?:\s*=[^,]*)?\Z")
_JS_AS_ITEM_RE = re.compile(r"\A(type\s+)?([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\Z")
_JS_PARAM_RE = re.compile(r"\A[A-Za-z_$][\w$]*\Z")


def _js_back(code, i, floor=0):
    """Offset of the last non-blank character before i, or floor - 1."""
    i -= 1
    while i >= floor and code[i] in _JS_BLANK:
        i -= 1
    return i


def _js_word_before(code, i, floor=0):
    """(start, word) of the identifier characters ending at offset i."""
    j = i
    while j >= floor and _JS_IDCHAR_RE.match(code[j]):
        j -= 1
    return j + 1, code[j + 1:i + 1]


def _js_bracket_pairs(code):
    """{offset of an opening bracket: offset of the closer that ends it}:
    any closer ends the innermost open bracket, as _js_arg_end counts."""
    pairs, stack = {}, []
    for bm in _JS_BRACKET_RE.finditer(code):
        i = bm.start()
        if code[i] in "([{":
            stack.append(i)
        elif stack:
            pairs[stack.pop()] = i
    return pairs


def _js_close(code, paren, pairs):
    """_js_arg_end(code, paren + 1, False), read from the bracket table."""
    k = paren + 1
    c = pairs.get(paren)
    if c is not None and c - k < _JS_ARG_SCAN:
        return c
    return min(len(code), k + _JS_ARG_SCAN)


def _js_call_at(code, m, pairs, floor=0):
    """(name, receiver, start, paren, close) of the call _JS_CALL_RE matched
    at m, or None: a function header (`function f(`), a method definition
    (`f(a) {`) and an unterminated call are not calls. receiver is None for
    a plain call, the name before the dot for `m.f(…)` / `m?.f(…)`, and ''
    for any other receiver (`a.b.f(…)`, `g().f(…)`). start includes it."""
    name, start, paren = m.group(1), m.start(1), m.end() - 1
    close = _js_close(code, paren, pairs)
    if close >= len(code) or code[close] != ")":
        return None
    after = close + 1
    while after < len(code) and code[after] in _JS_BLANK:
        after += 1
    if after < len(code) and code[after] == "{":
        return None
    b = _js_back(code, start, floor)
    if b >= floor and code[b] == ".":
        d = b - 1
        if d >= floor and code[d] == "?":
            d -= 1
        d = _js_back(code, d + 1, floor)
        ws, word = _js_word_before(code, d, floor)
        if not word:
            return name, "", b, paren, close
        pb = _js_back(code, ws, floor)
        if pb >= floor and code[pb] == ".":
            return name, "", ws, paren, close
        return name, word, ws, paren, close
    if b >= floor:
        if code[b] == "*":
            b = _js_back(code, b, floor)
        if b >= floor and _js_word_before(code, b, floor)[1] == "function":
            return None
    return name, None, start, paren, close


def _js_after_new(code, start, floor):
    """Is the call that starts at start a constructor call (`new f(…)`)?"""
    b = _js_back(code, start, floor)
    return b >= floor and _js_word_before(code, b, floor)[1] == "new"


_JS_SPLIT_RE = re.compile(r"[()\[\]{},]")
_JS_NONBLANK_RE = re.compile(r"\S")


def _js_arg_end_at(code, k, statement, pairs):
    """_js_arg_end(code, k, statement), jumping over bracket groups with the
    file's bracket table: work in top-level tokens, not characters."""
    stop = min(len(code), k + _JS_ARG_SCAN)
    rx = _JS_STATEMENT_STOP_RE if statement else _JS_ARG_STOP_RE
    pos = k
    while True:
        m = rx.search(code, pos, stop)
        if m is None:
            return stop
        i = m.start()
        if code[i] in "([{":
            c = pairs.get(i)
            if c is None or c >= stop:
                return stop
            pos = c + 1
        else:                               # a closer, ';' or a newline at depth 0
            return i


def _js_sink_span(code, start, end, pairs):
    """(start, stop) of _js_sink_args(code, start, end) in code."""
    k = end
    if not (end > start and code[end - 1] == "("):
        k2 = end
        while k2 < len(code) and code[k2] in " \t":
            k2 += 1
        if k2 < len(code) and code[k2] == "(":
            k = k2 + 1
        else:
            return end, _js_arg_end_at(code, end, True, pairs)
    return k, _js_arg_end_at(code, k, False, pairs)


def _js_split_at(code, k, stop, pairs):
    """_js_split_args(code[k:stop]) for a span with no unbalanced closer
    (as _js_arg_end ends one), jumping over bracket groups."""
    return [code[a:b] for a, b in _js_split_spans(code, k, stop, pairs)]


def _js_trim(code, a, b):
    """(a, b) without the blanks str.strip() takes off either end."""
    while a < b and code[a].isspace():
        a += 1
    while b > a and code[b - 1].isspace():
        b -= 1
    return a, b


def _js_split_spans(code, k, stop, pairs):
    """The (start, stop) of each top-level comma-separated argument in
    code[k:stop], blanks trimmed (see _js_split_at)."""
    if _JS_NONBLANK_RE.search(code, k, stop) is None:
        return []
    out, last, pos = [], k, k
    while True:
        m = _JS_SPLIT_RE.search(code, pos, stop)
        if m is None:
            break
        i = m.start()
        ch = code[i]
        if ch == ",":
            out.append(_js_trim(code, last, i))
            last = pos = i + 1
        elif ch in "([{":
            c = pairs.get(i)
            if c is None or c >= stop:
                break
            pos = c + 1
        else:
            pos = i + 1
    out.append(_js_trim(code, last, stop))
    return out


def _js_split_args(text):
    """The top-level comma-separated arguments in text, stripped."""
    if not text.strip():
        return []
    out, depth, last = [], 0, 0
    for idx, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth:
                depth -= 1
        elif ch == "," and depth == 0:
            out.append(text[last:idx].strip())
            last = idx + 1
    out.append(text[last:].strip())
    return out


def _js_items(text, item_re):
    """The matches of item_re on the comma-separated items of text."""
    out = []
    for piece in text.split(","):
        m = item_re.match(piece.strip())
        if m:
            out.append(m)
    return out


def _js_norm_path(path):
    return path.replace("\\", "/")


def _js_builtin(spec):
    """Is spec a Node built-in module (`fs`, `fs/promises`, `node:path`)?"""
    return spec.startswith("node:") or spec.split("/")[0] in _JS_NODE_BUILTINS


def _js_fn_result(code, a, b, pairs):
    """None when code[a:b] is not a function value; else the (start, stop)
    of what it returns: an arrow function's expression, or the returned
    expressions of its block body (those of functions inside it too)."""
    m = _JS_FUNCTION_HEAD_RE.match(code, a, b)
    if m is None:
        return None
    k = m.end()
    if m.group(1) is None:                          # function …(…) {…}
        close = pairs.get(k)
        if close is None or close >= b:
            return []
        k = close + 1
    while k < b and code[k] in _JS_BLANK:
        k += 1
    if k < b and code[k] == "{":
        end = pairs.get(k)
        if end is None or end > b:
            end = b
        return [(rm.end(), min(_js_arg_end_at(code, rm.end(), True, pairs), end))
                for rm in _JS_RETURN_RE.finditer(code, k + 1, end)]
    if m.group(1) is None:
        return []
    return [(k, b)]


def _js_body_params(code, brace, opener, pairs):
    """The names the parameters of the function whose body opens at brace
    bind (`(a, { b }) => {`, `a => {`, `function f(a) {`, `m(a) {`)."""
    p = _js_back(code, brace)
    if p < 0:
        return []
    if code[p] == ">":
        if p < 1 or code[p - 1] != "=":
            return []
        q = _js_back(code, p - 1)
        if q < 0:
            return []
        if code[q] != ")":
            word = _js_word_before(code, q)[1]
            return [word] if _JS_PARAM_RE.match(word) else []
        p = q
    elif code[p] != ")":
        return []
    o = opener.get(p)
    if o is None:
        return []
    return _js_binding_names(code, o + 1, p, pairs)


_JS_BINDING_RE = re.compile(r"(?:\s|\.\.\.)*(?:([A-Za-z_$][\w$]*)|([\[{]))")
_JS_BINDING_END_RE = re.compile(r"[()\[\]{};\n,]")


def _js_binding_names(code, a, b, pairs, statement=False):
    """The names that the parameter list or (statement=True) const / let /
    var declarator list code[a:b] binds: `x`, `...rest`, the locals of the
    patterns `{ key: local = v, other }` and `[p, q]` (a TypeScript
    annotation `x: T` is not a key); default values and initializers are
    skipped. A declarator list ends at a ';', a newline or a closer."""
    out, todo = [], [(a, b, "decl" if statement else "list")]
    while todo:
        i, stop, kind = todo.pop()
        while i < stop:
            m = _JS_BINDING_RE.match(code, i, stop)          # an element
            if m is not None:
                i = m.end()
                if m.group(2):                               # a nested pattern
                    c = pairs.get(i - 1)
                    if c is None or c >= stop:
                        break
                    todo.append((i, c, "obj" if m.group(2) == "{" else "arr"))
                    i = c + 1
                else:
                    j = i
                    while j < stop and code[j] in _JS_BLANK:
                        j += 1
                    if kind == "obj" and j < stop and code[j] == ":":   # key: local
                        i = j + 1
                        continue
                    out.append(m.group(1))
            while i < stop:                                  # to the next element
                e = _JS_BINDING_END_RE.search(code, i, stop)
                if e is None:
                    i = stop
                    break
                i = e.start()
                ch = code[i]
                if ch in "([{":
                    c = pairs.get(i)
                    if c is None or c >= stop:
                        i = stop
                        break
                    i = c + 1
                elif ch == ",":
                    i += 1
                    break
                elif kind == "decl" or ch not in "\n;":    # the end of the list
                    i = stop
                    break
                else:
                    i += 1
    return out


# ---- values through local variables (review follow-up) ----
# A parameter used to reach a sink only where its own name was written in
# the sink's arguments: `const q = "SELECT …" + id; db.query(q)` was not a
# flow, and `const { id } = req.body` carried nothing to a call. Now:
#   * a parameter reaches a sink through the locals of its function (and of
#     the functions inside it) that hold it: param_map() gives, per scope,
#     the parameters each name may hold — a scope's own assignments (in
#     source order) on top of its enclosing scope's names, less the names it
#     declares itself — and carry() reads an expression against it the way
#     run() reads request data: sanitizer calls clear their categories, a
#     definite call keeps its arguments unless no return of it can hold them;
#   * names are bound by `name = …` (also after `if (…)`, `else` and `=>`
#     without braces), by patterns (`const { a, b: c } = v`, `let [x] = v`),
#     by `for (const x of v)` / `for (k in v)` heads, and `list.push(v)`
#     adds v to list (_js_other_bindings) — for request data as well;
#   * SQL: the parameter must be joined into the query text — a `+`, a `${…}`
#     in a template no tag reads, `.join()`, `.concat()`, `+=` (_js_joins) —
#     in a local's value on the way or in the sink's first argument; the
#     other arguments are bound, a query passed through whole is the
#     caller's, and sql`…${x}` is the tag's to quote;
#   * a pattern parameter (`function f({ id })`) binds its names to its
#     argument, and parameters come from the whole list (_js_header_params);
#   * bounds: a value holds at most _JS_MAX_CARRY parameters, a scope that
#     adds or hides nothing shares its enclosing scope's maps, and copying
#     maps and reading sinks for locals come out of the file's budget.
def _js_header_params(code, head, stop, pairs):
    """[(key, names)] of each parameter of the function whose header spans
    head, read from its whole parameter list (`(a = f(1, 2), { b, c: d })`
    is two parameters) when the list closes before stop, else None. key is
    the name a use spells (_js_param_name), or "{i}" for the i-th parameter
    when it is a pattern; names are the names it binds."""
    o = code.find("(", head[0], head[1])
    if o < 0:
        return None
    c = pairs.get(o)
    if c is None or c >= stop:
        return None
    out = []
    for i, (a, b) in enumerate(_js_split_spans(code, o + 1, c, pairs)):
        if a < b and code[a] in "[{":
            out.append(("{%d}" % i, _js_binding_names(code, a, b, pairs)))
        else:
            name = _js_param_name(code[a:b])
            out.append((name, [name] if name else []))
    return out


def _js_other_bindings(code, pairs):
    """(name, value start, value stop, offset, bare) of each name bound other
    than by `name = …`: the names of a `const { a, b: c } = v` / `let [x] = v`
    pattern and of a `for (const x of v)` / `for (let [k, w] of v)` / `for
    (var k in v)` head, each assigned v; `list.push(v)` / `list.unshift(v)`
    assign v to list, adding to what it holds (bare). A region (from its
    offset to the end of its value) starting inside an earlier one is
    dropped before it is read, so what they read stays linear, like the
    assignments'."""
    cands = [(m.start(1), 0, m) for m in _JS_PATTERN_DECL_RE.finditer(code)]
    cands += [(m.start(2) if m.group(2) else m.start(3), 1, m) for m in _JS_FOR_HEAD_RE.finditer(code)]
    cands += [(m.start(1), 2, m) for m in _JS_PUSH_RE.finditer(code)]
    cands.sort(key=lambda t: (t[0], t[1]))
    out, end = [], -1
    for off, kind, m in cands:
        if off < end:
            continue
        if kind == 0:                                   # const { a } = v
            c = pairs.get(off)
            if c is None:
                continue
            vm = _JS_PATTERN_VALUE_RE.match(code, c + 1)
            if vm is None:
                continue
            names, (a, b), bare = _js_binding_names(code, off, c + 1, pairs), vm.span(1), False
        elif kind == 1:                                 # for (const x of v)
            close = pairs.get(m.start(1))
            if close is None:
                continue
            if m.group(2):
                names, k = [m.group(2)], m.end(2)
            else:
                c = pairs.get(off)
                if c is None or c >= close:
                    continue
                names, k = _js_binding_names(code, off, c + 1, pairs), c + 1
            om = _JS_OF_RE.match(code, k, close)
            if om is None:
                continue
            (a, b), bare = _js_trim(code, om.end(), close), False
        else:                                           # list.push(v)
            paren = m.end() - 1
            close = pairs.get(paren)
            if close is None:
                continue
            names, (a, b), bare = [m.group(1)], _js_trim(code, paren + 1, close), True
        if a >= b:
            continue
        end = b
        for name in names:
            out.append((name, a, b, off, bare))
    return out


def _js_joins(code, a, b):
    """Does the expression code[a:b] (masked) join strings: a binary `+`, a
    `${…}` in a template literal no tag function reads (sql`…${x}` is the
    tag's to quote), `.join(…)` or `.concat(…)`?"""
    for m in _JS_JOIN_RE.finditer(code, a, b):
        i = m.start()
        ch = code[i]
        if ch == ".":
            return True
        if ch == "+":
            if i > a and code[i - 1] == "+":
                continue                                    # `++`
            p = _js_back(code, i, a)
            if p >= a and (code[p] in ")]'\"`" or _JS_IDCHAR_RE.match(code[p])):
                return True                                 # after a value: not a unary +
            continue
        t = code.rfind("`", a, i)                           # the template's opening quote
        if t < 0:
            return True
        p = _js_back(code, t, a)
        if p >= a and (code[p] in ")]" or (_JS_IDCHAR_RE.match(code[p])
                                           and _js_word_before(code, p, a)[1] not in _JS_REGEX_KEYWORDS)):
            continue                                        # a tagged template
        return True
    return False


def _js_member(text, i):
    """Is the word at text[i] a property name (`a.b`, `a?.b`) rather than a
    variable (`...b` is one)?"""
    p = _js_back(text, i)
    return p >= 0 and text[p] == "." and not (p >= 1 and text[p - 1] == ".")


def _js_plus_assign(code, a):
    """Is the assignment whose value starts at a a `+=`?"""
    k = _js_back(code, a)
    return k >= 1 and code[k] == "=" and code[k - 1] == "+"


def _js_carry_add(out, pid, built, clean):
    """Add a path of parameter pid to out {pid: (built, clean)}: built if any
    path joined it into a string, clean for what every path sanitized. A
    value holds at most _JS_MAX_CARRY parameters (the first ones added)."""
    prev = out.get(pid)
    if prev is not None:
        out[pid] = (prev[0] or built, prev[1] & clean)
    elif len(out) < _JS_MAX_CARRY:
        out[pid] = (built, clean)


def _js_node_merge(a, b):
    """One compiled expression for two read together."""
    return a[0] + b[0], a[1] or b[1], a[2] + b[2], a[3] or b[3]


# ---- RegExp receivers (review backlog: the regex .exec() sink) ----
# `pattern.exec(s)` matches the command sink `exec(`, but a RegExp's exec
# runs no command. A call leaves the sinks only when its receiver is proven
# to be a RegExp:
#   * a /…/ literal;
#   * `new RegExp(…)` / `RegExp(…)`, the global RegExp: the file never
#     declares, assigns or defines that name (`instanceof RegExp`,
#     `RegExp.escape(…)` and calls are reads);
#   * a name the file declares once, as one of those (`const | let | var
#     name = /…/g`, the whole value), and otherwise only uses for RegExp
#     members (`name.exec(…)`, `.test(…)`, `.lastIndex`, `.source`, …;
#     assigning only `.lastIndex`), called inside that declaration's block.
# Any other receiver stays a sink: a property (`opts.re.exec`), a parameter,
# a name bound twice, reassigned, passed to a function, destructured or
# shadowed. A file with a direct eval() or a with statement (either can
# rebind a name) proves nothing but literals, and one that touches
# RegExp.prototype nothing at all.
_JS_REGEXP_DECL_RE = re.compile(
    r"(?:const|let|var)" + _JS_NOT_AFTER + r"\s+([A-Za-z_$][\w$]*)(?:\s*:\s*RegExp)?\s*=(?![=>])\s*")
_JS_REGEXP_NEW_RE = re.compile(r"(?:new\s+)?RegExp\s*\(")
_JS_REBIND_RE = re.compile(r"(?<![\w$.])(?:eval|with)\s*\(")
_JS_REGEXP_PROTO_RE = re.compile(r"(?<![\w$.])RegExp\s*\.\s*prototype(?![\w$])")
_JS_IDENT_RE = re.compile(r"(?<![\w$])[A-Za-z_$][\w$]*")     # a whole identifier
_JS_ASSIGN_AFTER_RE = re.compile(r"\s*" + _JS_ASSIGN_OP + r"(?![=>])")
_JS_REGEX_FLAGS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_JS_REGEXP_MEMBERS = frozenset((
    "exec", "test", "lastIndex", "source", "flags", "global", "ignoreCase", "multiline", "sticky",
    "unicode", "unicodeSets", "dotAll", "hasIndices", "toString"))


def _js_regex_literal(code, p):
    """Offset of the opening slash of the /…/flags literal (masked: its
    content is blank) whose last character is at p, or -1."""
    j = p
    while j >= 0 and code[j] in _JS_REGEX_FLAGS:
        j -= 1
    if j < 1 or code[j] != "/":
        return -1
    k = j - 1
    while k >= 0 and code[k] == " ":
        k -= 1
    return k if k >= 0 and code[k] == "/" and k < j - 1 else -1


def _js_regexp_value(code, k, pairs):
    """(end, whether it is the global RegExp's) when a RegExp is written at
    code[k] — a /…/ literal, `new RegExp(…)`, `RegExp(…)` — else None."""
    n = len(code)
    if k < n and code[k] == "/":
        j = k + 1
        while j < n and code[j] == " ":
            j += 1
        if j < n and code[j] == "/" and j > k + 1:
            j += 1
            while j < n and code[j] in _JS_REGEX_FLAGS:
                j += 1
            return j, False
        return None
    m = _JS_REGEXP_NEW_RE.match(code, k)
    if m is not None:
        c = pairs.get(m.end() - 1)
        if c is not None:
            return c + 1, True
    return None


def _js_value_ends(code, e):
    """Does a declarator's value end at e: a `,` `;` `}` or the end of the
    code next, or a line break before a word that cannot continue it?"""
    n = len(code)
    j = e
    while j < n and code[j] in " \t":
        j += 1
    if j >= n or code[j] in ",;}":
        return True
    if code[j] not in "\r\n":
        return False
    while j < n and code[j] in _JS_BLANK:
        j += 1
    if j >= n or code[j] in ";}":
        return True
    m = _JS_WORD_RE.match(code, j)
    return m is not None and m.group() not in ("in", "instanceof")


def _js_regexp_member_use(code, e):
    """Is the name ending at e read as `name.<a RegExp member>` (assigned
    only through `.lastIndex`)?"""
    n = len(code)
    k = e
    while k < n and code[k] in _JS_BLANK:
        k += 1
    if k >= n or code[k] != ".":
        return False
    k += 1
    while k < n and code[k] in _JS_BLANK:
        k += 1
    m = _JS_WORD_RE.match(code, k)
    if m is None or m.group() not in _JS_REGEXP_MEMBERS:
        return False
    return m.group() == "lastIndex" or _JS_ASSIGN_AFTER_RE.match(code, m.end()) is None


def _js_enclosing(code, positions):
    """The innermost bracket open around each of the ascending positions
    (paired as _js_bracket_pairs pairs them), or -1."""
    out, stack = [], []
    it = _JS_BRACKET_RE.finditer(code)
    nxt = next(it, None)
    for pos in positions:
        while nxt is not None and nxt.start() < pos:
            i = nxt.start()
            if code[i] in "([{":
                stack.append(i)
            elif stack:
                stack.pop()
            nxt = next(it, None)
        out.append(stack[-1] if stack else -1)
    return out


def _js_regexp_calls(code, pairs, starts):
    """The offsets in starts (each where an `exec(` call's name begins) of
    the calls made on a value proven to be a RegExp (see above)."""
    if _JS_REGEXP_PROTO_RE.search(code):
        return ()
    lits, ctors, named = [], [], {}           # named: receiver name -> its calls
    opener = None
    for s in starts:
        d = _js_back(code, s)
        if d < 1 or code[d] != "." or code[d - 1] in ".?":
            continue
        p = _js_back(code, d)
        if p < 0:
            continue
        if code[p] == ")":
            if opener is None:
                opener = {c: o for o, c in pairs.items()}
            o = opener.get(p)
            q = _js_back(code, o) if o is not None else -1
            if q >= 0:
                ws, word = _js_word_before(code, q)
                if word == "RegExp" and not _js_member(code, ws):
                    ctors.append(s)
        elif _js_regex_literal(code, p) >= 0:
            lits.append(s)
        else:
            ws, word = _js_word_before(code, p)
            if _JS_PARAM_RE.match(word) and not _js_member(code, ws):
                named.setdefault(word, []).append(s)
    proven = set(lits)
    if not (ctors or named) or _JS_REBIND_RE.search(code):
        return proven
    decls = {}                  # name -> (declaration offset, name offset, is the global RegExp's) | None
    for m in _JS_REGEXP_DECL_RE.finditer(code):
        name = m.group(1)
        if name not in named:
            continue
        v = _js_regexp_value(code, m.end(), pairs)
        ok = v is not None and name not in decls and _js_value_ends(code, v[0])
        decls[name] = (m.start(), m.start(1), v[1]) if ok else None
    watch = sorted(n for n, d in decls.items() if d is not None)
    need = bool(ctors) or any(decls[n][2] for n in watch)
    if need:
        watch.append("RegExp")
    bad = set()
    if watch:
        watched = frozenset(watch)
        for m in _JS_IDENT_RE.finditer(code):
            w = m.group()
            if w not in watched or w in bad:
                continue
            i = m.start()
            if w == "RegExp":
                # the global RegExp, read: `new RegExp(`, `RegExp(`, `RegExp.x`, `instanceof RegExp`
                b = _js_back(code, i)
                k = m.end()
                while k < len(code) and code[k] in _JS_BLANK:
                    k += 1
                before = _js_word_before(code, b)[1] if b >= 0 else ""
                if b >= 0 and code[b] == ".":
                    bad.add(w)                              # globalThis.RegExp = …
                elif before == "function" or not ((k < len(code) and code[k] in "(.") or before == "instanceof"):
                    bad.add(w)
            elif _js_member(code, i):
                continue                                    # a property: obj.re
            elif i != decls[w][1] and not _js_regexp_member_use(code, m.end()):
                bad.add(w)
    global_ok = need and "RegExp" not in bad
    if global_ok:
        proven.update(ctors)
    names = sorted((decls[n][0], n) for n in watch if n != "RegExp" and n not in bad and (global_ok or not decls[n][2]))
    for (at, n), o in zip(names, _js_enclosing(code, [at for at, _ in names])):
        if o == -1:
            a, b = -1, len(code)
        elif code[o] == "{":
            a, b = o, pairs.get(o, len(code))
        else:
            continue                                        # declared in a for (…) head or an expression
        proven.update(s for s in named[n] if a < s < b)
    return proven


class _JsFile:
    """One analyzed JavaScript file: text, masked code and the tables the
    call and return passes read."""

    def __init__(self, f, text, code, literals):
        self.path, self.text = f["path"], text
        self.mods = {}       # local name -> module specifier (the module itself)
        self.named = {}      # local name -> (specifier, exported name)
        self.exports = {}    # exported name -> ("local", name, offset) | ("from", specifier, name)
        self.star = []       # `export * from` specifiers
        self.cjs = None      # module.exports = require(specifier)
        self._module(code, literals)
        code = self._inline_requires(code, literals)
        self.code = code
        self.nl = [m.start() for m in re.finditer("\n", code)]
        self.pairs = _js_bracket_pairs(code)
        self.hard = [m.start() for m in _JS_HARD_RE.finditer(code)]
        self.writes = {}     # name -> offsets of the assignments to it (declarations included)
        for m in _JS_WRITE_RE.finditer(code):
            self.writes.setdefault(m.group(1), []).append(m.start(1))
        # (name, value start, value stop, offset, bare) of each assignment, in
        # source order: `name = …`, then the names bound another way
        # (patterns, for … of / in heads, push), which are no aliases
        plain = [(am.group(1), am.start(2), am.end(2), am.start(1), False) if am.group(1)
                 else (am.group(3), am.start(4), am.end(4), am.start(3), True)
                 for am in _JS_ASSIGN_RE.finditer(code)]
        other = _js_other_bindings(code, self.pairs)
        tagged = sorted([(r[3], 0, r) for r in plain] + [(r[3], 1, r) for r in other],
                        key=lambda t: (t[0], t[1]))
        self.assigns = [t[2] for t in tagged]
        self.other = frozenset(k for k, t in enumerate(tagged) if t[1])
        # per assignment: does its value join strings (or is it `+=`); is it `+=`
        self.plus = [bare and k not in self.other and _js_plus_assign(code, a)
                     for k, (_, a, _, _, bare) in enumerate(self.assigns)]
        self.joins = [self.plus[k] or _js_joins(code, a, b)
                      for k, (_, a, b, _, _) in enumerate(self.assigns)]
        self.targets = frozenset(a[0] for a in self.assigns)
        self.alias = {}      # name -> (name assigned to it, assignment number) (`go = runIt`)
        self.const_alias = set()   # names only ever `const x = y`: a call through x is one through y
        self._aliases(code)
        self.assign_nodes = []
        self.tainted = {}    # variable -> provenance, file-wide (the call-site pass)
        self.fns = []        # fids of the functions defined here
        self.scope_fns = {}  # scope -> fids of the functions whose body it is
        self.defs = {}       # name -> fids of the functions of that name defined here
        self.defs_at = {}    # (name, scope defining it) -> fid of the last one defined there
        self.heads = {}      # name -> [(start, stop)] of the headers defining one
        self.reassigned = set()   # (name, scope): a binding assigned other than by its definition
        self.scopes = []     # (start, stop) of each function body, enclosing ones first
        self.starts = []     # their starts
        self.parent = []     # the enclosing scope of each scope, or None (the module)
        self.top = []        # assignments that belong to the module, then per scope: its own
        self.own = []
        self.decl = []       # per scope: the names it declares (parameters, const / let / var)
        self.top_decl = set()   # the module's
        self.assign_scope = []   # per assignment: the scope it belongs to (None: the module)
        self.call_scope = {}  # offset of a call's name -> the innermost scope around it
        self.sinks = []
        for sink_re, cat in _JS_SINKS:
            matches = list(_js_sink_matches(sink_re, code))
            if sink_re is _JS_CMD_SINK_RE:         # `re.exec(s)` on a RegExp runs no command
                calls = [s for s, _ in matches if code.startswith("exec", s) and not code.startswith("execSync", s)]
                regexp = _js_regexp_calls(code, self.pairs, calls) if calls else ()
                if regexp:
                    matches = [(s, e) for s, e in matches if s not in regexp]
            self.sinks.append((cat, matches))
        self.sink_scopes = []
        # nested code makes the expressions read overlap (a return inside a
        # callback inside a return…): what one file may have read is bounded
        self.budget = _JS_READ_BUDGET * len(code) + 65536
        self.over = False
        self.idx = 0

    def line(self, pos):
        return bisect.bisect_left(self.nl, pos) + 1

    def _module(self, code, literals):
        def spec(m, g):
            return literals.get(m.start(g))
        for m in _JS_REQUIRE_BIND_RE.finditer(code):
            s = spec(m, 2)
            if s is not None:
                if m.group(3):
                    self.named[m.group(1)] = (s, m.group(3))
                else:
                    self.mods[m.group(1)] = s
        for m in _JS_REQUIRE_DESTRUCTURE_RE.finditer(code):
            s = spec(m, 2)
            if s is not None:
                for it in _js_items(m.group(1), _JS_BIND_ITEM_RE):
                    self.named[it.group(2) or it.group(1)] = (s, it.group(1))
        for m in _JS_IMPORT_RE.finditer(code):
            s = spec(m, 4)
            if s is None or m.group(1) == "type":
                continue
            if m.group(1):
                self.mods[m.group(1)] = s
            if m.group(2) is not None:
                for it in _js_items(m.group(2), _JS_AS_ITEM_RE):
                    if not it.group(1):
                        self.named[it.group(3) or it.group(2)] = (s, it.group(2))
            if m.group(3):
                self.mods[m.group(3)] = s
        for m in _JS_EXPORT_LIST_RE.finditer(code):
            s = spec(m, 2) if m.group(2) else None
            if m.group(2) and s is None:
                continue
            for it in _js_items(m.group(1), _JS_AS_ITEM_RE):
                if not it.group(1):
                    self.exports[it.group(3) or it.group(2)] = (
                        ("from", s, it.group(2)) if s is not None else ("local", it.group(2), m.start()))
        for m in _JS_EXPORT_STAR_RE.finditer(code):
            s = spec(m, 1)
            if s is not None:
                self.star.append(s)
        for m in _JS_EXPORT_DEFAULT_RE.finditer(code):
            self.exports["default"] = ("local", m.group(1), m.start())
        for m in _JS_MODULE_EXPORTS_RE.finditer(code):
            if m.group(1):
                s = spec(m, 1)
                if s is not None:
                    self.cjs = s
            elif m.group(2):
                self.exports["default"] = ("local", m.group(2), m.start())
            elif m.group(3) is not None:
                for it in _js_items(m.group(3), _JS_BIND_ITEM_RE):
                    self.exports[it.group(1)] = ("local", it.group(2) or it.group(1), m.start())
            else:
                self.exports["default"] = ("local", m.group(4), m.start())
        for m in _JS_EXPORTS_PROP_RE.finditer(code):
            self.exports[m.group(1)] = ("local", m.group(2) or m.group(3), m.start())

    def _inline_requires(self, code, literals):
        """code with each one-line require('spec') replaced by a name of the
        same length that the module table maps to spec, so
        `require('./x').f(…)` and `require('./x')(…)` read as calls on that
        module."""
        pieces, last, k = [], 0, 0
        for m in _JS_INLINE_REQUIRE_RE.finditer(code):
            s = literals.get(m.start(1))
            a, b = m.span()
            if s is None or code.find("\n", a, b) >= 0:
                continue
            name = "R%d" % k
            if len(name) > b - a:
                continue
            k += 1
            name += "$" * (b - a - len(name))
            self.mods[name] = s
            pieces.append(code[last:a])
            pieces.append(name)
            last = b
        if not pieces:
            return code
        pieces.append(code[last:])
        return "".join(pieces)

    def _unbind(self):
        """A name assigned more than once is not a module or an import: a
        call through it may reach anything."""
        for table in (self.mods, self.named):
            for name in [n for n in table if len(self.writes.get(n, ())) > 1]:
                del table[name]

    def _aliases(self, code):
        """A module or an export copied to another name (`const o = lib`,
        `const f = lib.g`, `const { g } = lib`) binds like the original; a
        const copy of any other name (`const go = runIt`) is followed."""
        self._unbind()
        for _ in range(4):
            grew = False
            for k, (name, a, b, _, _) in enumerate(self.assigns):
                if k in self.other:
                    continue
                m = _JS_ALIAS_RE.fullmatch(code[a:b].strip())
                if m is None:
                    continue
                spec = self.mods.get(m.group(1))
                if spec is None or name in self.mods or name in self.named:
                    continue
                if m.group(2):
                    self.named[name] = (spec, m.group(2))
                else:
                    self.mods[name] = spec
                grew = True
            for m in _JS_DESTRUCTURE_RE.finditer(code):
                spec = self.mods.get(m.group(2))
                if spec is None:
                    continue
                for it in _js_items(m.group(1), _JS_BIND_ITEM_RE):
                    local = it.group(2) or it.group(1)
                    if local not in self.named and local not in self.mods:
                        self.named[local] = (spec, it.group(1))
                        grew = True
            if not grew:
                break
        self._unbind()
        # any other name assigned a name (`go = runIt`): a call through the
        # same binding may reach that one's functions too
        for k, (name, a, b, _, bare) in enumerate(self.assigns):
            if k in self.other or name in self.mods or name in self.named:
                continue
            m = _JS_ALIAS_RE.fullmatch(code[a:b].strip())
            if m is None or m.group(2) is not None or m.group(1) == name or m.group(1) in _JS_NOT_ALIAS:
                continue
            self.alias.setdefault(name, []).append((m.group(1), k))
            if not bare and len(self.writes.get(name, ())) == 1:
                self.const_alias.add(name)

    def scope_at(self, pos):
        """The innermost scope around pos, or None (the module)."""
        k = self.call_scope.get(pos, -1)
        if k != -1:
            return k
        k = bisect.bisect_right(self.starts, pos) - 1
        if k < 0:
            return None
        while k is not None and self.scopes[k][1] <= pos:
            k = self.parent[k]
        return k

    def bound_at(self, name, pos):
        """Does a scope around pos (or the module) declare name: a
        parameter, a const / let / var?"""
        k, steps = self.scope_at(pos), 0
        while k is not None and steps <= _JS_SCOPE_WALK:
            if name in self.decl[k]:
                return True
            k = self.parent[k]
            steps += 1
        return name in self.top_decl

    def binding_scope(self, name, pos):
        """The scope whose declaration of name a use at pos refers to: None
        for the module (or no declaration), -1 when too deep to tell."""
        k, steps = self.scope_at(pos), 0
        while k is not None:
            if name in self.decl[k]:
                return k
            steps += 1
            if steps > _JS_SCOPE_WALK:
                return -1
            k = self.parent[k]
        return None

    def in_head(self, name, p):
        """Is offset p inside the header of a definition of name?"""
        heads = self.heads.get(name)
        if not heads:
            return False
        k = bisect.bisect_right(heads, (p, len(self.code) + 1)) - 1
        return k >= 0 and p < heads[k][1]


class _JsFunction:
    def __init__(self, fid, rec, name, params, span, expr, head):
        self.fid, self.rec, self.name, self.params, self.span = fid, rec, name, params, span
        self.expr = expr          # an arrow function whose body is an expression
        self.head = head          # (start, stop) of its header
        self.pnames = [[p] if p else [] for p in params]   # per parameter: the names it binds
        self.reach = {}           # param -> (category, sink line)
        self.returns = []         # (start, end, line) of each returned expression
        self.return_nodes = []    # (compiled expression, line)
        self.scope = None         # the scope of its body


class _JsProgram:
    """The JavaScript files of a scan, their functions and summaries."""

    def __init__(self, recs, funcs):
        self.recs, self.funcs = recs, funcs
        self.index = {}
        for r in recs:
            self.index.setdefault(_js_norm_path(r.path), r)
        self.by_name = {}         # name -> fids of the functions of that name, the last defined first
        for fn in reversed(funcs):
            self.by_name.setdefault(fn.name, []).append(fn.fid)
        self.reach_named = {}     # name -> those with a parameter that reaches a sink (index_reach)
        self.clean = [frozenset()] * len(funcs)   # fid -> categories its value is free of its arguments for
        self.ret_src = {}         # fid -> (file, line, function) where the returned data is read
        self.ret_src_clean = {}   # fid -> categories every returned path of it is sanitized for
        self.ret_named = {}       # name -> fids with a ret_src, the last defined first
        self.config_san = _js_config_active()
        self._resolved, self._exported = {}, {}

    def resolve(self, rec, spec):
        """The analyzed file a relative specifier names from rec, or None."""
        key = (rec.path, spec)
        if key in self._resolved:
            return self._resolved[key]
        target = None
        if spec in (".", "..") or spec.startswith(("./", "../")):
            parts = _js_norm_path(rec.path).split("/")[:-1]
            ok = True
            for seg in spec.split("/"):
                if seg in ("", "."):
                    continue
                if seg == "..":
                    if not parts:
                        ok = False
                        break
                    parts.pop()
                else:
                    parts.append(seg)
            if ok:
                base = "/".join(parts)
                cands = [base] + [base + e for e in _JS_EXTS]
                last = parts[-1] if parts else ""
                dot = last.rfind(".")
                ext = last[dot:] if dot > 0 else ""
                if ext in _JS_TS_SOURCES:
                    cands += [base[:-len(ext)] + t for t in _JS_TS_SOURCES[ext]]
                cands += [(base + "/" if base else "") + "index" + e for e in _JS_EXTS]
                for c in cands:
                    target = self.index.get(c)
                    if target is not None:
                        break
        self._resolved[key] = target
        return target

    def visible(self, rec, name, pos):
        """fid of the function named name that is visible at pos in rec (the
        innermost, the last defined of a scope), or None."""
        if name not in rec.defs:
            return None
        k, steps = rec.scope_at(pos), 0
        while k is not None:
            fid = rec.defs_at.get((name, k))
            if fid is not None:
                return fid
            steps += 1
            if steps > _JS_SCOPE_WALK:
                return None
            k = rec.parent[k]
        return rec.defs_at.get((name, None))

    def local(self, rec, name, pos):
        """visible(), unless that binding is also assigned (`runIt = other`)."""
        fid = self.visible(rec, name, pos)
        if fid is None:
            return None
        scope = rec.parent[self.funcs[fid].scope]
        if (name, scope) in rec.reassigned or (name, -1) in rec.reassigned:
            return None
        return fid

    def exported(self, rec, name):
        """fid of the function module rec exports as name, or None: its own
        export, else `export … from`, `export *` and module.exports =
        require(), breadth-first through up to _JS_EXPORT_HOPS modules."""
        if rec is None:
            return None
        key = (rec.path, name)
        if key in self._exported:
            return self._exported[key]
        found = None
        level, seen = [(rec, name)], {key}
        for _ in range(_JS_EXPORT_HOPS + 1):
            nxt = []
            for r, n in level:
                entry = r.exports.get(n)
                if entry is not None:
                    if entry[0] == "local":
                        found = self.local(r, entry[1], entry[2])
                        if found is not None:
                            break
                        continue
                    targets = [(entry[1], entry[2])]
                else:
                    targets = []
                    if n != "default":
                        found = self.local(r, n, -1)
                        if found is not None:
                            break
                        targets = [(s, n) for s in r.star]
                    if r.cjs is not None:
                        targets.append((r.cjs, n))
                for s, tn in targets:
                    t = self.resolve(r, s)
                    if t is not None and (t.path, tn) not in seen:
                        seen.add((t.path, tn))
                        nxt.append((t, tn))
            if found is not None or not nxt:
                break
            level = nxt
        self._exported[key] = found
        return found

    def bind(self, rec, name, recv, pos, depth=0):
        """What a call in rec reaches: (fid, None) when it names exactly that
        function; (None, names) when it may reach any of the project's
        functions of those names, and code outside the scan; (None, ())
        when it reaches no project function (see above)."""
        if recv is None:
            fid = self.local(rec, name, pos)
            if fid is not None:
                return fid, None
            imp = rec.named.get(name)
            if imp is not None:
                if _js_builtin(imp[0]):
                    return None, ()
                fid = self.exported(self.resolve(rec, imp[0]), imp[1])
                if fid is not None:
                    return fid, None
                return None, ((name,) if imp[1] == name else (name, imp[1]))
            spec = rec.mods.get(name)
            if spec is not None:
                if _js_builtin(spec):
                    return None, ()
                fid = self.exported(self.resolve(rec, spec), "default")
                if fid is not None:
                    return fid, None
                return None, (name,)
            # a name a scope around the call binds (a parameter, a variable)
            # holds what was assigned to it, not a namesake function in
            # another file: only what it is assigned from is followed
            out = ([name] if self.visible(rec, name, pos) is not None
                   or not rec.bound_at(name, pos) else [])
            targets = rec.alias.get(name)
            if targets is not None and depth < 4 and len(targets) <= _JS_MAX_ALIAS:
                scope = rec.binding_scope(name, pos)
                for t, k in targets:
                    if scope != -1 and rec.assign_scope[k] != scope:
                        continue                    # another binding of that name
                    fid, names = self.bind(rec, t, None, pos, depth + 1)
                    if fid is not None:
                        if name in rec.const_alias and name not in rec.defs:
                            return fid, None
                        names = (self.funcs[fid].name,)
                    for n in names:
                        if n not in out:
                            out.append(n)
            return None, tuple(out)
        if recv:
            spec = rec.mods.get(recv)
            if spec is not None:
                if _js_builtin(spec):
                    return None, ()
                fid = self.exported(self.resolve(rec, spec), name)
                if fid is not None:
                    return fid, None
                return None, (name,)
            if recv in _JS_GLOBAL_OBJECTS and recv not in rec.writes and recv not in rec.named:
                return None, ()
            if recv in ("this", "super"):
                return None, (name,)
        if name in _JS_COMMON_METHODS:
            return None, ()
        return None, (name,)

    def reach_candidates(self, rec, name, recv, pos):
        """The functions whose sink-reaching parameters a call's arguments
        are checked against: the one it names, else every function it may
        reach — the last one defined only, when there are more than
        _JS_MAX_OPEN (it is the one the name-based pass always checked)."""
        fid, names = self.bind(rec, name, recv, pos)
        if fid is not None:
            return (fid,) if self.funcs[fid].reach else ()
        out = []
        for n in names:                     # distinct names: no function twice
            for f in self.reach_named.get(n, ()):
                out.append(f)
                if len(out) > _JS_MAX_OPEN:
                    return (out[0],)
        return tuple(out)

    # An expression is read in two steps: compile() finds its structure once
    # (sanitizer calls, calls to project functions, whether it reads request
    # data or holds anything but literals, the words that may name a tainted
    # variable), run() evaluates it against the current summaries, as often
    # as the fixpoint needs.
    def compile(self, rec, a, b, depth=0):
        """The structure of the expression code[a:b] of rec (masked code):
        (calls, whether it reads request data, its words that may name a
        tainted variable, whether it holds any name but a literal's). A call
        to a sanitizer clears what it wraps (numeric coercion) or adds its
        categories to it; a call bound to a project function reads as that
        function's value (definite: its arguments compiled; open: its text
        stays, so its arguments and receiver count); any other call stays
        text, so its arguments count."""
        code = rec.code
        calls, spans = [], []
        if depth < _JS_EVAL_DEPTH and code.find("(", a, b) >= 0:
            pairs = rec.pairs
            pos = a
            for m in _JS_CALL_RE.finditer(code, a, b):
                if m.start(1) < pos:
                    continue
                call = _js_call_at(code, m, pairs, a)
                if call is None:
                    continue
                name, recv, cstart, paren, close = call
                if close >= b:
                    continue
                callee = name if recv is None else (recv + "." + name if recv else None)
                san = _js_config_sanitizer(callee) if self.config_san and callee is not None else None
                fid = names = None
                if san is None:
                    fid, names = self.bind(rec, name, recv, m.start(1))
                    if fid is None:
                        names = tuple(n for n in names if n in self.by_name)
                        if not names and callee is not None:
                            san = _js_sanitizer(callee)
                if san is not None:
                    if san is not True:
                        calls.append(("san", san, self.compile(rec, paren + 1, close, depth + 1)))
                    spans.append((cstart, close + 1))
                    pos = close + 1
                elif fid is not None:
                    args = tuple(self.value(rec, x, y, depth + 1)
                                 for x, y in _js_split_spans(code, paren + 1, close, pairs))
                    calls.append(("fn", fid, args, _js_after_new(code, cstart, a)))
                    spans.append((cstart, close + 1))
                    pos = close + 1
                elif names:
                    calls.append(("open", names))
        if spans:
            pieces, last = [], a
            for s, e in spans:
                pieces.append(code[last:s])
                pieces.append(" ")
                last = e
            pieces.append(code[last:b])
            text = "".join(pieces)
        else:
            text = code[a:b]
        targets, words, opaque = rec.targets, [], False
        for wm in _JS_WORD_RE.finditer(text):
            w = wm.group()
            if w in targets and not _js_member(text, wm.start()):
                words.append(w)
            if not opaque and w not in _JS_LITERAL_WORDS:
                opaque = True
        return tuple(calls), _JS_SOURCE_RE.search(text) is not None, tuple(words), opaque

    def value(self, rec, a, b, depth):
        """compile() of an argument; a function value by what it returns."""
        res = _js_fn_result(rec.code, a, b, rec.pairs)
        if res is None:
            return self.compile(rec, a, b, depth)
        node = _JS_EMPTY_NODE
        for x, y in res:
            node = _js_node_merge(node, self.compile(rec, x, y, depth))
        return node

    def free(self, node):
        """The categories (and _JS_ALL) for which the value of a compiled
        expression holds nothing given to its function: no name but
        literals', and only sanitizers or calls to functions that are free
        themselves around the rest."""
        calls, direct, _, opaque = node
        if opaque or direct:
            return frozenset()
        out = _JS_UNIVERSE
        for call in calls:
            if call[0] == "san":
                out = out & (call[1] | self.free(call[2]))
            elif call[0] == "fn" and not call[3]:
                out = out & self.clean[call[1]]
            else:
                return frozenset()
            if not out:
                break
        return out

    def run(self, node, rec, tainted, cats):
        """The provenance of a compiled expression, or None. A provenance is
        ("direct", clean) for request data read in the expression or held by
        a variable assigned from it, or ("ret", file, line, function, via,
        clean) for request data another function read and returned (via:
        the function called here). clean is the set of sink categories
        every path of it was sanitized for; a path sanitized for one of cats
        does not count."""
        calls, direct, words, _ = node
        cats = frozenset(cats)
        provs = []

        def add(prov, extra=frozenset()):
            clean = prov[-1] | extra
            if not clean & cats:
                provs.append(prov[:-1] + (clean,))

        for call in calls:
            kind = call[0]
            if kind == "san":
                sub = self.run(call[2], rec, tainted, cats)
                if sub is not None:
                    add(sub, call[1])
            elif kind == "fn":
                fid = call[1]
                src = self.ret_src.get(fid)
                if src is not None:
                    add(("ret",) + src + (self.funcs[fid].name, self.ret_src_clean[fid]))
                clean = frozenset() if call[3] else self.clean[fid]
                if _JS_ALL not in clean:
                    for arg in call[2]:
                        sub = self.run(arg, rec, tainted, cats)
                        if sub is not None:
                            add(sub, clean)
            else:
                # the functions of those names that return request data: one
                # sanitized for nothing decides the merge, the rest can't change it
                done = False
                for n in call[1]:
                    for fid in self.ret_named.get(n, ()):
                        clean = self.ret_src_clean[fid]
                        if clean & cats:
                            continue
                        add(("ret",) + self.ret_src[fid] + (self.funcs[fid].name, clean))
                        if not clean:
                            done = True
                            break
                    if done:
                        break
        if direct:
            add(("direct", frozenset()))
        for w in words:
            prov = tainted.get(w)
            if prov is not None:
                add(prov)
        return _js_merge(provs)

    def _fill(self, rec, tainted, which):
        """Add the assignments numbered `which` to tainted, in order: the first
        carrying request data names its origin, later ones narrow what it is
        sanitized for."""
        nodes = rec.assign_nodes
        for k in which:
            src = self.run(nodes[k], rec, tainted, ())
            if src is not None:
                name = rec.assigns[k][0]
                tainted[name] = _js_merge([tainted[name], src]) if name in tainted else src
        return tainted

    def taint_map(self, rec):
        """Variable -> provenance for all of rec's assignments, in source
        order: the file-wide map the call-site pass has always used."""
        return self._fill(rec, {}, range(len(rec.assigns)))

    def scope_map(self, rec, k, cache):
        """The tainted variables scope k of rec sees (None: the module): its
        own assignments on top of what its enclosing scope sees, the
        module's at the top. Returned values and sinks read these, so a name
        tainted in one function doesn't taint its namesake in another."""
        chain = []
        while k is not None and (rec.idx, k) not in cache:
            chain.append(k)
            k = rec.parent[k]
        base = cache.get((rec.idx, k))
        if base is None:                    # k is None: the module, not read yet
            base = cache[(rec.idx, None)] = self._fill(rec, {}, rec.top)
        for j in reversed(chain):
            base = cache[(rec.idx, j)] = self._fill(rec, dict(base), rec.own[j])
        return base

    def _deps(self, fn):
        """The functions fn's returns and own assignments call."""
        out = []
        stack = [node for node, _ in fn.return_nodes]
        stack += [fn.rec.assign_nodes[k] for k in fn.rec.own[fn.scope]]
        while stack:
            for call in stack.pop()[0]:
                if call[0] == "san":
                    stack.append(call[2])
                elif call[0] == "fn":
                    out.append(call[1])
                    stack.extend(call[2])
                else:
                    for n in call[1]:
                        fids = self.by_name.get(n, ())
                        if len(fids) <= _JS_MAX_OPEN_EDGES:
                            out.extend(fids)
        return out

    def order(self):
        """Every fid, the functions a function calls before it where they
        don't call each other (depth-first post-order): the fixpoints then
        settle in a round or two unless functions are recursive."""
        deps = [self._deps(fn) for fn in self.funcs]
        order, seen = [], [False] * len(deps)
        for root in range(len(deps)):
            if seen[root]:
                continue
            seen[root] = True
            stack = [[root, 0]]
            while stack:
                top = stack[-1]
                f, i = top
                if i < len(deps[f]):
                    top[1] = i + 1
                    g = deps[f][i]
                    if not seen[g]:
                        seen[g] = True
                        stack.append([g, 0])
                else:
                    stack.pop()
                    order.append(f)
        return order

    def settle_clean(self, order):
        """self.clean, the least fixpoint: a function's returns are free of
        its arguments for a category when each of them is (see free())."""
        funcs = self.funcs
        for _ in range(_JS_RET_ROUNDS):
            changed = False
            for fid in order:
                c = _JS_UNIVERSE
                for node, _ in funcs[fid].return_nodes:
                    c = c & self.free(node)
                    if not c:
                        break
                if c != self.clean[fid]:          # it only grows
                    self.clean[fid] = c
                    changed = True
            if not changed:
                return

    def settle_returns(self, order):
        """ret_src, to a fixpoint (it only grows): what each function's
        returns hold, read with the variables its scope sees. False when
        _JS_RET_ROUNDS rounds did not settle it."""
        funcs = self.funcs
        for _ in range(_JS_RET_ROUNDS):
            changed = False
            cache = {}
            for fid in order:
                fn = funcs[fid]
                if not fn.return_nodes:
                    continue
                rec = fn.rec
                tainted = self.scope_map(rec, fn.scope, cache)
                for node, line in fn.return_nodes:
                    src = self.run(node, rec, tainted, ())
                    if src is None:
                        continue
                    if fid not in self.ret_src:
                        self.ret_src[fid] = src[1:4] if src[0] == "ret" else (rec.path, line, fn.name)
                        self.ret_src_clean[fid] = src[-1]
                        named = self.ret_named.setdefault(fn.name, [])
                        named.insert(_js_desc_index(named, fid), fid)
                        changed = True
                    elif not self.ret_src_clean[fid] <= src[-1]:
                        self.ret_src_clean[fid] &= src[-1]
                        changed = True
            if not changed:
                return True
        return False

    def index_reach(self):
        """reach_named, once every function's reach is known."""
        for name, fids in self.by_name.items():
            reach = [fid for fid in fids if self.funcs[fid].reach]
            if reach:
                self.reach_named[name] = reach

    # A parameter reaches a sink through its function's local variables too
    # (`const q = "…" + p; db.query(q)`), read the way request data is:
    # param_map() gives the parameters the names a scope sees may hold,
    # carry() those an expression's value may hold.
    def param_map(self, rec, k, cache):
        """(parameters, locals) scope k of rec sees: name -> {(fid, index):
        (built, clean)}, for the parameters of the functions around it. A
        scope's parameters and its own assignments (a bare one belongs to the
        scope declaring its name) come on top of its enclosing scope's, whose
        names it declares itself hide. built: a path joined the parameter
        into a string (_js_joins, `+=`); clean: the categories every path
        sanitized. A scope that adds or hides nothing shares its enclosing
        scope's maps; copying them is read within the file's budget (empty
        maps once it is spent)."""
        if rec.over:
            return _JS_NO_PARAMS
        chain = []
        while k is not None and (rec.idx, k) not in cache:
            chain.append(k)
            k = rec.parent[k]
        seeds, locs = cache[(rec.idx, k)] if k is not None else _JS_NO_PARAMS
        for j in reversed(chain):
            decl, fids, own = rec.decl[j], rec.scope_fns.get(j, ()), rec.own[j]
            if not fids and not own and seeds.keys().isdisjoint(decl) and locs.keys().isdisjoint(decl):
                cache[(rec.idx, j)] = (seeds, locs)
                continue
            cost = len(seeds) + len(locs) + 1
            if cost > rec.budget:
                rec.over = True
                return _JS_NO_PARAMS
            rec.budget -= cost
            seeds = {n: v for n, v in seeds.items() if n not in decl}
            locs = {n: v for n, v in locs.items() if n not in decl}
            for fid in fids:
                for i, names in enumerate(self.funcs[fid].pnames):
                    for n in names:
                        ent = dict(seeds.get(n, ()))
                        ent[(fid, i)] = (False, frozenset())
                        seeds[n] = ent
            for a in own:
                name = rec.assigns[a][0]
                val = self.carry(rec.assign_nodes[a], seeds, locs)
                old = locs.get(name)
                plus = rec.plus[a]
                if not val and not (plus and old):
                    continue
                ent = {pid: (bt or plus, cl) for pid, (bt, cl) in old.items()} if old else {}
                joins = rec.joins[a]
                for pid, (bt, cl) in val.items():
                    _js_carry_add(ent, pid, bt or joins, cl)
                locs[name] = ent
            cache[(rec.idx, j)] = (seeds, locs)
        return seeds, locs

    def carry(self, node, seeds, locs):
        """{(fid, index): (built, clean)}: the parameters a compiled
        expression's value may hold — through the names seeds and locs map
        (param_map), sanitizer calls (clean for their categories) and project
        functions' values (their arguments, unless no return of the function
        can hold them)."""
        calls, _, words, _ = node
        out = {}
        for call in calls:
            kind = call[0]
            if kind == "san":
                for pid, (bt, cl) in self.carry(call[2], seeds, locs).items():
                    _js_carry_add(out, pid, bt, cl | call[1])
            elif kind == "fn":
                clean = frozenset() if call[3] else self.clean[call[1]]
                if _JS_ALL not in clean:
                    for arg in call[2]:
                        for pid, (bt, cl) in self.carry(arg, seeds, locs).items():
                            _js_carry_add(out, pid, bt, cl | clean)
        for w in words:
            for table in (seeds, locs):
                ent = table.get(w)
                if ent:
                    for pid, (bt, cl) in ent.items():
                        _js_carry_add(out, pid, bt, cl)
        return out


class _JsLayers:
    """Two variable maps read as one: the first's provenance where it has one."""
    __slots__ = ("first", "second")

    def __init__(self, first, second):
        self.first, self.second = first, second

    def get(self, name):
        prov = self.first.get(name)
        return self.second.get(name) if prov is None else prov


def _js_desc_index(values, x):
    """Where x goes in the descending list values."""
    lo, hi = 0, len(values)
    while lo < hi:
        mid = (lo + hi) // 2
        if values[mid] > x:
            lo = mid + 1
        else:
            hi = mid
    return lo


def _js_merge(provs):
    """One provenance for several paths: the first returned value's if any
    path is one (else request data read here), clean for what every path was
    sanitized for; None for no path."""
    if not provs:
        return None
    clean = frozenset.intersection(*(p[-1] for p in provs))
    first = next((p for p in provs if p[0] == "ret"), provs[0])
    return first[:-1] + (clean,)


def _js_sanitizer(callee):
    """True when a call to callee (`f` or `m.f`) is a full sanitizer, the
    categories it clears when a partial one, else None."""
    probe = callee + "()"
    if _JS_FULL_SAN_RE.fullmatch(probe):
        return True
    cats = frozenset(c for c, rx in _JS_PARTIAL_SAN.items() if rx.fullmatch(probe))
    return cats or None


def _js_config_active():
    """Has a taint config added JavaScript sanitizers?"""
    return _JS_FULL_SAN_RE is not _JS_FULL_SAN_RE0 or _JS_PARTIAL_SAN != _JS_PARTIAL_SAN0


def _js_config_sanitizer(callee):
    """_js_sanitizer(callee) for the sanitizers a taint config added (not
    the built-in ones): they are trusted even where the project defines a
    function of that name — the operator named them."""
    probe = callee + "()"
    if _JS_FULL_SAN_RE.fullmatch(probe) and not _JS_FULL_SAN_RE0.fullmatch(probe):
        return True
    cats = frozenset(c for c, rx in _JS_PARTIAL_SAN.items() if rx.fullmatch(probe)
                     and not (c in _JS_PARTIAL_SAN0 and _JS_PARTIAL_SAN0[c].fullmatch(probe)))
    return cats or None


def _js_function_bodies(code, opens, opener, named):
    """Offsets of the '{' that open a function body: the named functions',
    and every '{' after `=>`, or after `(…)` that follows a name or
    `function` (not if / for / while / switch / catch / with / await).
    opener: {offset of a closer: offset of the bracket it closes}."""
    bodies = set(named)
    for b in opens:
        p = _js_back(code, b)
        if p < 0:
            continue
        if code[p] == ">":
            if p >= 1 and code[p - 1] == "=":
                bodies.add(b)
        elif code[p] == ")":
            o = opener.get(p)
            if o is None or code[o] != "(":
                continue
            q = _js_back(code, o)
            if q < 0:
                continue
            word = _js_word_before(code, q)[1]
            if word and word not in _JS_CONTROL_WORDS:
                bodies.add(b)
    return bodies


def _js_returns(code, bodies, match_close, line, pairs):
    """{body '{': [(start, end, line) of each returned expression]}: a
    `return` belongs to the innermost function body around it."""
    order = sorted(bodies)
    out, stack, k = {}, [], 0
    for rm in _JS_RETURN_RE.finditer(code):
        r = rm.start()
        while k < len(order) and order[k] < r:
            stack.append(order[k])
            k += 1
        while stack and match_close.get(stack[-1], len(code)) < r:
            stack.pop()
        if stack:
            a = rm.end()
            out.setdefault(stack[-1], []).append((a, _js_arg_end_at(code, a, True, pairs), line(r)))
    return out


def _js_scope_tree(spans):
    """(scopes sorted outer first, [enclosing scope of each or None])."""
    scopes = sorted(spans, key=lambda sp: (sp[0], -sp[1]))
    parent, stack = [], []
    for k, (a, _) in enumerate(scopes):
        while stack and scopes[stack[-1]][1] <= a:
            stack.pop()
        parent.append(stack[-1] if stack else None)
        stack.append(k)
    return scopes, parent


def _js_innermost(scopes, positions):
    """The innermost scope around each of the ascending positions, or None."""
    out, stack, k = [], [], 0
    for pos in positions:
        while k < len(scopes) and scopes[k][0] <= pos:
            stack.append(k)
            k += 1
        while stack and scopes[stack[-1]][1] <= pos:
            stack.pop()
        out.append(stack[-1] if stack else None)
    return out


def _js_sink_reach(prog, rec):
    """fn.reach for the functions of rec: each parameter that reaches one of
    their sinks, with the sink's category and line. A parameter reaches a
    sink when a name it binds is written in the sink's arguments (for SQL,
    joined into them: a placeholder array doesn't count), or when a local
    the sink reads holds it (param_map; for SQL, in the query text — the
    first argument — and joined into a string on the way or there). A later
    sink kind's category wins; within one category the first sink call is
    the one reported. The locals are read within the file's budget."""
    funcs = prog.funcs
    mine = [funcs[fid] for fid in rec.fns]
    if not mine:
        return
    code, pairs, cache = rec.code, rec.pairs, {}
    # Sink attribution, identical in effect to the old per-body finditer
    # (which found exactly the matches inside each copied body — spans give
    # the same set, including sinks inside nested closures). Each sink gets
    # its OWN sweep: spans are walked in start order, become active when
    # their start precedes the sink position and are retired when their end
    # precedes it; sink positions advance monotonically within one sink's
    # scan, so each span is appended once and removed once — linear per sink.
    spans = [(fn.span[0], fn.span[1], k) for k, fn in enumerate(mine)]
    for (cat, matches), where in zip(rec.sinks, rec.sink_scopes):
        spans_by_start = sorted(spans)
        active = []
        add_idx = 0
        for (pos, send), sc in zip(matches, where):
            while add_idx < len(spans_by_start) and spans_by_start[add_idx][0] <= pos:
                active.append(spans_by_start[add_idx])
                add_idx += 1
            active[:] = [sp for sp in active if sp[1] > pos]
            if not active:
                continue
            a, b = _js_sink_span(code, pos, send, pairs)
            seg = code[a:b]
            hits = []
            for _, _, k in active:
                fn = mine[k]
                for i, names in enumerate(fn.pnames):
                    for p in names:
                        if _js_param_dangerous(seg, p, cat):
                            hits.append((fn, fn.params[i]))
                            break
            if sc is not None and not rec.over:
                _, locs = prog.param_map(rec, sc, cache)
                if locs:
                    if b - a > rec.budget:
                        rec.over = True
                    else:
                        rec.budget -= b - a
                        args = _js_split_spans(code, a, b, pairs)
                        if cat == "SQL injection":
                            args = args[:1]          # the query text; parameters are bound
                        if any(w in locs for x, y in args for w in _JS_WORD_RE.findall(code, x, y)):
                            node = _JS_EMPTY_NODE
                            for x, y in args:
                                node = _js_node_merge(node, prog.value(rec, x, y, 0))
                            joins = cat == "SQL injection" and any(_js_joins(code, x, y) for x, y in args)
                            for (fid, i), (built, clean) in prog.carry(node, {}, locs).items():
                                if cat in clean or (cat == "SQL injection" and not (built or joins)):
                                    continue
                                hits.append((funcs[fid], funcs[fid].params[i]))
            if hits:
                line = rec.line(pos)
                for fn, key in hits:
                    # the category a later sink kind sets wins, as before;
                    # within one category the first sink call is reported
                    prev = fn.reach.get(key)
                    if prev is None or prev[0] != cat:
                        fn.reach[key] = (cat, line)


def _analyze_js(files, findings):
    # summary: fname -> the params reaching a sink, with the sink's category
    # and the line of the sink call itself (reported in the finding)
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
    recs, funcs = [], []
    for f in js_files:
        content = _js_text(f["content"])              # U+2028/9 -> \n
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
        literals = {}
        rec = _JsFile(f, content, _js_mask(content, literals), literals)
        rec.idx = len(recs)
        recs.append(rec)
        code, pairs = rec.code, rec.pairs
        braces = _js_braces(code)
        heads = []
        found = _js_functions(content, code, braces, pairs, heads)
        first = len(funcs)
        for (name, params, (s, e), _), head in zip(found, heads):
            fn = _JsFunction(len(funcs), rec, name, params, (s, e), s >= len(code) or code[s] != "{", head)
            # parameters from the whole list: `(a = f(1, 2), { b })` is two,
            # the second binding b
            plist = _js_header_params(code, head, s, pairs)
            if plist is not None:
                fn.params = [key for key, _ in plist]
                fn.pnames = [names for _, names in plist]
            funcs.append(fn)
            rec.fns.append(fn.fid)
        mine = funcs[first:]
        # what an expression holds is read by name: parameters too
        rec.targets = rec.targets | {n for fn in mine for names in fn.pnames for n in names}
        # what each function returns: the expression of an arrow function,
        # else the `return`s of its own body (not of a function inside it)
        opens, match_close = braces
        opener = {c: o for o, c in pairs.items()}
        named = {fn.span[0] for fn in mine if not fn.expr}
        bodies = _js_function_bodies(code, opens, opener, named)
        owned = _js_returns(code, bodies, match_close, rec.line, pairs)
        for fn in mine:
            fn.returns = ([(fn.span[0], fn.span[1], rec.line(fn.span[0]))] if fn.expr
                          else owned.get(fn.span[0], []))
        # scopes: every function body. A function is visible in the scope
        # that defines it; an assignment belongs to the innermost scope
        # around it — a bare one (`x = …`) to the scope that declares x
        # (const / let / var, a parameter), else to the module
        spans = {(b, match_close.get(b, len(code)) + 1) for b in bodies}
        spans.update(fn.span for fn in mine if fn.expr)
        rec.scopes, rec.parent = _js_scope_tree(spans)
        where = {sp: k for k, sp in enumerate(rec.scopes)}
        decl = [set() for _ in rec.scopes]
        for b in bodies:
            decl[where[(b, match_close.get(b, len(code)) + 1)]].update(_js_body_params(code, b, opener, pairs))
        for fn in mine:
            fn.scope = where[fn.span]
            rec.scope_fns.setdefault(fn.scope, []).append(fn.fid)
            if fn.expr:                     # `const f = (a, { b }) => …`: before its `=>`
                q = _js_back(code, fn.head[1] - 2)
                o = opener.get(q) if q >= 0 else None
                if o is not None:
                    decl[fn.scope].update(_js_binding_names(code, o + 1, q, pairs))
            rec.defs.setdefault(fn.name, []).append(fn.fid)
            rec.defs_at[(fn.name, rec.parent[fn.scope])] = fn.fid
            rec.heads.setdefault(fn.name, []).append(fn.head)
        dms = list(_JS_DECL_RE.finditer(code))
        for dm, sc in zip(dms, _js_innermost(rec.scopes, [dm.start() for dm in dms])):
            (rec.top_decl if sc is None else decl[sc]).update(_js_binding_names(
                code, dm.end(), min(len(code), dm.end() + _JS_ARG_SCAN), pairs, True))
        # an assignment rebinds the definition of its name that it resolves to:
        # the innermost scope around it that declares the name or defines a
        # function of that name (-1: too deep to tell)
        defined = {(fn.name, rec.parent[fn.scope]) for fn in mine}
        wms = list(_JS_WRITE_RE.finditer(code))
        for wm, sc in zip(wms, _js_innermost(rec.scopes, [wm.start(1) for wm in wms])):
            name = wm.group(1)
            if name not in rec.defs or rec.in_head(name, wm.start(1)):
                continue
            steps = 0
            while sc is not None and name not in decl[sc] and (name, sc) not in defined:
                steps += 1
                sc = rec.parent[sc] if steps <= _JS_SCOPE_WALK else -1
                if sc == -1:
                    break
            rec.reassigned.add((name, sc))
        rec.starts = [sp[0] for sp in rec.scopes]
        cps = [m.start(1) for m in _JS_CALL_RE.finditer(code)]
        rec.call_scope = dict(zip(cps, _js_innermost(rec.scopes, cps)))
        rec.decl = decl
        rec.own = [[] for _ in rec.scopes]
        for k, sc in enumerate(_js_innermost(rec.scopes, [a[3] for a in rec.assigns])):
            name = rec.assigns[k][0]
            if rec.assigns[k][4]:
                steps = 0
                while sc is not None and name not in decl[sc]:
                    steps += 1
                    sc = rec.parent[sc] if steps <= _JS_SCOPE_WALK else None
            (rec.top if sc is None else rec.own[sc]).append(k)
            rec.assign_scope.append(sc)
        rec.sink_scopes = [_js_innermost(rec.scopes, [pos for pos, _ in matches])
                           for _, matches in rec.sinks]
    if not funcs:
        return
    prog = _JsProgram(recs, funcs)
    # assignments are always read: they don't overlap, and what is read of
    # the calls nested in one is bounded by _JS_EVAL_DEPTH
    for rec in recs:
        rec.assign_nodes = [prog.compile(rec, a, b) for _, a, b, _, _ in rec.assigns]
    # returned expressions can overlap: each file's are read within its budget
    for fn in funcs:
        rec, nodes = fn.rec, []
        for a, b, line in fn.returns:
            if rec.over or b - a > rec.budget:
                rec.over = True
                nodes.append((_JS_OPAQUE_NODE, line))
            else:
                rec.budget -= b - a
                nodes.append((prog.compile(rec, a, b), line))
        fn.return_nodes = nodes
    order = prog.order()
    prog.settle_clean(order)
    # which parameters reach a sink: written in its arguments, or held by a
    # local it reads
    for rec in recs:
        _js_sink_reach(prog, rec)
    prog.index_reach()
    # the call-site pass's file-wide map holds request data read directly
    # (as it always has); what functions return is read through the scopes
    for rec in recs:
        rec.tainted = prog.taint_map(rec)
    settled = prog.settle_returns(order)
    if not settled:
        findings.append(_flow_note(
            "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (iteration cap)",
            recs[0].path, 1,
            f"What JavaScript functions return did not settle within "
            f"{_JS_RET_ROUNDS} rounds; flows through long chains of returned "
            f"values may be missing.",
            "Return values are iterated to a fixpoint with a safety cap; "
            "hitting it means an unusually long chain of functions returning "
            "each other's values.",
            "Report the pattern to the Lazaret maintainers."))
    # scan call sites: request data passed into a function whose parameter
    # reaches a sink
    if prog.reach_named:
        for rec in recs:
            lines = rec.text.split("\n")
            code, pairs, hard, cache = rec.code, rec.pairs, rec.hard, {}
            for m in _JS_CALL_RE.finditer(code):
                call = _js_call_at(code, m, pairs)
                if call is None:
                    continue
                name, recv, _, paren, close = call
                cands = prog.reach_candidates(rec, name, recv, m.start(1))
                if not cands:
                    continue
                if bisect.bisect_left(hard, paren + 1) != bisect.bisect_left(hard, close):
                    # a nested call or statement in the arguments: arguments
                    # of nested calls overlap, so they are read in the budget
                    if rec.over or close - paren - 1 > rec.budget:
                        rec.over = True
                        continue
                    rec.budget -= close - paren - 1
                args = _js_split_spans(code, paren + 1, close, pairs)
                tainted = _JsLayers(prog.scope_map(rec, rec.scope_at(m.start(1)), cache), rec.tainted)
                hit = False
                for fid in cands:
                    fn = funcs[fid]
                    for idx, pname in enumerate(fn.params):
                        if pname not in fn.reach or idx >= len(args):
                            continue
                        cat, sline = fn.reach[pname]
                        node = prog.value(rec, args[idx][0], args[idx][1], 0)
                        if prog.run(node, rec, tainted, (cat,)) is not None:   # sink-category sanitizers
                            # the sink's own line (was: the function's first
                            # line), like the Python engine reports it
                            line = rec.line(m.start(1))
                            findings.append(_issue(
                                cat, rec.path, line, lines,
                                source_loc=f"{rec.path}:{line}",
                                sink_loc=f"{fn.rec.path}:{sline} (in {fn.name}())",
                                chain=f"the call to {name}()"))
                            hit = True
                            break
                    if hit:
                        break
    # sinks fed by a value another function read from the request and returned
    if prog.ret_src:
        for rec in recs:
            lines = rec.text.split("\n")
            code, pairs, cache = rec.code, rec.pairs, {}
            for (cat, matches), where in zip(rec.sinks, rec.sink_scopes):
                for (pos, send), sc in zip(matches, where):
                    a, b = _js_sink_span(code, pos, send, pairs)
                    if rec.over or b - a > rec.budget:
                        rec.over = True
                        break
                    rec.budget -= b - a
                    args = _js_split_spans(code, a, b, pairs)
                    if cat == "SQL injection":
                        args = args[:1]              # the query text; parameters are bound
                    node = _JS_EMPTY_NODE
                    for x, y in args:
                        node = _js_node_merge(node, prog.value(rec, x, y, 0))
                    src = prog.run(node, rec, prog.scope_map(rec, sc, cache), (cat,))
                    if src is not None and src[0] == "ret":
                        line = rec.line(pos)
                        findings.append(_issue(
                            cat, rec.path, line, lines,
                            source_loc=f"{src[1]}:{src[2]} (in {src[3]}())",
                            sink_loc=f"{rec.path}:{line}",
                            chain=f"the value returned by {src[4]}()"))
    for rec in recs:
        if rec.over:
            findings.append(_flow_note(
                "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)",
                rec.path, 1,
                f"The JavaScript cross-file pass stopped following returned values "
                f"and nested calls in {rec.path} after reading {_JS_READ_BUDGET} "
                f"times its size; calls whose arguments hold no nested call were "
                f"still checked, but flows through returned values in the rest of "
                f"it may be missing.",
                "Deeply nested code makes the expressions the pass reads overlap; "
                "each file has a budget so a scan cannot run unbounded.",
                "Split or deminify the file, or exclude it from the scan "
                "explicitly if the code is generated."))


_JS_MAX_FILE = 2_000_000      # skip interprocedural JS flow above 2 MB


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
    global _JS_SOURCE_RE, _JS_FULL_SAN_RE
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
    _JS_SOURCE_RE = taintspec.extend_pattern(_JS_SOURCE_RE, js.sources)
    _JS_SINKS.extend(js.sinks)
    for name in js.full:
        _JS_FULL_SAN_RE = re.compile(
            _JS_FULL_SAN_RE.pattern + "|" + re.escape(name) + r"\s*\([^()]*\)")
    for name, cats in js.partial.items():
        add = re.escape(name) + r"\s*\([^()]*\)"
        for c in sorted(cats):
            base = _JS_PARTIAL_SAN.get(c)
            _JS_PARTIAL_SAN[c] = re.compile((base.pattern + "|" + add) if base else add)


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
    for engine, lang in ((_analyze_python, "py"), (_analyze_js, "js")):
        try:
            engine(files, findings)
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
