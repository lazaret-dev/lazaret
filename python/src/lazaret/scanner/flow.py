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
import builtins as _builtins
import collections
import posixpath
import re
import sys
import time

from lazaret.scanner import frameworks
from lazaret.scanner import jsflow
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
# JavaScript — on parsed trees (lazaret.scanner.jsflow)
# ======================================================================
# The configured part of the JavaScript model (configure()); jsflow reads it
# at each analysis.
_JS_SOURCE_RE = jsflow.SOURCE_RE      # request data by a member's or a callee's text, + configured sources
_JS_SINKS = []                        # configured sinks: (guarded pattern, category)
_JS_FULL_SAN = set()                  # configured full sanitizers (call names)
_JS_PARTIAL_SAN = {}                  # configured partial sanitizers: call name -> set(categories)
_JS_MAX_FILE = jsflow.MAX_FILE        # code points: a larger file is skipped (X-FLOW-SKIPPED)


def _analyze_js(files, findings):
    js_files = [f for f in files if f.get("lang") == "js"]
    if not js_files:
        return
    cfg = jsflow.config(_JS_SOURCE_RE, _JS_SINKS, _JS_FULL_SAN, _JS_PARTIAL_SAN)
    jsflow.analyze(js_files, findings, _issue, _flow_note, cfg)


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
    global _JS_SOURCE_RE
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
