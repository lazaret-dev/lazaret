"""Cross-file taint for JavaScript and TypeScript, on parsed trees (0.1.7).

The interprocedural pass's JavaScript half, read from the trees
lazaret.scanner.jsparse builds (the heuristic over masked text it replaces
followed a value one call into a sink). The model is the Python half's
(lazaret.scanner.flow): each function gets a summary — which of its
parameters reach which sinks, what its return value carries — computed to a
fixpoint over the call graph, callees first; findings come from a last pass
over every function:

* a call that passes request data into a function whose parameter reaches a
  sink, through any number of calls in between (X-*, at the call site);
* a sink that request data reaches as the value another function returned,
  or as a variable another module exports (X-*, at the sink).

Request data read in the sink's own function, or in a function around it,
is the intra-file engine's (T-*) finding, not repeated.

Names are resolved with scopes (var and function hoisting, block-scoped let,
const and class, parameters, catch clauses, imports) and values with a
flow-insensitive points-to for functions, modules, objects and classes: a
call binds to the function its name, a relative require() / import (named,
default, namespace; ESM and CommonJS exports; re-exports; `./x.js` naming
`x.ts`), an object literal's method, a class's method through `this`,
`super`, `new C` or `C.m`, or a function assigned to it holds. Where it
cannot tell — a package, an alias path, an unknown receiver — the call may
reach any project function of that name (at most MAX_OPEN of them);
positive evidence binds nothing: a Node built-in module, a global object's
member (JSON.parse), a built-in method name on an unknown receiver, a
parameter or local variable.

Values are followed through locals (flow-sensitive in a function, with
branches merged and a loop's body read again when its first reading changed
a value), destructuring, containers, template literals, closures (a variable
another function writes or reads is read as everything written to it),
callbacks (a function passed as a value carries what it returns), returns
and a module's exported variables. Sanitizers clear the categories they
cover (a project function of a sanitizer's name is read as itself); for SQL
a value must be joined into the query text (`+`, a `${…}` in an untagged
template, `+=`, `.join()`, `.concat()`) somewhere on its way: values bound
as parameters, a query passed through whole and a tagged template
(sql`…${x}`) are no findings.

Express-style routes: a function registered as a route handler
(`app.get('/path', fn)`, `router.post(...)`, `app.use(fn)`,
`router.route('/path').get(fn)`) gets the request as its first parameter and
the response as its second (after the error of a four-parameter one),
whatever their names; `req.query` / `req.body` / … are sources, `res.send` /
`write` / `end` (not of a whole parsed object: JSON), `res.redirect`,
`res.location` and `res.sendFile` / `download` (without a `root`) sinks.
React's `dangerouslySetInnerHTML` is an XSS sink.

Deterministic: no wall clock — a work budget (steps per tree node), a cap on
one function's reading and a per-function re-analysis cap bound the pass,
the same in both engines. Twin: js/src/scanner/jsflow.js
(tests/architecture/test_js_parity_flow.py).
"""
import heapq
import re
import sys

from lazaret.scanner import jsparse

MAX_FILE = 2_000_000          # code points: a larger file is skipped (X-FLOW-SKIPPED)
MAX_TOTAL = 8_000_000         # code points analyzed per run (the rest: Q-FLOW-INCOMPLETE)
MAX_OPEN = 4                  # project functions a name-only call may reach
MAX_ITERS = 50                # re-analyses of one function
MAX_PARAMS = 64               # parameters one value is followed for (the first ones)
PARAM_BASE = 1 << 20          # a parameter's key: function id * PARAM_BASE + index
EXPORT_HOPS = 8               # modules followed through re-exports
ALIAS_DEPTH = 16              # values followed through names and properties
WORK_BASE = 200_000           # evaluation steps of the fixpoint: WORK_BASE + WORK_PER_NODE per node
WORK_PER_NODE = 24
EMIT_PER_NODE = 8             # ... and of the reporting pass
RUN_BASE = 2_000              # one reading of one function: RUN_BASE + RUN_PER_NODE per node of it
RUN_PER_NODE = 64
TEXT_MAX = 400                # characters of a callee's or member's text
_RECURSION = 20_000

CATS = ("SQL injection", "command injection", "code injection", "template injection", "path traversal",
        "server-side request forgery", "open redirect", "cross-site scripting")
BIT = {c: 1 << k for k, c in enumerate(CATS)}
ALL = (1 << len(CATS)) - 1
SQL = "SQL injection"
XSS = "cross-site scripting"
FIXED_HOST = BIT["server-side request forgery"] | BIT["open redirect"]

EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
TS_SOURCES = {".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",)}
NODE_BUILTINS = frozenset((
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
    "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module",
    "net", "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
    "worker_threads", "zlib"))
GLOBAL_OBJECTS = frozenset((
    "JSON", "Math", "Object", "Array", "Number", "String", "Boolean", "Symbol", "BigInt", "Date", "RegExp",
    "Error", "Promise", "Reflect", "Proxy", "Intl", "Atomics", "WebAssembly", "console", "Buffer", "process",
    "globalThis", "window", "document", "navigator", "Map", "Set", "WeakMap", "WeakSet",
    "$", "jQuery", "_"))                # a library's namespace (jQuery, lodash / underscore): its members are its own
# methods of the language's and the runtime's objects: on a receiver the pass
# cannot identify, `x.replace(…)` is String's, not a project function
COMMON_METHODS = frozenset("""
at charAt charCodeAt codePointAt concat endsWith includes indexOf lastIndexOf localeCompare match matchAll
normalize padEnd padStart repeat replace replaceAll search slice split startsWith substr substring toLowerCase
toUpperCase toLocaleLowerCase toLocaleUpperCase toString toLocaleString trim trimStart trimEnd trimLeft
trimRight valueOf copyWithin entries every fill filter find findIndex findLast findLastIndex flat flatMap
forEach join keys map pop push reduce reduceRight reverse shift some sort splice unshift values
hasOwnProperty isPrototypeOf propertyIsEnumerable apply bind call then catch finally get set has delete
clear add exec test getTime toISOString toJSON parse stringify on once off emit addListener removeListener
removeAllListeners addEventListener removeEventListener dispatchEvent pipe write end read destroy resume
pause log debug info warn error trace send json status render sendFile sendStatus cookie header type
""".split())
# a call's value that is no text the caller chose (a boolean, a number, an index)
CLEAN_RESULT = frozenset("""
test includes startsWith endsWith indexOf lastIndexOf findIndex findLastIndex localeCompare some every has
isArray isNaN isFinite isInteger isSafeInteger hasOwnProperty getTime charCodeAt codePointAt search
""".split())
REGEXP_MEMBERS = frozenset(("exec", "test", "lastIndex", "source", "flags", "global", "ignoreCase", "multiline",
                            "sticky", "unicode", "dotAll", "hasIndices", "toString"))
ROUTE_METHODS = frozenset(("get", "post", "put", "patch", "delete", "del", "all", "options", "head", "use"))
# what a request object carries from the client (Express, Fastify, Koa's ctx)
REQUEST_PROPS = frozenset(("query", "body", "params", "headers", "cookies", "signedCookies", "files", "file",
                           "originalUrl", "url", "path", "hostname"))
REQUEST_CALLS = frozenset(("get", "header", "param"))
REQUEST_WRAPPERS = frozenset(("request", "req"))      # Koa: ctx.request, ctx.req
# a response method that sends a whole parsed request object sends JSON
REQUEST_OBJECTS = frozenset(("query", "body", "params", "headers", "cookies", "signedCookies"))
# a URL whose text starts with a path on this site or a fixed host: what is
# joined after it can change neither (core._SAME_SITE_RE, for SSRF too)
FIXED_PREFIX_RE = re.compile(r"/[^/\\]|[Hh][Tt][Tt][Pp][Ss]?://[^/?#\\\s{}$]+/")
# a Server-Sent Events frame: not HTML
SSE_RE = re.compile(r"(?:data|event|id|retry)[ \t]*:")

# request data by the text of a member expression (`req.query`) or a call's
# callee followed by "(" (`req.get(`)
SOURCE_RE = re.compile(
    r"(?<![\w$.])(?:req|request)\.(?:query|body|params|headers|cookies)\b"
    r"|(?<![\w$.])req\.(?:signedCookies|files?|originalUrl|url|path|hostname)\b"
    r"|(?<![\w$.])req\.(?:get|header|param)\($|(?<![\w$.])process\.argv\b"
    r"|(?<![\w$.])(?:window\.|document\.)?location\.(?:search|hash|href)\b")

# (pattern over a sink's text, category, the arguments that carry the injection)
# The text is a call's callee followed by "(" (`db.query(`, `new Function(`)
# or an assignment's target followed by " =" (`el.innerHTML =`); arguments:
# "first", "last", "all", "second", or "value" (an assignment's right side).
SINKS = [
    (re.compile(r"\.(?:query|execute)\($"), SQL, "first"),
    (re.compile(r"\.(?:whereRaw|havingRaw|orderByRaw|joinRaw|groupByRaw|fromRaw)\($"), SQL, "first"),
    (re.compile(r"(?<![\w$.])(?:knex\.raw|sequelize\.literal|sequelize\.query)\($"), SQL, "first"),
    (re.compile(r"(?<![\w$])(?:exec|execSync|spawn|spawnSync)\($"), "command injection", "all"),
    (re.compile(r"(?<![\w$.])eval\($|^new Function\($|(?<![\w$.])vm\.(?:runInNewContext|runInThisContext"
                r"|runInContext|compileFunction)\($|^new vm\.Script\($"), "code injection", "first"),
    (re.compile(r"(?<![\w$])(?:ejs|pug|jade|Handlebars|handlebars|Mustache|mustache|nunjucks|doT|_)\.(?:render"
                r"|renderString|compile|template)\($"), "template injection", "first"),
    (re.compile(r"\.(?:sendFile|download)\($"), "path traversal", "first"),
    (re.compile(r"(?<![\w$])(?:readFile|readFileSync|createReadStream)\($"), "path traversal", "first"),
    (re.compile(r"(?<![\w$.])fs(?:\.promises)?\.(?:writeFile|appendFile|unlink|rm|rmdir|mkdir|readdir|rename"
                r"|copyFile|createWriteStream)(?:Sync)?\($"), "path traversal", "first"),
    (re.compile(r"(?<![\w$.])(?:fetch|needle)\($|(?<![\w$.])axios(?:\.(?:get|post|put|patch|delete|head"
                r"|request))?\($|(?<![\w$.])https?\.(?:get|request)\($|(?<![\w$.])got(?:\.(?:get|post|put|patch"
                r"|delete|head|stream))?\($"), "server-side request forgery", "first"),
    (re.compile(r"\.redirect\($"), "open redirect", "last"),
    (re.compile(r"(?<![\w$.])(?:res|response)\.location\($"), "open redirect", "first"),
    (re.compile(r"\.(?:innerHTML|outerHTML) =$"), XSS, "value"),
    (re.compile(r"(?<![\w$.])document\.(?:write|writeln)\($"), XSS, "all"),
    (re.compile(r"\.insertAdjacentHTML\($"), XSS, "second"),
    (re.compile(r"(?<![\w$.])(?:res|response)(?:\.[\w$]+\(\))*\.(?:send|write|end)\($"), XSS, "first"),
]
FULL_SANITIZERS = frozenset(("parseInt", "parseFloat", "Number", "Boolean", "Math.floor", "Math.round",
                             "Math.ceil", "Math.abs", "Math.trunc"))
PARTIAL_SANITIZERS = {
    "DOMPurify.sanitize": BIT[XSS], "encodeURIComponent": BIT[XSS], "escapeHtml": BIT[XSS],
    "sanitizeHtml": BIT[XSS], "mysql.escape": BIT[SQL], "mysql2.escape": BIT[SQL], "pool.escape": BIT[SQL],
    "connection.escape": BIT[SQL], "conn.escape": BIT[SQL], "db.escape": BIT[SQL], "SqlString.escape": BIT[SQL],
    "path.basename": BIT["path traversal"], "shellQuote": BIT["command injection"],
    "shell_quote": BIT["command injection"], "quote": BIT["command injection"],
}
_LINES_RE = re.compile(r"\r\n|[\n\r\u2028\u2029]")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _lower(text):
    """ASCII letters lowered (the same in both engines, whatever the Unicode tables)."""
    return text.translate(_ASCII_LOWER)


def _join(base, rel):
    """base/rel with its "." and ".." segments resolved (empty segments
    dropped); None when it climbs above the root."""
    parts = []
    for seg in base.split("/") + rel.split("/"):
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    return "/".join(parts)


def config(source=SOURCE_RE, sinks=(), full=(), partial=None):
    """The taint model's configured part: the source pattern (SOURCE_RE and
    what a config adds), extra sinks ((pattern, category) — a call's callee
    text and "(", or an assignment's target and " ="), full sanitizers (call
    names) and partial ones (name -> categories)."""
    bits = {}
    for name, cats in (partial or {}).items():
        b = 0
        for c in cats:
            b |= BIT.get(c, 0)
        bits[name] = b
    return {"source": source, "sinks": list(sinks), "full": frozenset(full), "partial": bits}


# ------------------------------------------------------------------ values --
_NO_PARAMS = frozenset()


class _V:
    """What a value carries: request data (src, read at origin in function
    fname; via: the chain it arrived by — a returned value, an imported
    variable), the parameters of the function being read or of functions
    around it (params: keys), the sink categories it is sanitized for (clean,
    a bit set), whether it was joined into a string (built), and kind: bit 1
    a request object, bit 2 a response object."""
    __slots__ = ("src", "origin", "fname", "via", "params", "clean", "built", "kind")

    def __init__(self, src=False, origin=None, fname=None, via=None, params=_NO_PARAMS, clean=0, built=False,
                 kind=0):
        self.src = src
        self.origin = origin if src else None
        self.fname = fname if src else None
        self.via = via if src else None
        self.params = params
        self.clean = clean
        self.built = built
        self.kind = kind

    def tainted(self):
        return self.src or bool(self.params)

    def union(self, o):
        if o is EMPTY:
            return self
        if self is EMPTY:
            return o
        s = self if self.src else o
        params = self.params | o.params if o.params else self.params
        if len(params) > MAX_PARAMS:
            params = frozenset(sorted(params)[:MAX_PARAMS])
        return _V(self.src or o.src, s.origin, s.fname, s.via, params, self.clean & o.clean,
                  self.built or o.built, self.kind | o.kind)

    def sanitize(self, bits):
        if not self.tainted():
            return EMPTY
        return _V(self.src, self.origin, self.fname, self.via, self.params, self.clean | bits, self.built, 0)

    def with_built(self):
        if not self.tainted() or self.built:
            return self
        return _V(self.src, self.origin, self.fname, self.via, self.params, self.clean, True, self.kind)

    def with_via(self, via):
        return _V(self.src, self.origin, self.fname, via, self.params, self.clean, self.built, self.kind)

    def within(self, fids):
        """The value with only the parameters of functions fids."""
        if not self.params:
            return self
        params = frozenset(k for k in self.params if k // PARAM_BASE in fids)
        if len(params) == len(self.params):
            return self
        if not self.src and not params:
            return EMPTY
        return _V(self.src, self.origin, self.fname, self.via, params, self.clean, self.built, self.kind)

    def plain(self):
        """The value without a request or response object's mark."""
        if not self.kind:
            return self
        if not self.tainted():
            return EMPTY
        return _V(self.src, self.origin, self.fname, self.via, self.params, self.clean, self.built, 0)

    def key(self):
        return (self.src, self.origin, self.fname, self.via, self.params, self.clean, self.built, self.kind)


EMPTY = _V(clean=ALL)


def _union_all(vals):
    out = EMPTY
    for v in vals:
        out = out.union(v)
    return out


# ------------------------------------------------------------------- model --
class _Scope:
    __slots__ = ("kind", "parent", "names", "fid")

    def __init__(self, kind, parent, fid):
        self.kind = kind            # "function" (a var scope: functions and the module) or "block"
        self.parent = parent
        self.names = {}
        self.fid = fid              # the function the scope's code belongs to

    def var_scope(self):
        s = self
        while s.kind != "function":
            s = s.parent
        return s


class _Bind:
    __slots__ = ("bid", "name", "kind", "fid", "writes", "shared", "mod", "refs", "targets")

    def __init__(self, bid, name, kind, scope, mod):
        self.bid = bid
        self.name = name
        self.kind = kind            # var let const using param function class import catch enum
        self.fid = scope.fid        # the function whose code declares it
        self.writes = []            # (kind, node, scope, extra): what is written to it
        self.shared = False         # read or written by another function (closures, module variables)
        self.mod = mod
        self.refs = []              # (identifier node, parent node) of every reference
        self.targets = None         # an import: the bindings it reads in the modules it names


class _Fn:
    __slots__ = ("fid", "mod", "node", "name", "params", "scope", "parent", "line", "cls", "obj", "module",
                 "route", "reach", "ret_params", "ret_src", "ret_outer", "callers", "runs", "calls", "size")

    def __init__(self, fid, mod, node, name, params, scope, parent, line, module=False):
        self.fid = fid
        self.mod = mod
        self.node = node
        self.name = name
        self.params = params
        self.scope = scope
        self.parent = parent        # fid of the enclosing function (None: the module's own code)
        self.line = line
        self.cls = None             # the class of a method
        self.obj = None             # the object literal of a method
        self.module = module        # the module's own code
        self.route = 0              # a route handler: 1 (request, response), 2 (error, request, response)
        self.reach = {}             # param index -> {category: (file, line, label, needs joining)}
        self.ret_params = {}        # param index -> (clean, built) of the value it returns
        self.ret_src = None         # _V: request data it returns
        self.ret_outer = {}         # key of an enclosing function's parameter it returns -> (clean, built)
        self.callers = {}           # fid -> the parameters it passed tainted values in its last reading
        self.runs = 0
        self.calls = []             # (call node, scope) of its call sites
        self.size = 0

    def label(self):
        if self.module:
            return "(module level)"
        if self.name:
            return f"(in {self.name}())"
        return "(in an anonymous function)"

    def display(self):
        if self.module:
            return "the module's own code"
        return f"{self.name}()" if self.name else "an anonymous function"


class _Class:
    __slots__ = ("cid", "name", "methods", "statics", "sup")

    def __init__(self, cid, name):
        self.cid = cid
        self.name = name
        self.methods = {}           # prototype method name -> fid
        self.statics = {}           # static member name -> fid
        self.sup = None             # the superclass expression, (node, scope)


class _Obj:
    __slots__ = ("oid", "props")

    def __init__(self, oid):
        self.oid = oid
        self.props = {}             # key -> [(value node, scope)]


class _Mod:
    __slots__ = ("idx", "path", "dir", "lines", "ast", "scope", "fn", "named", "stars", "cjs", "cjs_props",
                 "eval_with", "regexp_proto", "regexp_rebound", "nodes")

    def __init__(self, idx, path, norm, content, ast):
        self.idx = idx
        self.path = path
        self.dir = norm[:norm.rfind("/")] if "/" in norm else ""
        self.lines = _LINES_RE.split(content)
        self.ast = ast
        self.scope = None
        self.fn = None              # fid of the module's own code
        self.named = {}             # ESM export name -> [entry]
        self.stars = []             # `export * from` specifiers
        self.cjs = []               # module.exports = … : [(node, scope)]
        self.cjs_props = {}         # exports.x = … : name -> [(node, scope)]
        self.eval_with = False      # a direct eval() or a with statement
        self.regexp_proto = False   # RegExp.prototype touched
        self.regexp_rebound = False  # the global RegExp assigned
        self.nodes = 0


# field names of each node type's children, in source order
_KIDS = {
    "Program": ("body",), "ExpressionStatement": ("expression",), "BlockStatement": ("body",),
    "EmptyStatement": (), "DebuggerStatement": (), "WithStatement": ("object", "body"),
    "ReturnStatement": ("argument",), "LabeledStatement": ("body",), "BreakStatement": (),
    "ContinueStatement": (), "IfStatement": ("test", "consequent", "alternate"),
    "SwitchStatement": ("discriminant", "cases"), "SwitchCase": ("test", "consequent"),
    "ThrowStatement": ("argument",), "TryStatement": ("block", "handler", "finalizer"),
    "CatchClause": ("param", "body"), "WhileStatement": ("test", "body"), "DoWhileStatement": ("body", "test"),
    "ForStatement": ("init", "test", "update", "body"), "ForInStatement": ("left", "right", "body"),
    "ForOfStatement": ("left", "right", "body"), "FunctionDeclaration": ("params", "body"),
    "VariableDeclaration": ("declarations",), "VariableDeclarator": ("id", "init"),
    "ClassDeclaration": ("decorators", "superClass", "body"), "ClassExpression": ("decorators", "superClass", "body"),
    "ClassBody": ("body",), "MethodDefinition": ("decorators", "key", "value"),
    "PropertyDefinition": ("decorators", "key", "value"), "StaticBlock": ("body",),
    "ImportDeclaration": (), "ExportNamedDeclaration": ("declaration", "specifiers"),
    "ExportDefaultDeclaration": ("declaration",), "ExportAllDeclaration": (), "ExportSpecifier": ("local",),
    "Identifier": (), "PrivateIdentifier": (), "Literal": (), "ThisExpression": (), "Super": (),
    "ArrayExpression": ("elements",), "ObjectExpression": ("properties",), "Property": ("key", "value"),
    "FunctionExpression": ("params", "body"), "ArrowFunctionExpression": ("params", "body"),
    "TemplateLiteral": ("expressions",), "TemplateElement": (), "TaggedTemplateExpression": ("tag", "quasi"),
    "MemberExpression": ("object", "property"), "ChainExpression": ("expression",),
    "CallExpression": ("callee", "arguments"), "NewExpression": ("callee", "arguments"), "MetaProperty": (),
    "ImportExpression": ("source", "options"), "UpdateExpression": ("argument",),
    "UnaryExpression": ("argument",), "AwaitExpression": ("argument",), "YieldExpression": ("argument",),
    "BinaryExpression": ("left", "right"), "LogicalExpression": ("left", "right"),
    "ConditionalExpression": ("test", "consequent", "alternate"), "AssignmentExpression": ("left", "right"),
    "SequenceExpression": ("expressions",), "SpreadElement": ("argument",), "RestElement": ("argument",),
    "AssignmentPattern": ("left", "right"), "ArrayPattern": ("elements",), "ObjectPattern": ("properties",),
    "JSXElement": ("openingElement", "children"), "JSXOpeningElement": ("attributes",),
    "JSXClosingElement": (), "JSXAttribute": ("value",), "JSXSpreadAttribute": ("argument",),
    "JSXExpressionContainer": ("expression",), "JSXSpreadChild": ("expression",), "JSXFragment": ("children",),
    "JSXText": (), "JSXEmptyExpression": (), "JSXIdentifier": (), "JSXMemberExpression": (),
    "JSXNamespacedName": (), "TSEnumDeclaration": ("members",), "TSEnumMember": ("initializer",),
    "TSModuleDeclaration": ("body",), "TSExportAssignment": ("expression",), "TSImportEquals": (),
}
_FUNCTIONS = frozenset(("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"))
_LOOPS = frozenset(("ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement", "DoWhileStatement"))


def _kids(node):
    """The child nodes of node, in source order."""
    out = []
    for field in _KIDS.get(node["type"], ()):
        v = node.get(field)
        if v is None:
            continue
        if isinstance(v, list):
            for x in v:
                if x is not None:
                    out.append(x)
        else:
            out.append(v)
    return out


def _pattern_names(pat):
    """(identifier node, property path) of each name a pattern binds, in
    source order; the path holds the property names read on the way (None
    for an element, a rest or a computed key)."""
    out = []
    stack = [(pat, ())]
    while stack:
        p, pth = stack.pop()
        if p is None:
            continue
        t = p["type"]
        if t == "Identifier":
            out.append((p, pth))
        elif t == "ObjectPattern":
            for prop in reversed(p["properties"]):
                if prop["type"] == "RestElement":
                    stack.append((prop["argument"], pth + (None,)))
                else:
                    name = None
                    if not prop["computed"]:
                        key = prop["key"]
                        name = key["name"] if key["type"] == "Identifier" else (
                            key["value"] if key.get("kind") == "string" else None)
                    stack.append((prop["value"], pth + (name,)))
        elif t == "ArrayPattern":
            for el in reversed(p["elements"]):
                stack.append((el, pth + (None,)))
        elif t == "RestElement":
            stack.append((p["argument"], pth + (None,)))
        elif t == "AssignmentPattern":
            stack.append((p["left"], pth))
    return out


def _pattern_members(pat):
    """The member expressions a pattern assigns to (`[a.b] = …`)."""
    out = []
    stack = [pat]
    while stack:
        p = stack.pop()
        if p is None:
            continue
        t = p["type"]
        if t == "MemberExpression":
            out.append(p)
        elif t == "ObjectPattern":
            for prop in p["properties"]:
                stack.append(prop["argument"] if prop["type"] == "RestElement" else prop["value"])
        elif t == "ArrayPattern":
            stack.extend(p["elements"])
        elif t in ("RestElement", "AssignmentPattern"):
            stack.append(p["argument"] if t == "RestElement" else p["left"])
    return out


def _prop_name(member):
    """A member expression's property name, or None (computed, not a literal)."""
    prop = member["property"]
    if not member["computed"]:
        return ("#" if prop["type"] == "PrivateIdentifier" else "") + prop["name"]
    if prop["type"] == "Literal" and prop.get("kind") in ("string", "number"):
        return str(prop["value"])
    return None


def _key_name(prop):
    """An object's or a class's member name, or None (computed)."""
    key = prop["key"]
    if prop.get("computed"):
        if key["type"] == "Literal" and key.get("kind") == "string":
            return key["value"]
        return None
    if key["type"] == "Identifier":
        return key["name"]
    if key["type"] == "PrivateIdentifier":
        return "#" + key["name"]
    if key["type"] == "Literal":
        return str(key["value"])
    return None


def _unwrap(node):
    while node["type"] == "ChainExpression":
        node = node["expression"]
    return node


def _text(node):
    """A callee's or a member's text: `a.b().c`, `new F()`, `this.x`, `a[]`
    for a computed member; "" for anything else. At most TEXT_MAX
    characters. Memoized on the nodes (`_t`); deep chains in a loop."""
    got = node.get("_t")
    if got is not None:
        return got
    chain = []
    n = node
    while n.get("_t") is None:
        t = n["type"]
        if t == "MemberExpression":
            chain.append(n)
            n = n["object"]
        elif t == "CallExpression":
            chain.append(n)
            n = n["callee"]
        elif t == "ChainExpression":
            chain.append(n)
            n = n["expression"]
        else:
            break
    text = n.get("_t")
    if text is None:
        t = n["type"]
        if t == "Identifier":
            text = n["name"]
        elif t == "ThisExpression":
            text = "this"
        elif t == "Super":
            text = "super"
        elif t == "NewExpression":
            text = "new " + _text(n["callee"]) + "()"
        else:
            text = ""
        text = text[:TEXT_MAX]
        n["_t"] = text
    for m in reversed(chain):
        t = m["type"]
        if t == "MemberExpression":
            name = _prop_name(m)
            text = text + ("." + name if name is not None else "[]")
        elif t == "CallExpression":
            text = text + "()"
        text = text[:TEXT_MAX]
        m["_t"] = text
    return node["_t"]


def _route_path(node):
    """A route's path: '/…' or '*', a `/…` template, a regex literal, or an
    array of those."""
    t = node["type"]
    if t == "Literal":
        if node.get("kind") == "regex":
            return True
        return node.get("kind") == "string" and (node["value"].startswith("/") or node["value"] == "*")
    if t == "TemplateLiteral":
        return node["quasis"][0]["raw"].startswith("/")
    if t == "ArrayExpression":
        return bool(node["elements"]) and all(e is not None and e["type"] != "ArrayExpression" and _route_path(e)
                                              for e in node["elements"])
    return False


def _leftmost_text(node):
    """The text a string expression starts with, when it starts with a
    literal: a string, a template's first part, the left end of a `+`
    chain; else None."""
    seen = 0
    while seen < ALIAS_DEPTH:
        seen += 1
        t = node["type"]
        if t == "Literal":
            return node["value"] if node.get("kind") == "string" else None
        if t == "TemplateLiteral":
            return node["quasis"][0]["raw"]
        if t == "BinaryExpression" and node["operator"] == "+":
            node = node["left"]
            continue
        return None
    return None


def _fixed_prefix(node):
    text = _leftmost_text(node)
    return text is not None and FIXED_PREFIX_RE.match(text) is not None


def _html_type(value):
    v = _lower(value)
    return "html" in v or "xml" in v or "svg" in v


def mod_scope(scope):
    s = scope
    while s.parent is not None:
        s = s.parent
    return s


def lookup(scope, name):
    s = scope
    while s is not None:
        b = s.names.get(name)
        if b is not None:
            return b
        s = s.parent
    return None


# ------------------------------------------------------------------ program --
class _Program:
    def __init__(self, cfg):
        self.mods = []
        self.by_path = {}
        self.fns = []
        self.classes = []
        self.objs = []
        self.binds = []
        self.by_name = {}           # function name -> [fid], every project function of that name
        self.shared = {}            # bid -> _V: everything written to a shared binding
        self.readers = {}           # bid -> {fid: True}: who reads a shared binding
        self.desc_memo = {}
        self.cfg = cfg
        self.work = 0
        self.budget = WORK_BASE
        self.nodes = 0
        self.issue = None
        self.anc = {}

    def scope_fns(self, fid):
        """fid and the functions around it (memoized)."""
        got = self.anc.get(fid)
        if got is None:
            out = []
            f = self.fns[fid]
            while True:
                out.append(f.fid)
                if f.parent is None:
                    break
                f = self.fns[f.parent]
            got = self.anc[fid] = frozenset(out)
        return got

    # ---- indexing ----
    def add_module(self, path, content, ast):
        norm = path.replace("\\", "/")
        joined = _join("", norm)
        if joined is not None:
            norm = joined
        mod = _Mod(len(self.mods), path, norm, content, ast)
        self.mods.append(mod)
        self.by_path.setdefault(norm, mod.idx)
        mfn = _Fn(len(self.fns), mod.idx, ast, None, [], None, None, 1, module=True)
        self.fns.append(mfn)
        mod.fn = mfn.fid
        scope = _Scope("function", None, mfn.fid)
        mfn.scope = scope
        mod.scope = scope
        ast["_scope"] = scope
        self.declare(mod, ast, scope, mfn)
        self.nodes += mod.nodes
        return mod

    def new_bind(self, name, kind, scope, mod, node):
        b = _Bind(len(self.binds), name, kind, scope, mod.idx)
        self.binds.append(b)
        scope.names[name] = b
        return b

    def declare(self, mod, root, root_scope, root_fn):
        """Scopes and bindings: every name declared in root, and the
        functions, classes and object literals in it."""
        # (node, scope, the function whose code it is, name hint)
        stack = [(root["body"][k], root_scope, root_fn, None) for k in range(len(root["body"]) - 1, -1, -1)]
        mod.nodes += 1
        root_fn.size += 1
        while stack:
            node, scope, fn, hint = stack.pop()
            mod.nodes += 1
            fn.size += 1
            t = node["type"]
            if t in _FUNCTIONS:
                inner = self.new_function(mod, node, scope, fn, hint)
                fscope = inner.scope
                node["_scope"] = fscope
                if t == "FunctionExpression" and node.get("id") is not None:
                    fb = self.new_bind(node["id"]["name"], "function", fscope, mod, node["id"])
                    fb.writes.append(("fn", node, fscope, inner.fid))
                for i, p in enumerate(node["params"]):
                    for ident, _ in _pattern_names(p):
                        b = self.new_bind(ident["name"], "param", fscope, mod, ident)
                        b.writes.append(("param", p, fscope, i))
                body = node["body"]
                if body["type"] == "BlockStatement":
                    body["_scope"] = fscope
                    for st in reversed(body["body"]):
                        stack.append((st, fscope, inner, None))
                else:
                    stack.append((body, fscope, inner, None))
                for p in reversed(node["params"]):
                    self.push_pattern_parts(p, fscope, inner, stack)
                if t == "FunctionDeclaration" and node.get("id") is not None:
                    b = scope.names.get(node["id"]["name"])
                    if b is None or b.kind not in ("var", "function"):
                        b = self.new_bind(node["id"]["name"], "function", scope, mod, node["id"])
                    b.writes.append(("fn", node, scope, inner.fid))
                continue
            if t in ("ClassDeclaration", "ClassExpression"):
                c = self.new_class(node, hint)
                cscope = _Scope("block", scope, fn.fid)
                node["_scope"] = cscope
                if node.get("id") is not None:
                    b = self.new_bind(node["id"]["name"], "class", scope if t == "ClassDeclaration" else cscope,
                                      mod, node["id"])
                    b.writes.append(("class", node, scope, c.cid))
                members = node["body"]["body"]
                for member in reversed(members):
                    mt = member["type"]
                    if mt == "StaticBlock":
                        sscope = _Scope("function", cscope, fn.fid)
                        member["_scope"] = sscope
                        for st in reversed(member["body"]):
                            stack.append((st, sscope, fn, None))
                        continue
                    name = _key_name(member)
                    v = member["value"]
                    if v is not None:
                        if mt == "MethodDefinition":
                            stack.append((v, cscope, fn, ("method", c.cid, name, member["static"], member["kind"])))
                        elif v["type"] in _FUNCTIONS:
                            stack.append((v, cscope, fn, ("method", c.cid, name, member["static"], "method")))
                        else:
                            stack.append((v, cscope, fn, None))
                    if member["computed"]:
                        stack.append((member["key"], scope, fn, None))
                    for d in reversed(member.get("decorators") or ()):
                        stack.append((d, scope, fn, None))
                if node.get("superClass") is not None:
                    c.sup = (node["superClass"], scope)
                    stack.append((node["superClass"], scope, fn, None))
                for d in reversed(node.get("decorators") or ()):
                    stack.append((d, scope, fn, None))
                continue
            if t == "ObjectExpression":
                o = self.new_object(node)
                for prop in reversed(node["properties"]):
                    if prop["type"] == "SpreadElement":
                        stack.append((prop["argument"], scope, fn, None))
                        continue
                    name = _key_name(prop)
                    v = prop["value"]
                    if name is not None:
                        o.props.setdefault(name, []).insert(0, (v, scope))
                    stack.append((v, scope, fn, ("objprop", o.oid, name) if v["type"] in _FUNCTIONS else None))
                    if prop["computed"]:
                        stack.append((prop["key"], scope, fn, None))
                continue
            if t == "VariableDeclaration":
                kind = node["kind"]
                target = scope.var_scope() if kind == "var" else scope
                for d in node["declarations"]:
                    for ident, path in _pattern_names(d["id"]):
                        b = target.names.get(ident["name"]) if kind == "var" else None
                        if b is None or b.kind not in ("var", "function", "param"):
                            b = self.new_bind(ident["name"], kind, target, mod, ident)
                        if d["init"] is not None:
                            b.writes.append(("init", d["init"], scope, path))
                        elif kind != "var":
                            b.writes.append(("none", None, scope, None))
                for d in reversed(node["declarations"]):
                    if d["init"] is not None:
                        hint2 = None
                        it = d["init"]["type"]
                        if d["id"]["type"] == "Identifier" and (it in _FUNCTIONS or it == "ClassExpression"):
                            hint2 = ("var", d["id"]["name"])
                        stack.append((d["init"], scope, fn, hint2))
                    self.push_pattern_parts(d["id"], scope, fn, stack)
                continue
            if t == "BlockStatement":
                bscope = _Scope("block", scope, fn.fid)
                node["_scope"] = bscope
                for st in reversed(node["body"]):
                    stack.append((st, bscope, fn, None))
                continue
            if t in ("ForStatement", "ForInStatement", "ForOfStatement", "SwitchStatement"):
                lscope = _Scope("block", scope, fn.fid)
                node["_scope"] = lscope
                for k in reversed(_kids(node)):
                    stack.append((k, lscope, fn, None))
                continue
            if t == "CatchClause":
                cscope = _Scope("block", scope, fn.fid)
                node["_scope"] = cscope
                if node["param"] is not None:
                    for ident, _ in _pattern_names(node["param"]):
                        b = self.new_bind(ident["name"], "catch", cscope, mod, ident)
                        b.writes.append(("none", None, cscope, None))
                    self.push_pattern_parts(node["param"], cscope, fn, stack)
                body = node["body"]
                body["_scope"] = cscope
                for st in reversed(body["body"]):
                    stack.append((st, cscope, fn, None))
                continue
            if t == "ImportDeclaration":
                src = node["source"]["value"]
                for spec in node["specifiers"]:
                    st = spec["type"]
                    if st == "ImportDefaultSpecifier":
                        name = "default"
                    elif st == "ImportNamespaceSpecifier":
                        name = "*"
                    else:
                        imp = spec["imported"]
                        name = imp["name"] if imp["type"] == "Identifier" else imp["value"]
                    b = self.new_bind(spec["local"]["name"], "import", mod_scope(scope), mod, spec["local"])
                    b.writes.append(("import", src, scope, name))
                continue
            if t == "TSImportEquals":
                b = self.new_bind(node["id"]["name"], "import", scope, mod, node["id"])
                if node["module"] is not None:
                    b.writes.append(("import", node["module"]["value"], scope, "="))
                else:
                    b.writes.append(("init", node["entity"], scope, ()))
                continue
            if t in ("TSEnumDeclaration", "TSModuleDeclaration"):
                name = node["id"]["name"] if node["id"]["type"] == "Identifier" else None
                if name is not None and name not in scope.names:
                    b = self.new_bind(name, "enum", scope, mod, node["id"])
                    b.writes.append(("none", None, scope, None))
                for k in reversed(_kids(node)):
                    stack.append((k, scope, fn, None))
                continue
            if t == "WithStatement":
                mod.eval_with = True
            elif t == "AssignmentExpression":
                right, left = node["right"], node["left"]
                hint2 = None
                if right["type"] in _FUNCTIONS or right["type"] == "ClassExpression":
                    if left["type"] == "Identifier":
                        hint2 = ("var", left["name"])
                    elif left["type"] == "MemberExpression":
                        hint2 = ("var", _prop_name(left))
                stack.append((right, scope, fn, hint2))
                stack.append((left, scope, fn, None))
                continue
            elif t == "ExportDefaultDeclaration":
                stack.append((node["declaration"], scope, fn, None))
                continue
            for k in reversed(_kids(node)):
                stack.append((k, scope, fn, None))

    def push_pattern_parts(self, pat, scope, fn, stack):
        """A pattern's default values and computed keys, read in scope."""
        todo = [pat]
        while todo:
            p = todo.pop()
            if p is None:
                continue
            t = p["type"]
            if t == "AssignmentPattern":
                right = p["right"]
                hint = ("var", p["left"]["name"]) if (p["left"]["type"] == "Identifier"
                                                      and right["type"] in _FUNCTIONS) else None
                stack.append((right, scope, fn, hint))
                todo.append(p["left"])
            elif t == "ObjectPattern":
                for prop in p["properties"]:
                    if prop["type"] == "RestElement":
                        todo.append(prop["argument"])
                    else:
                        if prop["computed"]:
                            stack.append((prop["key"], scope, fn, None))
                        todo.append(prop["value"])
            elif t == "ArrayPattern":
                todo.extend(p["elements"])
            elif t == "RestElement":
                todo.append(p["argument"])
            elif t == "MemberExpression":
                stack.append((p, scope, fn, None))

    def new_function(self, mod, node, scope, parent_fn, hint):
        name = None
        if node["type"] != "ArrowFunctionExpression" and node.get("id") is not None:
            name = node["id"]["name"]
        fid = len(self.fns)
        cls = obj = None
        if hint is not None:
            if hint[0] == "method":
                _, cid, mname, is_static, kind = hint
                name = name or mname
                if kind in ("method", "constructor") and mname is not None:
                    table = self.classes[cid].statics if is_static else self.classes[cid].methods
                    table[mname] = fid
                cls = cid
            elif hint[0] == "objprop":
                name = name or hint[2]
                obj = hint[1]
            elif hint[0] == "var":
                name = name or hint[1]
        fscope = _Scope("function", scope, fid)
        fn = _Fn(fid, mod.idx, node, name, node["params"], fscope, parent_fn.fid, node["line"])
        fn.cls = cls
        fn.obj = obj
        self.fns.append(fn)
        node["_fid"] = fid
        if name:
            self.by_name.setdefault(name, []).append(fid)
        return fn

    def new_class(self, node, hint):
        name = node["id"]["name"] if node.get("id") is not None else (hint[1] if hint and hint[0] == "var" else None)
        c = _Class(len(self.classes), name)
        self.classes.append(c)
        node["_cid"] = c.cid
        return c

    def new_object(self, node):
        o = _Obj(len(self.objs))
        self.objs.append(o)
        node["_oid"] = o.oid
        return o

    # ---- references ----
    def resolve_module(self, idx):
        """Every identifier resolved to its binding (`_b`, None: a global);
        the writes of assignments, the call sites of each function, the
        members a program assigns to (`_asg`), exports, module.exports and
        the file's eval / with / RegExp facts."""
        m = self.mods[idx]
        stack = [(m.ast, m.scope, m.fn, None, "ref")]
        while stack:
            node, scope, fid, parent, field = stack.pop()
            t = node["type"]
            s = node.get("_scope")
            if s is not None:
                scope = s
                if t in _FUNCTIONS:
                    fid = node["_fid"]
            if t == "Identifier":
                b = lookup(scope, node["name"])
                node["_b"] = b
                if field == "ref":
                    if b is not None:
                        b.refs.append((node, parent))
                        if b.fid != fid:
                            b.shared = True
                continue
            if t == "MemberExpression":
                obj = node["object"]
                name = _prop_name(node)
                if name == "prototype" and obj["type"] == "Identifier" and obj["name"] == "RegExp":
                    m.regexp_proto = True
                if name == "RegExp" and obj["type"] == "Identifier" and obj["name"] in (
                        "globalThis", "window", "global", "self") and node.get("_asg"):
                    m.regexp_rebound = True
                stack.append((obj, scope, fid, node, "ref"))
                if node["computed"]:
                    stack.append((node["property"], scope, fid, node, "ref"))
                continue
            if t == "CallExpression" or t == "NewExpression" or t == "TaggedTemplateExpression":
                callee = node["tag"] if t == "TaggedTemplateExpression" else node["callee"]
                if t == "CallExpression" and callee["type"] == "Identifier" and callee["name"] == "eval":
                    m.eval_with = True
                self.fns[fid].calls.append((node, scope))
            elif t == "AssignmentExpression":
                self.record_assignment(m, node, scope, fid)
            elif t == "UpdateExpression" or (t == "UnaryExpression" and node["operator"] == "delete"):
                arg = node["argument"]
                if arg["type"] == "MemberExpression":
                    arg["_asg"] = True
                elif t == "UpdateExpression" and arg["type"] == "Identifier":
                    b = lookup(scope, arg["name"])
                    if b is not None:
                        b.writes.append(("opaque", node, scope, None))
                        if b.fid != fid:
                            b.shared = True
            elif t == "ExportNamedDeclaration":
                self.record_export(m, node, scope)
            elif t == "ExportDefaultDeclaration":
                m.named.setdefault("default", []).append(("expr", node["declaration"], scope))
            elif t == "ExportAllDeclaration":
                if node["exported"] is None:
                    m.stars.append(node["source"]["value"])
                else:
                    ex = node["exported"]
                    name = ex["name"] if ex["type"] == "Identifier" else ex["value"]
                    m.named.setdefault(name, []).append(("namespace", node["source"]["value"], scope))
            elif t == "TSExportAssignment":
                m.cjs.append((node["expression"], scope))
            elif t == "ForInStatement" or t == "ForOfStatement":
                left = node["left"]
                if left["type"] == "VariableDeclaration":
                    for d in left["declarations"]:
                        for ident, _ in _pattern_names(d["id"]):
                            b = lookup(scope, ident["name"])
                            if b is not None:
                                b.writes.append(("opaque", node, scope, None))
                else:
                    for mem in _pattern_members(left):
                        mem["_asg"] = True
                    for ident, _ in _pattern_names(left):
                        b = lookup(scope, ident["name"])
                        if b is not None:
                            b.writes.append(("opaque", node, scope, None))
                            if b.fid != fid:
                                b.shared = True
            # children: references and declared names
            if t == "Property":
                if node["computed"]:
                    stack.append((node["key"], scope, fid, node, "ref"))
                stack.append((node["value"], scope, fid, node, field if parent is not None
                              and parent["type"] == "ObjectPattern" else "ref"))
                continue
            if t == "MethodDefinition" or t == "PropertyDefinition":
                if node["value"] is not None:
                    stack.append((node["value"], scope, fid, node, "ref"))
                if node["computed"]:
                    stack.append((node["key"], scope.parent if scope.parent is not None else scope, fid, node,
                                  "ref"))
                for d in reversed(node.get("decorators") or ()):
                    stack.append((d, scope.parent if scope.parent is not None else scope, fid, node, "ref"))
                continue
            if t == "LabeledStatement":
                stack.append((node["body"], scope, fid, node, "ref"))
                continue
            if t == "ExportSpecifier" or t == "ImportDeclaration" or t == "ExportAllDeclaration" \
                    or t == "TSImportEquals" or t == "MetaProperty":
                if t == "TSImportEquals" and node["entity"] is not None:
                    stack.append((node["entity"], scope, fid, node, "ref"))
                continue
            if t == "ExportNamedDeclaration":
                if node["declaration"] is not None:
                    stack.append((node["declaration"], scope, fid, node, "ref"))
                continue
            if t == "ClassDeclaration" or t == "ClassExpression":
                outer = scope.parent        # the class's own scope holds its name (expressions)
                for member in reversed(node["body"]["body"]):
                    if member["type"] == "StaticBlock":
                        sscope = member["_scope"]
                        for st in reversed(member["body"]):
                            stack.append((st, sscope, fid, member, "ref"))
                    else:
                        stack.append((member, scope, fid, node, "ref"))
                if node.get("superClass") is not None:
                    stack.append((node["superClass"], outer, fid, node, "ref"))
                for d in reversed(node.get("decorators") or ()):
                    stack.append((d, outer, fid, node, "ref"))
                continue
            if t in _FUNCTIONS:
                body = node["body"]
                stack.append((body, scope, fid, node, "ref"))
                for p in reversed(node["params"]):
                    stack.append((p, scope, fid, node, "decl"))
                continue
            if t == "VariableDeclarator":
                if node["init"] is not None:
                    stack.append((node["init"], scope, fid, node, "ref"))
                stack.append((node["id"], scope, fid, node, "decl"))
                continue
            if t == "ObjectPattern" or t == "ArrayPattern" or t == "RestElement" or t == "AssignmentPattern":
                kids = _kids(node)
                for k in reversed(kids):
                    kf = field
                    if t == "AssignmentPattern" and k is node["right"]:
                        kf = "ref"
                    stack.append((k, scope, fid, node, kf))
                continue
            if t == "CatchClause":
                stack.append((node["body"], scope, fid, node, "ref"))
                if node["param"] is not None:
                    stack.append((node["param"], scope, fid, node, "decl"))
                continue
            if t == "JSXOpeningElement" or t == "JSXClosingElement":
                if t == "JSXOpeningElement":
                    for a in reversed(node["attributes"]):
                        stack.append((a, scope, fid, node, "ref"))
                continue
            if t == "JSXAttribute":
                if node["value"] is not None:
                    stack.append((node["value"], scope, fid, node, "ref"))
                continue
            for k in reversed(_kids(node)):
                stack.append((k, scope, fid, node, "ref"))

    def record_assignment(self, m, node, scope, fid):
        left, right, op = node["left"], node["right"], node["operator"]
        if left["type"] == "Identifier":
            b = lookup(scope, left["name"])
            if b is not None:
                b.writes.append(("assign" if op == "=" else "opaque", right, scope, ()))
                if b.fid != fid:
                    b.shared = True
            elif left["name"] == "RegExp":
                m.regexp_rebound = True
            return
        if left["type"] == "ObjectPattern" or left["type"] == "ArrayPattern":
            for mem in _pattern_members(left):
                mem["_asg"] = True
            for ident, path in _pattern_names(left):
                b = lookup(scope, ident["name"])
                if b is not None:
                    b.writes.append(("assign", right, scope, path))
                    if b.fid != fid:
                        b.shared = True
                elif ident["name"] == "RegExp":
                    m.regexp_rebound = True
            return
        if left["type"] != "MemberExpression":
            return
        left["_asg"] = True
        name = _prop_name(left)
        obj = left["object"]
        if name == "RegExp" and obj["type"] == "Identifier" \
                and obj["name"] in ("globalThis", "window", "global", "self"):
            m.regexp_rebound = True
        # module.exports = … / module.exports.x = … / exports.x = …
        if obj["type"] == "Identifier" and obj["name"] == "module" and name == "exports" \
                and lookup(scope, "module") is None:
            m.cjs.append((right, scope))
            return
        if name is not None and obj["type"] == "Identifier" and obj["name"] == "exports" \
                and lookup(scope, "exports") is None:
            m.cjs_props.setdefault(name, []).append((right, scope))
            return
        if name is not None and obj["type"] == "MemberExpression" and not obj["computed"] \
                and _prop_name(obj) == "exports" and obj["object"]["type"] == "Identifier" \
                and obj["object"]["name"] == "module" and lookup(scope, "module") is None:
            m.cjs_props.setdefault(name, []).append((right, scope))

    def record_export(self, m, node, scope):
        decl = node["declaration"]
        if decl is not None:
            if decl["type"] == "VariableDeclaration":
                for d in decl["declarations"]:
                    for ident, _ in _pattern_names(d["id"]):
                        m.named.setdefault(ident["name"], []).append(("binding", ident["name"], scope))
            elif decl.get("id") is not None and decl["id"]["type"] == "Identifier":
                m.named.setdefault(decl["id"]["name"], []).append(("binding", decl["id"]["name"], scope))
            return
        src = node["source"]["value"] if node["source"] is not None else None
        for spec in node["specifiers"]:
            local, exported = spec["local"], spec["exported"]
            lname = local["name"] if local["type"] == "Identifier" else local["value"]
            ename = exported["name"] if exported["type"] == "Identifier" else exported["value"]
            if src is not None:
                m.named.setdefault(ename, []).append(("reexport", src, lname))
            else:
                m.named.setdefault(ename, []).append(("binding", lname, scope))

    # ---- modules ----
    def resolve_spec(self, mod, spec):
        """A module specifier from module mod: ("mod", idx), ("builtin",
        name) or ("pkg", spec)."""
        if not isinstance(spec, str):
            return ("pkg", "")
        if spec.startswith("node:"):
            return ("builtin", spec[5:])
        if not (spec.startswith("./") or spec.startswith("../") or spec == "." or spec == ".."):
            head = spec.split("/")[0]
            if head in NODE_BUILTINS:
                return ("builtin", head)
            return ("pkg", spec)
        base = _join(self.mods[mod].dir, spec)
        if base is None:
            return ("pkg", spec)
        last = base[base.rfind("/") + 1:]
        dot = last.rfind(".")
        ext = last[dot:] if dot > 0 else ""
        cands = []
        if ext in EXTS:
            cands.append(base)
            for alt in TS_SOURCES.get(ext, ()):
                cands.append(base[:len(base) - len(ext)] + alt)
        else:
            cands.extend(base + e for e in EXTS)
            cands.extend((base + "/" if base else "") + "index" + e for e in EXTS)
        for c in cands:
            idx = self.by_path.get(c)
            if idx is not None:
                return ("mod", idx)
        return ("pkg", spec)

    # ---- what names hold (points-to) ----
    def descs_of_bind(self, b, depth):
        got = self.desc_memo.get(b.bid)
        if got is not None:
            return got
        if depth > ALIAS_DEPTH:
            return (("unknown",),)
        self.desc_memo[b.bid] = (("unknown",),)       # a cycle reads as unknown
        out = []
        for kind, node, scope, extra in b.writes:
            if kind == "fn":
                out.append(("fn", extra))
            elif kind == "class":
                out.append(("class", extra))
            elif kind == "import":
                target = self.resolve_spec(b.mod, node)
                if extra == "*" or extra == "=":
                    out.append(target)
                elif target[0] == "mod":
                    out.extend(self.member_descs(target[1], extra, depth + 1, 0))
                elif target[0] == "builtin":
                    out.append(("builtin", target[1] + "." + extra))
                else:
                    out.append(("open", extra if extra != "default" else b.name))
            elif kind == "init" or kind == "assign":
                ds = self.descs_of_expr(node, scope, depth + 1)
                for name in extra:
                    if name is None:
                        ds = (("unknown",),)
                        break
                    ds = tuple(x for d in ds for x in self.member_of(d, name, depth + 1))
                out.extend(ds)
            else:
                out.append(("local",))
        out = tuple(dict.fromkeys(out)) or (("local",),)
        self.desc_memo[b.bid] = out
        return out

    def descs_of_expr(self, node, scope, depth):
        """What an expression may be: ("fn", fid), ("class", cid), ("inst",
        cid), ("obj", oid), ("mod", idx), ("builtin", name), ("pkg", spec),
        ("open", name), ("global", name), ("local",), ("unknown",)."""
        if depth > ALIAS_DEPTH:
            return (("unknown",),)
        t = node["type"]
        if t == "Identifier":
            b = node.get("_b", False)
            if b is False:
                b = lookup(scope, node["name"])
            if b is None:
                return (("global", node["name"]),)
            return self.descs_of_bind(b, depth)
        if t in _FUNCTIONS:
            return (("fn", node["_fid"]),)
        if t == "ClassExpression":
            return (("class", node["_cid"]),)
        if t == "ObjectExpression":
            return (("obj", node["_oid"]),)
        if t == "CallExpression":
            callee = node["callee"]
            if callee["type"] == "Identifier" and callee["name"] == "require" and node["arguments"] \
                    and lookup(scope, "require") is None:
                arg = node["arguments"][0]
                if arg["type"] == "Literal" and arg.get("kind") == "string":
                    return (self.resolve_spec(self.fns[scope.fid].mod, arg["value"]),)
                if arg["type"] == "TemplateLiteral" and not arg["expressions"]:
                    return (self.resolve_spec(self.fns[scope.fid].mod, arg["quasis"][0]["raw"]),)
            return (("unknown",),)
        if t == "NewExpression":
            out = []
            for d in self.descs_of_expr(node["callee"], scope, depth + 1):
                if d[0] == "class":
                    out.append(("inst", d[1]))
            return tuple(out) or (("unknown",),)
        if t == "MemberExpression":
            name = _prop_name(node)
            if name is None:
                return (("unknown",),)
            out = []
            for d in self.descs_of_expr(node["object"], scope, depth + 1):
                out.extend(self.member_of(d, name, depth + 1))
            return tuple(dict.fromkeys(out)) or (("unknown",),)
        if t == "ChainExpression":
            return self.descs_of_expr(node["expression"], scope, depth + 1)
        if t == "AwaitExpression":
            return self.descs_of_expr(node["argument"], scope, depth + 1)
        if t == "SequenceExpression":
            return self.descs_of_expr(node["expressions"][-1], scope, depth + 1)
        if t == "AssignmentExpression" and node["operator"] == "=":
            return self.descs_of_expr(node["right"], scope, depth + 1)
        if t == "ConditionalExpression" or t == "LogicalExpression":
            parts = (node["consequent"], node["alternate"]) if t == "ConditionalExpression" \
                else (node["left"], node["right"])
            out = []
            for p in parts:
                out.extend(self.descs_of_expr(p, scope, depth + 1))
            return tuple(dict.fromkeys(out))
        if t == "ThisExpression":
            return self.this_descs(scope)
        if t == "Super":
            c = self.method_class(scope)
            if c is not None:
                sup = self.superclass(c, depth)
                if sup is not None:
                    return (("inst", sup.cid),)
        return (("unknown",),)

    def method_class(self, scope):
        """The class of the method whose code scope is (through arrows)."""
        fn = self.fns[scope.fid]
        seen = 0
        while fn.node is not None and fn.node["type"] == "ArrowFunctionExpression" and fn.parent is not None \
                and seen < ALIAS_DEPTH:
            fn = self.fns[fn.parent]
            seen += 1
        return self.classes[fn.cls] if fn.cls is not None else None

    def this_descs(self, scope):
        """`this` in a method: an instance of its class, or its object."""
        fn = self.fns[scope.fid]
        seen = 0
        while fn.node is not None and fn.node["type"] == "ArrowFunctionExpression" and fn.parent is not None \
                and seen < ALIAS_DEPTH:
            fn = self.fns[fn.parent]
            seen += 1
        if fn.cls is not None:
            return (("inst", fn.cls),)
        if fn.obj is not None:
            return (("obj", fn.obj),)
        return (("unknown",),)

    def member_of(self, d, name, depth):
        kind = d[0]
        if kind == "mod":
            return self.member_descs(d[1], name, depth, 0)
        if kind == "obj":
            out = []
            for node, scope in self.objs[d[1]].props.get(name, ()):
                out.extend(self.descs_of_expr(node, scope, depth + 1))
            return tuple(out) or (("open", name),)
        if kind == "class":
            fid = self.classes[d[1]].statics.get(name)
            return (("fn", fid),) if fid is not None else (("open", name),)
        if kind == "inst":
            c = self.classes[d[1]]
            seen = 0
            while c is not None and seen < ALIAS_DEPTH:
                seen += 1
                fid = c.methods.get(name)
                if fid is not None:
                    return (("fn", fid),)
                c = self.superclass(c, depth)
            return (("open", name),) if name not in COMMON_METHODS else (("unknown",),)
        if kind == "builtin":
            return (("builtin", d[1] + "." + name),)
        if kind == "global" and d[1] in GLOBAL_OBJECTS:
            return (("builtin", d[1] + "." + name),)
        if name in COMMON_METHODS:
            return (("unknown",),)
        return (("open", name),)

    def superclass(self, c, depth):
        if c.sup is None or depth > ALIAS_DEPTH:
            return None
        node, scope = c.sup
        for d in self.descs_of_expr(node, scope, depth + 1):
            if d[0] == "class":
                return self.classes[d[1]]
        return None

    def member_descs(self, idx, name, depth, hops):
        """What export `name` of module idx may be."""
        m = self.mods[idx]
        out = []
        for entry in m.named.get(name, ()):
            out.extend(self.export_entry(m, entry, depth))
        if name != "default" or not out:
            for node, scope in m.cjs_props.get(name, ()):
                out.extend(self.descs_of_expr(node, scope, depth + 1))
        for node, scope in m.cjs:
            for x in self.descs_of_expr(node, scope, depth + 1):
                if name == "default":
                    if not m.named.get("default"):
                        out.append(x)
                elif x[0] in ("obj", "mod", "class", "inst"):
                    out.extend(self.member_of(x, name, depth + 1))
        if not out and name != "default" and hops < EXPORT_HOPS:
            for spec in m.stars:
                target = self.resolve_spec(m.idx, spec)
                if target[0] == "mod":
                    got = self.member_descs(target[1], name, depth + 1, hops + 1)
                    out.extend(x for x in got if x[0] != "open")
        out = tuple(dict.fromkeys(out))
        if out:
            return out
        return (("open", name),) if name != "default" else (("unknown",),)

    def export_entry(self, m, entry, depth):
        kind = entry[0]
        if kind == "binding":
            b = lookup(entry[2], entry[1])
            if b is None:
                return (("open", entry[1]),)
            return self.descs_of_bind(b, depth + 1)
        if kind == "expr":
            node = entry[1]
            if node["type"] == "FunctionDeclaration":
                return (("fn", node["_fid"]),)
            if node["type"] == "ClassDeclaration":
                return (("class", node["_cid"]),)
            return self.descs_of_expr(node, entry[2], depth + 1)
        if kind == "reexport":
            target = self.resolve_spec(m.idx, entry[1])
            if target[0] == "mod" and depth < ALIAS_DEPTH:
                return self.member_descs(target[1], entry[2], depth + 1, 0)
            return (("open", entry[2]),)
        return (self.resolve_spec(m.idx, entry[1]),)          # namespace

    def mod_callables(self, idx, hops):
        """The functions a module's `module.exports` may be."""
        out = []
        for node, scope in self.mods[idx].cjs:
            for x in self.descs_of_expr(node, scope, 1):
                if x[0] == "fn":
                    out.append(x[1])
                elif x[0] == "class":
                    ctor = self.constructor(self.classes[x[1]])
                    if ctor is not None:
                        out.append(ctor)
                elif x[0] == "mod" and hops < EXPORT_HOPS:
                    out.extend(self.mod_callables(x[1], hops + 1))
        return out

    def constructor(self, c):
        seen = 0
        while c is not None and seen < ALIAS_DEPTH:
            seen += 1
            fid = c.methods.get("constructor")
            if fid is not None:
                return fid
            c = self.superclass(c, 0)
        return None

    # ---- calls ----
    def call_targets(self, call, scope):
        """(project functions the call may reach, how): how is "definite",
        "open" (by name), "mixed" or "none". Memoized on the call (`_tg`)."""
        got = call.get("_tg")
        if got is not None:
            return got
        t = call["type"]
        callee = _unwrap(call["tag"] if t == "TaggedTemplateExpression" else call["callee"])
        fids, open_names = [], []
        ct = callee["type"]
        if ct in _FUNCTIONS:
            fids.append(callee["_fid"])
        elif ct == "Super":
            c = self.method_class(scope)
            sup = self.superclass(c, 0) if c is not None else None
            ctor = self.constructor(sup) if sup is not None else None
            if ctor is not None:
                fids.append(ctor)
        else:
            for d in self.descs_of_expr(callee, scope, 0):
                k = d[0]
                if k == "fn":
                    fids.append(d[1])
                elif k == "class":
                    ctor = self.constructor(self.classes[d[1]])
                    if ctor is not None:
                        fids.append(ctor)
                elif k == "mod":
                    fids.extend(self.mod_callables(d[1], 0))
                elif k == "open":
                    open_names.append(d[1])
                elif k == "global" and ct == "Identifier":
                    open_names.append(d[1])
                elif k == "unknown" and ct == "MemberExpression":
                    name = _prop_name(callee)
                    if name is not None and name not in COMMON_METHODS:
                        open_names.append(name)
        fids = list(dict.fromkeys(fids))
        opens = []
        for name in dict.fromkeys(open_names):
            cands = self.by_name.get(name, ())
            if 0 < len(cands) <= MAX_OPEN:
                for c in cands:
                    if c not in fids and c not in opens:
                        opens.append(c)
        how = "none"
        if fids:
            how = "mixed" if opens else "definite"
        elif opens:
            how = "open"
        out = (fids + opens, how)
        call["_tg"] = out
        return out

    # ---- imports' values, routes, order ----
    def import_targets(self, b):
        """The bindings an import binding reads (a module's exported
        variables), following re-exports."""
        if b.targets is not None:
            return b.targets
        b.targets = []
        out = []
        for kind, spec, scope, name in b.writes:
            if kind != "import" or name == "*" or name == "=":
                continue
            target = self.resolve_spec(b.mod, spec)
            if target[0] == "mod":
                self.export_binds(target[1], name, out, 0)
        b.targets = list(dict.fromkeys(out))
        return b.targets

    def export_binds(self, idx, name, out, hops):
        m = self.mods[idx]
        for entry in m.named.get(name, ()):
            if entry[0] == "binding":
                t = lookup(entry[2], entry[1])
                if t is not None and t.kind in ("var", "let", "const"):
                    out.append(t)
            elif entry[0] == "reexport" and hops < EXPORT_HOPS:
                target = self.resolve_spec(m.idx, entry[1])
                if target[0] == "mod":
                    self.export_binds(target[1], entry[2], out, hops + 1)
        if not m.named.get(name) and name != "default" and hops < EXPORT_HOPS:
            for spec in m.stars:
                target = self.resolve_spec(m.idx, spec)
                if target[0] == "mod":
                    self.export_binds(target[1], name, out, hops + 1)

    def mark_routes(self):
        """Route handlers: functions registered with `app.get('/p', fn)`,
        `router.post([...], fn)`, `app.use(fn)`, `router.route('/p').get(fn)`."""
        for fn in self.fns:
            for node, scope in fn.calls:
                if node["type"] != "CallExpression":
                    continue
                callee = _unwrap(node["callee"])
                if callee["type"] != "MemberExpression":
                    continue
                name = _prop_name(callee)
                args = node["arguments"]
                if name not in ROUTE_METHODS or not args:
                    continue
                if _route_path(args[0]):
                    handlers = args[1:]
                elif name == "use" or self.route_chain(callee["object"]):
                    handlers = args
                else:
                    continue
                for a in handlers:
                    for h in (a["elements"] if a["type"] == "ArrayExpression" else (a,)):
                        if h is None or h["type"] == "SpreadElement":
                            continue
                        # a wrapped handler: asyncHandler(async (req, res) => …)
                        inner = [x for x in h["arguments"] if x["type"] != "SpreadElement"] \
                            if h["type"] == "CallExpression" else (h,)
                        for d in (d for x in inner for d in self.descs_of_expr(x, scope, 0)):
                            if d[0] == "fn":
                                f = self.fns[d[1]]
                                if not f.module:
                                    f.route = 2 if len(f.params) == 4 else 1

    def route_chain(self, obj):
        """`router.route('/p')`, or a route method called on one."""
        seen = 0
        while obj["type"] == "CallExpression" and seen < ALIAS_DEPTH:
            seen += 1
            callee = _unwrap(obj["callee"])
            if callee["type"] != "MemberExpression":
                return False
            name = _prop_name(callee)
            if name == "route":
                return bool(obj["arguments"]) and _route_path(obj["arguments"][0])
            if name not in ROUTE_METHODS:
                return False
            obj = callee["object"]
        return False

    def order(self):
        """Every function, the functions it calls and the functions defined
        in it first (DFS post-order, from each function in turn)."""
        succ = [[] for _ in self.fns]
        for fn in self.fns:
            if fn.parent is not None:
                succ[fn.parent].append(fn.fid)
        for fn in self.fns:
            out = succ[fn.fid]
            for node, scope in fn.calls:
                for x in self.call_targets(node, scope)[0]:
                    if x != fn.fid:
                        out.append(x)
            succ[fn.fid] = list(dict.fromkeys(out))
        seen = [False] * len(self.fns)
        order = []
        for root in range(len(self.fns)):
            if seen[root]:
                continue
            seen[root] = True
            stack = [[root, 0]]
            while stack:
                top = stack[-1]
                nexts = succ[top[0]]
                if top[1] < len(nexts):
                    nxt = nexts[top[1]]
                    top[1] += 1
                    if not seen[nxt]:
                        seen[nxt] = True
                        stack.append([nxt, 0])
                else:
                    stack.pop()
                    order.append(top[0])
        return order


# --------------------------------------------------------------- analysis --
class _Stop(Exception):
    """The pass's work budget is spent."""


class _Cut(Exception):
    """One reading of one function has run past its own limit."""


class _Eval:
    """One reading of one function: its summary and, with emit, its findings."""

    def __init__(self, prog, fn, emit, findings):
        self.p = prog
        self.fn = fn
        self.mod = prog.mods[fn.mod]
        self.emit = emit
        self.findings = findings
        self.env = {}
        self.version = 0
        self.cur = fn.scope
        self.reach_adds = []        # (key, category, sink entry)
        self.ret_val = None
        self.shared_writes = {}     # bid -> _V
        self.reads = {}             # shared bindings read
        self.uses = {}              # fid -> the parameters of it this reading passed tainted values
        self.lines = self.mod.lines
        self.limit = prog.work + RUN_BASE + RUN_PER_NODE * fn.size
        self.ancestors = set()
        f = fn
        while f is not None:
            self.ancestors.add(f.fid)
            f = prog.fns[f.parent] if f.parent is not None else None

    # ---- budget ----
    def tick(self, n=1):
        p = self.p
        p.work += n
        if p.work > p.budget:
            raise _Stop()
        if p.work > self.limit:
            raise _Cut()

    # ---- bindings ----
    def read(self, b):
        if b.kind == "import":
            targets = b.targets or ()
            if not targets:
                return EMPTY
            out = EMPTY
            for t in targets:
                self.reads[t.bid] = True
                v = self.p.shared.get(t.bid)
                if v is not None and v.tainted():
                    if v.src and v.via is None:
                        v = v.with_via(f"the value {b.name} imported from {self.p.mods[t.mod].path}")
                    out = out.union(v.plain())
            return out
        if b.fid == self.fn.fid and not b.shared:
            return self.env.get(b.bid, EMPTY)
        self.reads[b.bid] = True
        v = self.p.shared.get(b.bid, EMPTY)
        if b.fid == self.fn.fid:
            v = self.env.get(b.bid, EMPTY).union(v)
        return v

    def write(self, b, v, strong=True):
        if b.fid == self.fn.fid:
            old = self.env.get(b.bid)
            new = v if strong or old is None else old.union(v)
            if old is None or new.key() != old.key():
                self.env[b.bid] = new
                self.version += 1
        if b.shared:
            # a closure's variable carries the parameters of the function
            # that declares it and of the functions around that one
            v = v.within(self.p.scope_fns(b.fid))
            old = self.shared_writes.get(b.bid)
            self.shared_writes[b.bid] = v if old is None else old.union(v)

    def copy_env(self):
        self.tick(1 + (len(self.env) >> 5))
        return dict(self.env)

    def merge(self, a, b):
        """Both environments' values (a branch's and another's)."""
        self.tick(1 + ((len(a) + len(b)) >> 5))
        out = dict(a)
        for k, v in b.items():
            old = out.get(k)
            out[k] = v if old is None else old.union(v)
        return out

    # ---- the function ----
    def run(self):
        fn, node = self.fn, self.fn.node
        if fn.module:
            self.stmts(node["body"])
            return
        for i, p in enumerate(fn.params):
            v = _V(params=frozenset((fn.fid * PARAM_BASE + i,))) if i < PARAM_BASE else EMPTY
            if fn.route and v is not EMPTY:
                if i == fn.route - 1:
                    v = _V(params=v.params, kind=1)
                elif i == fn.route:
                    v = _V(params=v.params, kind=2)
            self.bind_pattern(p, v, fn.scope)
        body = node["body"]
        if body["type"] == "BlockStatement":
            self.stmts(body["body"])
        else:
            self.ret(self.expr(body, fn.scope))

    def ret(self, v):
        self.ret_val = v if self.ret_val is None else self.ret_val.union(v)

    # ---- statements ----
    def stmts(self, body):
        for st in body:
            self.stmt(st)

    def stmt(self, st):
        self.tick()
        t = st["type"]
        cur = self.cur
        if t == "ExpressionStatement":
            self.expr(st["expression"], cur)
        elif t == "VariableDeclaration":
            for d in st["declarations"]:
                v = self.expr(d["init"], cur) if d["init"] is not None else EMPTY
                if d["init"] is not None or st["kind"] != "var":
                    self.bind_pattern(d["id"], v, cur)
                else:
                    self.pattern_parts(d["id"], cur)
        elif t == "ReturnStatement":
            self.ret(self.expr(st["argument"], cur) if st["argument"] is not None else EMPTY)
        elif t == "IfStatement":
            node = st
            outs = []
            while True:
                self.expr(node["test"], cur)
                before = self.copy_env()
                self.sub(node["consequent"])
                outs.append(self.env)
                self.env = before
                alt = node["alternate"]
                if alt is not None and alt["type"] == "IfStatement":
                    self.tick()
                    node = alt
                    continue
                if alt is not None:
                    self.sub(alt)
                outs.append(self.env)
                break
            acc = outs[-1]
            for o in outs[:-1]:
                acc = self.merge(acc, o)
            self.env = acc
        elif t == "BlockStatement":
            self.cur = st.get("_scope") or cur
            self.stmts(st["body"])
            self.cur = cur
        elif t in _LOOPS:
            self.loop(st)
        elif t == "TryStatement":
            before = self.copy_env()
            self.stmt(st["block"])
            h = st["handler"]
            if h is not None:
                after = self.env
                self.env = self.merge(before, after)
                self.cur = h["_scope"]
                if h["param"] is not None:
                    self.bind_pattern(h["param"], EMPTY, self.cur)
                self.stmts(h["body"]["body"])
                self.cur = cur
                self.env = self.merge(after, self.env)
            if st["finalizer"] is not None:
                self.stmt(st["finalizer"])
        elif t == "SwitchStatement":
            self.cur = st.get("_scope") or cur
            self.expr(st["discriminant"], self.cur)
            before = self.copy_env()
            acc = before
            for case in st["cases"]:
                if case["test"] is not None:
                    self.expr(case["test"], self.cur)
                self.env = self.merge(before, self.env)
                self.stmts(case["consequent"])
                acc = self.merge(acc, self.env)
            self.env = acc
            self.cur = cur
        elif t == "LabeledStatement":
            self.stmt(st["body"])
        elif t == "ThrowStatement":
            self.expr(st["argument"], cur)
        elif t == "WithStatement":
            self.expr(st["object"], cur)
            self.sub(st["body"])
        elif t == "ClassDeclaration":
            self.class_parts(st, cur)
        elif t == "ExportNamedDeclaration":
            if st["declaration"] is not None:
                self.stmt(st["declaration"])
        elif t == "ExportDefaultDeclaration":
            d = st["declaration"]
            if d["type"] == "ClassDeclaration":
                self.class_parts(d, cur)
            elif d["type"] != "FunctionDeclaration":
                self.expr(d, cur)
        elif t == "TSModuleDeclaration":
            if st["body"] is not None:
                self.sub(st["body"])
        elif t == "TSExportAssignment":
            self.expr(st["expression"], cur)
        elif t == "TSEnumDeclaration":
            for mem in st["members"]:
                if mem["initializer"] is not None:
                    self.expr(mem["initializer"], cur)

    def sub(self, st):
        cur = self.cur
        self.stmt(st)
        self.cur = cur

    def loop(self, st):
        t = st["type"]
        cur = self.cur
        self.cur = st.get("_scope") or cur
        if t == "ForStatement" and st["init"] is not None:
            if st["init"]["type"] == "VariableDeclaration":
                self.stmt(st["init"])
            else:
                self.expr(st["init"], self.cur)
        it = None
        if t == "ForInStatement" or t == "ForOfStatement":
            it = self.expr(st["right"], self.cur).plain()
        before = self.copy_env()
        for k in range(2):
            version = self.version
            if it is not None:
                left = st["left"]
                if left["type"] == "VariableDeclaration":
                    for d in left["declarations"]:
                        self.bind_pattern(d["id"], it, self.cur)
                else:
                    self.assign_pattern(left, it, self.cur)
            if (t == "ForStatement" or t == "WhileStatement") and st["test"] is not None:
                self.expr(st["test"], self.cur)
            self.sub(st["body"])
            if t == "DoWhileStatement":
                self.expr(st["test"], self.cur)
            if t == "ForStatement" and st["update"] is not None:
                self.expr(st["update"], self.cur)
            if self.version == version:
                break
        if t != "DoWhileStatement":
            self.env = self.merge(before, self.env)
        self.cur = cur

    def class_parts(self, node, scope):
        """A class's superclass, decorators, computed keys, field
        initializers and static blocks run where it is defined; its methods
        are functions of their own."""
        cscope = node["_scope"]
        for d in node.get("decorators") or ():
            self.expr(d, scope)
        if node.get("superClass") is not None:
            self.expr(node["superClass"], scope)
        for member in node["body"]["body"]:
            mt = member["type"]
            if mt == "StaticBlock":
                cur = self.cur
                self.cur = member["_scope"]
                self.stmts(member["body"])
                self.cur = cur
                continue
            for d in member.get("decorators") or ():
                self.expr(d, scope)
            if member["computed"]:
                self.expr(member["key"], scope)
            if mt == "PropertyDefinition" and member["value"] is not None \
                    and member["value"]["type"] not in _FUNCTIONS:
                self.expr(member["value"], cscope)

    # ---- patterns ----
    def bind(self, ident, scope):
        b = ident.get("_b", False)
        if b is False:
            b = lookup(scope, ident["name"])
        return b

    def bind_pattern(self, pat, v, scope):
        for ident, path in _pattern_names(pat):
            b = self.bind(ident, scope)
            if b is None:
                continue
            if path and v.kind & 1 and path[0] in REQUEST_PROPS:
                val = self.source(ident["line"]).union(v.plain())
            else:
                val = v.plain() if path else v
            self.write(b, val)
        self.pattern_parts(pat, scope)

    def pattern_parts(self, pat, scope):
        """A pattern's default values (a name gets its default too) and
        computed keys."""
        if pat["type"] == "Identifier":
            return
        todo = [pat]
        while todo:
            p = todo.pop()
            if p is None:
                continue
            t = p["type"]
            if t == "AssignmentPattern":
                dv = self.expr(p["right"], scope)
                for ident, _ in _pattern_names(p["left"]):
                    b = self.bind(ident, scope)
                    if b is not None:
                        self.write(b, dv.plain(), strong=False)
                todo.append(p["left"])
            elif t == "ObjectPattern":
                for prop in reversed(p["properties"]):
                    if prop["type"] == "RestElement":
                        todo.append(prop["argument"])
                    else:
                        if prop["computed"]:
                            self.expr(prop["key"], scope)
                        todo.append(prop["value"])
            elif t == "ArrayPattern":
                for el in reversed(p["elements"]):
                    todo.append(el)
            elif t == "RestElement":
                todo.append(p["argument"])
            elif t == "MemberExpression":
                self.expr(p["object"], scope)

    def assign_pattern(self, pat, v, scope):
        t = pat["type"]
        if t == "Identifier":
            b = self.bind(pat, scope)
            if b is not None:
                self.write(b, v)
            return
        if t == "MemberExpression":
            self.expr(pat["object"], scope)
            if pat["computed"]:
                self.expr(pat["property"], scope)
            self.member_write(pat, v, scope)
            return
        for ident, path in _pattern_names(pat):
            b = self.bind(ident, scope)
            if b is not None:
                self.write(b, v.plain() if path else v)
        for mem in _pattern_members(pat):
            self.member_write(mem, v.plain(), scope)
        self.pattern_parts(pat, scope)

    def member_write(self, target, v, scope):
        """`o.x = v`: the container o holds v too (a weak update)."""
        if not v.tainted():
            return
        obj = target["object"]
        seen = 0
        while obj["type"] == "MemberExpression" and seen < ALIAS_DEPTH:
            obj = obj["object"]
            seen += 1
        if obj["type"] == "Identifier":
            b = self.bind(obj, scope)
            if b is not None and b.kind != "import":
                self.write(b, v.plain(), strong=False)

    # ---- sources ----
    def source(self, line):
        return _V(True, (self.mod.path, line), None if self.fn.module else self.fn.name)

    def is_source_text(self, text):
        return bool(text) and self.p.cfg["source"].search(text) is not None

    # ---- expressions ----
    def expr(self, e, scope):
        if e is None:
            return EMPTY
        self.tick()
        t = e["type"]
        if t == "Identifier":
            b = e.get("_b", False)
            if b is False:
                b = lookup(scope, e["name"])
            if b is None:
                return EMPTY
            return self.read(b)
        if t == "Literal" or t == "ThisExpression" or t == "Super" or t == "MetaProperty":
            return EMPTY
        if t == "TemplateLiteral":
            out = EMPTY
            for x in e["expressions"]:
                out = out.union(self.expr(x, scope).plain())
            out = out.with_built()
            if out.tainted() and FIXED_PREFIX_RE.match(e["quasis"][0]["raw"]):
                out = out.sanitize(FIXED_HOST)
            return out
        if t == "MemberExpression" or t == "CallExpression" or t == "NewExpression" \
                or t == "TaggedTemplateExpression" or t == "ChainExpression":
            return self.chain(e, scope)
        if t == "BinaryExpression" or t == "LogicalExpression":
            return self.binary(e, scope)
        if t == "AssignmentExpression":
            return self.assignment(e, scope)
        if t == "ConditionalExpression":
            self.expr(e["test"], scope)
            return self.expr(e["consequent"], scope).union(self.expr(e["alternate"], scope))
        if t == "UnaryExpression" or t == "UpdateExpression":
            self.expr(e["argument"], scope)
            return EMPTY
        if t == "AwaitExpression" or t == "SpreadElement":
            return self.expr(e["argument"], scope)
        if t == "YieldExpression":
            self.ret(self.expr(e["argument"], scope))
            return EMPTY
        if t == "SequenceExpression":
            v = EMPTY
            for x in e["expressions"]:
                v = self.expr(x, scope)
            return v
        if t == "ArrayExpression":
            out = EMPTY
            for x in e["elements"]:
                if x is not None:
                    out = out.union(self.expr(x, scope).plain())
            return out
        if t == "ObjectExpression":
            out = EMPTY
            for prop in e["properties"]:
                if prop["type"] == "SpreadElement":
                    out = out.union(self.expr(prop["argument"], scope).plain())
                    continue
                if prop["computed"]:
                    self.expr(prop["key"], scope)
                v = prop["value"]
                if v["type"] in _FUNCTIONS:
                    continue
                out = out.union(self.expr(v, scope).plain())
            return out
        if t in _FUNCTIONS:
            return self.function_value(e["_fid"])
        if t == "ClassExpression":
            self.class_parts(e, scope)
            return EMPTY
        if t == "ImportExpression":
            self.expr(e["source"], scope)
            if e.get("options") is not None:
                self.expr(e["options"], scope)
            return EMPTY
        if t == "JSXElement" or t == "JSXFragment":
            self.jsx(e, scope)
            return EMPTY
        return EMPTY

    def function_value(self, fid):
        """A function as a value: what it returns (request data, the
        parameters of functions around it) — a callback carries it."""
        f = self.p.fns[fid]
        self.uses.setdefault(fid, set())
        out = EMPTY
        if f.ret_src is not None:
            out = out.union(f.ret_src)
        for key in sorted(f.ret_outer):
            if key // PARAM_BASE in self.ancestors:
                clean, built = f.ret_outer[key]
                out = out.union(_V(params=frozenset((key,)), clean=clean, built=built))
        return out

    def binary(self, e, scope):
        # a left-deep chain (a + b + c …) is read in a loop
        chain = []
        n = e
        while n["type"] == "BinaryExpression" or n["type"] == "LogicalExpression":
            chain.append(n)
            n = n["left"]
        v = self.expr(n, scope)
        # 'https://host/' + … or '/path/' + …: a fixed host or this site
        fixed = _fixed_prefix(n)
        for node in reversed(chain):
            self.tick()
            op = node["operator"]
            r = self.expr(node["right"], scope)
            if op == "+":
                v = v.plain().union(r.plain()).with_built()
                if fixed and v.tainted():
                    v = v.sanitize(FIXED_HOST)
            elif op == "||" or op == "&&" or op == "??":
                v = v.union(r)
                fixed = False
            else:
                v = EMPTY
                fixed = False
        return v

    def assignment(self, e, scope):
        left, op = e["left"], e["operator"]
        if op == "=":
            v = self.expr(e["right"], scope)
            if left["type"] == "Identifier":
                b = self.bind(left, scope)
                if b is not None:
                    self.write(b, v)
            elif left["type"] == "MemberExpression":
                self.expr(left["object"], scope)
                if left["computed"]:
                    self.expr(left["property"], scope)
                self.sink_assignment(left, v)
                self.member_write(left, v, scope)
            else:
                self.assign_pattern(left, v, scope)
            return v
        # compound: x += v, x ||= v, …
        old = self.expr(left, scope)
        v = self.expr(e["right"], scope)
        if op == "+=":
            nv = old.plain().union(v.plain()).with_built()
        elif op == "||=" or op == "&&=" or op == "??=":
            nv = old.union(v)
        else:
            nv = EMPTY
        if left["type"] == "Identifier":
            b = self.bind(left, scope)
            if b is not None:
                self.write(b, nv)
        elif left["type"] == "MemberExpression":
            self.sink_assignment(left, nv)
            self.member_write(left, nv, scope)
        return nv

    def sink_assignment(self, target, v):
        text = _text(target) + " ="
        line = target["line"] if target["computed"] else target["property"]["line"]
        for pat, cat in self.p.cfg["sinks"]:
            if pat.search(text):
                self.sink(cat, v, line)
                return
        for pat, cat, which in SINKS:
            if which == "value" and pat.search(text):
                self.sink(cat, v, line)
                return

    def chain(self, e, scope):
        """A member, call, tagged template or new expression; its object /
        callee chain is read in a loop (deep chains need no recursion)."""
        spine = []
        n = e
        while True:
            t = n["type"]
            if t == "MemberExpression":
                spine.append(n)
                n = n["object"]
            elif t == "CallExpression":
                spine.append(n)
                n = n["callee"]
            elif t == "ChainExpression":
                n = n["expression"]
            elif t == "TaggedTemplateExpression":
                spine.append(n)
                n = n["tag"]
            else:
                break
        if n["type"] == "NewExpression":
            v = self.new_expr(n, scope)
        else:
            v = self.expr(n, scope)
        recv = EMPTY
        for node in reversed(spine):
            self.tick()
            t = node["type"]
            if t == "MemberExpression":
                recv = v
                v = self.member(node, v, scope)
            elif t == "CallExpression":
                callee = _unwrap(node["callee"])
                v = self.call(node, recv if callee["type"] == "MemberExpression" else EMPTY, v, scope)
                recv = EMPTY
            else:
                v = self.tagged(node, scope)
                recv = EMPTY
        return v

    def member(self, node, obj, scope):
        if node["computed"]:
            self.expr(node["property"], scope)
        name = _prop_name(node)
        line = node["line"] if node["computed"] else node["property"]["line"]
        if obj.kind & 1:
            if name in REQUEST_PROPS:
                return self.source(line)
            if name in REQUEST_WRAPPERS:
                return obj
        if self.is_source_text(_text(node)):
            return self.source(line)
        if name == "length":
            return EMPTY
        return obj.plain() if obj.kind else obj

    def args_of(self, node, scope):
        """The arguments' values, and the index of the first spread (or -1)."""
        args = []
        spread = -1
        for a in node["arguments"]:
            if a["type"] == "SpreadElement":
                if spread < 0:
                    spread = len(args)
                args.append(self.expr(a["argument"], scope).plain())
            else:
                args.append(self.expr(a, scope))
        return args, spread

    def new_expr(self, node, scope):
        callee = node["callee"]
        if callee["type"] != "Identifier":
            self.expr(callee, scope)
        args, spread = self.args_of(node, scope)
        text = "new " + _text(callee) + "("
        fids, how = self.p.call_targets(node, scope)
        if how != "definite":
            cat, which = self.sink_of(text)
            if cat is not None:
                self.sink(cat, self.sink_value(which, args), node["line"])
        if fids:
            self.apply(node, fids, args, spread, node["line"], ctor=True)
        return _union_all(a.plain() for a in args)

    def tagged(self, node, scope):
        args = [self.expr(x, scope).plain() for x in node["quasi"]["expressions"]]
        fids, how = self.p.call_targets(node, scope)
        if fids:
            v = self.apply(node, fids, [EMPTY] + args, -1, node["line"])
            if how != "definite":
                v = v.union(_union_all(args))
            return v
        return _union_all(args)

    def call_line(self, node):
        callee = _unwrap(node["callee"])
        if callee["type"] == "MemberExpression" and not callee["computed"]:
            return callee["property"]["line"]
        return callee["line"]

    def call(self, node, recv, callee_val, scope):
        """A call: its sources and sinks, the functions it reaches, its value."""
        args, spread = self.args_of(node, scope)
        callee = _unwrap(node["callee"])
        member = callee["type"] == "MemberExpression"
        ctext = _text(callee)
        text = ctext + "("
        name = _prop_name(callee) if member else (callee["name"] if callee["type"] == "Identifier" else None)
        line = self.call_line(node)
        # request data
        if member and recv.kind & 1 and name in REQUEST_CALLS:
            return self.source(line)
        if self.is_source_text(text):
            return self.source(line)
        fids, how = self.p.call_targets(node, scope)
        if member and recv.kind:
            fids, how = (), "none"          # a request's or a response's method is the framework's
        definite = how == "definite"
        # sinks: not a call that is known to reach project code
        if not definite:
            cat, which = self.sink_of(text)
            if cat is not None:
                if not self.not_a_sink(cat, callee, node, scope):
                    self.sink(cat, self.sink_value(which, args), line)
            elif member and recv.kind & 2:
                self.response_sink(callee, node, args, line)
        san = self.sanitizer(ctext, name, fids, definite)
        if fids:
            v = self.apply(node, fids, args, spread, line)
            if not definite:
                v = v.union(_union_all(a.plain() for a in args)).union(recv.plain())
        elif name in CLEAN_RESULT:
            v = EMPTY
        else:
            v = _union_all(a.plain() for a in args).union(recv.plain())
            if not member:
                v = v.union(callee_val.plain())
            elif name == "join" or name == "concat":
                v = v.with_built()
        # a container a value is put into holds it
        if member and (name == "push" or name == "unshift") and callee["object"]["type"] == "Identifier":
            b = self.bind(callee["object"], scope)
            if b is not None and b.kind != "import":
                self.write(b, _union_all(a.plain() for a in args), strong=False)
        if san == ALL:
            return EMPTY
        if san:
            return v.sanitize(san)
        return v

    def sink_of(self, text):
        for pat, cat in self.p.cfg["sinks"]:
            if pat.search(text):
                return cat, "all"
        for pat, cat, which in SINKS:
            if which != "value" and pat.search(text):
                return cat, which
        return None, None

    def sink_value(self, which, args):
        if not args:
            return EMPTY
        if which == "first":
            return args[0]
        if which == "last":
            return args[-1]
        if which == "second":
            return args[1] if len(args) > 1 else EMPTY
        return _union_all(args)

    def not_a_sink(self, cat, callee, node, scope):
        """A RegExp's exec(), Express's sendFile / download given a root, a
        response sending a whole parsed object or set to a non-HTML type."""
        if callee["type"] != "MemberExpression":
            return False
        name = _prop_name(callee)
        if cat == "command injection" and name == "exec":
            return self.regexp_receiver(callee, scope)
        if cat == "path traversal" and (name == "sendFile" or name == "download"):
            return self.has_root(node)
        if cat == XSS and (name == "send" or name == "write" or name == "end"):
            return self.not_html_response(callee, node)
        return False

    def has_root(self, node):
        for a in node["arguments"][1:]:
            if a["type"] == "ObjectExpression":
                for p in a["properties"]:
                    if p["type"] == "Property" and _key_name(p) == "root":
                        return True
        return False

    def not_html_response(self, callee, node):
        args = node["arguments"]
        if args:
            a = args[0]
            if a["type"] == "MemberExpression" and _prop_name(a) in REQUEST_OBJECTS:
                return True
            if a["type"] == "ObjectExpression" or a["type"] == "ArrayExpression":
                return True
            text = _leftmost_text(a)
            if text is not None and SSE_RE.match(text):
                return True             # a Server-Sent Events frame
        obj = callee["object"]
        seen = 0
        while obj["type"] == "CallExpression" and seen < ALIAS_DEPTH:
            seen += 1
            m = _unwrap(obj["callee"])
            if m["type"] != "MemberExpression":
                break
            name = _prop_name(m)
            cargs = obj["arguments"]
            if name == "type" and cargs and cargs[0]["type"] == "Literal" and cargs[0].get("kind") == "string":
                return not _html_type(cargs[0]["value"])
            if (name == "set" or name == "header") and len(cargs) >= 2 and cargs[0]["type"] == "Literal" \
                    and cargs[0].get("kind") == "string" and _lower(cargs[0]["value"]) == "content-type" \
                    and cargs[1]["type"] == "Literal" and cargs[1].get("kind") == "string":
                return not _html_type(cargs[1]["value"])
            obj = m["object"]
        return False

    def response_sink(self, callee, node, args, line):
        """A route handler's response object, whatever its name."""
        name = _prop_name(callee)
        if not args:
            return
        if name == "send" or name == "write" or name == "end":
            if not self.not_html_response(callee, node):
                self.sink(XSS, args[0], line)
        elif name == "redirect":
            self.sink("open redirect", args[-1], line)
        elif name == "location":
            self.sink("open redirect", args[0], line)
        elif name == "sendFile" or name == "download":
            if not self.has_root(node):
                self.sink("path traversal", args[0], line)

    def regexp_receiver(self, callee, scope):
        """Is exec()'s receiver proven to be a RegExp?"""
        mod = self.mod
        if mod.regexp_proto or callee["optional"]:
            return False
        obj = callee["object"]
        if obj["type"] == "Literal" and obj.get("kind") == "regex":
            return True
        if mod.eval_with:
            return False
        if self.regexp_construction(obj, scope):
            return True
        if obj["type"] != "Identifier":
            return False
        b = self.bind(obj, scope)
        if b is None or b.kind not in ("const", "let", "var") or len(b.writes) != 1:
            return False
        kind, init, iscope, path = b.writes[0]
        if kind != "init" or path:
            return False
        if not ((init["type"] == "Literal" and init.get("kind") == "regex") or self.regexp_construction(init, iscope)):
            return False
        for ref, parent in b.refs:
            if parent is None or parent["type"] != "MemberExpression" or parent["object"] is not ref \
                    or parent["optional"]:
                return False
            name = _prop_name(parent)
            if name not in REGEXP_MEMBERS:
                return False
            if parent.get("_asg") and name != "lastIndex":
                return False
        return True

    def regexp_construction(self, node, scope):
        """`new RegExp(…)` / `RegExp(…)`, RegExp being the global."""
        if node["type"] != "NewExpression" and node["type"] != "CallExpression":
            return False
        callee = node["callee"]
        if callee["type"] != "Identifier" or callee["name"] != "RegExp":
            return False
        return not self.mod.regexp_rebound and lookup(scope, "RegExp") is None

    def sanitizer(self, ctext, name, fids, definite):
        """The categories the call's value is clean for (ALL: every one): a
        configured sanitizer always; a built-in one unless the call reaches a
        project function (by the name alone: one of that name shadows it)."""
        cfg = self.p.cfg
        for cand in (ctext, name):
            if cand:
                if cand in cfg["full"]:
                    return ALL
                bits = cfg["partial"].get(cand)
                if bits:
                    return bits
        if definite:
            return 0
        for cand in (ctext, name):
            if not cand or (fids and "." not in cand):
                continue
            if cand in FULL_SANITIZERS:
                return ALL
            bits = PARTIAL_SANITIZERS.get(cand)
            if bits:
                return bits
        return 0

    # ---- sinks and calls into summaries ----
    def sink(self, cat, v, line):
        if v is None or not v.tainted() or v.clean & BIT[cat]:
            return
        needs = cat == SQL and not v.built
        entry = (self.mod.path, line, self.fn.label(), needs)
        for key in sorted(v.params):
            self.reach_adds.append((key, cat, entry))
        if v.src and v.via is not None and self.emit and not needs:
            origin = v.origin
            src_loc = f"{origin[0]}:{origin[1]}" + (f" (in {v.fname}())" if v.fname else "")
            self.findings.append(self.p.issue(cat, self.mod.path, line, self.lines, src_loc,
                                              f"{self.mod.path}:{line}", v.via))

    def apply(self, node, fids, args, spread, line, ctor=False):
        """The functions a call reaches: their parameters' sinks (a finding
        when request data arrives; the reach of the caller's parameters when
        they do) and what they return."""
        p = self.p
        out = EMPTY
        reported = 0
        name = self.callee_name(node)
        for fid in fids:
            f = p.fns[fid]
            nparams = len(f.params)
            rest = nparams - 1 if nparams and f.params[-1]["type"] == "RestElement" else -1
            used = self.uses.setdefault(fid, set())
            for i in range(nparams):
                if self.bound(args, spread, rest, i).tainted():
                    used.add(i)
            for i in sorted(f.reach):
                t = self.bound(args, spread, rest, i)
                if not t.tainted():
                    continue
                table = f.reach[i]
                for cat in CATS:
                    entry = table.get(cat)
                    if entry is None or t.clean & BIT[cat]:
                        continue
                    needs = entry[3] and not t.built
                    if t.src and self.emit and not needs and not reported & BIT[cat]:
                        self.findings.append(p.issue(cat, self.mod.path, line, self.lines,
                                                     f"{self.mod.path}:{line}", f"{entry[0]}:{entry[1]} {entry[2]}",
                                                     f"the call to {name}()"))
                        reported |= BIT[cat]
                    for key in sorted(t.params):
                        self.reach_adds.append((key, cat, (entry[0], entry[1], entry[2], needs)))
            if ctor:
                continue
            if f.ret_src is not None:
                rs = f.ret_src
                out = out.union(_V(True, rs.origin, rs.fname, f"the value returned by {f.name or 'an anonymous function'}()",
                                   _NO_PARAMS, rs.clean, rs.built))
            for i in sorted(f.ret_params):
                clean, built = f.ret_params[i]
                b = self.bound(args, spread, rest, i)
                if b.tainted():
                    b = b.plain()
                    if clean:
                        b = b.sanitize(clean)
                    out = out.union(b.with_built() if built else b)
            for key in sorted(f.ret_outer):
                if key // PARAM_BASE in self.ancestors:
                    clean, built = f.ret_outer[key]
                    out = out.union(_V(params=frozenset((key,)), clean=clean, built=built))
        return out

    @staticmethod
    def bound(args, spread, rest, i):
        """The value parameter i of a function receives."""
        if i == rest:
            return _union_all(args[i:])
        if 0 <= spread <= i:
            return _union_all(args[spread:])
        return args[i] if i < len(args) else EMPTY

    def callee_name(self, node):
        callee = _unwrap(node["tag"] if node["type"] == "TaggedTemplateExpression" else node["callee"])
        if callee["type"] == "Identifier":
            return callee["name"]
        if callee["type"] == "MemberExpression":
            name = _prop_name(callee)
            if name is not None:
                return name
        return "an anonymous function"

    # ---- JSX ----
    def jsx(self, e, scope):
        stack = [e]
        while stack:
            n = stack.pop()
            self.tick()
            t = n["type"]
            if t == "JSXElement":
                for attr in n["openingElement"]["attributes"]:
                    if attr["type"] == "JSXSpreadAttribute":
                        self.expr(attr["argument"], scope)
                        continue
                    value = attr["value"]
                    if value is None:
                        continue
                    if value["type"] == "JSXElement" or value["type"] == "JSXFragment":
                        stack.append(value)
                        continue
                    if value["type"] != "JSXExpressionContainer" or value["expression"]["type"] == "JSXEmptyExpression":
                        continue
                    inner = value["expression"]
                    aname = attr["name"]
                    if aname["type"] == "JSXIdentifier" and aname["name"] == "dangerouslySetInnerHTML" \
                            and inner["type"] == "ObjectExpression":
                        for prop in inner["properties"]:
                            if prop["type"] == "SpreadElement":
                                self.expr(prop["argument"], scope)
                            elif prop["type"] == "Property" and not prop["computed"] and _key_name(prop) == "__html":
                                self.sink(XSS, self.expr(prop["value"], scope), attr["line"])
                            else:
                                self.expr(prop["value"], scope)
                    else:
                        v = self.expr(inner, scope)
                        if aname["type"] == "JSXIdentifier" and aname["name"] == "dangerouslySetInnerHTML":
                            self.sink(XSS, v, attr["line"])
                for c in reversed(n["children"]):
                    stack.append(c)
            elif t == "JSXFragment":
                for c in reversed(n["children"]):
                    stack.append(c)
            elif t == "JSXExpressionContainer" or t == "JSXSpreadChild":
                if n["expression"]["type"] != "JSXEmptyExpression":
                    self.expr(n["expression"], scope)

    # ---- the summary ----
    def commit(self):
        """This reading into the function's summary and the shared bindings
        (monotone). Returns the functions whose summaries changed, each with
        what changed ({fid: [returned request data, parameter indices,
        enclosing functions' parameter keys]}), and the bindings whose value
        grew."""
        p, f = self.p, self.fn
        changes = {}

        def change(fid):
            c = changes.get(fid)
            if c is None:
                c = changes[fid] = [False, set(), set()]
            return c
        for key, cat, entry in self.reach_adds:
            owner = p.fns[key // PARAM_BASE]
            i = key % PARAM_BASE
            d = owner.reach.setdefault(i, {})
            old = d.get(cat)
            if old is None or (old[3] and not entry[3]):
                d[cat] = entry
                change(owner.fid)[1].add(i)
        rv = self.ret_val
        if rv is not None and not f.module and rv.tainted():
            if rv.src:
                old = f.ret_src
                if old is None:
                    f.ret_src = _V(True, rv.origin, rv.fname, None, _NO_PARAMS, rv.clean, rv.built)
                    change(f.fid)[0] = True
                else:
                    clean = old.clean & rv.clean
                    built = old.built or rv.built
                    if clean != old.clean or built != old.built:
                        f.ret_src = _V(True, old.origin, old.fname, None, _NO_PARAMS, clean, built)
                        change(f.fid)[0] = True
            for key in sorted(rv.params):
                own = key // PARAM_BASE == f.fid
                table = f.ret_params if own else f.ret_outer
                k = key % PARAM_BASE if own else key
                old = table.get(k)
                new = (rv.clean, rv.built) if old is None else (old[0] & rv.clean, old[1] or rv.built)
                if new != old:
                    table[k] = new
                    if own:
                        change(f.fid)[1].add(k)
                    else:
                        change(f.fid)[2].add(k)
        if not self.emit:
            for fid in sorted(self.uses):
                p.fns[fid].callers[f.fid] = self.uses[fid]
        grown = []
        for bid in sorted(self.shared_writes):
            v = self.shared_writes[bid]
            if not v.tainted():
                continue
            old = p.shared.get(bid)
            new = v if old is None else old.union(v)
            if old is None or new.key() != old.key():
                p.shared[bid] = new
                grown.append(bid)
        for bid in sorted(self.reads):
            p.readers.setdefault(bid, {})[f.fid] = True
        return changes, grown


# ------------------------------------------------------------------ driver --
def _skipped_size(path, n):
    return {"rule": "X-FLOW-SKIPPED", "name": "JS flow analysis skipped (size)",
            "type": "HOTSPOT", "sev": "INFO",
            "msg": f"{path} is {n} characters; interprocedural JS taint analysis is skipped above {MAX_FILE} "
                   f"characters.",
            "why": "Reading a file this large (usually minified or machine-generated) would cost the "
                   "cross-file pass more time and memory than a scan should spend on one file.",
            "fix": "Split or deminify the file, or exclude it from the scan explicitly if the code is generated.",
            "ref": "Scalability", "file": path, "line": 1, "snippet": [], "snipStart": 1}


def analyze(files, findings, issue, note, cfg=None):
    """The cross-file JavaScript pass over files ({"path", "content"}:
    the project's own JavaScript and TypeScript, no dependencies). issue and
    note build findings (lazaret.scanner.flow._issue / _flow_note); cfg is
    config()'s. Findings are appended to findings."""
    limit = sys.getrecursionlimit()
    if limit < _RECURSION:
        sys.setrecursionlimit(_RECURSION)
    try:
        _analyze(files, findings, issue, note, cfg if cfg is not None else config())
    finally:
        if limit < _RECURSION:
            sys.setrecursionlimit(limit)


def _analyze(files, findings, issue, note, cfg):
    prog = _Program(cfg)
    prog.issue = issue
    skipped = {}
    over = []
    total = 0
    for f in files:
        path, content = f["path"], f.get("content")
        if _lower(path).endswith((".d.ts", ".d.mts", ".d.cts")):
            continue                    # a declaration file: types, no code
        if not isinstance(content, str):
            skipped[path] = "its content is not text"
            continue
        if len(content) > MAX_FILE:
            findings.append(_skipped_size(path, len(content)))
            continue
        if total + len(content) > MAX_TOTAL:
            over.append(path)
            continue
        try:
            tree = jsparse.parse_file(path, content)
        except jsparse.JsSyntaxError as exc:
            skipped[path] = f"it could not be read as {'TypeScript' if jsparse.dialect(path)[0] else 'JavaScript'} " \
                            f"(line {exc.line}: {exc.reason})"
            continue
        total += len(content)
        prog.add_module(path, content, tree)
    notes = []
    if over:
        notes.append(note(
            "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)", over[0], 1,
            f"Cross-file taint analysis skipped {len(over)} JavaScript file(s) beyond its budget "
            f"({MAX_TOTAL:,} characters), starting with {over[0]!r}.",
            "Very large code bases are analyzed up to a fixed budget so a scan cannot run unbounded; flows "
            "through the skipped files are not seen.",
            "Scan sub-trees separately, or exclude generated code."))
    if prog.mods:
        for m in prog.mods:
            prog.resolve_module(m.idx)
        for b in prog.binds:
            if b.kind == "import":
                for t in prog.import_targets(b):
                    t.shared = True
        prog.mark_routes()
        notes.extend(_fixpoint(prog, findings, note))
    for path in sorted(skipped):
        notes.append(note(
            "Q-FLOW-SKIPPED", "File skipped by flow analysis", path, 1,
            f"Cross-file taint analysis skipped {path!r}: {skipped[path]}.",
            "Only files the JavaScript reader can parse take part in the interprocedural pass; flows into or "
            "out of this file are not seen (the per-file rules still ran).",
            "Fix the syntax error, or exclude the file if it is not JavaScript (a template, for instance), then "
            "re-run."))
    findings.extend(notes)


def _fixpoint(prog, findings, note):
    """Summaries to a fixpoint (callees first; a function is read again when
    a summary or a shared value it used changed), then the reporting pass."""
    notes = []
    order = prog.order()
    pos = [0] * len(prog.fns)
    for k, fid in enumerate(order):
        pos[fid] = k
    heap = [(k, fid) for k, fid in enumerate(order)]
    queued = [True] * len(prog.fns)
    cutoff = []
    cut = []
    prog.budget = WORK_BASE + WORK_PER_NODE * prog.nodes
    stopped = None
    stopped_at = [0, 0]             # the steps taken when the fixpoint / the reporting pass stopped
    while heap:
        _, fid = heapq.heappop(heap)
        queued[fid] = False
        fn = prog.fns[fid]
        fn.runs += 1
        ev = _Eval(prog, fn, False, findings)
        try:
            ev.run()
        except _Cut:
            if fid not in cut:
                cut.append(fid)
        except _Stop:
            stopped = fn
            stopped_at[0] = prog.work
            break
        changes, grown = ev.commit()
        deps = []
        for owner in sorted(changes):
            src, params, outer = changes[owner]
            for c, used in prog.fns[owner].callers.items():
                # a caller is read again when what it used changed: request
                # data returned, a parameter it passed a tainted value, a
                # parameter of a function around it returned
                if src or not params.isdisjoint(used) or any(k // PARAM_BASE in prog.scope_fns(c) for k in outer):
                    deps.append(c)
        for bid in grown:
            deps.extend(prog.readers.get(bid, ()))
        for d in deps:
            if queued[d]:
                continue
            if prog.fns[d].runs >= MAX_ITERS:
                if d not in cutoff:
                    cutoff.append(d)
                continue
            queued[d] = True
            heapq.heappush(heap, (pos[d], d))
    # the reporting pass: every function once, in order of definition
    prog.budget = prog.work + WORK_BASE + EMIT_PER_NODE * prog.nodes
    emit_stopped = None
    for fn in prog.fns:
        ev = _Eval(prog, fn, True, findings)
        try:
            ev.run()
        except _Cut:
            if fn.fid not in cut:
                cut.append(fn.fid)
        except _Stop:
            emit_stopped = fn
            stopped_at[1] = prog.work
            break
    if cutoff:
        first = prog.fns[min(cutoff)]
        path = prog.mods[first.mod].path
        notes.append(note(
            "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (iteration cap)", path, first.line,
            f"Interprocedural summaries for {len(cutoff)} JavaScript function(s) did not converge within "
            f"{MAX_ITERS} re-analyses (first: {first.display()} in {path!r}); flows through them may be "
            f"missing.",
            "Summaries are iterated to a fixpoint with a generous safety cap; hitting it means an unusually long "
            "or cyclic chain of calls or shared variables.",
            "Report the pattern to the Lazaret maintainers; split the chain if possible."))
    for k, fn in enumerate((stopped, emit_stopped)):
        if fn is None:
            continue
        path = prog.mods[fn.mod].path
        notes.append(note(
            "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)", path, fn.line,
            f"The JavaScript cross-file pass stopped {'reporting' if k else 'following values'} "
            f"at {fn.display()} in {path!r} after {stopped_at[k]:,} steps (its budget for {prog.nodes:,} syntax "
            f"tree nodes); flows through the rest of the code may be missing.",
            "Every file is read within a budget proportional to its size, so a scan cannot run unbounded.",
            "Split or deminify very large or deeply nested files, or exclude generated code from the scan."))
    for fid in sorted(cut):
        fn = prog.fns[fid]
        path = prog.mods[fn.mod].path
        notes.append(note(
            "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)", path, fn.line,
            f"The JavaScript cross-file pass stopped reading {fn.display()} in {path!r} at its limit of "
            f"{RUN_BASE:,} + {RUN_PER_NODE} steps per syntax tree node; flows through the rest of it may be "
            f"missing.",
            "Deeply nested loops make one function's reading repeat; each reading has a limit so a scan cannot "
            "run unbounded.",
            "Split the function, or exclude generated code from the scan."))
    return notes
