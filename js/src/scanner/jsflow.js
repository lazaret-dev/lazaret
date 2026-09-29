// Cross-file taint for JavaScript and TypeScript, on parsed trees (0.1.7):
// twin of python/src/lazaret/scanner/jsflow.py, statement for statement —
// the same summaries, the same fixpoint, the same work counted step for
// step, the same findings in the same order
// (tests/architecture/test_js_parity_flow.py).
//
// Each function gets a summary (which of its parameters reach which sinks,
// what its return value carries), computed to a fixpoint over the call graph
// callees first; findings come from a last pass over every function: request
// data passed into a function whose parameter reaches a sink (X-*, at the
// call site), or reaching a sink as the value another function returned or
// another module exports (X-*, at the sink). The Python module's docstring
// describes the model in full.
import { cmpCodePoints, cpLen, pyRe, pyRepr } from "../lib/pycompat.js";
import { JsSyntaxError, dialect, parseFile } from "../lib/jsparse.js";

export const MAX_FILE = 2_000_000;       // code points: a larger file is skipped (X-FLOW-SKIPPED)
export const MAX_TOTAL = 8_000_000;      // code points analyzed per run (the rest: Q-FLOW-INCOMPLETE)
const MAX_OPEN = 4;                      // project functions a name-only call may reach
export const MAX_ITERS = 50;             // re-analyses of one function
const MAX_PARAMS = 64;                   // parameters one value is followed for (the first ones)
const PARAM_BASE = 1 << 20;              // a parameter's key: function id * PARAM_BASE + index
const EXPORT_HOPS = 8;                   // modules followed through re-exports
const ALIAS_DEPTH = 16;                  // values followed through names and properties
// The pass's limits (mutable for tests; the Python module's constants)
export const LIMITS = {
  WORK_BASE: 200_000,                    // evaluation steps of the fixpoint: WORK_BASE + WORK_PER_NODE per node
  WORK_PER_NODE: 24,
  EMIT_PER_NODE: 8,                      // ... and of the reporting pass
  RUN_BASE: 2_000,                       // one reading of one function: RUN_BASE + RUN_PER_NODE per node of it
  RUN_PER_NODE: 64,
};
const TEXT_MAX = 400;                    // code points of a callee's or member's text

const CATS = ["SQL injection", "command injection", "code injection", "template injection", "path traversal",
  "server-side request forgery", "open redirect", "cross-site scripting"];
const BIT = Object.fromEntries(CATS.map((c, k) => [c, 1 << k]));
const ALL = (1 << CATS.length) - 1;
const SQL = "SQL injection";
const XSS = "cross-site scripting";
const FIXED_HOST = BIT["server-side request forgery"] | BIT["open redirect"];

const EXTS = [".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"];
const TS_SOURCES = new Map([[".js", [".ts", ".tsx"]], [".jsx", [".tsx"]], [".mjs", [".mts"]], [".cjs", [".cts"]]]);
const NODE_BUILTINS = new Set([
  "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
  "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module",
  "net", "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream",
  "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
  "worker_threads", "zlib"]);
const GLOBAL_OBJECTS = new Set([
  "JSON", "Math", "Object", "Array", "Number", "String", "Boolean", "Symbol", "BigInt", "Date", "RegExp",
  "Error", "Promise", "Reflect", "Proxy", "Intl", "Atomics", "WebAssembly", "console", "Buffer", "process",
  "globalThis", "window", "document", "navigator", "Map", "Set", "WeakMap", "WeakSet",
  "$", "jQuery", "_"]);                  // a library's namespace (jQuery, lodash / underscore): its members are its own
// methods of the language's and the runtime's objects: on a receiver the pass
// cannot identify, `x.replace(…)` is String's, not a project function
const COMMON_METHODS = new Set(`
at charAt charCodeAt codePointAt concat endsWith includes indexOf lastIndexOf localeCompare match matchAll
normalize padEnd padStart repeat replace replaceAll search slice split startsWith substr substring toLowerCase
toUpperCase toLocaleLowerCase toLocaleUpperCase toString toLocaleString trim trimStart trimEnd trimLeft
trimRight valueOf copyWithin entries every fill filter find findIndex findLast findLastIndex flat flatMap
forEach join keys map pop push reduce reduceRight reverse shift some sort splice unshift values
hasOwnProperty isPrototypeOf propertyIsEnumerable apply bind call then catch finally get set has delete
clear add exec test getTime toISOString toJSON parse stringify on once off emit addListener removeListener
removeAllListeners addEventListener removeEventListener dispatchEvent pipe write end read destroy resume
pause log debug info warn error trace send json status render sendFile sendStatus cookie header type
`.split(/\s+/).filter(Boolean));
// a call's value that is no text the caller chose (a boolean, a number, an index)
const CLEAN_RESULT = new Set(`
test includes startsWith endsWith indexOf lastIndexOf findIndex findLastIndex localeCompare some every has
isArray isNaN isFinite isInteger isSafeInteger hasOwnProperty getTime charCodeAt codePointAt search
`.split(/\s+/).filter(Boolean));
const REGEXP_MEMBERS = new Set(["exec", "test", "lastIndex", "source", "flags", "global", "ignoreCase", "multiline",
  "sticky", "unicode", "dotAll", "hasIndices", "toString"]);
const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "del", "all", "options", "head", "use"]);
// what a request object carries from the client (Express, Fastify, Koa's ctx)
const REQUEST_PROPS = new Set(["query", "body", "params", "headers", "cookies", "signedCookies", "files", "file",
  "originalUrl", "url", "path", "hostname"]);
const REQUEST_CALLS = new Set(["get", "header", "param"]);
const REQUEST_WRAPPERS = new Set(["request", "req"]);      // Koa: ctx.request, ctx.req
// a response method that sends a whole parsed request object sends JSON
const REQUEST_OBJECTS = new Set(["query", "body", "params", "headers", "cookies", "signedCookies"]);
// a URL whose text starts with a path on this site or a fixed host: what is
// joined after it can change neither (core._SAME_SITE_RE, for SSRF too)
const FIXED_PREFIX_RE = pyRe(String.raw`^(?:/[^/\\]|[Hh][Tt][Tt][Pp][Ss]?://[^/?#\\\s{}$]+/)`);
// a Server-Sent Events frame: not HTML
const SSE_RE = pyRe(String.raw`^(?:(?:data|event|id|retry)[ \t]*:)`);

// request data by the text of a member expression (`req.query`) or a call's
// callee followed by "(" (`req.get(`)
export const SOURCE_RE = pyRe(
  String.raw`(?<![\w$.])(?:req|request)\.(?:query|body|params|headers|cookies)\b` +
  String.raw`|(?<![\w$.])req\.(?:signedCookies|files?|originalUrl|url|path|hostname)\b` +
  String.raw`|(?<![\w$.])req\.(?:get|header|param)\($|(?<![\w$.])process\.argv\b` +
  String.raw`|(?<![\w$.])(?:window\.|document\.)?location\.(?:search|hash|href)\b`);

// [pattern over a sink's text, category, the arguments that carry the injection]
const SINKS = [
  [pyRe(String.raw`\.(?:query|execute)\($`), SQL, "first"],
  [pyRe(String.raw`\.(?:whereRaw|havingRaw|orderByRaw|joinRaw|groupByRaw|fromRaw)\($`), SQL, "first"],
  [pyRe(String.raw`(?<![\w$.])(?:knex\.raw|sequelize\.literal|sequelize\.query)\($`), SQL, "first"],
  [pyRe(String.raw`(?<![\w$])(?:exec|execSync|spawn|spawnSync)\($`), "command injection", "all"],
  [pyRe(String.raw`(?<![\w$.])eval\($|^new Function\($|(?<![\w$.])vm\.(?:runInNewContext|runInThisContext` +
    String.raw`|runInContext|compileFunction)\($|^new vm\.Script\($`), "code injection", "first"],
  [pyRe(String.raw`(?<![\w$])(?:ejs|pug|jade|Handlebars|handlebars|Mustache|mustache|nunjucks|doT|_)\.(?:render` +
    String.raw`|renderString|compile|template)\($`), "template injection", "first"],
  [pyRe(String.raw`\.(?:sendFile|download)\($`), "path traversal", "first"],
  [pyRe(String.raw`(?<![\w$])(?:readFile|readFileSync|createReadStream)\($`), "path traversal", "first"],
  [pyRe(String.raw`(?<![\w$.])fs(?:\.promises)?\.(?:writeFile|appendFile|unlink|rm|rmdir|mkdir|readdir|rename` +
    String.raw`|copyFile|createWriteStream)(?:Sync)?\($`), "path traversal", "first"],
  [pyRe(String.raw`(?<![\w$.])(?:fetch|needle)\($|(?<![\w$.])axios(?:\.(?:get|post|put|patch|delete|head` +
    String.raw`|request))?\($|(?<![\w$.])https?\.(?:get|request)\($|(?<![\w$.])got(?:\.(?:get|post|put|patch` +
    String.raw`|delete|head|stream))?\($`), "server-side request forgery", "first"],
  [pyRe(String.raw`\.redirect\($`), "open redirect", "last"],
  [pyRe(String.raw`(?<![\w$.])(?:res|response)\.location\($`), "open redirect", "first"],
  [pyRe(String.raw`\.(?:innerHTML|outerHTML) =$`), XSS, "value"],
  [pyRe(String.raw`(?<![\w$.])document\.(?:write|writeln)\($`), XSS, "all"],
  [pyRe(String.raw`\.insertAdjacentHTML\($`), XSS, "second"],
  [pyRe(String.raw`(?<![\w$.])(?:res|response)(?:\.[\w$]+\(\))*\.(?:send|write|end)\($`), XSS, "first"],
];
const FULL_SANITIZERS = new Set(["parseInt", "parseFloat", "Number", "Boolean", "Math.floor", "Math.round",
  "Math.ceil", "Math.abs", "Math.trunc"]);
const PARTIAL_SANITIZERS = new Map([
  ["DOMPurify.sanitize", BIT[XSS]], ["encodeURIComponent", BIT[XSS]], ["escapeHtml", BIT[XSS]],
  ["sanitizeHtml", BIT[XSS]], ["mysql.escape", BIT[SQL]], ["mysql2.escape", BIT[SQL]], ["pool.escape", BIT[SQL]],
  ["connection.escape", BIT[SQL]], ["conn.escape", BIT[SQL]], ["db.escape", BIT[SQL]], ["SqlString.escape", BIT[SQL]],
  ["path.basename", BIT["path traversal"]], ["shellQuote", BIT["command injection"]],
  ["shell_quote", BIT["command injection"]], ["quote", BIT["command injection"]],
]);
const LS = String.fromCharCode(0x2028), PS = String.fromCharCode(0x2029);
const LINES_RE = new RegExp("\\r\\n|[\\n\\r" + LS + PS + "]");

/** ASCII letters lowered (the same in both engines, whatever the Unicode tables). */
const lower = (text) => text.replace(/[A-Z]+/g, (m) => m.toLowerCase());

/** base/rel with its "." and ".." segments resolved (empty segments dropped); null above the root. */
function join(base, rel) {
  const parts = [];
  for (const seg of [...base.split("/"), ...rel.split("/")]) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (!parts.length) return null;
      parts.pop();
    } else parts.push(seg);
  }
  return parts.join("/");
}

/** s[:n] in code points. */
function cpHead(s, n) {
  if (s.length <= n) return s;
  let i = 0, k = 0;
  while (i < s.length && k < n) {
    const c = s.charCodeAt(i);
    i += c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
    k++;
  }
  return s.slice(0, i);
}

/** 1234567 -> "1,234,567" (Python's format spec ","). */
const commas = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");

const numeric = (a, b) => a - b;

/**
 * The taint model's configured part (the Python engine's jsflow.config()):
 * the source pattern, extra sinks ([pattern, category]), full sanitizers
 * (call names) and partial ones (name -> categories).
 */
export function config(source = SOURCE_RE, sinks = [], full = [], partial = new Map()) {
  const bits = new Map();
  for (const [name, cats] of partial) {
    let b = 0;
    for (const c of cats) b |= BIT[c] ?? 0;
    bits.set(name, b);
  }
  return { source, sinks: [...sinks], full: new Set(full), partial: bits };
}

// ------------------------------------------------------------------ values --
const NO_PARAMS = Object.freeze([]);

/** The sorted union of two sorted key arrays. */
function mergeKeys(a, b) {
  if (!a.length) return b;
  if (!b.length) return a;
  const out = [];
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    if (j >= b.length || (i < a.length && a[i] < b[j])) out.push(a[i++]);
    else if (i >= a.length || b[j] < a[i]) out.push(b[j++]);
    else { out.push(a[i]); i++; j++; }
  }
  return out;
}

/**
 * What a value carries (the Python engine's _V): request data (src, read at
 * origin in function fname; via: the chain it arrived by), the parameters
 * of the function being read or of functions around it (params: sorted
 * keys), the categories it is sanitized for (clean, a bit set), whether it
 * was joined into a string (built), and kind: bit 1 a request object, bit 2
 * a response object.
 */
class V {
  constructor(src = false, origin = null, fname = null, via = null, params = NO_PARAMS, clean = 0, built = false,
    kind = 0) {
    this.src = src;
    this.origin = src ? origin : null;
    this.fname = src ? fname : null;
    this.via = src ? via : null;
    this.params = params;
    this.clean = clean;
    this.built = built;
    this.kind = kind;
  }

  tainted() { return this.src || this.params.length > 0; }

  union(o) {
    if (o === EMPTY) return this;
    if (this === EMPTY) return o;
    const s = this.src ? this : o;
    let params = o.params.length ? mergeKeys(this.params, o.params) : this.params;
    if (params.length > MAX_PARAMS) params = params.slice(0, MAX_PARAMS);
    return new V(this.src || o.src, s.origin, s.fname, s.via, params, this.clean & o.clean,
      this.built || o.built, this.kind | o.kind);
  }

  sanitize(bits) {
    if (!this.tainted()) return EMPTY;
    return new V(this.src, this.origin, this.fname, this.via, this.params, this.clean | bits, this.built, 0);
  }

  withBuilt() {
    if (!this.tainted() || this.built) return this;
    return new V(this.src, this.origin, this.fname, this.via, this.params, this.clean, true, this.kind);
  }

  withVia(via) {
    return new V(this.src, this.origin, this.fname, via, this.params, this.clean, this.built, this.kind);
  }

  /** The value with only the parameters of functions fids (a Set). */
  within(fids) {
    if (!this.params.length) return this;
    const params = this.params.filter((k) => fids.has(Math.floor(k / PARAM_BASE)));
    if (params.length === this.params.length) return this;
    if (!this.src && !params.length) return EMPTY;
    return new V(this.src, this.origin, this.fname, this.via, params, this.clean, this.built, this.kind);
  }

  /** The value without a request or response object's mark. */
  plain() {
    if (!this.kind) return this;
    if (!this.tainted()) return EMPTY;
    return new V(this.src, this.origin, this.fname, this.via, this.params, this.clean, this.built, 0);
  }
}

const EMPTY = new V(false, null, null, null, NO_PARAMS, ALL);

/** Python's _V.key() equality. */
function same(a, b) {
  if (a === b) return true;
  if (a.src !== b.src || a.fname !== b.fname || a.via !== b.via || a.clean !== b.clean || a.built !== b.built
    || a.kind !== b.kind) return false;
  if (a.origin === null || b.origin === null) {
    if (a.origin !== b.origin) return false;
  } else if (a.origin[0] !== b.origin[0] || a.origin[1] !== b.origin[1]) return false;
  if (a.params.length !== b.params.length) return false;
  for (let i = 0; i < a.params.length; i++) if (a.params[i] !== b.params[i]) return false;
  return true;
}

function unionAll(vals) {
  let out = EMPTY;
  for (const v of vals) out = out.union(v);
  return out;
}

// ------------------------------------------------------------------- model --
class Scope {
  constructor(kind, parent, fid) {
    this.kind = kind;           // "function" (a var scope: functions and the module) or "block"
    this.parent = parent;
    this.names = new Map();
    this.fid = fid;             // the function the scope's code belongs to
  }

  varScope() {
    let s = this;
    while (s.kind !== "function") s = s.parent;
    return s;
  }
}

class Bind {
  constructor(bid, name, kind, scope, mod) {
    this.bid = bid;
    this.name = name;
    this.kind = kind;           // var let const using param function class import catch enum
    this.fid = scope.fid;       // the function whose code declares it
    this.writes = [];           // [kind, node, scope, extra]: what is written to it
    this.shared = false;        // read or written by another function (closures, module variables)
    this.mod = mod;
    this.refs = [];             // [identifier node, parent node] of every reference
    this.targets = null;        // an import: the bindings it reads in the modules it names
  }
}

class Fn {
  constructor(fid, mod, node, name, params, scope, parent, line, module = false) {
    this.fid = fid;
    this.mod = mod;
    this.node = node;
    this.name = name;
    this.params = params;
    this.scope = scope;
    this.parent = parent;       // fid of the enclosing function (null: the module's own code)
    this.line = line;
    this.cls = null;            // the class of a method
    this.obj = null;            // the object literal of a method
    this.module = module;       // the module's own code
    this.route = 0;             // a route handler: 1 (request, response), 2 (error, request, response)
    this.reach = new Map();     // param index -> Map(category -> [file, line, label, needs joining])
    this.retParams = new Map(); // param index -> [clean, built] of the value it returns
    this.retSrc = null;         // V: request data it returns
    this.retOuter = new Map();  // key of an enclosing function's parameter it returns -> [clean, built]
    this.callers = new Map();   // fid -> Set of the parameters it passed tainted values in its last reading
    this.runs = 0;
    this.calls = [];            // [call node, scope] of its call sites
    this.size = 0;
  }

  label() {
    if (this.module) return "(module level)";
    if (this.name) return `(in ${this.name}())`;
    return "(in an anonymous function)";
  }

  display() {
    if (this.module) return "the module's own code";
    return this.name ? `${this.name}()` : "an anonymous function";
  }
}

class Klass {
  constructor(cid, name) {
    this.cid = cid;
    this.name = name;
    this.methods = new Map();   // prototype method name -> fid
    this.statics = new Map();   // static member name -> fid
    this.sup = null;            // the superclass expression, [node, scope]
  }
}

class Obj {
  constructor(oid) {
    this.oid = oid;
    this.props = new Map();     // key -> [[value node, scope]]
  }
}

class Mod {
  constructor(idx, path, norm, content, ast) {
    this.idx = idx;
    this.path = path;
    this.dir = norm.includes("/") ? norm.slice(0, norm.lastIndexOf("/")) : "";
    this.lines = content.split(LINES_RE);
    this.ast = ast;
    this.scope = null;
    this.fn = null;             // fid of the module's own code
    this.named = new Map();     // ESM export name -> [entry]
    this.stars = [];            // `export * from` specifiers
    this.cjs = [];              // module.exports = … : [node, scope]
    this.cjsProps = new Map();  // exports.x = … : name -> [[node, scope]]
    this.evalWith = false;      // a direct eval() or a with statement
    this.regexpProto = false;   // RegExp.prototype touched
    this.regexpRebound = false; // the global RegExp assigned
    this.nodes = 0;
  }
}

// field names of each node type's children, in source order
const KIDS = {
  Program: ["body"], ExpressionStatement: ["expression"], BlockStatement: ["body"],
  EmptyStatement: [], DebuggerStatement: [], WithStatement: ["object", "body"],
  ReturnStatement: ["argument"], LabeledStatement: ["body"], BreakStatement: [],
  ContinueStatement: [], IfStatement: ["test", "consequent", "alternate"],
  SwitchStatement: ["discriminant", "cases"], SwitchCase: ["test", "consequent"],
  ThrowStatement: ["argument"], TryStatement: ["block", "handler", "finalizer"],
  CatchClause: ["param", "body"], WhileStatement: ["test", "body"], DoWhileStatement: ["body", "test"],
  ForStatement: ["init", "test", "update", "body"], ForInStatement: ["left", "right", "body"],
  ForOfStatement: ["left", "right", "body"], FunctionDeclaration: ["params", "body"],
  VariableDeclaration: ["declarations"], VariableDeclarator: ["id", "init"],
  ClassDeclaration: ["decorators", "superClass", "body"], ClassExpression: ["decorators", "superClass", "body"],
  ClassBody: ["body"], MethodDefinition: ["decorators", "key", "value"],
  PropertyDefinition: ["decorators", "key", "value"], StaticBlock: ["body"],
  ImportDeclaration: [], ExportNamedDeclaration: ["declaration", "specifiers"],
  ExportDefaultDeclaration: ["declaration"], ExportAllDeclaration: [], ExportSpecifier: ["local"],
  Identifier: [], PrivateIdentifier: [], Literal: [], ThisExpression: [], Super: [],
  ArrayExpression: ["elements"], ObjectExpression: ["properties"], Property: ["key", "value"],
  FunctionExpression: ["params", "body"], ArrowFunctionExpression: ["params", "body"],
  TemplateLiteral: ["expressions"], TemplateElement: [], TaggedTemplateExpression: ["tag", "quasi"],
  MemberExpression: ["object", "property"], ChainExpression: ["expression"],
  CallExpression: ["callee", "arguments"], NewExpression: ["callee", "arguments"], MetaProperty: [],
  ImportExpression: ["source", "options"], UpdateExpression: ["argument"],
  UnaryExpression: ["argument"], AwaitExpression: ["argument"], YieldExpression: ["argument"],
  BinaryExpression: ["left", "right"], LogicalExpression: ["left", "right"],
  ConditionalExpression: ["test", "consequent", "alternate"], AssignmentExpression: ["left", "right"],
  SequenceExpression: ["expressions"], SpreadElement: ["argument"], RestElement: ["argument"],
  AssignmentPattern: ["left", "right"], ArrayPattern: ["elements"], ObjectPattern: ["properties"],
  JSXElement: ["openingElement", "children"], JSXOpeningElement: ["attributes"],
  JSXClosingElement: [], JSXAttribute: ["value"], JSXSpreadAttribute: ["argument"],
  JSXExpressionContainer: ["expression"], JSXSpreadChild: ["expression"], JSXFragment: ["children"],
  JSXText: [], JSXEmptyExpression: [], JSXIdentifier: [], JSXMemberExpression: [],
  JSXNamespacedName: [], TSEnumDeclaration: ["members"], TSEnumMember: ["initializer"],
  TSModuleDeclaration: ["body"], TSExportAssignment: ["expression"], TSImportEquals: [],
};
const FUNCTIONS = new Set(["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"]);
const LOOPS = new Set(["ForStatement", "ForInStatement", "ForOfStatement", "WhileStatement", "DoWhileStatement"]);

/** The child nodes of node, in source order. */
function kids(node) {
  const out = [];
  for (const field of Object.hasOwn(KIDS, node.type) ? KIDS[node.type] : []) {
    const v = node[field];
    if (v === null || v === undefined) continue;
    if (Array.isArray(v)) {
      for (const x of v) if (x !== null && x !== undefined) out.push(x);
    } else out.push(v);
  }
  return out;
}

/**
 * [identifier node, property path] of each name a pattern binds, in source
 * order; the path holds the property names read on the way (null for an
 * element, a rest or a computed key).
 */
function patternNames(pat) {
  const out = [];
  const stack = [[pat, []]];
  while (stack.length) {
    const [p, pth] = stack.pop();
    if (p === null || p === undefined) continue;
    const t = p.type;
    if (t === "Identifier") out.push([p, pth]);
    else if (t === "ObjectPattern") {
      for (let k = p.properties.length - 1; k >= 0; k--) {
        const prop = p.properties[k];
        if (prop.type === "RestElement") stack.push([prop.argument, [...pth, null]]);
        else {
          let name = null;
          if (!prop.computed) {
            const key = prop.key;
            name = key.type === "Identifier" ? key.name : (key.kind === "string" ? key.value : null);
          }
          stack.push([prop.value, [...pth, name]]);
        }
      }
    } else if (t === "ArrayPattern") {
      for (let k = p.elements.length - 1; k >= 0; k--) stack.push([p.elements[k], [...pth, null]]);
    } else if (t === "RestElement") stack.push([p.argument, [...pth, null]]);
    else if (t === "AssignmentPattern") stack.push([p.left, pth]);
  }
  return out;
}

/** The member expressions a pattern assigns to (`[a.b] = …`). */
function patternMembers(pat) {
  const out = [];
  const stack = [pat];
  while (stack.length) {
    const p = stack.pop();
    if (p === null || p === undefined) continue;
    const t = p.type;
    if (t === "MemberExpression") out.push(p);
    else if (t === "ObjectPattern") {
      for (const prop of p.properties) stack.push(prop.type === "RestElement" ? prop.argument : prop.value);
    } else if (t === "ArrayPattern") stack.push(...p.elements);
    else if (t === "RestElement" || t === "AssignmentPattern") stack.push(t === "RestElement" ? p.argument : p.left);
  }
  return out;
}

/** A member expression's property name, or null (computed, not a literal). */
function propName(member) {
  const prop = member.property;
  if (!member.computed) return (prop.type === "PrivateIdentifier" ? "#" : "") + prop.name;
  if (prop.type === "Literal" && (prop.kind === "string" || prop.kind === "number")) return String(prop.value);
  return null;
}

/** An object's or a class's member name, or null (computed). */
function keyName(prop) {
  const key = prop.key;
  if (prop.computed) {
    if (key.type === "Literal" && key.kind === "string") return key.value;
    return null;
  }
  if (key.type === "Identifier") return key.name;
  if (key.type === "PrivateIdentifier") return "#" + key.name;
  if (key.type === "Literal") return String(key.value);
  return null;
}

function unwrap(node) {
  while (node.type === "ChainExpression") node = node.expression;
  return node;
}

/**
 * A callee's or a member's text: `a.b().c`, `new F()`, `this.x`, `a[]` for a
 * computed member; "" for anything else. At most TEXT_MAX code points.
 * Memoized on the nodes (`_t`); deep chains in a loop.
 */
function text(node) {
  if (node._t !== undefined) return node._t;
  const chain = [];
  let n = node;
  while (n._t === undefined) {
    const t = n.type;
    if (t === "MemberExpression") { chain.push(n); n = n.object; }
    else if (t === "CallExpression") { chain.push(n); n = n.callee; }
    else if (t === "ChainExpression") { chain.push(n); n = n.expression; }
    else break;
  }
  let out = n._t;
  if (out === undefined) {
    const t = n.type;
    if (t === "Identifier") out = n.name;
    else if (t === "ThisExpression") out = "this";
    else if (t === "Super") out = "super";
    else if (t === "NewExpression") out = "new " + text(n.callee) + "()";
    else out = "";
    out = cpHead(out, TEXT_MAX);
    n._t = out;
  }
  for (let k = chain.length - 1; k >= 0; k--) {
    const m = chain[k];
    if (m.type === "MemberExpression") {
      const name = propName(m);
      out = out + (name !== null ? "." + name : "[]");
    } else if (m.type === "CallExpression") out = out + "()";
    out = cpHead(out, TEXT_MAX);
    m._t = out;
  }
  return node._t;
}

/** A route's path: '/…' or '*', a `/…` template, a regex literal, or an array of those. */
function routePath(node) {
  const t = node.type;
  if (t === "Literal") {
    if (node.kind === "regex") return true;
    return node.kind === "string" && (node.value.startsWith("/") || node.value === "*");
  }
  if (t === "TemplateLiteral") return node.quasis[0].raw.startsWith("/");
  if (t === "ArrayExpression") {
    return node.elements.length > 0
      && node.elements.every((e) => e !== null && e.type !== "ArrayExpression" && routePath(e));
  }
  return false;
}

/**
 * The text a string expression starts with, when it starts with a literal:
 * a string, a template's first part, the left end of a `+` chain; else null.
 */
function leftmostText(node) {
  let seen = 0;
  while (seen < ALIAS_DEPTH) {
    seen++;
    const t = node.type;
    if (t === "Literal") return node.kind === "string" ? node.value : null;
    if (t === "TemplateLiteral") return node.quasis[0].raw;
    if (t === "BinaryExpression" && node.operator === "+") { node = node.left; continue; }
    return null;
  }
  return null;
}

function fixedPrefix(node) {
  const t = leftmostText(node);
  return t !== null && FIXED_PREFIX_RE.test(t);
}

function htmlType(value) {
  const v = lower(value);
  return v.includes("html") || v.includes("xml") || v.includes("svg");
}

function modScope(scope) {
  let s = scope;
  while (s.parent !== null) s = s.parent;
  return s;
}

function lookup(scope, name) {
  let s = scope;
  while (s !== null) {
    const b = s.names.get(name);
    if (b !== undefined) return b;
    s = s.parent;
  }
  return null;
}

/** list with repeated descriptors dropped (the first kept). */
function uniqDescs(list) {
  const seen = new Set(), out = [];
  for (const d of list) {
    const k = d[0] + "\u0000" + String(d[1]);
    if (!seen.has(k)) { seen.add(k); out.push(d); }
  }
  return out;
}

const UNKNOWN = [["unknown"]];

// ------------------------------------------------------------------ program --
class Program {
  constructor(cfg) {
    this.mods = [];
    this.byPath = new Map();
    this.fns = [];
    this.classes = [];
    this.objs = [];
    this.binds = [];
    this.byName = new Map();    // function name -> [fid], every project function of that name
    this.shared = new Map();    // bid -> V: everything written to a shared binding
    this.readers = new Map();   // bid -> Map(fid -> true): who reads a shared binding
    this.descMemo = new Map();
    this.cfg = cfg;
    this.work = 0;
    this.budget = LIMITS.WORK_BASE;
    this.nodes = 0;
    this.issue = null;
    this.anc = new Map();
  }

  /** fid and the functions around it (memoized). */
  scopeFns(fid) {
    let got = this.anc.get(fid);
    if (got === undefined) {
      got = new Set();
      let f = this.fns[fid];
      for (;;) {
        got.add(f.fid);
        if (f.parent === null) break;
        f = this.fns[f.parent];
      }
      this.anc.set(fid, got);
    }
    return got;
  }

  // ---- indexing ----
  addModule(path, content, ast) {
    let norm = path.replaceAll("\\", "/");
    const joined = join("", norm);
    if (joined !== null) norm = joined;
    const mod = new Mod(this.mods.length, path, norm, content, ast);
    this.mods.push(mod);
    if (!this.byPath.has(norm)) this.byPath.set(norm, mod.idx);
    const mfn = new Fn(this.fns.length, mod.idx, ast, null, [], null, null, 1, true);
    this.fns.push(mfn);
    mod.fn = mfn.fid;
    const scope = new Scope("function", null, mfn.fid);
    mfn.scope = scope;
    mod.scope = scope;
    ast._scope = scope;
    this.declare(mod, ast, scope, mfn);
    this.nodes += mod.nodes;
    return mod;
  }

  newBind(name, kind, scope, mod, node) {
    const b = new Bind(this.binds.length, name, kind, scope, mod.idx);
    this.binds.push(b);
    scope.names.set(name, b);
    return b;
  }

  /** Scopes and bindings: every name declared in root, and the functions, classes and object literals in it. */
  declare(mod, root, rootScope, rootFn) {
    // [node, scope, the function whose code it is, name hint]
    const stack = [];
    for (let k = root.body.length - 1; k >= 0; k--) stack.push([root.body[k], rootScope, rootFn, null]);
    mod.nodes += 1;
    rootFn.size += 1;
    while (stack.length) {
      const [node, scope, fn, hint] = stack.pop();
      mod.nodes += 1;
      fn.size += 1;
      const t = node.type;
      if (FUNCTIONS.has(t)) {
        const inner = this.newFunction(mod, node, scope, fn, hint);
        const fscope = inner.scope;
        node._scope = fscope;
        if (t === "FunctionExpression" && node.id != null) {
          const fb = this.newBind(node.id.name, "function", fscope, mod, node.id);
          fb.writes.push(["fn", node, fscope, inner.fid]);
        }
        node.params.forEach((p, i) => {
          for (const [ident] of patternNames(p)) {
            const b = this.newBind(ident.name, "param", fscope, mod, ident);
            b.writes.push(["param", p, fscope, i]);
          }
        });
        const body = node.body;
        if (body.type === "BlockStatement") {
          body._scope = fscope;
          for (let k = body.body.length - 1; k >= 0; k--) stack.push([body.body[k], fscope, inner, null]);
        } else stack.push([body, fscope, inner, null]);
        for (let k = node.params.length - 1; k >= 0; k--) this.pushPatternParts(node.params[k], fscope, inner, stack);
        if (t === "FunctionDeclaration" && node.id != null) {
          let b = scope.names.get(node.id.name);
          if (b === undefined || (b.kind !== "var" && b.kind !== "function")) {
            b = this.newBind(node.id.name, "function", scope, mod, node.id);
          }
          b.writes.push(["fn", node, scope, inner.fid]);
        }
        continue;
      }
      if (t === "ClassDeclaration" || t === "ClassExpression") {
        const c = this.newClass(node, hint);
        const cscope = new Scope("block", scope, fn.fid);
        node._scope = cscope;
        if (node.id != null) {
          const b = this.newBind(node.id.name, "class", t === "ClassDeclaration" ? scope : cscope, mod, node.id);
          b.writes.push(["class", node, scope, c.cid]);
        }
        const members = node.body.body;
        for (let k = members.length - 1; k >= 0; k--) {
          const member = members[k];
          const mt = member.type;
          if (mt === "StaticBlock") {
            const sscope = new Scope("function", cscope, fn.fid);
            member._scope = sscope;
            for (let j = member.body.length - 1; j >= 0; j--) stack.push([member.body[j], sscope, fn, null]);
            continue;
          }
          const name = keyName(member);
          const v = member.value;
          if (v !== null && v !== undefined) {
            if (mt === "MethodDefinition") stack.push([v, cscope, fn, ["method", c.cid, name, member.static, member.kind]]);
            else if (FUNCTIONS.has(v.type)) stack.push([v, cscope, fn, ["method", c.cid, name, member.static, "method"]]);
            else stack.push([v, cscope, fn, null]);
          }
          if (member.computed) stack.push([member.key, scope, fn, null]);
          const decs = member.decorators || [];
          for (let j = decs.length - 1; j >= 0; j--) stack.push([decs[j], scope, fn, null]);
        }
        if (node.superClass != null) {
          c.sup = [node.superClass, scope];
          stack.push([node.superClass, scope, fn, null]);
        }
        const decs = node.decorators || [];
        for (let j = decs.length - 1; j >= 0; j--) stack.push([decs[j], scope, fn, null]);
        continue;
      }
      if (t === "ObjectExpression") {
        const o = this.newObject(node);
        for (let k = node.properties.length - 1; k >= 0; k--) {
          const prop = node.properties[k];
          if (prop.type === "SpreadElement") { stack.push([prop.argument, scope, fn, null]); continue; }
          const name = keyName(prop);
          const v = prop.value;
          if (name !== null) {
            if (!o.props.has(name)) o.props.set(name, []);
            o.props.get(name).unshift([v, scope]);
          }
          stack.push([v, scope, fn, FUNCTIONS.has(v.type) ? ["objprop", o.oid, name] : null]);
          if (prop.computed) stack.push([prop.key, scope, fn, null]);
        }
        continue;
      }
      if (t === "VariableDeclaration") {
        const kind = node.kind;
        const target = kind === "var" ? scope.varScope() : scope;
        for (const d of node.declarations) {
          for (const [ident, path] of patternNames(d.id)) {
            let b = kind === "var" ? target.names.get(ident.name) : undefined;
            if (b === undefined || (b.kind !== "var" && b.kind !== "function" && b.kind !== "param")) {
              b = this.newBind(ident.name, kind, target, mod, ident);
            }
            if (d.init !== null) b.writes.push(["init", d.init, scope, path]);
            else if (kind !== "var") b.writes.push(["none", null, scope, null]);
          }
        }
        for (let k = node.declarations.length - 1; k >= 0; k--) {
          const d = node.declarations[k];
          if (d.init !== null) {
            let hint2 = null;
            const it = d.init.type;
            if (d.id.type === "Identifier" && (FUNCTIONS.has(it) || it === "ClassExpression")) hint2 = ["var", d.id.name];
            stack.push([d.init, scope, fn, hint2]);
          }
          this.pushPatternParts(d.id, scope, fn, stack);
        }
        continue;
      }
      if (t === "BlockStatement") {
        const bscope = new Scope("block", scope, fn.fid);
        node._scope = bscope;
        for (let k = node.body.length - 1; k >= 0; k--) stack.push([node.body[k], bscope, fn, null]);
        continue;
      }
      if (t === "ForStatement" || t === "ForInStatement" || t === "ForOfStatement" || t === "SwitchStatement") {
        const lscope = new Scope("block", scope, fn.fid);
        node._scope = lscope;
        const ks = kids(node);
        for (let k = ks.length - 1; k >= 0; k--) stack.push([ks[k], lscope, fn, null]);
        continue;
      }
      if (t === "CatchClause") {
        const cscope = new Scope("block", scope, fn.fid);
        node._scope = cscope;
        if (node.param !== null) {
          for (const [ident] of patternNames(node.param)) {
            const b = this.newBind(ident.name, "catch", cscope, mod, ident);
            b.writes.push(["none", null, cscope, null]);
          }
          this.pushPatternParts(node.param, cscope, fn, stack);
        }
        const body = node.body;
        body._scope = cscope;
        for (let k = body.body.length - 1; k >= 0; k--) stack.push([body.body[k], cscope, fn, null]);
        continue;
      }
      if (t === "ImportDeclaration") {
        const src = node.source.value;
        for (const spec of node.specifiers) {
          const st = spec.type;
          let name;
          if (st === "ImportDefaultSpecifier") name = "default";
          else if (st === "ImportNamespaceSpecifier") name = "*";
          else {
            const imp = spec.imported;
            name = imp.type === "Identifier" ? imp.name : imp.value;
          }
          const b = this.newBind(spec.local.name, "import", modScope(scope), mod, spec.local);
          b.writes.push(["import", src, scope, name]);
        }
        continue;
      }
      if (t === "TSImportEquals") {
        const b = this.newBind(node.id.name, "import", scope, mod, node.id);
        if (node.module !== null) b.writes.push(["import", node.module.value, scope, "="]);
        else b.writes.push(["init", node.entity, scope, []]);
        continue;
      }
      if (t === "TSEnumDeclaration" || t === "TSModuleDeclaration") {
        const name = node.id.type === "Identifier" ? node.id.name : null;
        if (name !== null && !scope.names.has(name)) {
          const b = this.newBind(name, "enum", scope, mod, node.id);
          b.writes.push(["none", null, scope, null]);
        }
        const ks = kids(node);
        for (let k = ks.length - 1; k >= 0; k--) stack.push([ks[k], scope, fn, null]);
        continue;
      }
      if (t === "WithStatement") mod.evalWith = true;
      else if (t === "AssignmentExpression") {
        const right = node.right, left = node.left;
        let hint2 = null;
        if (FUNCTIONS.has(right.type) || right.type === "ClassExpression") {
          if (left.type === "Identifier") hint2 = ["var", left.name];
          else if (left.type === "MemberExpression") hint2 = ["var", propName(left)];
        }
        stack.push([right, scope, fn, hint2]);
        stack.push([left, scope, fn, null]);
        continue;
      } else if (t === "ExportDefaultDeclaration") {
        stack.push([node.declaration, scope, fn, null]);
        continue;
      }
      const ks = kids(node);
      for (let k = ks.length - 1; k >= 0; k--) stack.push([ks[k], scope, fn, null]);
    }
  }

  /** A pattern's default values and computed keys, read in scope. */
  pushPatternParts(pat, scope, fn, stack) {
    const todo = [pat];
    while (todo.length) {
      const p = todo.pop();
      if (p === null || p === undefined) continue;
      const t = p.type;
      if (t === "AssignmentPattern") {
        const right = p.right;
        const hint = p.left.type === "Identifier" && FUNCTIONS.has(right.type) ? ["var", p.left.name] : null;
        stack.push([right, scope, fn, hint]);
        todo.push(p.left);
      } else if (t === "ObjectPattern") {
        for (const prop of p.properties) {
          if (prop.type === "RestElement") todo.push(prop.argument);
          else {
            if (prop.computed) stack.push([prop.key, scope, fn, null]);
            todo.push(prop.value);
          }
        }
      } else if (t === "ArrayPattern") todo.push(...p.elements);
      else if (t === "RestElement") todo.push(p.argument);
      else if (t === "MemberExpression") stack.push([p, scope, fn, null]);
    }
  }

  newFunction(mod, node, scope, parentFn, hint) {
    let name = null;
    if (node.type !== "ArrowFunctionExpression" && node.id != null) name = node.id.name;
    const fid = this.fns.length;
    let cls = null, obj = null;
    if (hint !== null) {
      if (hint[0] === "method") {
        const [, cid, mname, isStatic, kind] = hint;
        name = name || mname;
        if ((kind === "method" || kind === "constructor") && mname !== null) {
          (isStatic ? this.classes[cid].statics : this.classes[cid].methods).set(mname, fid);
        }
        cls = cid;
      } else if (hint[0] === "objprop") {
        name = name || hint[2];
        obj = hint[1];
      } else if (hint[0] === "var") name = name || hint[1];
    }
    const fscope = new Scope("function", scope, fid);
    const fn = new Fn(fid, mod.idx, node, name, node.params, fscope, parentFn.fid, node.line);
    fn.cls = cls;
    fn.obj = obj;
    this.fns.push(fn);
    node._fid = fid;
    if (name) {
      if (!this.byName.has(name)) this.byName.set(name, []);
      this.byName.get(name).push(fid);
    }
    return fn;
  }

  newClass(node, hint) {
    const name = node.id != null ? node.id.name : (hint && hint[0] === "var" ? hint[1] : null);
    const c = new Klass(this.classes.length, name);
    this.classes.push(c);
    node._cid = c.cid;
    return c;
  }

  newObject(node) {
    const o = new Obj(this.objs.length);
    this.objs.push(o);
    node._oid = o.oid;
    return o;
  }

  // ---- references ----
  /**
   * Every identifier resolved to its binding (`_b`, null: a global); the
   * writes of assignments, the call sites of each function, the members a
   * program assigns to (`_asg`), exports, module.exports and the file's
   * eval / with / RegExp facts.
   */
  resolveModule(idx) {
    const m = this.mods[idx];
    const stack = [[m.ast, m.scope, m.fn, null, "ref"]];
    while (stack.length) {
      const top = stack.pop();
      const node = top[0], parent = top[3], field = top[4];
      let scope = top[1], fid = top[2];
      const t = node.type;
      const s = node._scope;
      if (s !== undefined) {
        scope = s;
        if (FUNCTIONS.has(t)) fid = node._fid;
      }
      if (t === "Identifier") {
        const b = lookup(scope, node.name);
        node._b = b;
        if (field === "ref" && b !== null) {
          b.refs.push([node, parent]);
          if (b.fid !== fid) b.shared = true;
        }
        continue;
      }
      if (t === "MemberExpression") {
        const obj = node.object;
        const name = propName(node);
        if (name === "prototype" && obj.type === "Identifier" && obj.name === "RegExp") m.regexpProto = true;
        if (name === "RegExp" && obj.type === "Identifier"
          && ["globalThis", "window", "global", "self"].includes(obj.name) && node._asg) m.regexpRebound = true;
        stack.push([obj, scope, fid, node, "ref"]);
        if (node.computed) stack.push([node.property, scope, fid, node, "ref"]);
        continue;
      }
      if (t === "CallExpression" || t === "NewExpression" || t === "TaggedTemplateExpression") {
        const callee = t === "TaggedTemplateExpression" ? node.tag : node.callee;
        if (t === "CallExpression" && callee.type === "Identifier" && callee.name === "eval") m.evalWith = true;
        this.fns[fid].calls.push([node, scope]);
      } else if (t === "AssignmentExpression") this.recordAssignment(m, node, scope, fid);
      else if (t === "UpdateExpression" || (t === "UnaryExpression" && node.operator === "delete")) {
        const arg = node.argument;
        if (arg.type === "MemberExpression") arg._asg = true;
        else if (t === "UpdateExpression" && arg.type === "Identifier") {
          const b = lookup(scope, arg.name);
          if (b !== null) {
            b.writes.push(["opaque", node, scope, null]);
            if (b.fid !== fid) b.shared = true;
          }
        }
      } else if (t === "ExportNamedDeclaration") this.recordExport(m, node, scope);
      else if (t === "ExportDefaultDeclaration") {
        if (!m.named.has("default")) m.named.set("default", []);
        m.named.get("default").push(["expr", node.declaration, scope]);
      } else if (t === "ExportAllDeclaration") {
        if (node.exported === null) m.stars.push(node.source.value);
        else {
          const ex = node.exported;
          const name = ex.type === "Identifier" ? ex.name : ex.value;
          if (!m.named.has(name)) m.named.set(name, []);
          m.named.get(name).push(["namespace", node.source.value, scope]);
        }
      } else if (t === "TSExportAssignment") m.cjs.push([node.expression, scope]);
      else if (t === "ForInStatement" || t === "ForOfStatement") {
        const left = node.left;
        if (left.type === "VariableDeclaration") {
          for (const d of left.declarations) {
            for (const [ident] of patternNames(d.id)) {
              const b = lookup(scope, ident.name);
              if (b !== null) b.writes.push(["opaque", node, scope, null]);
            }
          }
        } else {
          for (const mem of patternMembers(left)) mem._asg = true;
          for (const [ident] of patternNames(left)) {
            const b = lookup(scope, ident.name);
            if (b !== null) {
              b.writes.push(["opaque", node, scope, null]);
              if (b.fid !== fid) b.shared = true;
            }
          }
        }
      }
      // children: references and declared names
      if (t === "Property") {
        if (node.computed) stack.push([node.key, scope, fid, node, "ref"]);
        stack.push([node.value, scope, fid, node, parent !== null && parent.type === "ObjectPattern" ? field : "ref"]);
        continue;
      }
      if (t === "MethodDefinition" || t === "PropertyDefinition") {
        if (node.value !== null && node.value !== undefined) stack.push([node.value, scope, fid, node, "ref"]);
        const outer = scope.parent !== null ? scope.parent : scope;
        if (node.computed) stack.push([node.key, outer, fid, node, "ref"]);
        const decs = node.decorators || [];
        for (let k = decs.length - 1; k >= 0; k--) stack.push([decs[k], outer, fid, node, "ref"]);
        continue;
      }
      if (t === "LabeledStatement") { stack.push([node.body, scope, fid, node, "ref"]); continue; }
      if (t === "ExportSpecifier" || t === "ImportDeclaration" || t === "ExportAllDeclaration"
        || t === "TSImportEquals" || t === "MetaProperty") {
        if (t === "TSImportEquals" && node.entity !== null) stack.push([node.entity, scope, fid, node, "ref"]);
        continue;
      }
      if (t === "ExportNamedDeclaration") {
        if (node.declaration !== null) stack.push([node.declaration, scope, fid, node, "ref"]);
        continue;
      }
      if (t === "ClassDeclaration" || t === "ClassExpression") {
        const outer = scope.parent;        // the class's own scope holds its name (expressions)
        const members = node.body.body;
        for (let k = members.length - 1; k >= 0; k--) {
          const member = members[k];
          if (member.type === "StaticBlock") {
            const sscope = member._scope;
            for (let j = member.body.length - 1; j >= 0; j--) stack.push([member.body[j], sscope, fid, member, "ref"]);
          } else stack.push([member, scope, fid, node, "ref"]);
        }
        if (node.superClass != null) stack.push([node.superClass, outer, fid, node, "ref"]);
        const decs = node.decorators || [];
        for (let k = decs.length - 1; k >= 0; k--) stack.push([decs[k], outer, fid, node, "ref"]);
        continue;
      }
      if (FUNCTIONS.has(t)) {
        stack.push([node.body, scope, fid, node, "ref"]);
        for (let k = node.params.length - 1; k >= 0; k--) stack.push([node.params[k], scope, fid, node, "decl"]);
        continue;
      }
      if (t === "VariableDeclarator") {
        if (node.init !== null) stack.push([node.init, scope, fid, node, "ref"]);
        stack.push([node.id, scope, fid, node, "decl"]);
        continue;
      }
      if (t === "ObjectPattern" || t === "ArrayPattern" || t === "RestElement" || t === "AssignmentPattern") {
        const ks = kids(node);
        for (let k = ks.length - 1; k >= 0; k--) {
          const kf = t === "AssignmentPattern" && ks[k] === node.right ? "ref" : field;
          stack.push([ks[k], scope, fid, node, kf]);
        }
        continue;
      }
      if (t === "CatchClause") {
        stack.push([node.body, scope, fid, node, "ref"]);
        if (node.param !== null) stack.push([node.param, scope, fid, node, "decl"]);
        continue;
      }
      if (t === "JSXOpeningElement" || t === "JSXClosingElement") {
        if (t === "JSXOpeningElement") {
          for (let k = node.attributes.length - 1; k >= 0; k--) stack.push([node.attributes[k], scope, fid, node, "ref"]);
        }
        continue;
      }
      if (t === "JSXAttribute") {
        if (node.value !== null) stack.push([node.value, scope, fid, node, "ref"]);
        continue;
      }
      const ks = kids(node);
      for (let k = ks.length - 1; k >= 0; k--) stack.push([ks[k], scope, fid, node, "ref"]);
    }
  }

  recordAssignment(m, node, scope, fid) {
    const left = node.left, right = node.right, op = node.operator;
    if (left.type === "Identifier") {
      const b = lookup(scope, left.name);
      if (b !== null) {
        b.writes.push([op === "=" ? "assign" : "opaque", right, scope, []]);
        if (b.fid !== fid) b.shared = true;
      } else if (left.name === "RegExp") m.regexpRebound = true;
      return;
    }
    if (left.type === "ObjectPattern" || left.type === "ArrayPattern") {
      for (const mem of patternMembers(left)) mem._asg = true;
      for (const [ident, path] of patternNames(left)) {
        const b = lookup(scope, ident.name);
        if (b !== null) {
          b.writes.push(["assign", right, scope, path]);
          if (b.fid !== fid) b.shared = true;
        } else if (ident.name === "RegExp") m.regexpRebound = true;
      }
      return;
    }
    if (left.type !== "MemberExpression") return;
    left._asg = true;
    const name = propName(left);
    const obj = left.object;
    if (name === "RegExp" && obj.type === "Identifier" && ["globalThis", "window", "global", "self"].includes(obj.name)) {
      m.regexpRebound = true;
    }
    // module.exports = … / module.exports.x = … / exports.x = …
    if (obj.type === "Identifier" && obj.name === "module" && name === "exports" && lookup(scope, "module") === null) {
      m.cjs.push([right, scope]);
      return;
    }
    if (name !== null && obj.type === "Identifier" && obj.name === "exports" && lookup(scope, "exports") === null) {
      if (!m.cjsProps.has(name)) m.cjsProps.set(name, []);
      m.cjsProps.get(name).push([right, scope]);
      return;
    }
    if (name !== null && obj.type === "MemberExpression" && !obj.computed && propName(obj) === "exports"
      && obj.object.type === "Identifier" && obj.object.name === "module" && lookup(scope, "module") === null) {
      if (!m.cjsProps.has(name)) m.cjsProps.set(name, []);
      m.cjsProps.get(name).push([right, scope]);
    }
  }

  recordExport(m, node, scope) {
    const add = (name, entry) => {
      if (!m.named.has(name)) m.named.set(name, []);
      m.named.get(name).push(entry);
    };
    const decl = node.declaration;
    if (decl !== null) {
      if (decl.type === "VariableDeclaration") {
        for (const d of decl.declarations) {
          for (const [ident] of patternNames(d.id)) add(ident.name, ["binding", ident.name, scope]);
        }
      } else if (decl.id != null && decl.id.type === "Identifier") add(decl.id.name, ["binding", decl.id.name, scope]);
      return;
    }
    const src = node.source !== null ? node.source.value : null;
    for (const spec of node.specifiers) {
      const local = spec.local, exported = spec.exported;
      const lname = local.type === "Identifier" ? local.name : local.value;
      const ename = exported.type === "Identifier" ? exported.name : exported.value;
      if (src !== null) add(ename, ["reexport", src, lname]);
      else add(ename, ["binding", lname, scope]);
    }
  }

  // ---- modules ----
  /** A module specifier from module mod: ["mod", idx], ["builtin", name] or ["pkg", spec]. */
  resolveSpec(mod, spec) {
    if (typeof spec !== "string") return ["pkg", ""];
    if (spec.startsWith("node:")) return ["builtin", spec.slice(5)];
    if (!(spec.startsWith("./") || spec.startsWith("../") || spec === "." || spec === "..")) {
      const head = spec.split("/")[0];
      if (NODE_BUILTINS.has(head)) return ["builtin", head];
      return ["pkg", spec];
    }
    const base = join(this.mods[mod].dir, spec);
    if (base === null) return ["pkg", spec];
    const last = base.slice(base.lastIndexOf("/") + 1);
    const dot = last.lastIndexOf(".");
    const ext = dot > 0 ? last.slice(dot) : "";
    const cands = [];
    if (EXTS.includes(ext)) {
      cands.push(base);
      for (const alt of TS_SOURCES.get(ext) || []) cands.push(base.slice(0, base.length - ext.length) + alt);
    } else {
      for (const e of EXTS) cands.push(base + e);
      for (const e of EXTS) cands.push((base ? base + "/" : "") + "index" + e);
    }
    for (const c of cands) {
      const idx = this.byPath.get(c);
      if (idx !== undefined) return ["mod", idx];
    }
    return ["pkg", spec];
  }

  // ---- what names hold (points-to) ----
  descsOfBind(b, depth) {
    const got = this.descMemo.get(b.bid);
    if (got !== undefined) return got;
    if (depth > ALIAS_DEPTH) return UNKNOWN;
    this.descMemo.set(b.bid, UNKNOWN);          // a cycle reads as unknown
    let out = [];
    for (const [kind, node, scope, extra] of b.writes) {
      if (kind === "fn") out.push(["fn", extra]);
      else if (kind === "class") out.push(["class", extra]);
      else if (kind === "import") {
        const target = this.resolveSpec(b.mod, node);
        if (extra === "*" || extra === "=") out.push(target);
        else if (target[0] === "mod") out.push(...this.memberDescs(target[1], extra, depth + 1, 0));
        else if (target[0] === "builtin") out.push(["builtin", target[1] + "." + extra]);
        else out.push(["open", extra !== "default" ? extra : b.name]);
      } else if (kind === "init" || kind === "assign") {
        let ds = this.descsOfExpr(node, scope, depth + 1);
        for (const name of extra) {
          if (name === null) { ds = UNKNOWN; break; }
          const next = [];
          for (const d of ds) next.push(...this.memberOf(d, name, depth + 1));
          ds = next;
        }
        out.push(...ds);
      } else out.push(["local"]);
    }
    out = uniqDescs(out);
    if (!out.length) out = [["local"]];
    this.descMemo.set(b.bid, out);
    return out;
  }

  /**
   * What an expression may be: ["fn", fid], ["class", cid], ["inst", cid],
   * ["obj", oid], ["mod", idx], ["builtin", name], ["pkg", spec], ["open",
   * name], ["global", name], ["local"], ["unknown"].
   */
  descsOfExpr(node, scope, depth) {
    if (depth > ALIAS_DEPTH) return UNKNOWN;
    const t = node.type;
    if (t === "Identifier") {
      let b = node._b;
      if (b === undefined) b = lookup(scope, node.name);
      if (b === null) return [["global", node.name]];
      return this.descsOfBind(b, depth);
    }
    if (FUNCTIONS.has(t)) return [["fn", node._fid]];
    if (t === "ClassExpression") return [["class", node._cid]];
    if (t === "ObjectExpression") return [["obj", node._oid]];
    if (t === "CallExpression") {
      const callee = node.callee;
      if (callee.type === "Identifier" && callee.name === "require" && node.arguments.length
        && lookup(scope, "require") === null) {
        const arg = node.arguments[0];
        if (arg.type === "Literal" && arg.kind === "string") return [this.resolveSpec(this.fns[scope.fid].mod, arg.value)];
        if (arg.type === "TemplateLiteral" && !arg.expressions.length) {
          return [this.resolveSpec(this.fns[scope.fid].mod, arg.quasis[0].raw)];
        }
      }
      return UNKNOWN;
    }
    if (t === "NewExpression") {
      const out = [];
      for (const d of this.descsOfExpr(node.callee, scope, depth + 1)) if (d[0] === "class") out.push(["inst", d[1]]);
      return out.length ? out : UNKNOWN;
    }
    if (t === "MemberExpression") {
      const name = propName(node);
      if (name === null) return UNKNOWN;
      const out = [];
      for (const d of this.descsOfExpr(node.object, scope, depth + 1)) out.push(...this.memberOf(d, name, depth + 1));
      const u = uniqDescs(out);
      return u.length ? u : UNKNOWN;
    }
    if (t === "ChainExpression") return this.descsOfExpr(node.expression, scope, depth + 1);
    if (t === "AwaitExpression") return this.descsOfExpr(node.argument, scope, depth + 1);
    if (t === "SequenceExpression") return this.descsOfExpr(node.expressions[node.expressions.length - 1], scope, depth + 1);
    if (t === "AssignmentExpression" && node.operator === "=") return this.descsOfExpr(node.right, scope, depth + 1);
    if (t === "ConditionalExpression" || t === "LogicalExpression") {
      const parts = t === "ConditionalExpression" ? [node.consequent, node.alternate] : [node.left, node.right];
      const out = [];
      for (const p of parts) out.push(...this.descsOfExpr(p, scope, depth + 1));
      return uniqDescs(out);
    }
    if (t === "ThisExpression") return this.thisDescs(scope);
    if (t === "Super") {
      const c = this.methodClass(scope);
      if (c !== null) {
        const sup = this.superclass(c, depth);
        if (sup !== null) return [["inst", sup.cid]];
      }
    }
    return UNKNOWN;
  }

  /** The class of the method whose code scope is (through arrows). */
  methodClass(scope) {
    let fn = this.fns[scope.fid];
    let seen = 0;
    while (fn.node !== null && fn.node.type === "ArrowFunctionExpression" && fn.parent !== null && seen < ALIAS_DEPTH) {
      fn = this.fns[fn.parent];
      seen++;
    }
    return fn.cls !== null ? this.classes[fn.cls] : null;
  }

  /** `this` in a method: an instance of its class, or its object. */
  thisDescs(scope) {
    let fn = this.fns[scope.fid];
    let seen = 0;
    while (fn.node !== null && fn.node.type === "ArrowFunctionExpression" && fn.parent !== null && seen < ALIAS_DEPTH) {
      fn = this.fns[fn.parent];
      seen++;
    }
    if (fn.cls !== null) return [["inst", fn.cls]];
    if (fn.obj !== null) return [["obj", fn.obj]];
    return UNKNOWN;
  }

  memberOf(d, name, depth) {
    const kind = d[0];
    if (kind === "mod") return this.memberDescs(d[1], name, depth, 0);
    if (kind === "obj") {
      const out = [];
      for (const [node, scope] of this.objs[d[1]].props.get(name) || []) out.push(...this.descsOfExpr(node, scope, depth + 1));
      return out.length ? out : [["open", name]];
    }
    if (kind === "class") {
      const fid = this.classes[d[1]].statics.get(name);
      return fid !== undefined ? [["fn", fid]] : [["open", name]];
    }
    if (kind === "inst") {
      let c = this.classes[d[1]];
      let seen = 0;
      while (c !== null && seen < ALIAS_DEPTH) {
        seen++;
        const fid = c.methods.get(name);
        if (fid !== undefined) return [["fn", fid]];
        c = this.superclass(c, depth);
      }
      return COMMON_METHODS.has(name) ? UNKNOWN : [["open", name]];
    }
    if (kind === "builtin") return [["builtin", d[1] + "." + name]];
    if (kind === "global" && GLOBAL_OBJECTS.has(d[1])) return [["builtin", d[1] + "." + name]];
    if (COMMON_METHODS.has(name)) return UNKNOWN;
    return [["open", name]];
  }

  superclass(c, depth) {
    if (c.sup === null || depth > ALIAS_DEPTH) return null;
    const [node, scope] = c.sup;
    for (const d of this.descsOfExpr(node, scope, depth + 1)) if (d[0] === "class") return this.classes[d[1]];
    return null;
  }

  /** What export `name` of module idx may be. */
  memberDescs(idx, name, depth, hops) {
    const m = this.mods[idx];
    let out = [];
    for (const entry of m.named.get(name) || []) out.push(...this.exportEntry(m, entry, depth));
    if (name !== "default" || !out.length) {
      for (const [node, scope] of m.cjsProps.get(name) || []) out.push(...this.descsOfExpr(node, scope, depth + 1));
    }
    for (const [node, scope] of m.cjs) {
      for (const x of this.descsOfExpr(node, scope, depth + 1)) {
        if (name === "default") {
          if (!(m.named.get("default") || []).length) out.push(x);
        } else if (x[0] === "obj" || x[0] === "mod" || x[0] === "class" || x[0] === "inst") {
          out.push(...this.memberOf(x, name, depth + 1));
        }
      }
    }
    if (!out.length && name !== "default" && hops < EXPORT_HOPS) {
      for (const spec of m.stars) {
        const target = this.resolveSpec(m.idx, spec);
        if (target[0] === "mod") {
          for (const x of this.memberDescs(target[1], name, depth + 1, hops + 1)) if (x[0] !== "open") out.push(x);
        }
      }
    }
    out = uniqDescs(out);
    if (out.length) return out;
    return name !== "default" ? [["open", name]] : UNKNOWN;
  }

  exportEntry(m, entry, depth) {
    const kind = entry[0];
    if (kind === "binding") {
      const b = lookup(entry[2], entry[1]);
      if (b === null) return [["open", entry[1]]];
      return this.descsOfBind(b, depth + 1);
    }
    if (kind === "expr") {
      const node = entry[1];
      if (node.type === "FunctionDeclaration") return [["fn", node._fid]];
      if (node.type === "ClassDeclaration") return [["class", node._cid]];
      return this.descsOfExpr(node, entry[2], depth + 1);
    }
    if (kind === "reexport") {
      const target = this.resolveSpec(m.idx, entry[1]);
      if (target[0] === "mod" && depth < ALIAS_DEPTH) return this.memberDescs(target[1], entry[2], depth + 1, 0);
      return [["open", entry[2]]];
    }
    return [this.resolveSpec(m.idx, entry[1])];          // namespace
  }

  /** The functions a module's `module.exports` may be. */
  modCallables(idx, hops) {
    const out = [];
    for (const [node, scope] of this.mods[idx].cjs) {
      for (const x of this.descsOfExpr(node, scope, 1)) {
        if (x[0] === "fn") out.push(x[1]);
        else if (x[0] === "class") {
          const ctor = this.constructorOf(this.classes[x[1]]);
          if (ctor !== null) out.push(ctor);
        } else if (x[0] === "mod" && hops < EXPORT_HOPS) out.push(...this.modCallables(x[1], hops + 1));
      }
    }
    return out;
  }

  constructorOf(c) {
    let seen = 0;
    while (c !== null && seen < ALIAS_DEPTH) {
      seen++;
      const fid = c.methods.get("constructor");
      if (fid !== undefined) return fid;
      c = this.superclass(c, 0);
    }
    return null;
  }

  // ---- calls ----
  /**
   * [project functions the call may reach, how]: how is "definite", "open"
   * (by name), "mixed" or "none". Memoized on the call (`_tg`).
   */
  callTargets(call, scope) {
    if (call._tg !== undefined) return call._tg;
    const t = call.type;
    const callee = unwrap(t === "TaggedTemplateExpression" ? call.tag : call.callee);
    let fids = [];
    const openNames = [];
    const ct = callee.type;
    if (FUNCTIONS.has(ct)) fids.push(callee._fid);
    else if (ct === "Super") {
      const c = this.methodClass(scope);
      const sup = c !== null ? this.superclass(c, 0) : null;
      const ctor = sup !== null ? this.constructorOf(sup) : null;
      if (ctor !== null) fids.push(ctor);
    } else {
      for (const d of this.descsOfExpr(callee, scope, 0)) {
        const k = d[0];
        if (k === "fn") fids.push(d[1]);
        else if (k === "class") {
          const ctor = this.constructorOf(this.classes[d[1]]);
          if (ctor !== null) fids.push(ctor);
        } else if (k === "mod") fids.push(...this.modCallables(d[1], 0));
        else if (k === "open") openNames.push(d[1]);
        else if (k === "global" && ct === "Identifier") openNames.push(d[1]);
        else if (k === "unknown" && ct === "MemberExpression") {
          const name = propName(callee);
          if (name !== null && !COMMON_METHODS.has(name)) openNames.push(name);
        }
      }
    }
    fids = [...new Set(fids)];
    const opens = [];
    for (const name of new Set(openNames)) {
      const cands = this.byName.get(name) || [];
      if (cands.length > 0 && cands.length <= MAX_OPEN) {
        for (const c of cands) if (!fids.includes(c) && !opens.includes(c)) opens.push(c);
      }
    }
    let how = "none";
    if (fids.length) how = opens.length ? "mixed" : "definite";
    else if (opens.length) how = "open";
    const out = [[...fids, ...opens], how];
    call._tg = out;
    return out;
  }

  // ---- imports' values, routes, order ----
  /** The bindings an import binding reads (a module's exported variables), following re-exports. */
  importTargets(b) {
    if (b.targets !== null) return b.targets;
    b.targets = [];
    const out = [];
    for (const [kind, spec, , name] of b.writes) {
      if (kind !== "import" || name === "*" || name === "=") continue;
      const target = this.resolveSpec(b.mod, spec);
      if (target[0] === "mod") this.exportBinds(target[1], name, out, 0);
    }
    b.targets = [...new Set(out)];
    return b.targets;
  }

  exportBinds(idx, name, out, hops) {
    const m = this.mods[idx];
    for (const entry of m.named.get(name) || []) {
      if (entry[0] === "binding") {
        const t = lookup(entry[2], entry[1]);
        if (t !== null && (t.kind === "var" || t.kind === "let" || t.kind === "const")) out.push(t);
      } else if (entry[0] === "reexport" && hops < EXPORT_HOPS) {
        const target = this.resolveSpec(m.idx, entry[1]);
        if (target[0] === "mod") this.exportBinds(target[1], entry[2], out, hops + 1);
      }
    }
    if (!(m.named.get(name) || []).length && name !== "default" && hops < EXPORT_HOPS) {
      for (const spec of m.stars) {
        const target = this.resolveSpec(m.idx, spec);
        if (target[0] === "mod") this.exportBinds(target[1], name, out, hops + 1);
      }
    }
  }

  /** Route handlers: functions registered with `app.get('/p', fn)`, `router.post([...], fn)`, `app.use(fn)`, `router.route('/p').get(fn)`. */
  markRoutes() {
    for (const fn of this.fns) {
      for (const [node, scope] of fn.calls) {
        if (node.type !== "CallExpression") continue;
        const callee = unwrap(node.callee);
        if (callee.type !== "MemberExpression") continue;
        const name = propName(callee);
        const args = node.arguments;
        if (!ROUTE_METHODS.has(name) || !args.length) continue;
        let handlers;
        if (routePath(args[0])) handlers = args.slice(1);
        else if (name === "use" || this.routeChain(callee.object)) handlers = args;
        else continue;
        for (const a of handlers) {
          for (const h of a.type === "ArrayExpression" ? a.elements : [a]) {
            if (h === null || h.type === "SpreadElement") continue;
            // a wrapped handler: asyncHandler(async (req, res) => …)
            const inner = h.type === "CallExpression" ? h.arguments.filter((x) => x.type !== "SpreadElement") : [h];
            for (const x of inner) {
              for (const d of this.descsOfExpr(x, scope, 0)) {
                if (d[0] === "fn") {
                  const f = this.fns[d[1]];
                  if (!f.module) f.route = f.params.length === 4 ? 2 : 1;
                }
              }
            }
          }
        }
      }
    }
  }

  /** `router.route('/p')`, or a route method called on one. */
  routeChain(obj) {
    let seen = 0;
    while (obj.type === "CallExpression" && seen < ALIAS_DEPTH) {
      seen++;
      const callee = unwrap(obj.callee);
      if (callee.type !== "MemberExpression") return false;
      const name = propName(callee);
      if (name === "route") return obj.arguments.length > 0 && routePath(obj.arguments[0]);
      if (!ROUTE_METHODS.has(name)) return false;
      obj = callee.object;
    }
    return false;
  }

  /** Every function, the functions it calls and the functions defined in it first (DFS post-order). */
  order() {
    const succ = this.fns.map(() => []);
    for (const fn of this.fns) if (fn.parent !== null) succ[fn.parent].push(fn.fid);
    for (const fn of this.fns) {
      const out = succ[fn.fid];
      for (const [node, scope] of fn.calls) {
        for (const x of this.callTargets(node, scope)[0]) if (x !== fn.fid) out.push(x);
      }
      succ[fn.fid] = [...new Set(out)];
    }
    const seen = this.fns.map(() => false);
    const order = [];
    for (let root = 0; root < this.fns.length; root++) {
      if (seen[root]) continue;
      seen[root] = true;
      const stack = [[root, 0]];
      while (stack.length) {
        const top = stack[stack.length - 1];
        const nexts = succ[top[0]];
        if (top[1] < nexts.length) {
          const nxt = nexts[top[1]];
          top[1]++;
          if (!seen[nxt]) {
            seen[nxt] = true;
            stack.push([nxt, 0]);
          }
        } else {
          stack.pop();
          order.push(top[0]);
        }
      }
    }
    return order;
  }
}

// --------------------------------------------------------------- analysis --
class Stop {}           // the pass's work budget is spent
class Cut {}            // one reading of one function has run past its own limit

/** One reading of one function: its summary and, with emit, its findings. */
class Eval {
  constructor(prog, fn, emit, findings) {
    this.p = prog;
    this.fn = fn;
    this.mod = prog.mods[fn.mod];
    this.emit = emit;
    this.findings = findings;
    this.env = new Map();
    this.version = 0;
    this.cur = fn.scope;
    this.reachAdds = [];         // [key, category, sink entry]
    this.retVal = null;
    this.sharedWrites = new Map();   // bid -> V
    this.reads = new Map();      // shared bindings read
    this.uses = new Map();       // fid -> Set of the parameters of it this reading passed tainted values
    this.lines = this.mod.lines;
    this.limit = prog.work + LIMITS.RUN_BASE + LIMITS.RUN_PER_NODE * fn.size;
    this.ancestors = new Set();
    let f = fn;
    while (f !== null) {
      this.ancestors.add(f.fid);
      f = f.parent !== null ? prog.fns[f.parent] : null;
    }
  }

  // ---- budget ----
  tick(n = 1) {
    const p = this.p;
    p.work += n;
    if (p.work > p.budget) throw new Stop();
    if (p.work > this.limit) throw new Cut();
  }

  // ---- bindings ----
  read(b) {
    if (b.kind === "import") {
      const targets = b.targets || [];
      if (!targets.length) return EMPTY;
      let out = EMPTY;
      for (const t of targets) {
        this.reads.set(t.bid, true);
        let v = this.p.shared.get(t.bid);
        if (v !== undefined && v.tainted()) {
          if (v.src && v.via === null) v = v.withVia(`the value ${b.name} imported from ${this.p.mods[t.mod].path}`);
          out = out.union(v.plain());
        }
      }
      return out;
    }
    if (b.fid === this.fn.fid && !b.shared) return this.env.get(b.bid) ?? EMPTY;
    this.reads.set(b.bid, true);
    let v = this.p.shared.get(b.bid) ?? EMPTY;
    if (b.fid === this.fn.fid) v = (this.env.get(b.bid) ?? EMPTY).union(v);
    return v;
  }

  write(b, v, strong = true) {
    if (b.fid === this.fn.fid) {
      const old = this.env.get(b.bid);
      const nv = strong || old === undefined ? v : old.union(v);
      if (old === undefined || !same(nv, old)) {
        this.env.set(b.bid, nv);
        this.version++;
      }
    }
    if (b.shared) {
      // a closure's variable carries the parameters of the function that
      // declares it and of the functions around that one
      v = v.within(this.p.scopeFns(b.fid));
      const old = this.sharedWrites.get(b.bid);
      this.sharedWrites.set(b.bid, old === undefined ? v : old.union(v));
    }
  }

  copyEnv() {
    this.tick(1 + (this.env.size >> 5));
    return new Map(this.env);
  }

  /** Both environments' values (a branch's and another's). */
  merge(a, b) {
    this.tick(1 + ((a.size + b.size) >> 5));
    const out = new Map(a);
    for (const [k, v] of b) {
      const old = out.get(k);
      out.set(k, old === undefined ? v : old.union(v));
    }
    return out;
  }

  // ---- the function ----
  run() {
    const fn = this.fn, node = fn.node;
    if (fn.module) { this.stmts(node.body); return; }
    fn.params.forEach((p, i) => {
      let v = i < PARAM_BASE ? new V(false, null, null, null, [fn.fid * PARAM_BASE + i]) : EMPTY;
      if (fn.route && v !== EMPTY) {
        if (i === fn.route - 1) v = new V(false, null, null, null, v.params, 0, false, 1);
        else if (i === fn.route) v = new V(false, null, null, null, v.params, 0, false, 2);
      }
      this.bindPattern(p, v, fn.scope);
    });
    const body = node.body;
    if (body.type === "BlockStatement") this.stmts(body.body);
    else this.ret(this.expr(body, fn.scope));
  }

  ret(v) { this.retVal = this.retVal === null ? v : this.retVal.union(v); }

  // ---- statements ----
  stmts(body) { for (const st of body) this.stmt(st); }

  stmt(st) {
    this.tick();
    const t = st.type;
    const cur = this.cur;
    if (t === "ExpressionStatement") this.expr(st.expression, cur);
    else if (t === "VariableDeclaration") {
      for (const d of st.declarations) {
        const v = d.init !== null ? this.expr(d.init, cur) : EMPTY;
        if (d.init !== null || st.kind !== "var") this.bindPattern(d.id, v, cur);
        else this.patternParts(d.id, cur);
      }
    } else if (t === "ReturnStatement") this.ret(st.argument !== null ? this.expr(st.argument, cur) : EMPTY);
    else if (t === "IfStatement") {
      let node = st;
      const outs = [];
      for (;;) {
        this.expr(node.test, cur);
        const before = this.copyEnv();
        this.sub(node.consequent);
        outs.push(this.env);
        this.env = before;
        const alt = node.alternate;
        if (alt !== null && alt.type === "IfStatement") {
          this.tick();
          node = alt;
          continue;
        }
        if (alt !== null) this.sub(alt);
        outs.push(this.env);
        break;
      }
      let acc = outs[outs.length - 1];
      for (let k = 0; k < outs.length - 1; k++) acc = this.merge(acc, outs[k]);
      this.env = acc;
    } else if (t === "BlockStatement") {
      this.cur = st._scope || cur;
      this.stmts(st.body);
      this.cur = cur;
    } else if (LOOPS.has(t)) this.loop(st);
    else if (t === "TryStatement") {
      const before = this.copyEnv();
      this.stmt(st.block);
      const h = st.handler;
      if (h !== null) {
        const after = this.env;
        this.env = this.merge(before, after);
        this.cur = h._scope;
        if (h.param !== null) this.bindPattern(h.param, EMPTY, this.cur);
        this.stmts(h.body.body);
        this.cur = cur;
        this.env = this.merge(after, this.env);
      }
      if (st.finalizer !== null) this.stmt(st.finalizer);
    } else if (t === "SwitchStatement") {
      this.cur = st._scope || cur;
      this.expr(st.discriminant, this.cur);
      const before = this.copyEnv();
      let acc = before;
      for (const c of st.cases) {
        if (c.test !== null) this.expr(c.test, this.cur);
        this.env = this.merge(before, this.env);
        this.stmts(c.consequent);
        acc = this.merge(acc, this.env);
      }
      this.env = acc;
      this.cur = cur;
    } else if (t === "LabeledStatement") this.stmt(st.body);
    else if (t === "ThrowStatement") this.expr(st.argument, cur);
    else if (t === "WithStatement") {
      this.expr(st.object, cur);
      this.sub(st.body);
    } else if (t === "ClassDeclaration") this.classParts(st, cur);
    else if (t === "ExportNamedDeclaration") {
      if (st.declaration !== null) this.stmt(st.declaration);
    } else if (t === "ExportDefaultDeclaration") {
      const d = st.declaration;
      if (d.type === "ClassDeclaration") this.classParts(d, cur);
      else if (d.type !== "FunctionDeclaration") this.expr(d, cur);
    } else if (t === "TSModuleDeclaration") {
      if (st.body !== null) this.sub(st.body);
    } else if (t === "TSExportAssignment") this.expr(st.expression, cur);
    else if (t === "TSEnumDeclaration") {
      for (const mem of st.members) if (mem.initializer !== null) this.expr(mem.initializer, cur);
    }
  }

  sub(st) {
    const cur = this.cur;
    this.stmt(st);
    this.cur = cur;
  }

  loop(st) {
    const t = st.type;
    const cur = this.cur;
    this.cur = st._scope || cur;
    if (t === "ForStatement" && st.init !== null) {
      if (st.init.type === "VariableDeclaration") this.stmt(st.init);
      else this.expr(st.init, this.cur);
    }
    let it = null;
    if (t === "ForInStatement" || t === "ForOfStatement") it = this.expr(st.right, this.cur).plain();
    const before = this.copyEnv();
    for (let k = 0; k < 2; k++) {
      const version = this.version;
      if (it !== null) {
        const left = st.left;
        if (left.type === "VariableDeclaration") {
          for (const d of left.declarations) this.bindPattern(d.id, it, this.cur);
        } else this.assignPattern(left, it, this.cur);
      }
      if ((t === "ForStatement" || t === "WhileStatement") && st.test !== null) this.expr(st.test, this.cur);
      this.sub(st.body);
      if (t === "DoWhileStatement") this.expr(st.test, this.cur);
      if (t === "ForStatement" && st.update !== null) this.expr(st.update, this.cur);
      if (this.version === version) break;
    }
    if (t !== "DoWhileStatement") this.env = this.merge(before, this.env);
    this.cur = cur;
  }

  /** A class's superclass, decorators, computed keys, field initializers and static blocks. */
  classParts(node, scope) {
    const cscope = node._scope;
    for (const d of node.decorators || []) this.expr(d, scope);
    if (node.superClass != null) this.expr(node.superClass, scope);
    for (const member of node.body.body) {
      const mt = member.type;
      if (mt === "StaticBlock") {
        const cur = this.cur;
        this.cur = member._scope;
        this.stmts(member.body);
        this.cur = cur;
        continue;
      }
      for (const d of member.decorators || []) this.expr(d, scope);
      if (member.computed) this.expr(member.key, scope);
      if (mt === "PropertyDefinition" && member.value !== null && member.value !== undefined
        && !FUNCTIONS.has(member.value.type)) this.expr(member.value, cscope);
    }
  }

  // ---- patterns ----
  bind(ident, scope) {
    const b = ident._b;
    return b === undefined ? lookup(scope, ident.name) : b;
  }

  bindPattern(pat, v, scope) {
    for (const [ident, path] of patternNames(pat)) {
      const b = this.bind(ident, scope);
      if (b === null) continue;
      let val;
      if (path.length && v.kind & 1 && REQUEST_PROPS.has(path[0])) val = this.source(ident.line).union(v.plain());
      else val = path.length ? v.plain() : v;
      this.write(b, val);
    }
    this.patternParts(pat, scope);
  }

  /** A pattern's default values (a name gets its default too) and computed keys. */
  patternParts(pat, scope) {
    if (pat.type === "Identifier") return;
    const todo = [pat];
    while (todo.length) {
      const p = todo.pop();
      if (p === null || p === undefined) continue;
      const t = p.type;
      if (t === "AssignmentPattern") {
        const dv = this.expr(p.right, scope);
        for (const [ident] of patternNames(p.left)) {
          const b = this.bind(ident, scope);
          if (b !== null) this.write(b, dv.plain(), false);
        }
        todo.push(p.left);
      } else if (t === "ObjectPattern") {
        for (let k = p.properties.length - 1; k >= 0; k--) {
          const prop = p.properties[k];
          if (prop.type === "RestElement") todo.push(prop.argument);
          else {
            if (prop.computed) this.expr(prop.key, scope);
            todo.push(prop.value);
          }
        }
      } else if (t === "ArrayPattern") {
        for (let k = p.elements.length - 1; k >= 0; k--) todo.push(p.elements[k]);
      } else if (t === "RestElement") todo.push(p.argument);
      else if (t === "MemberExpression") this.expr(p.object, scope);
    }
  }

  assignPattern(pat, v, scope) {
    const t = pat.type;
    if (t === "Identifier") {
      const b = this.bind(pat, scope);
      if (b !== null) this.write(b, v);
      return;
    }
    if (t === "MemberExpression") {
      this.expr(pat.object, scope);
      if (pat.computed) this.expr(pat.property, scope);
      this.memberWrite(pat, v, scope);
      return;
    }
    for (const [ident, path] of patternNames(pat)) {
      const b = this.bind(ident, scope);
      if (b !== null) this.write(b, path.length ? v.plain() : v);
    }
    for (const mem of patternMembers(pat)) this.memberWrite(mem, v.plain(), scope);
    this.patternParts(pat, scope);
  }

  /** `o.x = v`: the container o holds v too (a weak update). */
  memberWrite(target, v, scope) {
    if (!v.tainted()) return;
    let obj = target.object;
    let seen = 0;
    while (obj.type === "MemberExpression" && seen < ALIAS_DEPTH) {
      obj = obj.object;
      seen++;
    }
    if (obj.type === "Identifier") {
      const b = this.bind(obj, scope);
      if (b !== null && b.kind !== "import") this.write(b, v.plain(), false);
    }
  }

  // ---- sources ----
  source(line) {
    return new V(true, [this.mod.path, line], this.fn.module ? null : this.fn.name);
  }

  isSourceText(t) {
    return t !== "" && this.p.cfg.source.test(t);
  }

  // ---- expressions ----
  expr(e, scope) {
    if (e === null || e === undefined) return EMPTY;
    this.tick();
    const t = e.type;
    if (t === "Identifier") {
      let b = e._b;
      if (b === undefined) b = lookup(scope, e.name);
      if (b === null) return EMPTY;
      return this.read(b);
    }
    if (t === "Literal" || t === "ThisExpression" || t === "Super" || t === "MetaProperty") return EMPTY;
    if (t === "TemplateLiteral") {
      let out = EMPTY;
      for (const x of e.expressions) out = out.union(this.expr(x, scope).plain());
      out = out.withBuilt();
      if (out.tainted() && FIXED_PREFIX_RE.test(e.quasis[0].raw)) out = out.sanitize(FIXED_HOST);
      return out;
    }
    if (t === "MemberExpression" || t === "CallExpression" || t === "NewExpression"
      || t === "TaggedTemplateExpression" || t === "ChainExpression") return this.chain(e, scope);
    if (t === "BinaryExpression" || t === "LogicalExpression") return this.binary(e, scope);
    if (t === "AssignmentExpression") return this.assignment(e, scope);
    if (t === "ConditionalExpression") {
      this.expr(e.test, scope);
      return this.expr(e.consequent, scope).union(this.expr(e.alternate, scope));
    }
    if (t === "UnaryExpression" || t === "UpdateExpression") {
      this.expr(e.argument, scope);
      return EMPTY;
    }
    if (t === "AwaitExpression" || t === "SpreadElement") return this.expr(e.argument, scope);
    if (t === "YieldExpression") {
      this.ret(this.expr(e.argument, scope));
      return EMPTY;
    }
    if (t === "SequenceExpression") {
      let v = EMPTY;
      for (const x of e.expressions) v = this.expr(x, scope);
      return v;
    }
    if (t === "ArrayExpression") {
      let out = EMPTY;
      for (const x of e.elements) if (x !== null) out = out.union(this.expr(x, scope).plain());
      return out;
    }
    if (t === "ObjectExpression") {
      let out = EMPTY;
      for (const prop of e.properties) {
        if (prop.type === "SpreadElement") {
          out = out.union(this.expr(prop.argument, scope).plain());
          continue;
        }
        if (prop.computed) this.expr(prop.key, scope);
        const v = prop.value;
        if (FUNCTIONS.has(v.type)) continue;
        out = out.union(this.expr(v, scope).plain());
      }
      return out;
    }
    if (FUNCTIONS.has(t)) return this.functionValue(e._fid);
    if (t === "ClassExpression") {
      this.classParts(e, scope);
      return EMPTY;
    }
    if (t === "ImportExpression") {
      this.expr(e.source, scope);
      if (e.options != null) this.expr(e.options, scope);
      return EMPTY;
    }
    if (t === "JSXElement" || t === "JSXFragment") {
      this.jsx(e, scope);
      return EMPTY;
    }
    return EMPTY;
  }

  /** A function as a value: what it returns (request data, the parameters of functions around it). */
  functionValue(fid) {
    const f = this.p.fns[fid];
    if (!this.uses.has(fid)) this.uses.set(fid, new Set());
    let out = EMPTY;
    if (f.retSrc !== null) out = out.union(f.retSrc);
    for (const key of [...f.retOuter.keys()].sort(numeric)) {
      if (this.ancestors.has(Math.floor(key / PARAM_BASE))) {
        const [clean, built] = f.retOuter.get(key);
        out = out.union(new V(false, null, null, null, [key], clean, built));
      }
    }
    return out;
  }

  binary(e, scope) {
    // a left-deep chain (a + b + c …) is read in a loop
    const chain = [];
    let n = e;
    while (n.type === "BinaryExpression" || n.type === "LogicalExpression") {
      chain.push(n);
      n = n.left;
    }
    let v = this.expr(n, scope);
    // 'https://host/' + … or '/path/' + …: a fixed host or this site
    let fixed = fixedPrefix(n);
    for (let k = chain.length - 1; k >= 0; k--) {
      const node = chain[k];
      this.tick();
      const op = node.operator;
      const r = this.expr(node.right, scope);
      if (op === "+") {
        v = v.plain().union(r.plain()).withBuilt();
        if (fixed && v.tainted()) v = v.sanitize(FIXED_HOST);
      } else if (op === "||" || op === "&&" || op === "??") {
        v = v.union(r);
        fixed = false;
      } else {
        v = EMPTY;
        fixed = false;
      }
    }
    return v;
  }

  assignment(e, scope) {
    const left = e.left, op = e.operator;
    if (op === "=") {
      const v = this.expr(e.right, scope);
      if (left.type === "Identifier") {
        const b = this.bind(left, scope);
        if (b !== null) this.write(b, v);
      } else if (left.type === "MemberExpression") {
        this.expr(left.object, scope);
        if (left.computed) this.expr(left.property, scope);
        this.sinkAssignment(left, v);
        this.memberWrite(left, v, scope);
      } else this.assignPattern(left, v, scope);
      return v;
    }
    // compound: x += v, x ||= v, …
    const old = this.expr(left, scope);
    const v = this.expr(e.right, scope);
    let nv;
    if (op === "+=") nv = old.plain().union(v.plain()).withBuilt();
    else if (op === "||=" || op === "&&=" || op === "??=") nv = old.union(v);
    else nv = EMPTY;
    if (left.type === "Identifier") {
      const b = this.bind(left, scope);
      if (b !== null) this.write(b, nv);
    } else if (left.type === "MemberExpression") {
      this.sinkAssignment(left, nv);
      this.memberWrite(left, nv, scope);
    }
    return nv;
  }

  sinkAssignment(target, v) {
    const t = text(target) + " =";
    const line = target.computed ? target.line : target.property.line;
    for (const [pat, cat] of this.p.cfg.sinks) {
      if (pat.test(t)) { this.sink(cat, v, line); return; }
    }
    for (const [pat, cat, which] of SINKS) {
      if (which === "value" && pat.test(t)) { this.sink(cat, v, line); return; }
    }
  }

  /** A member, call, tagged template or new expression; its object / callee chain is read in a loop. */
  chain(e, scope) {
    const spine = [];
    let n = e;
    for (;;) {
      const t = n.type;
      if (t === "MemberExpression") { spine.push(n); n = n.object; }
      else if (t === "CallExpression") { spine.push(n); n = n.callee; }
      else if (t === "ChainExpression") n = n.expression;
      else if (t === "TaggedTemplateExpression") { spine.push(n); n = n.tag; }
      else break;
    }
    let v = n.type === "NewExpression" ? this.newExpr(n, scope) : this.expr(n, scope);
    let recv = EMPTY;
    for (let k = spine.length - 1; k >= 0; k--) {
      const node = spine[k];
      this.tick();
      const t = node.type;
      if (t === "MemberExpression") {
        recv = v;
        v = this.member(node, v, scope);
      } else if (t === "CallExpression") {
        const callee = unwrap(node.callee);
        v = this.call(node, callee.type === "MemberExpression" ? recv : EMPTY, v, scope);
        recv = EMPTY;
      } else {
        v = this.tagged(node, scope);
        recv = EMPTY;
      }
    }
    return v;
  }

  member(node, obj, scope) {
    if (node.computed) this.expr(node.property, scope);
    const name = propName(node);
    const line = node.computed ? node.line : node.property.line;
    if (obj.kind & 1) {
      if (REQUEST_PROPS.has(name)) return this.source(line);
      if (REQUEST_WRAPPERS.has(name)) return obj;
    }
    if (this.isSourceText(text(node))) return this.source(line);
    if (name === "length") return EMPTY;
    return obj.kind ? obj.plain() : obj;
  }

  /** The arguments' values, and the index of the first spread (or -1). */
  argsOf(node, scope) {
    const args = [];
    let spread = -1;
    for (const a of node.arguments) {
      if (a.type === "SpreadElement") {
        if (spread < 0) spread = args.length;
        args.push(this.expr(a.argument, scope).plain());
      } else args.push(this.expr(a, scope));
    }
    return [args, spread];
  }

  newExpr(node, scope) {
    const callee = node.callee;
    if (callee.type !== "Identifier") this.expr(callee, scope);
    const [args, spread] = this.argsOf(node, scope);
    const t = "new " + text(callee) + "(";
    const [fids, how] = this.p.callTargets(node, scope);
    if (how !== "definite") {
      const [cat, which] = this.sinkOf(t);
      if (cat !== null) this.sink(cat, this.sinkValue(which, args), node.line);
    }
    if (fids.length) this.apply(node, fids, args, spread, node.line, true);
    return unionAll(args.map((a) => a.plain()));
  }

  tagged(node, scope) {
    const args = node.quasi.expressions.map((x) => this.expr(x, scope).plain());
    const [fids, how] = this.p.callTargets(node, scope);
    if (fids.length) {
      let v = this.apply(node, fids, [EMPTY, ...args], -1, node.line);
      if (how !== "definite") v = v.union(unionAll(args));
      return v;
    }
    return unionAll(args);
  }

  callLine(node) {
    const callee = unwrap(node.callee);
    if (callee.type === "MemberExpression" && !callee.computed) return callee.property.line;
    return callee.line;
  }

  /** A call: its sources and sinks, the functions it reaches, its value. */
  call(node, recv, calleeVal, scope) {
    const [args, spread] = this.argsOf(node, scope);
    const callee = unwrap(node.callee);
    const member = callee.type === "MemberExpression";
    const ctext = text(callee);
    const t = ctext + "(";
    const name = member ? propName(callee) : (callee.type === "Identifier" ? callee.name : null);
    const line = this.callLine(node);
    // request data
    if (member && recv.kind & 1 && REQUEST_CALLS.has(name)) return this.source(line);
    if (this.isSourceText(t)) return this.source(line);
    let [fids, how] = this.p.callTargets(node, scope);
    if (member && recv.kind) { fids = []; how = "none"; }      // a request's or a response's method is the framework's
    const definite = how === "definite";
    // sinks: not a call that is known to reach project code
    if (!definite) {
      const [cat, which] = this.sinkOf(t);
      if (cat !== null) {
        if (!this.notASink(cat, callee, node, scope)) this.sink(cat, this.sinkValue(which, args), line);
      } else if (member && recv.kind & 2) this.responseSink(callee, node, args, line);
    }
    const san = this.sanitizer(ctext, name, fids, definite);
    let v;
    if (fids.length) {
      v = this.apply(node, fids, args, spread, line);
      if (!definite) v = v.union(unionAll(args.map((a) => a.plain()))).union(recv.plain());
    } else if (CLEAN_RESULT.has(name)) v = EMPTY;
    else {
      v = unionAll(args.map((a) => a.plain())).union(recv.plain());
      if (!member) v = v.union(calleeVal.plain());
      else if (name === "join" || name === "concat") v = v.withBuilt();
    }
    // a container a value is put into holds it
    if (member && (name === "push" || name === "unshift") && callee.object.type === "Identifier") {
      const b = this.bind(callee.object, scope);
      if (b !== null && b.kind !== "import") this.write(b, unionAll(args.map((a) => a.plain())), false);
    }
    if (san === ALL) return EMPTY;
    if (san) return v.sanitize(san);
    return v;
  }

  sinkOf(t) {
    for (const [pat, cat] of this.p.cfg.sinks) if (pat.test(t)) return [cat, "all"];
    for (const [pat, cat, which] of SINKS) if (which !== "value" && pat.test(t)) return [cat, which];
    return [null, null];
  }

  sinkValue(which, args) {
    if (!args.length) return EMPTY;
    if (which === "first") return args[0];
    if (which === "last") return args[args.length - 1];
    if (which === "second") return args.length > 1 ? args[1] : EMPTY;
    return unionAll(args);
  }

  /** A RegExp's exec(), Express's sendFile / download given a root, a response sending JSON or a non-HTML type. */
  notASink(cat, callee, node, scope) {
    if (callee.type !== "MemberExpression") return false;
    const name = propName(callee);
    if (cat === "command injection" && name === "exec") return this.regexpReceiver(callee, scope);
    if (cat === "path traversal" && (name === "sendFile" || name === "download")) return this.hasRoot(node);
    if (cat === XSS && (name === "send" || name === "write" || name === "end")) return this.notHtmlResponse(callee, node);
    return false;
  }

  hasRoot(node) {
    for (const a of node.arguments.slice(1)) {
      if (a.type === "ObjectExpression") {
        for (const p of a.properties) if (p.type === "Property" && keyName(p) === "root") return true;
      }
    }
    return false;
  }

  notHtmlResponse(callee, node) {
    const args = node.arguments;
    if (args.length) {
      const a = args[0];
      if (a.type === "MemberExpression" && REQUEST_OBJECTS.has(propName(a))) return true;
      if (a.type === "ObjectExpression" || a.type === "ArrayExpression") return true;
      const t = leftmostText(a);
      if (t !== null && SSE_RE.test(t)) return true;        // a Server-Sent Events frame
    }
    let obj = callee.object;
    let seen = 0;
    while (obj.type === "CallExpression" && seen < ALIAS_DEPTH) {
      seen++;
      const m = unwrap(obj.callee);
      if (m.type !== "MemberExpression") break;
      const name = propName(m);
      const cargs = obj.arguments;
      if (name === "type" && cargs.length && cargs[0].type === "Literal" && cargs[0].kind === "string") {
        return !htmlType(cargs[0].value);
      }
      if ((name === "set" || name === "header") && cargs.length >= 2 && cargs[0].type === "Literal"
        && cargs[0].kind === "string" && lower(cargs[0].value) === "content-type"
        && cargs[1].type === "Literal" && cargs[1].kind === "string") {
        return !htmlType(cargs[1].value);
      }
      obj = m.object;
    }
    return false;
  }

  /** A route handler's response object, whatever its name. */
  responseSink(callee, node, args, line) {
    const name = propName(callee);
    if (!args.length) return;
    if (name === "send" || name === "write" || name === "end") {
      if (!this.notHtmlResponse(callee, node)) this.sink(XSS, args[0], line);
    } else if (name === "redirect") this.sink("open redirect", args[args.length - 1], line);
    else if (name === "location") this.sink("open redirect", args[0], line);
    else if (name === "sendFile" || name === "download") {
      if (!this.hasRoot(node)) this.sink("path traversal", args[0], line);
    }
  }

  /** Is exec()'s receiver proven to be a RegExp? */
  regexpReceiver(callee, scope) {
    const mod = this.mod;
    if (mod.regexpProto || callee.optional) return false;
    const obj = callee.object;
    if (obj.type === "Literal" && obj.kind === "regex") return true;
    if (mod.evalWith) return false;
    if (this.regexpConstruction(obj, scope)) return true;
    if (obj.type !== "Identifier") return false;
    const b = this.bind(obj, scope);
    if (b === null || !(b.kind === "const" || b.kind === "let" || b.kind === "var") || b.writes.length !== 1) return false;
    const [kind, init, iscope, path] = b.writes[0];
    if (kind !== "init" || path.length) return false;
    if (!((init.type === "Literal" && init.kind === "regex") || this.regexpConstruction(init, iscope))) return false;
    for (const [ref, parent] of b.refs) {
      if (parent === null || parent.type !== "MemberExpression" || parent.object !== ref || parent.optional) return false;
      const name = propName(parent);
      if (!REGEXP_MEMBERS.has(name)) return false;
      if (parent._asg && name !== "lastIndex") return false;
    }
    return true;
  }

  /** `new RegExp(…)` / `RegExp(…)`, RegExp being the global. */
  regexpConstruction(node, scope) {
    if (node.type !== "NewExpression" && node.type !== "CallExpression") return false;
    const callee = node.callee;
    if (callee.type !== "Identifier" || callee.name !== "RegExp") return false;
    return !this.mod.regexpRebound && lookup(scope, "RegExp") === null;
  }

  /**
   * The categories the call's value is clean for (ALL: every one): a
   * configured sanitizer always; a built-in one unless the call reaches a
   * project function (by the name alone: one of that name shadows it).
   */
  sanitizer(ctext, name, fids, definite) {
    const cfg = this.p.cfg;
    for (const cand of [ctext, name]) {
      if (cand) {
        if (cfg.full.has(cand)) return ALL;
        const bits = cfg.partial.get(cand);
        if (bits) return bits;
      }
    }
    if (definite) return 0;
    for (const cand of [ctext, name]) {
      if (!cand || (fids.length && !cand.includes("."))) continue;
      if (FULL_SANITIZERS.has(cand)) return ALL;
      const bits = PARTIAL_SANITIZERS.get(cand);
      if (bits) return bits;
    }
    return 0;
  }

  // ---- sinks and calls into summaries ----
  sink(cat, v, line) {
    if (v === null || !v.tainted() || v.clean & BIT[cat]) return;
    const needs = cat === SQL && !v.built;
    const entry = [this.mod.path, line, this.fn.label(), needs];
    for (const key of v.params) this.reachAdds.push([key, cat, entry]);
    if (v.src && v.via !== null && this.emit && !needs) {
      const origin = v.origin;
      const srcLoc = `${origin[0]}:${origin[1]}` + (v.fname ? ` (in ${v.fname}())` : "");
      this.findings.push(this.p.issue(cat, this.mod.path, line, this.lines, srcLoc, `${this.mod.path}:${line}`, v.via));
    }
  }

  /**
   * The functions a call reaches: their parameters' sinks (a finding when
   * request data arrives; the reach of the caller's parameters when they
   * do) and what they return.
   */
  apply(node, fids, args, spread, line, ctor = false) {
    const p = this.p;
    let out = EMPTY;
    let reported = 0;
    const name = this.calleeName(node);
    for (const fid of fids) {
      const f = p.fns[fid];
      const nparams = f.params.length;
      const rest = nparams && f.params[nparams - 1].type === "RestElement" ? nparams - 1 : -1;
      if (!this.uses.has(fid)) this.uses.set(fid, new Set());
      const used = this.uses.get(fid);
      for (let i = 0; i < nparams; i++) if (Eval.bound(args, spread, rest, i).tainted()) used.add(i);
      for (const i of [...f.reach.keys()].sort(numeric)) {
        const t = Eval.bound(args, spread, rest, i);
        if (!t.tainted()) continue;
        const table = f.reach.get(i);
        for (const cat of CATS) {
          const entry = table.get(cat);
          if (entry === undefined || t.clean & BIT[cat]) continue;
          const needs = entry[3] && !t.built;
          if (t.src && this.emit && !needs && !(reported & BIT[cat])) {
            this.findings.push(p.issue(cat, this.mod.path, line, this.lines, `${this.mod.path}:${line}`,
              `${entry[0]}:${entry[1]} ${entry[2]}`, `the call to ${name}()`));
            reported |= BIT[cat];
          }
          for (const key of t.params) this.reachAdds.push([key, cat, [entry[0], entry[1], entry[2], needs]]);
        }
      }
      if (ctor) continue;
      if (f.retSrc !== null) {
        const rs = f.retSrc;
        out = out.union(new V(true, rs.origin, rs.fname, `the value returned by ${f.name || "an anonymous function"}()`,
          NO_PARAMS, rs.clean, rs.built));
      }
      for (const i of [...f.retParams.keys()].sort(numeric)) {
        const [clean, built] = f.retParams.get(i);
        let b = Eval.bound(args, spread, rest, i);
        if (b.tainted()) {
          b = b.plain();
          if (clean) b = b.sanitize(clean);
          out = out.union(built ? b.withBuilt() : b);
        }
      }
      for (const key of [...f.retOuter.keys()].sort(numeric)) {
        if (this.ancestors.has(Math.floor(key / PARAM_BASE))) {
          const [clean, built] = f.retOuter.get(key);
          out = out.union(new V(false, null, null, null, [key], clean, built));
        }
      }
    }
    return out;
  }

  /** The value parameter i of a function receives. */
  static bound(args, spread, rest, i) {
    if (i === rest) return unionAll(args.slice(i));
    if (spread >= 0 && spread <= i) return unionAll(args.slice(spread));
    return i < args.length ? args[i] : EMPTY;
  }

  calleeName(node) {
    const callee = unwrap(node.type === "TaggedTemplateExpression" ? node.tag : node.callee);
    if (callee.type === "Identifier") return callee.name;
    if (callee.type === "MemberExpression") {
      const name = propName(callee);
      if (name !== null) return name;
    }
    return "an anonymous function";
  }

  // ---- JSX ----
  jsx(e, scope) {
    const stack = [e];
    while (stack.length) {
      const n = stack.pop();
      this.tick();
      const t = n.type;
      if (t === "JSXElement") {
        for (const attr of n.openingElement.attributes) {
          if (attr.type === "JSXSpreadAttribute") { this.expr(attr.argument, scope); continue; }
          const value = attr.value;
          if (value === null) continue;
          if (value.type === "JSXElement" || value.type === "JSXFragment") { stack.push(value); continue; }
          if (value.type !== "JSXExpressionContainer" || value.expression.type === "JSXEmptyExpression") continue;
          const inner = value.expression;
          const aname = attr.name;
          if (aname.type === "JSXIdentifier" && aname.name === "dangerouslySetInnerHTML" && inner.type === "ObjectExpression") {
            for (const prop of inner.properties) {
              if (prop.type === "SpreadElement") this.expr(prop.argument, scope);
              else if (prop.type === "Property" && !prop.computed && keyName(prop) === "__html") {
                this.sink(XSS, this.expr(prop.value, scope), attr.line);
              } else this.expr(prop.value, scope);
            }
          } else {
            const v = this.expr(inner, scope);
            if (aname.type === "JSXIdentifier" && aname.name === "dangerouslySetInnerHTML") this.sink(XSS, v, attr.line);
          }
        }
        for (let k = n.children.length - 1; k >= 0; k--) stack.push(n.children[k]);
      } else if (t === "JSXFragment") {
        for (let k = n.children.length - 1; k >= 0; k--) stack.push(n.children[k]);
      } else if (t === "JSXExpressionContainer" || t === "JSXSpreadChild") {
        if (n.expression.type !== "JSXEmptyExpression") this.expr(n.expression, scope);
      }
    }
  }

  // ---- the summary ----
  /**
   * This reading into the function's summary and the shared bindings
   * (monotone). Returns the functions whose summaries changed, each with
   * what changed (Map fid -> [returned request data, parameter indices,
   * enclosing functions' parameter keys]), and the bindings whose value grew.
   */
  commit() {
    const p = this.p, f = this.fn;
    const changes = new Map();
    const change = (fid) => {
      let c = changes.get(fid);
      if (c === undefined) { c = [false, new Set(), new Set()]; changes.set(fid, c); }
      return c;
    };
    for (const [key, cat, entry] of this.reachAdds) {
      const owner = p.fns[Math.floor(key / PARAM_BASE)];
      const i = key % PARAM_BASE;
      if (!owner.reach.has(i)) owner.reach.set(i, new Map());
      const d = owner.reach.get(i);
      const old = d.get(cat);
      if (old === undefined || (old[3] && !entry[3])) {
        d.set(cat, entry);
        change(owner.fid)[1].add(i);
      }
    }
    const rv = this.retVal;
    if (rv !== null && !f.module && rv.tainted()) {
      if (rv.src) {
        const old = f.retSrc;
        if (old === null) {
          f.retSrc = new V(true, rv.origin, rv.fname, null, NO_PARAMS, rv.clean, rv.built);
          change(f.fid)[0] = true;
        } else {
          const clean = old.clean & rv.clean;
          const built = old.built || rv.built;
          if (clean !== old.clean || built !== old.built) {
            f.retSrc = new V(true, old.origin, old.fname, null, NO_PARAMS, clean, built);
            change(f.fid)[0] = true;
          }
        }
      }
      for (const key of rv.params) {
        const own = Math.floor(key / PARAM_BASE) === f.fid;
        const table = own ? f.retParams : f.retOuter;
        const k = own ? key % PARAM_BASE : key;
        const old = table.get(k);
        const nv = old === undefined ? [rv.clean, rv.built] : [old[0] & rv.clean, old[1] || rv.built];
        if (old === undefined || nv[0] !== old[0] || nv[1] !== old[1]) {
          table.set(k, nv);
          if (own) change(f.fid)[1].add(k);
          else change(f.fid)[2].add(k);
        }
      }
    }
    if (!this.emit) {
      for (const fid of [...this.uses.keys()].sort(numeric)) p.fns[fid].callers.set(f.fid, this.uses.get(fid));
    }
    const grown = [];
    for (const bid of [...this.sharedWrites.keys()].sort(numeric)) {
      const v = this.sharedWrites.get(bid);
      if (!v.tainted()) continue;
      const old = p.shared.get(bid);
      const nv = old === undefined ? v : old.union(v);
      if (old === undefined || !same(nv, old)) {
        p.shared.set(bid, nv);
        grown.push(bid);
      }
    }
    for (const bid of [...this.reads.keys()].sort(numeric)) {
      if (!p.readers.has(bid)) p.readers.set(bid, new Map());
      p.readers.get(bid).set(f.fid, true);
    }
    return [changes, grown];
  }
}

// ------------------------------------------------------------------ driver --
function skippedSize(path, n) {
  return {
    rule: "X-FLOW-SKIPPED", name: "JS flow analysis skipped (size)", type: "HOTSPOT", sev: "INFO",
    msg: `${path} is ${n} characters; interprocedural JS taint analysis is skipped above ${MAX_FILE} characters.`,
    why: "Reading a file this large (usually minified or machine-generated) would cost the " +
      "cross-file pass more time and memory than a scan should spend on one file.",
    fix: "Split or deminify the file, or exclude it from the scan explicitly if the code is generated.",
    ref: "Scalability", file: path, line: 1, snippet: [], snipStart: 1,
  };
}

/** A min-heap of [position, fid] pairs (positions are distinct). */
class Heap {
  constructor(items) { this.a = items; for (let i = (this.a.length >> 1) - 1; i >= 0; i--) this.down(i); }
  get size() { return this.a.length; }
  push(x) {
    const a = this.a;
    a.push(x);
    let i = a.length - 1;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (a[p][0] <= a[i][0]) break;
      [a[p], a[i]] = [a[i], a[p]];
      i = p;
    }
  }
  pop() {
    const a = this.a;
    const top = a[0];
    const last = a.pop();
    if (a.length) { a[0] = last; this.down(0); }
    return top;
  }
  down(i) {
    const a = this.a;
    for (;;) {
      const l = 2 * i + 1, r = l + 1;
      let m = i;
      if (l < a.length && a[l][0] < a[m][0]) m = l;
      if (r < a.length && a[r][0] < a[m][0]) m = r;
      if (m === i) return;
      [a[m], a[i]] = [a[i], a[m]];
      i = m;
    }
  }
}

/**
 * The cross-file JavaScript pass over files ({path, content}: the project's
 * own JavaScript and TypeScript, no dependencies); issue and note build
 * findings (flow.js's flowIssue / flowNote); cfg is config()'s. Findings are
 * appended to findings.
 */
export function analyze(files, findings, issue, note, cfg = config()) {
  const prog = new Program(cfg);
  prog.issue = issue;
  const skipped = new Map();
  const over = [];
  let total = 0;
  for (const f of files) {
    const path = f.path, content = f.content;
    const lp = lower(path);
    if (lp.endsWith(".d.ts") || lp.endsWith(".d.mts") || lp.endsWith(".d.cts")) continue;   // a declaration file: types, no code
    if (typeof content !== "string") { skipped.set(path, "its content is not text"); continue; }
    const n = cpLen(content);
    if (n > MAX_FILE) { findings.push(skippedSize(path, n)); continue; }
    if (total + n > MAX_TOTAL) { over.push(path); continue; }
    let tree;
    try {
      tree = parseFile(path, content);
    } catch (e) {
      if (!(e instanceof JsSyntaxError)) throw e;
      skipped.set(path, `it could not be read as ${dialect(path)[0] ? "TypeScript" : "JavaScript"} ` +
        `(line ${e.line}: ${e.reason})`);
      continue;
    }
    total += n;
    prog.addModule(path, content, tree);
  }
  const notes = [];
  if (over.length) {
    notes.push(note("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)", over[0], 1,
      `Cross-file taint analysis skipped ${over.length} JavaScript file(s) beyond its budget ` +
        `(${commas(MAX_TOTAL)} characters), starting with ${pyRepr(over[0])}.`,
      "Very large code bases are analyzed up to a fixed budget so a scan cannot run unbounded; flows " +
        "through the skipped files are not seen.",
      "Scan sub-trees separately, or exclude generated code."));
  }
  if (prog.mods.length) {
    for (const m of prog.mods) prog.resolveModule(m.idx);
    for (const b of prog.binds) {
      if (b.kind === "import") for (const t of prog.importTargets(b)) t.shared = true;
    }
    prog.markRoutes();
    notes.push(...fixpoint(prog, findings, note));
  }
  for (const path of [...skipped.keys()].sort(cmpCodePoints)) {
    notes.push(note("Q-FLOW-SKIPPED", "File skipped by flow analysis", path, 1,
      `Cross-file taint analysis skipped ${pyRepr(path)}: ${skipped.get(path)}.`,
      "Only files the JavaScript reader can parse take part in the interprocedural pass; flows into or " +
        "out of this file are not seen (the per-file rules still ran).",
      "Fix the syntax error, or exclude the file if it is not JavaScript (a template, for instance), then re-run."));
  }
  findings.push(...notes);
}

/**
 * Summaries to a fixpoint (callees first; a function is read again when a
 * summary or a shared value it used changed), then the reporting pass.
 */
function fixpoint(prog, findings, note) {
  const notes = [];
  const order = prog.order();
  const pos = new Array(prog.fns.length).fill(0);
  order.forEach((fid, k) => { pos[fid] = k; });
  const heap = new Heap(order.map((fid, k) => [k, fid]));
  const queued = new Array(prog.fns.length).fill(true);
  const cutoff = [];
  const cut = [];
  prog.budget = LIMITS.WORK_BASE + LIMITS.WORK_PER_NODE * prog.nodes;
  let stopped = null;
  const stoppedAt = [0, 0];          // the steps taken when the fixpoint / the reporting pass stopped
  while (heap.size) {
    const [, fid] = heap.pop();
    queued[fid] = false;
    const fn = prog.fns[fid];
    fn.runs++;
    const ev = new Eval(prog, fn, false, findings);
    try {
      ev.run();
    } catch (e) {
      if (e instanceof Cut) {
        if (!cut.includes(fid)) cut.push(fid);
      } else if (e instanceof Stop) {
        stopped = fn;
        stoppedAt[0] = prog.work;
        break;
      } else throw e;
    }
    const [changes, grown] = ev.commit();
    const deps = [];
    for (const owner of [...changes.keys()].sort(numeric)) {
      const [src, params, outer] = changes.get(owner);
      for (const [c, used] of prog.fns[owner].callers) {
        // a caller is read again when what it used changed: request data
        // returned, a parameter it passed a tainted value, a parameter of a
        // function around it returned
        let hit = src;
        if (!hit) for (const i of params) if (used.has(i)) { hit = true; break; }
        if (!hit) {
          const around = prog.scopeFns(c);
          for (const k of outer) if (around.has(Math.floor(k / PARAM_BASE))) { hit = true; break; }
        }
        if (hit) deps.push(c);
      }
    }
    for (const bid of grown) {
      const r = prog.readers.get(bid);
      if (r !== undefined) deps.push(...r.keys());
    }
    for (const d of deps) {
      if (queued[d]) continue;
      if (prog.fns[d].runs >= MAX_ITERS) {
        if (!cutoff.includes(d)) cutoff.push(d);
        continue;
      }
      queued[d] = true;
      heap.push([pos[d], d]);
    }
  }
  // the reporting pass: every function once, in order of definition
  prog.budget = prog.work + LIMITS.WORK_BASE + LIMITS.EMIT_PER_NODE * prog.nodes;
  let emitStopped = null;
  for (const fn of prog.fns) {
    const ev = new Eval(prog, fn, true, findings);
    try {
      ev.run();
    } catch (e) {
      if (e instanceof Cut) {
        if (!cut.includes(fn.fid)) cut.push(fn.fid);
      } else if (e instanceof Stop) {
        emitStopped = fn;
        stoppedAt[1] = prog.work;
        break;
      } else throw e;
    }
  }
  if (cutoff.length) {
    const first = prog.fns[Math.min(...cutoff)];
    const path = prog.mods[first.mod].path;
    notes.push(note("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (iteration cap)", path, first.line,
      `Interprocedural summaries for ${cutoff.length} JavaScript function(s) did not converge within ` +
        `${MAX_ITERS} re-analyses (first: ${first.display()} in ${pyRepr(path)}); flows through them may be missing.`,
      "Summaries are iterated to a fixpoint with a generous safety cap; hitting it means an unusually long " +
        "or cyclic chain of calls or shared variables.",
      "Report the pattern to the Lazaret maintainers; split the chain if possible."));
  }
  [stopped, emitStopped].forEach((fn, k) => {
    if (fn === null) return;
    const path = prog.mods[fn.mod].path;
    notes.push(note("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)", path, fn.line,
      `The JavaScript cross-file pass stopped ${k ? "reporting" : "following values"} ` +
        `at ${fn.display()} in ${pyRepr(path)} after ${commas(stoppedAt[k])} steps (its budget for ${commas(prog.nodes)} syntax ` +
        "tree nodes); flows through the rest of the code may be missing.",
      "Every file is read within a budget proportional to its size, so a scan cannot run unbounded.",
      "Split or deminify very large or deeply nested files, or exclude generated code from the scan."));
  });
  for (const fid of [...cut].sort(numeric)) {
    const fn = prog.fns[fid];
    const path = prog.mods[fn.mod].path;
    notes.push(note("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)", path, fn.line,
      `The JavaScript cross-file pass stopped reading ${fn.display()} in ${pyRepr(path)} at its limit of ` +
        `${commas(LIMITS.RUN_BASE)} + ${LIMITS.RUN_PER_NODE} steps per syntax tree node; flows through the rest of it may be ` +
        "missing.",
      "Deeply nested loops make one function's reading repeat; each reading has a limit so a scan cannot run unbounded.",
      "Split the function, or exclude generated code from the scan."));
  }
  return notes;
}
