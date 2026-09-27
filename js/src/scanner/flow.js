// Cross-function and cross-file taint flows in JavaScript: the twin of the
// JavaScript half of lazaret/scanner/flow.py (_js_mask, _js_functions,
// _js_sink_args, _js_neutralize, _js_param_dangerous, _analyze_js,
// analyze). The two must report the same X-* findings — rule, file, line,
// severity, message, snippet — for the same JavaScript files; the parity
// tests hold them to it. The Python engine's other half (Python files,
// AST-based) has no port: the npm engine's gate says so.
//
// A bounded heuristic, not a parser (no JS parser is available without
// dependencies): a small linear lexer blanks the content of strings,
// comments, regex literals and template text, function headers are found
// with regexes and their bodies by brace matching, and each function gets a
// summary of the parameters that reach a sink (directly or through the locals
// that hold them) and of what it returns. A call
// site passing a request-derived value into such a parameter, or a sink fed a
// value another function read from the request and returned, is a finding.
// Patterns are the Python engine's source text, compiled with Python
// semantics (pyRe).
import { cmpCodePoints, cpLen, isPySpace, pyRe, pyStrip } from "../lib/pycompat.js";
import { REDACT, contextRedacted, contextSecrets, redactText, registerScanContext, SECRET_SKIP_RE }
  from "../lib/redact.js";
import { splitLines } from "./lines.js";

// category -> [severity, cwe, fix]; twin of flow.SINK_META
const SINK_META = {
  "SQL injection": ["BLOCKER", "CWE-89", "Use parameterized queries with placeholders."],
  "command injection": ["CRITICAL", "CWE-78", "Pass args as a list with shell=False / use execFile."],
  "code injection": ["CRITICAL", "CWE-95", "Never execute untrusted strings; use safe parsing."],
  "template injection": ["CRITICAL", "CWE-1336", "Pass data as template parameters, not template source."],
  "path traversal": ["MAJOR", "CWE-22", "Resolve and confine the path to an allowed base directory."],
  "server-side request forgery": ["MAJOR", "CWE-918", "Allowlist hosts/schemes; block internal addresses."],
  "open redirect": ["MAJOR", "CWE-601", "Allowlist redirect targets or use relative paths."],
  "cross-site scripting": ["MAJOR", "CWE-79", "Escape/sanitize before rendering; prefer textContent."],
};
const CAT_SUFFIX = {
  "SQL injection": "SQL", "command injection": "CMD", "code injection": "CODE",
  "template injection": "SSTI", "path traversal": "PATH",
  "server-side request forgery": "SSRF", "open redirect": "REDIR",
  "cross-site scripting": "XSS",
};

const capitalize = (s) => s.slice(0, 1).toUpperCase() + s.slice(1).toLowerCase();   // str.capitalize

/** An X-* finding (twin of flow._issue). */
function flowIssue(cat, callerFile, line, lines, sourceLoc, sinkLoc, chain) {
  const [sev, cwe, fix] = SINK_META[cat];
  const start = Math.max(0, line - 3);
  const cross = sourceLoc.split(":")[0] !== sinkLoc.split(":")[0];
  const scope = cross ? "cross-file" : "interprocedural";
  return {
    rule: `X-${CAT_SUFFIX[cat]}`, name: `${capitalize(scope)} tainted flow → ${cat}`,
    type: "VULN", sev,
    msg: `Possible ${cat}: untrusted data from ${sourceLoc} reaches a sink at ${sinkLoc} (${scope}).`,
    why: "Whole-program taint tracking followed user-controlled input from its " +
      "source through " + (chain || "a function call") + " into a dangerous " +
      "operation, without visible sanitization along the way.",
    fix, ref: `${cwe} · Interprocedural taint`,
    file: callerFile, line,
    snippet: lines.slice(start, Math.min(lines.length, line + 2)), snipStart: start + 1,
  };
}

/** An INFO coverage note (twin of flow._flow_note). */
function flowNote(rule, name, fname, line, msg, why, fix) {
  return { rule, name, type: "SMELL", sev: "INFO", msg, why, fix,
    ref: rule === "Q-FLOW-RECURSION" ? "CWE-400 (uncontrolled resource consumption)" : "Analysis coverage",
    file: fname, line, snippet: [], snipStart: 1 };
}

// ---- patterns (the Python engine's source text) --------------------------
// Python's named groups (?P<n>…) are written (?<n>…); its re.S dots, (?:.|\n).
const JS_FUNC_RE = pyRe(String.raw`(?:function\s+(?<n1>\w+)\s*\((?<p1>[^)]*)\)` +
  String.raw`|(?:const|let|var)\s+(?<n2>\w+)\s*=\s*(?:async\s*)?\((?<p2>[^)]*)\)\s*=>` +
  String.raw`|(?:const|let|var)\s+(?<n3>\w+)\s*=\s*(?:async\s*)?function\s*\((?<p3>[^)]*)\))`, "g");
const JS_SOURCE_RE = pyRe(String.raw`req\.(query|body|params|headers|cookies)|process\.argv|location\.(search|hash|href)`);
const JS_SINKS = [
  [pyRe(String.raw`\.(query|execute)\s*\(`, "g"), "SQL injection"],
  [pyRe(String.raw`\b(exec|execSync|spawn|spawnSync)\s*\(`, "g"), "command injection"],
  [pyRe(String.raw`(?<![\w.])eval\s*\(|new\s+Function\s*\(`, "g"), "code injection"],
  [pyRe(String.raw`\.innerHTML\s*=|document\.write\s*\(`, "g"), "cross-site scripting"],
  [pyRe(String.raw`\bfetch\s*\(|axios(\.\w+)?\s*\(`, "g"), "server-side request forgery"],
  [pyRe(String.raw`\.redirect\s*\(`, "g"), "open redirect"],
];

// ---- a small linear lexer (twin of flow._js_mask) -------------------------
const TOKEN_RE = pyRe(String.raw`(?<ws>\s+)` +
  String.raw`|(?<lc>//[^\n\u2028\u2029]*)` +
  String.raw`|(?<bc>/\*(?:.|\n)*?(?:\*/|\Z))` +
  String.raw`|(?<sq>'(?:[^'\\\n]|\\(?:.|\n))*'?)` +
  String.raw`|(?<dq>"(?:[^"\\\n]|\\(?:.|\n))*"?)` +
  String.raw`|(?<bt>` + "`)" +
  String.raw`|(?<id>[A-Za-z_$\u0080-\uffff][\w$\u0080-\uffff]*)` +
  String.raw`|(?<num>\d[\w.]*)` +
  String.raw`|(?<p>(?:.|\n))`, "y");
const TPL_TEXT_RE = pyRe(String.raw`(?:[^` + "`" + String.raw`\\$]|\\(?:.|\n)|\$(?!\{))*`, "y");
const REGEX_LIT_RE = pyRe(String.raw`/(?:[^/\\\[\n]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[A-Za-z]*`, "y");
const NOT_NL_RE = pyRe(String.raw`[^\n\u2028\u2029]`, "g");
const REGEX_AFTER = new Set("(,=:[!&|?{};+-*%<>~^");
const REGEX_KEYWORDS = new Set(["return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
  "void", "throw", "instanceof", "yield", "await"]);
const TOKEN_KINDS = ["ws", "lc", "bc", "sq", "dq", "bt", "id", "num", "p"];
const kindOf = (m) => TOKEN_KINDS.find((k) => m.groups[k] !== undefined);

/**
 * src with the CONTENT of '…', "…", `…` template text, comments and regex
 * literals replaced by spaces (one per code point, as Python counts them;
 * newlines and ${…} code kept), so every later pass only sees code. Linear.
 * literals (a Map), when given, receives the text of every closed '…' /
 * "…" literal by the offset of its opening quote in the result.
 */
export function jsMask(src, literals = null) {
  const out = [];
  let lastCopy = 0, outLen = 0;
  const n = src.length;
  const push = (t) => { out.push(t); outLen += t.length; };
  const blank = (a, b) => {
    if (b > a) {
      push(src.slice(lastCopy, a));
      push(src.slice(a, b).replace(NOT_NL_RE, " "));
      lastCopy = b;
    }
  };
  const templateText = (i) => {          // -> [next index, opened ${]
    TPL_TEXT_RE.lastIndex = i;
    const m = TPL_TEXT_RE.exec(src);
    const j = i + m[0].length;
    blank(i, j);
    if (j >= n) return [n, false];
    if (src[j] === "`") return [j + 1, false];
    return [j + 2, true];                // at "${"
  };
  const stack = [];                      // brace depth inside each open ${ … }
  let lastSig = "", lastWord = "";
  let i = 0;
  while (i < n) {
    TOKEN_RE.lastIndex = i;
    const m = TOKEN_RE.exec(src);
    const kind = kindOf(m);
    const j = i + m[0].length;
    if (kind === "ws") { i = j; continue; }
    if (kind === "lc" || kind === "bc") { blank(i, j); i = j; continue; }
    if (kind === "sq" || kind === "dq") {
      const closed = cpLen(m[0]) >= 2 && src[j - 1] === src[i];
      if (literals !== null && closed) literals.set(outLen + (i - lastCopy), src.slice(i + 1, j - 1));
      blank(i + 1, closed ? j - 1 : j);
      lastSig = '"'; lastWord = "";
      i = j;
      continue;
    }
    if (kind === "bt") {
      const [k, opened] = templateText(i + 1);
      if (opened) stack.push(0);
      lastSig = opened ? "{" : "`"; lastWord = "";
      i = k;
      continue;
    }
    if (kind === "id") { lastSig = "a"; lastWord = m[0]; i = j; continue; }
    if (kind === "num") { lastSig = "0"; lastWord = ""; i = j; continue; }
    const ch = m[0];
    if (ch === "/" && (lastSig === "" || (REGEX_AFTER.has(lastSig) && lastSig !== "}")
        || (lastSig === "a" && REGEX_KEYWORDS.has(lastWord)))) {
      REGEX_LIT_RE.lastIndex = i;
      const rm = REGEX_LIT_RE.exec(src);
      if (rm !== null) {
        const end = i + rm[0].length;
        const close = src.lastIndexOf("/", end - 1);
        blank(i + 1, close);
        lastSig = ")"; lastWord = "";     // a value: '/' after it divides
        i = end;
        continue;
      }
    }
    if (ch === "{" && stack.length) stack[stack.length - 1] += 1;
    else if (ch === "}" && stack.length) {
      if (stack[stack.length - 1] === 0) {
        stack.pop();
        const [k, opened] = templateText(i + 1);
        if (opened) stack.push(0);
        lastSig = opened ? "{" : "`"; lastWord = "";
        i = k;
        continue;
      }
      stack[stack.length - 1] -= 1;
    }
    lastSig = ch; lastWord = "";
    i = j;
  }
  out.push(src.slice(lastCopy));
  return out.join("");
}

/** Index of the first element of the sorted array a that is >= x (bisect_left). */
function bisectLeft(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (a[mid] < x) lo = mid + 1; else hi = mid;
  }
  return lo;
}

function newlineOffsets(code) {
  const nl = [];
  for (let k = code.indexOf("\n"); k !== -1; k = code.indexOf("\n", k + 1)) nl.push(k);
  return nl;
}

/** [offsets of every '{', Map offset of a '{' -> offset of its '}'] (twin of flow._js_braces). */
export function jsBraces(code) {
  const opens = [], matchClose = new Map(), stack = [];
  for (let k = 0; k < code.length; k++) {
    const c = code[k];
    if (c === "{") { opens.push(k); stack.push(k); }
    else if (c === "}" && stack.length) matchClose.set(stack.pop(), k);
  }
  return [opens, matchClose];
}

/**
 * A parameter as its uses spell it: without a default (`a = 1`), a
 * TypeScript annotation (`a: string`, `a?: T`) or a rest marker (`...a`).
 */
export function jsParamName(p) {
  let name = pyStrip(pyStrip(pyStrip(p).split("=")[0]).split(":")[0]);
  if (name.endsWith("?")) name = pyStrip(name.slice(0, -1));
  if (name.startsWith("...")) name = pyStrip(name.slice(3));
  return name;
}

/**
 * [name, params, [body start, body end], start line] for every function
 * header (twin of flow._js_functions): headers and braces are read from the
 * masked code; one brace pass computes every body span. An arrow function
 * whose body is an expression spans that expression, to the end of its
 * statement. heads (an array), when given, receives [start, stop] of each
 * function's header.
 */
export function jsFunctions(content, code = null, braces = null, table = null, heads = null) {
  code ??= jsMask(content);
  const matches = [...code.matchAll(JS_FUNC_RE)];
  if (!matches.length) return [];
  const [opens, matchClose] = braces ?? jsBraces(code);
  const nl = newlineOffsets(code);
  const out = [];
  for (const m of matches) {
    const g = m.groups;
    const name = g.n1 || g.n2 || g.n3;
    const paramsS = g.p1 || g.p2 || g.p3 || "";
    const params = paramsS.split(",").filter((p) => pyStrip(p)).map(jsParamName);
    const end = m.index + m[0].length;
    if (g.n2 !== undefined) {
      let b = end;
      while (b < code.length && BLANK.has(code[b])) b++;
      if (b >= code.length || code[b] !== "{") {        // an expression body
        out.push([name, params, [b, table === null ? argEnd(code, b, true) : argEndAt(code, b, true, table)], bisectLeft(nl, m.index) + 1]);
        if (heads !== null) heads.push([m.index, end]);
        continue;
      }
    }
    const k = bisectLeft(opens, end - 1);
    if (k === opens.length) continue;
    const brace = opens[k];
    const close = matchClose.has(brace) ? matchClose.get(brace) : code.length;   // EOF if never closed
    const startLine = bisectLeft(nl, m.index) + 1;
    out.push([name, params, [brace, close + 1], startLine]);
    if (heads !== null) heads.push([m.index, end]);
  }
  return out;
}

const JS_ARG_SCAN = 4000;   // max characters (code points, as Python counts) scanned for a sink's arguments

/**
 * Where a sink's argument text ends, scanning from k: the first unbalanced
 * closing bracket (or, for a statement sink, a ';' or newline outside
 * brackets), else JS_ARG_SCAN code points on. Counted in code points so an
 * astral character is one step, as in flow.py.
 */
function argEnd(code, k, statement) {
  let depth = 0, idx = k;
  for (let n = 0; idx < code.length && n < JS_ARG_SCAN; n++) {
    const ch = code[idx];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return idx;
      depth--;
    } else if (statement && (ch === ";" || ch === "\n") && depth === 0) return idx;
    const u = code.charCodeAt(idx);
    idx += u >= 0xd800 && u <= 0xdbff && (code.charCodeAt(idx + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
  }
  return idx;
}

/**
 * The text a sink match can consume (twin of flow._js_sink_args): the
 * balanced argument list of a call sink (`exec(` … `)`), else the rest of the
 * statement (`x.innerHTML = …;`). Computed on masked code.
 */
export function jsSinkArgs(code, start, end) {
  let k = end;
  if (!(end > start && code[end - 1] === "(")) {
    let k2 = end;
    while (k2 < code.length && (code[k2] === " " || code[k2] === "\t")) k2++;
    if (k2 < code.length && code[k2] === "(") k = k2 + 1;
    else return code.slice(end, argEnd(code, end, true));
  }
  return code.slice(k, argEnd(code, k, false));
}

// ---- sanitizers (twin of flow._JS_FULL_SAN_RE / _JS_PARTIAL_SAN) ----------
const FULL_SAN_SRC = String.raw`(?:parseInt|parseFloat|Number)\s*\([^()]*\)`;
const PARTIAL_SAN_SRC = {
  "cross-site scripting": String.raw`(?:DOMPurify\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml)\s*\([^()]*\)`,
  "SQL injection": String.raw`(?:mysql2?|pool|connection|conn|db)\.escape\s*\([^()]*\)`,
  "path traversal": String.raw`path\.basename\s*\([^()]*\)`,
  "command injection": String.raw`(?:shellQuote|shell_quote|quote)\s*\([^()]*\)`,
};
const FULL_SAN_RE = pyRe(FULL_SAN_SRC, "g");
const PARTIAL_SAN = Object.fromEntries(Object.entries(PARTIAL_SAN_SRC).map(([c, src]) => [c, pyRe(src, "g")]));

/** Strip sanitizer calls so their content stops counting as tainted. */
export function jsNeutralize(text, cats) {
  text = text.replace(FULL_SAN_RE, " ");
  for (const c of cats) if (PARTIAL_SAN[c]) text = text.replace(PARTIAL_SAN[c], " ");
  return text;
}

// re.escape for u-mode: only syntax characters may be escaped there
const escapeRe = (s) => s.replace(/[\\^$.*+?()[\]{}|/]/g, "\\$&");
const paramReCache = new Map();
function paramRe(p, sql) {
  const key = (sql ? "s:" : "o:") + p;
  let re = paramReCache.get(key);
  if (re === undefined) {
    const pe = escapeRe(p);
    re = pyRe(sql ? String.raw`\+\s*${pe}\b|\b${pe}\s*\+|` + "`[^`]*" + String.raw`\$\{[^}]*\b${pe}\b`
      : String.raw`\b${pe}\b`);
    if (paramReCache.size > 4096) paramReCache.clear();
    paramReCache.set(key, re);
  }
  return re;
}

/** Does parameter p reach the sink in a dangerous way within seg? */
export function jsParamDangerous(seg, p, cat) {
  // SQL: safe when p only appears in a placeholder array (query(sql, [p]))
  return paramRe(p, cat === "SQL injection").test(seg);
}

/** JS source as the pattern engine numbers its lines: U+2028/U+2029 end a line. */
export function jsText(content) {
  return content.includes("\u2028") || content.includes("\u2029")
    ? content.replace(/[\u2028\u2029]/g, "\n") : content;
}

const JS_MAX_FILE = 2_000_000;   // skip interprocedural JS flow above 2 MB (code points)

// ---- modules, calls and returned values (twin of flow.py's section) ------
// Binding: a call binds to the function its file names — a definition
// visible from the call, else what a relative require() / import brings in
// (named, default and namespace imports, `require('./x').f()`, a module or
// export copied to another const, re-exports): a definite binding. Anything
// the pass cannot resolve — a package, a path alias, a workspace package,
// `this.f()`, `obj.f()`, a name the file neither defines nor imports, a
// reassigned binding — is open: the call may reach any project function of
// that name. Positive evidence binds nothing: a Node built-in module, a
// member of a JavaScript global object, a built-in method name on a receiver
// the pass cannot identify, a parameter or variable a scope around the call
// binds (what it is assigned from is followed). A call's value: a definite
// call reads as what its function returns — the request data it returns,
// and its arguments unless no return can hold them (or every return is
// sanitized for a category); a constructor keeps its arguments; an open call
// keeps its arguments and receiver and adds what any function it may reach
// returns. A project function shadows a sanitizer of the same name. Returned
// values, their sinks and calls with nested calls in their arguments are read
// within a per-file budget; every other call is always checked.
const BLANK = new Set([" ", "\t", "\n", "\r"]);
const EXTS = [".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"];
const TS_SOURCES = new Map([[".js", [".ts", ".tsx"]], [".jsx", [".tsx"]], [".mjs", [".mts"]], [".cjs", [".cts"]]]);
const EXPORT_HOPS = 8;          // modules followed through re-exports
const EVAL_DEPTH = 4;           // calls nested in arguments read as their return values
const RET_ROUNDS = 16;          // rounds of the returned-value fixpoint (a note if they don't settle)
const READ_BUDGET = 4;          // nested expression text read per file, in multiples of its size (+64 KiB)
const MAX_OPEN = 4;             // an open call's functions checked at a call site (more: the last one defined)
const MAX_OPEN_EDGES = 8;       // an open call orders the fixpoint after its functions when there are this few
const SCOPE_WALK = 64;          // enclosing scopes searched for a name's binding
const MAX_ALIAS = 16;           // names assigned to one name that a call through it follows
const MAX_CARRY = 64;           // parameters one value is followed for (the first ones found)
const ALL = "*";                // in a set of clean categories: no argument reaches the value at all
const UNIVERSE = new Set([...Object.keys(SINK_META), ALL]);
const EMPTY = new Set();
const EMPTY_NODE = [[], false, [], false];
const EMPTY_MAP = new Map();
const NO_PARAMS = [EMPTY_MAP, EMPTY_MAP];      // paramMap() of the module: no parameters (never written)
const OPAQUE_NODE = [[], false, [], true];   // an expression not read: never free of data
const LITERAL_WORDS = new Set(["true", "false", "null", "undefined", "NaN", "Infinity", "void"]);
const NOT_ALIAS = new Set([...LITERAL_WORDS, "this", "super", "arguments"]);
const GLOBAL_OBJECTS = new Set(["JSON", "Math", "Object", "Array", "Number", "String", "Boolean", "Symbol",
  "BigInt", "Date", "RegExp", "Error", "Promise", "Reflect", "Proxy", "Intl", "Atomics", "WebAssembly",
  "console", "Buffer", "process"]);
const NODE_BUILTINS = new Set(["assert", "async_hooks", "buffer", "child_process", "cluster", "console",
  "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2",
  "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode", "querystring",
  "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util",
  "v8", "vm", "wasi", "worker_threads", "zlib"]);
// methods of JavaScript's built-in and everyday runtime objects (twin of flow._JS_COMMON_METHODS)
const COMMON_METHODS = new Set(`
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
`.split(/\s+/).filter(Boolean));
const CONTROL_WORDS = new Set(["if", "for", "while", "switch", "catch", "with", "await"]);
const SEP = String.fromCharCode(0);
const IDCHAR_RE = pyRe(String.raw`[\w$]`);
const CALL_RE = pyRe(String.raw`(?<![\w$])(\w[\w$]*)\s*\(`, "g");
const CALL_SCAN_RE = pyRe(String.raw`(?<![\w$])(\w[\w$]*)\s*\(`, "g");   // compile()'s own copy: it recurses
const RETURN_RE = pyRe(String.raw`return(?<![\w$.]return)(?![\w$])`, "g");
const RETURN_SCAN_RE = pyRe(String.raw`return(?<![\w$.]return)(?![\w$])`, "g");
// the head of a function value: `function name` before its '(' ([1] unset), or `(a, b) =>` / `a =>`
const FUNCTION_HEAD_RE = pyRe(String.raw`(?:async\s*)?(?:function(?![\w$])\s*\*?\s*(?:[A-Za-z_$][\w$]*\s*)?(?=\()` +
  String.raw`|(\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>)`, "y");
const ASSIGN_OP = String.raw`(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=`;
const ASSIGN_RE = pyRe(String.raw`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)` +
  String.raw`|(?:^|[;{\n]\s*|\)[ \t]*|=>[ \t]*|(?<![\w$.])else\s+)([A-Za-z_$][\w$]*)\s*` + ASSIGN_OP +
  String.raw`(?![=>])\s*([^;\n]+)`, "dg");
const WRITE_RE = pyRe(String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)\s*` + ASSIGN_OP + String.raw`(?![=>])`, "dg");
const WORD_RE = pyRe(String.raw`[A-Za-z_$][\w$]*`, "g");
// The patterns start with their keyword and check what precedes it after
// it: the same matches, but the engine can skip ahead to the keyword.
const NOT_AFTER = String.raw`(?<![\w$.]const)(?<![\w$.]let)(?<![\w$.]var)`;
const DECL_RE = pyRe(String.raw`(?:const|let|var)` + NOT_AFTER + String.raw`(?![\w$])`, "g");
const REQUIRE_BIND_RE = pyRe(String.raw`(?:const|let|var|import)` + NOT_AFTER + String.raw`(?<![\w$.]import)` +
  String.raw`\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*(['"]) *\2\s*\)` +
  String.raw`(?:\s*\.\s*([A-Za-z_$][\w$]*))?[ \t]*(?![^;,}\n])`, "dg");
const REQUIRE_DESTRUCTURE_RE = pyRe(String.raw`(?:const|let|var)` + NOT_AFTER + String.raw`\s*\{([^{}]*)\}\s*=\s*require\s*\(\s*(['"]) *\2\s*\)[ \t]*(?![^;,}\n])`, "dg");
const INLINE_REQUIRE_RE = pyRe(String.raw`require(?<![\w$.]require)\s*\(\s*(['"]) *\1\s*\)`, "dg");
const ALIAS_RE = pyRe(String.raw`\A([A-Za-z_$][\w$]*)(?:\s*\.\s*([A-Za-z_$][\w$]*))?\Z`);
const DESTRUCTURE_RE = pyRe(String.raw`(?:const|let|var)` + NOT_AFTER + String.raw`\s*\{([^{}]*)\}\s*=\s*([A-Za-z_$][\w$]*)[ \t]*(?![^;,}\n])`, "g");
const IMPORT_RE = pyRe(String.raw`import(?<![\w$.]import)(?![\w$])\s*(?:([A-Za-z_$][\w$]*)\s*,?\s*)?` +
  String.raw`(?:\{([^{}]*)\}|\*\s*as\s+([A-Za-z_$][\w$]*))?\s*from\s*(['"]) *\4`, "dg");
const EXPORT_LIST_RE = pyRe(String.raw`export(?<![\w$.]export)(?![\w$])\s*\{([^{}]*)\}(?:\s*from\s*(['"]) *\2)?`, "dg");
const EXPORT_STAR_RE = pyRe(String.raw`export(?<![\w$.]export)(?![\w$])\s*\*\s*from\s*(['"]) *\1`, "dg");
const EXPORT_DEFAULT_RE = pyRe(String.raw`export(?<![\w$.]export)\s+default\s+(?:async\s+)?(?:function(?![\w$])\s*\*?\s*)?([A-Za-z_$][\w$]*)`, "g");
const MODULE_EXPORTS_RE = pyRe(String.raw`module(?<![\w$.]module)\s*\.\s*exports\s*=(?!=)\s*(?:` +
  String.raw`require\s*\(\s*(['"]) *\1\s*\)[ \t]*(?![^;,}\n])` +
  String.raw`|(?:async\s+)?function(?![\w$])\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(` +
  String.raw`|\{([^{}]*)\}` +
  String.raw`|([A-Za-z_$][\w$]*)[ \t]*(?![^;,}\n]))`, "dg");
const EXPORTS_PROP_RE = pyRe(String.raw`(?:module(?<![\w$.]module)\s*\.\s*exports|exports(?<![\w$.]exports))` +
  String.raw`\s*\.\s*([A-Za-z_$][\w$]*)\s*=(?!=)\s*(?:` +
  String.raw`(?:async\s+)?function(?![\w$])\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(` +
  String.raw`|([A-Za-z_$][\w$]*)[ \t]*(?![^;,}\n]))`, "g");
// names bound other than by `name = …` (twin of flow._JS_PATTERN_DECL_RE …)
const PATTERN_DECL_RE = pyRe(String.raw`(?:const|let|var)` + NOT_AFTER + String.raw`(?![\w$])\s*([\[{])`, "dg");
const PATTERN_VALUE_RE = pyRe(String.raw`\s*=(?![=>])\s*([^;\n]+)`, "dy");
const FOR_HEAD_RE = pyRe(String.raw`for(?<![\w$.]for)\s*(\()\s*(?:const|let|var)(?![\w$])\s*(?:([A-Za-z_$][\w$]*)(?![\w$])|([\[{]))`, "dg");
const OF_RE = pyRe(String.raw`\s*(?:of|in)(?![\w$])\s*`, "y");
const PUSH_RE = pyRe(String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:push|unshift)\s*\(`, "dg");
const JOIN_RE = pyRe(String.raw`\+(?![+=])|\$\{|\.\s*(?:join|concat)\s*\(`, "g");
const BIND_ITEM_RE = pyRe(String.raw`\A([A-Za-z_$][\w$]*)(?:\s*:\s*([A-Za-z_$][\w$]*))?(?:\s*=[^,]*)?\Z`);
const AS_ITEM_RE = pyRe(String.raw`\A(type\s+)?([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\Z`);
const PARAM_RE = pyRe(String.raw`\A[A-Za-z_$][\w$]*\Z`);
const BINDING_RE = pyRe(String.raw`(?:\s|\.\.\.)*(?:([A-Za-z_$][\w$]*)|([\[{]))`, "y");
const BINDING_END = new Set(["(", ")", "[", "]", "{", "}", ";", "\n", ","]);
// the sanitizer patterns, matched against a whole call written `name()`
const FULL_SAN_CALL_RE = pyRe(String.raw`\A(?:` + FULL_SAN_SRC + String.raw`)\Z`);
const PARTIAL_SAN_CALL = Object.entries(PARTIAL_SAN_SRC).map(([c, src]) => [c, pyRe(String.raw`\A(?:` + src + String.raw`)\Z`)]);

const union = (a, b) => { if (!b.size) return a; if (!a.size) return b; const u = new Set(a); for (const x of b) u.add(x); return u; };
const intersects = (a, b) => { for (const x of a) if (b.has(x)) return true; return false; };
const intersection = (a, b) => { const out = new Set(); for (const x of a) if (b.has(x)) out.add(x); return out; };
const subset = (a, b) => { for (const x of a) if (!b.has(x)) return false; return true; };
const sameSet = (a, b) => a.size === b.size && subset(a, b);
const normPath = (p) => p.replaceAll("\\", "/");

/** Index of the first element of the sorted array a that is > x (bisect_right). */
function bisectRight(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (x < a[mid]) hi = mid; else lo = mid + 1;
  }
  return lo;
}

/** Offset of the last non-blank character before i, or floor - 1 (twin of flow._js_back). */
function jsBack(code, i, floor = 0) {
  i -= 1;
  while (i >= floor && BLANK.has(code[i])) i--;
  return i;
}

/** [start, word] of the identifier characters ending at offset i, one code point at a time. */
function wordBefore(code, i, floor = 0) {
  let j = i;
  while (j >= floor) {
    let k = j;
    const u = code.charCodeAt(j);
    if (u >= 0xdc00 && u <= 0xdfff && j - 1 >= floor) {
      const h = code.charCodeAt(j - 1);
      if (h >= 0xd800 && h <= 0xdbff) k = j - 1;
    }
    if (!IDCHAR_RE.test(code.slice(k, j + 1))) break;
    j = k - 1;
  }
  return [j + 1, code.slice(j + 1, i + 1)];
}

/** Map offset of an opening bracket -> offset of the closer that ends it (twin of flow._js_bracket_pairs). */
export function jsBracketPairs(code) {
  const pairs = new Map(), stack = [];
  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    if (ch === "(" || ch === "[" || ch === "{") stack.push(i);
    else if ((ch === ")" || ch === "]" || ch === "}") && stack.length) pairs.set(stack.pop(), i);
  }
  return pairs;
}

/**
 * code's brackets for jsClose: the pairs, and (when code holds a surrogate)
 * the count of code points before each offset, so the 4,000-code-point window
 * Python counts is found without scanning. A pair adds its code point at its
 * second unit, so the window's end is never inside one.
 */
function jsBrackets(code) {
  let prefix = null;
  if (/[\ud800-\udfff]/.test(code)) {
    prefix = new Int32Array(code.length + 1);
    let n = 0;
    for (let i = 0; i < code.length; i++) {
      const u = code.charCodeAt(i);
      if (u >= 0xd800 && u <= 0xdbff && i + 1 < code.length && (code.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
        prefix[i + 1] = n;
        i++;
      }
      prefix[i + 1] = ++n;
    }
  }
  return { pairs: jsBracketPairs(code), prefix };
}

/** Code points in code[a, b), from the bracket table's prefix counts. */
function cpSpanOf(code, a, b, table) {
  return table.prefix === null ? b - a : table.prefix[b] - table.prefix[a];
}

/** Where the JS_ARG_SCAN-code-point window from k ends. */
function windowStop(code, k, table) {
  const prefix = table.prefix;
  if (prefix === null) return Math.min(code.length, k + JS_ARG_SCAN);
  const target = prefix[k] + JS_ARG_SCAN;
  if (prefix[code.length] < target) return code.length;
  let lo = k, hi = code.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (prefix[mid] < target) lo = mid + 1; else hi = mid;
  }
  return lo;
}

/** argEnd(code, paren + 1, false), read from the bracket table (twin of flow._js_close). */
function jsClose(code, paren, table) {
  const k = paren + 1;
  const c = table.pairs.get(paren);
  if (c !== undefined && (table.prefix === null ? c - k : table.prefix[c] - table.prefix[k]) < JS_ARG_SCAN) return c;
  return windowStop(code, k, table);
}

/** argEnd(code, k, statement), jumping over bracket groups (twin of flow._js_arg_end_at). */
function argEndAt(code, k, statement, table) {
  const stop = windowStop(code, k, table);
  const pairs = table.pairs;
  let i = k;
  while (i < stop) {
    const ch = code[i];
    if (ch === "(" || ch === "[" || ch === "{") {
      const c = pairs.get(i);
      if (c === undefined || c >= stop) return stop;
      i = c + 1;
      continue;
    }
    if (ch === ")" || ch === "]" || ch === "}") return i;
    if (statement && (ch === ";" || ch === "\n")) return i;
    i++;
  }
  return stop;
}

/** [start, stop] of jsSinkArgs(code, start, end) in code (twin of flow._js_sink_span). */
function jsSinkSpan(code, start, end, table) {
  let k = end;
  if (!(end > start && code[end - 1] === "(")) {
    let k2 = end;
    while (k2 < code.length && (code[k2] === " " || code[k2] === "\t")) k2++;
    if (k2 < code.length && code[k2] === "(") k = k2 + 1;
    else return [end, argEndAt(code, end, true, table)];
  }
  return [k, argEndAt(code, k, false, table)];
}

const NONBLANK_RE = pyRe(String.raw`\S`, "g");

/** [a, b] without the blanks str.strip() takes off either end (twin of flow._js_trim). */
function jsTrim(code, a, b) {
  while (a < b && isPySpace(code[a])) a++;
  while (b > a && isPySpace(code[b - 1])) b--;
  return [a, b];
}

/** [start, stop] of each top-level comma-separated argument in code[k, stop), trimmed (twin of flow._js_split_spans). */
function jsSplitSpans(code, k, stop, pairs) {
  NONBLANK_RE.lastIndex = k;
  const nb = NONBLANK_RE.exec(code);
  if (nb === null || nb.index >= stop) return [];
  const out = [];
  let last = k, i = k;
  while (i < stop) {
    const ch = code[i];
    if (ch === ",") { out.push(jsTrim(code, last, i)); last = i + 1; i++; continue; }
    if (ch === "(" || ch === "[" || ch === "{") {
      const c = pairs.get(i);
      if (c === undefined || c >= stop) break;
      i = c + 1;
      continue;
    }
    i++;
  }
  out.push(jsTrim(code, last, stop));
  return out;
}

/**
 * [name, receiver, start, paren, close] of the call whose name starts at
 * start and whose '(' is at paren, or null (twin of flow._js_call_at): a
 * function header, a method definition and an unterminated call are not
 * calls. receiver: null for a plain call, the name before the dot for
 * `m.f(…)` / `m?.f(…)`, "" for any other.
 */
function jsCallAt(code, name, start, paren, table, floor = 0) {
  const close = jsClose(code, paren, table);
  if (close >= code.length || code[close] !== ")") return null;
  let after = close + 1;
  while (after < code.length && BLANK.has(code[after])) after++;
  if (after < code.length && code[after] === "{") return null;
  let b = jsBack(code, start, floor);
  if (b >= floor && code[b] === ".") {
    let d = b - 1;
    if (d >= floor && code[d] === "?") d--;
    d = jsBack(code, d + 1, floor);
    const [ws, word] = wordBefore(code, d, floor);
    if (!word) return [name, "", b, paren, close];
    const pb = jsBack(code, ws, floor);
    if (pb >= floor && code[pb] === ".") return [name, "", ws, paren, close];
    return [name, word, ws, paren, close];
  }
  if (b >= floor) {
    if (code[b] === "*") b = jsBack(code, b, floor);
    if (b >= floor && wordBefore(code, b, floor)[1] === "function") return null;
  }
  return [name, null, start, paren, close];
}

/** Is the call that starts at start a constructor call (twin of flow._js_after_new)? */
function jsAfterNew(code, start, floor) {
  const b = jsBack(code, start, floor);
  return b >= floor && wordBefore(code, b, floor)[1] === "new";
}

/** The matches of itemRe on the comma-separated items of text. */
function jsItems(text, itemRe) {
  const out = [];
  for (const piece of text.split(",")) {
    const m = itemRe.exec(pyStrip(piece));
    if (m) out.push(m);
  }
  return out;
}

/** Is spec a Node built-in module (twin of flow._js_builtin)? */
function isBuiltin(spec) {
  return spec.startsWith("node:") || NODE_BUILTINS.has(spec.split("/")[0]);
}

/** null when code[a, b) is not a function value, else [start, stop] of what it returns (twin of flow._js_fn_result). */
function jsFnResult(code, a, b, table) {
  FUNCTION_HEAD_RE.lastIndex = 0;
  const m = FUNCTION_HEAD_RE.exec(code.slice(a, b));
  if (m === null) return null;
  const pairs = table.pairs;
  let k = a + m[0].length;
  if (m[1] === undefined) {                   // function …(…) {…}
    const close = pairs.get(k);
    if (close === undefined || close >= b) return [];
    k = close + 1;
  }
  while (k < b && BLANK.has(code[k])) k++;
  if (k < b && code[k] === "{") {
    let end = pairs.get(k);
    if (end === undefined || end > b) end = b;
    RETURN_SCAN_RE.lastIndex = 1;
    const it = code.slice(k, end).matchAll(RETURN_SCAN_RE);
    RETURN_SCAN_RE.lastIndex = 0;
    const out = [];
    for (const rm of it) {
      const s = k + rm.index + rm[0].length;
      out.push([s, Math.min(argEndAt(code, s, true, table), end)]);
    }
    return out;
  }
  if (m[1] === undefined) return [];
  return [[k, b]];
}

/** The names the parameters of the function whose body opens at brace bind (twin of flow._js_body_params). */
function jsBodyParams(code, brace, opener, pairs) {
  let p = jsBack(code, brace);
  if (p < 0) return [];
  if (code[p] === ">") {
    if (p < 1 || code[p - 1] !== "=") return [];
    const q = jsBack(code, p - 1);
    if (q < 0) return [];
    if (code[q] !== ")") {
      const word = wordBefore(code, q)[1];
      return PARAM_RE.test(word) ? [word] : [];
    }
    p = q;
  } else if (code[p] !== ")") return [];
  const o = opener.get(p);
  if (o === undefined) return [];
  return jsBindingNames(code, o + 1, p, pairs);
}

/** BINDING_RE matched at i and ending by stop (Python's match(code, i, stop)), or null. */
function bindingAt(code, i, stop) {
  BINDING_RE.lastIndex = i;
  let m = BINDING_RE.exec(code);
  if (m !== null && m.index + m[0].length <= stop) return [m[0].length, m[1], m[2]];
  BINDING_RE.lastIndex = 0;
  m = BINDING_RE.exec(code.slice(i, stop));
  return m === null ? null : [m[0].length, m[1], m[2]];
}

/**
 * The names a parameter list or (statement) a const / let / var declarator
 * list code[a, b) binds (twin of flow._js_binding_names).
 */
function jsBindingNames(code, a, b, pairs, statement = false) {
  const out = [], todo = [[a, b, statement ? "decl" : "list"]];
  while (todo.length) {
    let [i, stop, kind] = todo.pop();
    while (i < stop) {
      const m = bindingAt(code, i, stop);            // an element
      if (m !== null) {
        i += m[0];
        if (m[2]) {                                  // a nested pattern
          const c = pairs.get(i - 1);
          if (c === undefined || c >= stop) break;
          todo.push([i, c, m[2] === "{" ? "obj" : "arr"]);
          i = c + 1;
        } else {
          let j = i;
          while (j < stop && BLANK.has(code[j])) j++;
          if (kind === "obj" && j < stop && code[j] === ":") { i = j + 1; continue; }   // key: local
          out.push(m[1]);
        }
      }
      while (i < stop) {                             // to the next element
        while (i < stop && !BINDING_END.has(code[i])) i++;
        if (i >= stop) break;
        const ch = code[i];
        if (ch === "(" || ch === "[" || ch === "{") {
          const c = pairs.get(i);
          if (c === undefined || c >= stop) { i = stop; break; }
          i = c + 1;
        } else if (ch === ",") { i++; break; }
        else if (kind === "decl" || (ch !== "\n" && ch !== ";")) { i = stop; break; }
        else i++;
      }
    }
  }
  return out;
}

// ---- values through local variables (twin of flow.py's section) ----------
// A parameter reaches a sink through the locals of its function that hold it
// (paramMap / carry, read the way request data is), names are bound by
// assignments (also after `if (…)`, `else`, `=>` without braces), patterns,
// for … of / in heads and push; for SQL the parameter must be joined into the
// query text (jsJoins) on the way or in the sink's first argument. Pattern
// parameters bind their names; parameters come from the whole list. A value
// holds at most MAX_CARRY parameters; map copies and sink reads are budgeted.

/**
 * [[key, names]] of each parameter of the function whose header spans head,
 * read from its whole parameter list when it closes before stop, else null
 * (twin of flow._js_header_params): key is the name a use spells, or "{i}"
 * for the i-th parameter when it is a pattern.
 */
function jsHeaderParams(code, head, stop, pairs) {
  const o = code.indexOf("(", head[0]);
  if (o < 0 || o >= head[1]) return null;
  const c = pairs.get(o);
  if (c === undefined || c >= stop) return null;
  return jsSplitSpans(code, o + 1, c, pairs).map(([a, b], i) => {
    if (a < b && (code[a] === "[" || code[a] === "{")) return ["{" + i + "}", jsBindingNames(code, a, b, pairs)];
    const name = jsParamName(code.slice(a, b));
    return [name, name ? [name] : []];
  });
}

/**
 * [name, value start, value stop, offset, bare] of each name bound other than
 * by `name = …` (twin of flow._js_other_bindings): pattern declarations and
 * for … of / in heads (each name assigned the value), list.push(v) /
 * list.unshift(v) (bare). A region starting inside an earlier one is dropped
 * before it is read.
 */
function jsOtherBindings(code, pairs) {
  const cands = [];
  for (const m of code.matchAll(PATTERN_DECL_RE)) cands.push([m.indices[1][0], 0, m]);
  for (const m of code.matchAll(FOR_HEAD_RE)) cands.push([m[2] !== undefined ? m.indices[2][0] : m.indices[3][0], 1, m]);
  for (const m of code.matchAll(PUSH_RE)) cands.push([m.indices[1][0], 2, m]);
  cands.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const out = [];
  let end = -1;
  for (const [off, kind, m] of cands) {
    if (off < end) continue;
    let names, a, b, bare;
    if (kind === 0) {                                  // const { a } = v
      const c = pairs.get(off);
      if (c === undefined) continue;
      PATTERN_VALUE_RE.lastIndex = c + 1;
      const vm = PATTERN_VALUE_RE.exec(code);
      if (vm === null) continue;
      names = jsBindingNames(code, off, c + 1, pairs);
      [a, b] = vm.indices[1];
      bare = false;
    } else if (kind === 1) {                           // for (const x of v)
      const close = pairs.get(m.indices[1][0]);
      if (close === undefined) continue;
      let k;
      if (m[2] !== undefined) { names = [m[2]]; k = m.indices[2][1]; }
      else {
        const c = pairs.get(off);
        if (c === undefined || c >= close) continue;
        names = jsBindingNames(code, off, c + 1, pairs);
        k = c + 1;
      }
      OF_RE.lastIndex = k;
      const om = OF_RE.exec(code);
      if (om === null || k + om[0].length > close) continue;
      [a, b] = jsTrim(code, k + om[0].length, close);
      bare = false;
    } else {                                           // list.push(v)
      const paren = m.index + m[0].length - 1;
      const close = pairs.get(paren);
      if (close === undefined) continue;
      names = [m[1]];
      [a, b] = jsTrim(code, paren + 1, close);
      bare = true;
    }
    if (a >= b) continue;
    end = b;
    for (const name of names) out.push([name, a, b, off, bare]);
  }
  return out;
}

/** Does the expression code[a, b) join strings (twin of flow._js_joins)? */
function jsJoins(code, a, b) {
  for (const m of code.slice(a, b).matchAll(JOIN_RE)) {
    const i = a + m.index;
    const ch = code[i];
    if (ch === ".") return true;
    if (ch === "+") {
      if (i > a && code[i - 1] === "+") continue;                  // `++`
      const p = jsBack(code, i, a);
      if (p >= a && (")]'\"`".includes(code[p]) || wordBefore(code, p, a)[1] !== "")) return true;
      continue;
    }
    const t = i > a ? code.lastIndexOf("`", i - 1) : -1;          // the template's opening quote
    if (t < a) return true;
    const p = jsBack(code, t, a);
    if (p >= a) {
      const w = wordBefore(code, p, a)[1];
      if (")]".includes(code[p]) || (w !== "" && !REGEX_KEYWORDS.has(w))) continue;   // a tagged template
    }
    return true;
  }
  return false;
}

/** Is the word at text[i] a property name rather than a variable (twin of flow._js_member)? */
function jsMember(text, i) {
  const p = jsBack(text, i);
  return p >= 0 && text[p] === "." && !(p >= 1 && text[p - 1] === ".");
}

/** Is the assignment whose value starts at a a `+=` (twin of flow._js_plus_assign)? */
function jsPlusAssign(code, a) {
  const k = jsBack(code, a);
  return k >= 1 && code[k] === "=" && code[k - 1] === "+";
}

/** Add a path of parameter [fid, i] to out (twin of flow._js_carry_add): at most MAX_CARRY parameters. */
function carryAdd(out, key, fid, i, built, clean) {
  const prev = out.get(key);
  if (prev !== undefined) out.set(key, [fid, i, prev[2] || built, intersection(prev[3], clean)]);
  else if (out.size < MAX_CARRY) out.set(key, [fid, i, built, clean]);
}

const nodeMerge = (x, y) => [x[0].concat(y[0]), x[1] || y[1], x[2].concat(y[2]), x[3] || y[3]];

/** true for a full sanitizer, the categories of a partial one, else null (twin of flow._js_sanitizer). */
function jsSanitizer(callee) {
  const probe = callee + "()";
  if (FULL_SAN_CALL_RE.test(probe)) return true;
  const cats = new Set(PARTIAL_SAN_CALL.filter(([, re]) => re.test(probe)).map(([c]) => c));
  return cats.size ? cats : null;
}

/** One provenance for several paths (twin of flow._js_merge). */
function jsMerge(provs) {
  if (!provs.length) return null;
  let clean = provs[0].at(-1);
  for (let k = 1; k < provs.length; k++) clean = intersection(clean, provs[k].at(-1));
  const first = provs.find((p) => p[0] === "ret") ?? provs[0];
  return [...first.slice(0, -1), clean];
}

/** Two variable maps read as one: the first's provenance where it has one (twin of flow._JsLayers). */
class Layers {
  constructor(first, second) { this.first = first; this.second = second; }
  get(name) { const prov = this.first.get(name); return prov === undefined ? this.second.get(name) : prov; }
}

/** One analyzed JavaScript file (twin of flow._JsFile). */
class JsFile {
  constructor(f, text, code, literals) {
    this.path = f.path; this.text = text;
    this.mods = new Map();       // local name -> module specifier
    this.named = new Map();      // local name -> [specifier, exported name]
    this.exports = new Map();    // exported name -> ["local", name, offset] | ["from", specifier, name]
    this.star = [];
    this.cjs = null;
    this.module(code, literals);
    code = this.inlineRequires(code, literals);
    this.code = code;
    this.nl = newlineOffsets(code);
    this.table = jsBrackets(code);
    this.pairs = this.table.pairs;
    this.hard = [];              // offsets of ( ) ; and newlines
    this.parens = [];            // offsets of (
    for (let k = 0; k < code.length; k++) {
      const c = code[k];
      if (c === "(") { this.hard.push(k); this.parens.push(k); }
      else if (c === ")" || c === ";" || c === "\n") this.hard.push(k);
    }
    this.writes = new Map();     // name -> offsets of the assignments to it
    for (const m of code.matchAll(WRITE_RE)) {
      if (!this.writes.has(m[1])) this.writes.set(m[1], []);
      this.writes.get(m[1]).push(m.indices[1][0]);
    }
    // [name, value start, value stop, offset, bare] of each assignment, in
    // source order: `name = …`, then the names bound another way (no aliases)
    const plain = [];
    for (const am of code.matchAll(ASSIGN_RE)) {
      plain.push(am[1] !== undefined ? [am[1], am.indices[2][0], am.indices[2][1], am.indices[1][0], false]
        : [am[3], am.indices[4][0], am.indices[4][1], am.indices[3][0], true]);
    }
    const tagged = plain.map((r) => [r[3], 0, r]).concat(jsOtherBindings(code, this.pairs).map((r) => [r[3], 1, r]));
    tagged.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
    this.assigns = tagged.map((t) => t[2]);
    this.other = new Set();
    tagged.forEach((t, k) => { if (t[1]) this.other.add(k); });
    // per assignment: does its value join strings (or is it `+=`); is it `+=`
    this.plus = this.assigns.map(([, a, , , bare], k) => bare && !this.other.has(k) && jsPlusAssign(code, a));
    this.joins = this.assigns.map(([, a, b], k) => this.plus[k] || jsJoins(code, a, b));
    this.targets = new Set(this.assigns.map((a) => a[0]));
    this.alias = new Map();      // name -> [[name assigned to it, assignment number]]
    this.constAlias = new Set();
    this.aliases(code);
    this.assignNodes = [];
    this.tainted = new Map();    // variable -> provenance, file-wide (the call-site pass)
    this.fns = [];
    this.scopeFns = new Map();   // scope -> fids of the functions whose body it is
    this.defs = new Map();       // name -> fids of the functions of that name defined here
    this.defsAt = new Map();     // name SEP scope defining it -> fid of the last one defined there
    this.heads = new Map();      // name -> [[start, stop]] of the headers defining one
    this.reassigned = new Set(); // name SEP scope: a binding assigned other than by its definition
    this.scopes = [];
    this.starts = [];
    this.parent = [];
    this.top = [];
    this.own = [];
    this.decl = [];              // per scope: the names it declares
    this.topDecl = new Set();    // the module's
    this.assignScope = [];       // per assignment: the scope it belongs to (null: the module)
    this.callScope = new Map();
    this.sinks = JS_SINKS.map(([sinkRe, cat]) => [cat, [...code.matchAll(sinkRe)].map((m) => [m.index, m.index + m[0].length])]);
    this.sinkScopes = [];
    this.budget = READ_BUDGET * cpLen(code) + 65536;     // code points of expressions it may read
    this.over = false;
    this.idx = 0;
  }

  line(pos) { return bisectLeft(this.nl, pos) + 1; }

  module(code, literals) {
    const spec = (m, g) => literals.get(m.indices[g][0]);
    for (const m of code.matchAll(REQUIRE_BIND_RE)) {
      const s = spec(m, 2);
      if (s !== undefined) {
        if (m[3]) this.named.set(m[1], [s, m[3]]);
        else this.mods.set(m[1], s);
      }
    }
    for (const m of code.matchAll(REQUIRE_DESTRUCTURE_RE)) {
      const s = spec(m, 2);
      if (s !== undefined) for (const it of jsItems(m[1], BIND_ITEM_RE)) this.named.set(it[2] || it[1], [s, it[1]]);
    }
    for (const m of code.matchAll(IMPORT_RE)) {
      const s = spec(m, 4);
      if (s === undefined || m[1] === "type") continue;
      if (m[1]) this.mods.set(m[1], s);
      if (m[2] !== undefined) {
        for (const it of jsItems(m[2], AS_ITEM_RE)) if (!it[1]) this.named.set(it[3] || it[2], [s, it[2]]);
      }
      if (m[3]) this.mods.set(m[3], s);
    }
    for (const m of code.matchAll(EXPORT_LIST_RE)) {
      const s = m[2] ? spec(m, 2) : undefined;
      if (m[2] && s === undefined) continue;
      for (const it of jsItems(m[1], AS_ITEM_RE)) {
        if (!it[1]) this.exports.set(it[3] || it[2], s !== undefined ? ["from", s, it[2]] : ["local", it[2], m.index]);
      }
    }
    for (const m of code.matchAll(EXPORT_STAR_RE)) {
      const s = spec(m, 1);
      if (s !== undefined) this.star.push(s);
    }
    for (const m of code.matchAll(EXPORT_DEFAULT_RE)) this.exports.set("default", ["local", m[1], m.index]);
    for (const m of code.matchAll(MODULE_EXPORTS_RE)) {
      if (m[1]) {
        const s = spec(m, 1);
        if (s !== undefined) this.cjs = s;
      } else if (m[2]) this.exports.set("default", ["local", m[2], m.index]);
      else if (m[3] !== undefined) {
        for (const it of jsItems(m[3], BIND_ITEM_RE)) this.exports.set(it[1], ["local", it[2] || it[1], m.index]);
      } else this.exports.set("default", ["local", m[4], m.index]);
    }
    for (const m of code.matchAll(EXPORTS_PROP_RE)) this.exports.set(m[1], ["local", m[2] || m[3], m.index]);
  }

  /** code with each one-line require('spec') replaced by a same-length module name (twin of flow._JsFile._inline_requires). */
  inlineRequires(code, literals) {
    const pieces = [];
    let last = 0, k = 0;
    for (const m of code.matchAll(INLINE_REQUIRE_RE)) {
      const s = literals.get(m.indices[1][0]);
      const a = m.index, b = m.index + m[0].length;
      if (s === undefined || code.slice(a, b).includes("\n")) continue;
      let name = "R" + k;
      if (name.length > b - a) continue;
      k++;
      name += "$".repeat(b - a - name.length);
      this.mods.set(name, s);
      pieces.push(code.slice(last, a), name);
      last = b;
    }
    if (!pieces.length) return code;
    pieces.push(code.slice(last));
    return pieces.join("");
  }

  unbind() {
    for (const table of [this.mods, this.named]) {
      for (const name of [...table.keys()]) if ((this.writes.get(name)?.length ?? 0) > 1) table.delete(name);
    }
  }

  /** Modules and exports copied to another name, and names assigned a name (twin of flow._JsFile._aliases). */
  aliases(code) {
    this.unbind();
    for (let round = 0; round < 4; round++) {
      let grew = false;
      for (let k = 0; k < this.assigns.length; k++) {
        if (this.other.has(k)) continue;
        const [name, a, b] = this.assigns[k];
        const m = ALIAS_RE.exec(pyStrip(code.slice(a, b)));
        if (m === null) continue;
        const spec = this.mods.get(m[1]);
        if (spec === undefined || this.mods.has(name) || this.named.has(name)) continue;
        if (m[2]) this.named.set(name, [spec, m[2]]);
        else this.mods.set(name, spec);
        grew = true;
      }
      for (const m of code.matchAll(DESTRUCTURE_RE)) {
        const spec = this.mods.get(m[2]);
        if (spec === undefined) continue;
        for (const it of jsItems(m[1], BIND_ITEM_RE)) {
          const local = it[2] || it[1];
          if (!this.named.has(local) && !this.mods.has(local)) { this.named.set(local, [spec, it[1]]); grew = true; }
        }
      }
      if (!grew) break;
    }
    this.unbind();
    this.assigns.forEach(([name, a, b, , bare], k) => {
      if (this.other.has(k) || this.mods.has(name) || this.named.has(name)) return;
      const m = ALIAS_RE.exec(pyStrip(code.slice(a, b)));
      if (m === null || m[2] !== undefined || m[1] === name || NOT_ALIAS.has(m[1])) return;
      if (!this.alias.has(name)) this.alias.set(name, []);
      this.alias.get(name).push([m[1], k]);
      if (!bare && (this.writes.get(name)?.length ?? 0) === 1) this.constAlias.add(name);
    });
  }

  /** The innermost scope around pos, or null (twin of flow._JsFile.scope_at). */
  scopeAt(pos) {
    const known = this.callScope.get(pos);
    if (known !== undefined) return known;
    let k = bisectRight(this.starts, pos) - 1;
    if (k < 0) return null;
    while (k !== null && this.scopes[k][1] <= pos) k = this.parent[k];
    return k;
  }

  /** Does a scope around pos (or the module) declare name (twin of flow._JsFile.bound_at)? */
  boundAt(name, pos) {
    let k = this.scopeAt(pos), steps = 0;
    while (k !== null && steps <= SCOPE_WALK) {
      if (this.decl[k].has(name)) return true;
      k = this.parent[k];
      steps++;
    }
    return this.topDecl.has(name);
  }

  /** The scope whose declaration of name a use at pos refers to (twin of flow._JsFile.binding_scope). */
  bindingScope(name, pos) {
    let k = this.scopeAt(pos), steps = 0;
    while (k !== null) {
      if (this.decl[k].has(name)) return k;
      steps++;
      if (steps > SCOPE_WALK) return -1;
      k = this.parent[k];
    }
    return null;
  }

  /** Is offset p inside the header of a definition of name (twin of flow._JsFile.in_head)? */
  inHead(name, p) {
    const heads = this.heads.get(name);
    if (heads === undefined || !heads.length) return false;
    let lo = 0, hi = heads.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (p < heads[mid][0]) hi = mid; else lo = mid + 1; }
    return lo > 0 && p < heads[lo - 1][1];
  }
}

/** One function (twin of flow._JsFunction). */
class JsFunction {
  constructor(fid, rec, name, params, span, expr, head) {
    this.fid = fid; this.rec = rec; this.name = name; this.params = params; this.span = span;
    this.expr = expr;
    this.head = head;
    this.pnames = params.map((p) => (p ? [p] : []));   // per parameter: the names it binds
    this.reach = new Map();      // param -> [category, sink line]
    this.returns = [];           // [start, end, line] of each returned expression
    this.returnNodes = [];       // [compiled expression, line]
    this.scope = null;
  }
}

/** The JavaScript files of a scan, their functions and summaries (twin of flow._JsProgram). */
class JsProgram {
  constructor(recs, funcs) {
    this.recs = recs; this.funcs = funcs;
    this.index = new Map();
    for (const r of recs) { const k = normPath(r.path); if (!this.index.has(k)) this.index.set(k, r); }
    this.byName = new Map();       // name -> fids, the last defined first
    for (let k = funcs.length - 1; k >= 0; k--) {
      const fn = funcs[k];
      if (!this.byName.has(fn.name)) this.byName.set(fn.name, []);
      this.byName.get(fn.name).push(fn.fid);
    }
    this.reachNamed = new Map();   // name -> those with a parameter that reaches a sink (indexReach)
    this.clean = funcs.map(() => EMPTY);
    this.retSrc = new Map();       // fid -> [file, line, function]
    this.retSrcClean = new Map();  // fid -> Set of categories
    this.retNamed = new Map();     // name -> fids with a retSrc, the last defined first
    this.resolved = new Map(); this.exportedMemo = new Map();
  }

  resolve(rec, spec) {
    const key = rec.path + SEP + spec;
    if (this.resolved.has(key)) return this.resolved.get(key);
    let target = null;
    if (spec === "." || spec === ".." || spec.startsWith("./") || spec.startsWith("../")) {
      const parts = normPath(rec.path).split("/").slice(0, -1);
      let ok = true;
      for (const seg of spec.split("/")) {
        if (seg === "" || seg === ".") continue;
        if (seg === "..") {
          if (!parts.length) { ok = false; break; }
          parts.pop();
        } else parts.push(seg);
      }
      if (ok) {
        const base = parts.join("/");
        const cands = [base, ...EXTS.map((e) => base + e)];
        const last = parts.length ? parts[parts.length - 1] : "";
        const dot = last.lastIndexOf(".");
        const ext = dot > 0 ? last.slice(dot) : "";
        if (TS_SOURCES.has(ext)) for (const t of TS_SOURCES.get(ext)) cands.push(base.slice(0, base.length - ext.length) + t);
        for (const e of EXTS) cands.push((base ? base + "/" : "") + "index" + e);
        for (const c of cands) {
          const t = this.index.get(c);
          if (t !== undefined) { target = t; break; }
        }
      }
    }
    this.resolved.set(key, target);
    return target;
  }

  /** fid of the function named name visible at pos, or null (twin of flow._JsProgram.visible). */
  visible(rec, name, pos) {
    if (!rec.defs.has(name)) return null;
    let k = rec.scopeAt(pos), steps = 0;
    while (k !== null) {
      const fid = rec.defsAt.get(name + SEP + k);
      if (fid !== undefined) return fid;
      steps++;
      if (steps > SCOPE_WALK) return null;
      k = rec.parent[k];
    }
    return rec.defsAt.get(name + SEP + null) ?? null;
  }

  /** visible(), unless that binding is also assigned (twin of flow._JsProgram.local). */
  local(rec, name, pos) {
    const fid = this.visible(rec, name, pos);
    if (fid === null) return null;
    const scope = rec.parent[this.funcs[fid].scope];
    if (rec.reassigned.has(name + SEP + scope) || rec.reassigned.has(name + SEP + "-1")) return null;
    return fid;
  }

  /** fid of the function module rec exports as name, or null (twin of flow._JsProgram.exported). */
  exported(rec, name) {
    if (rec === null) return null;
    const key = rec.path + SEP + name;
    if (this.exportedMemo.has(key)) return this.exportedMemo.get(key);
    let found = null;
    let level = [[rec, name]];
    const seen = new Set([key]);
    for (let hop = 0; hop <= EXPORT_HOPS; hop++) {
      const next = [];
      for (const [r, n] of level) {
        const entry = r.exports.get(n);
        let targets;
        if (entry !== undefined) {
          if (entry[0] === "local") {
            found = this.local(r, entry[1], entry[2]);
            if (found !== null) break;
            continue;
          }
          targets = [[entry[1], entry[2]]];
        } else {
          targets = [];
          if (n !== "default") {
            found = this.local(r, n, -1);
            if (found !== null) break;
            targets = r.star.map((s) => [s, n]);
          }
          if (r.cjs !== null) targets.push([r.cjs, n]);
        }
        for (const [s, tn] of targets) {
          const t = this.resolve(r, s);
          if (t !== null && !seen.has(t.path + SEP + tn)) { seen.add(t.path + SEP + tn); next.push([t, tn]); }
        }
      }
      if (found !== null || !next.length) break;
      level = next;
    }
    this.exportedMemo.set(key, found);
    return found;
  }

  /** [fid, null] | [null, names] | [null, []]: what a call reaches (twin of flow._JsProgram.bind). */
  bind(rec, name, recv, pos, depth = 0) {
    if (recv === null) {
      let fid = this.local(rec, name, pos);
      if (fid !== null) return [fid, null];
      const imp = rec.named.get(name);
      if (imp !== undefined) {
        if (isBuiltin(imp[0])) return [null, []];
        fid = this.exported(this.resolve(rec, imp[0]), imp[1]);
        if (fid !== null) return [fid, null];
        return [null, imp[1] === name ? [name] : [name, imp[1]]];
      }
      const spec = rec.mods.get(name);
      if (spec !== undefined) {
        if (isBuiltin(spec)) return [null, []];
        fid = this.exported(this.resolve(rec, spec), "default");
        if (fid !== null) return [fid, null];
        return [null, [name]];
      }
      // a name a scope around the call binds holds what was assigned to it
      const out = this.visible(rec, name, pos) !== null || !rec.boundAt(name, pos) ? [name] : [];
      const targets = rec.alias.get(name);
      if (targets !== undefined && depth < 4 && targets.length <= MAX_ALIAS) {
        const scope = rec.bindingScope(name, pos);
        for (const [t, k] of targets) {
          if (scope !== -1 && rec.assignScope[k] !== scope) continue;   // another binding of that name
          let [f, names] = this.bind(rec, t, null, pos, depth + 1);
          if (f !== null) {
            if (rec.constAlias.has(name) && !rec.defs.has(name)) return [f, null];
            names = [this.funcs[f].name];
          }
          for (const n of names) if (!out.includes(n)) out.push(n);
        }
      }
      return [null, out];
    }
    if (recv) {
      const spec = rec.mods.get(recv);
      if (spec !== undefined) {
        if (isBuiltin(spec)) return [null, []];
        const fid = this.exported(this.resolve(rec, spec), name);
        if (fid !== null) return [fid, null];
        return [null, [name]];
      }
      if (GLOBAL_OBJECTS.has(recv) && !rec.writes.has(recv) && !rec.named.has(recv)) return [null, []];
      if (recv === "this" || recv === "super") return [null, [name]];
    }
    if (COMMON_METHODS.has(name)) return [null, []];
    return [null, [name]];
  }

  /** The functions whose sink-reaching parameters a call's arguments are checked against (twin of flow). */
  reachCandidates(rec, name, recv, pos) {
    const [fid, names] = this.bind(rec, name, recv, pos);
    if (fid !== null) return this.funcs[fid].reach.size ? [fid] : [];
    const out = [];
    for (const n of names) {                 // distinct names: no function twice
      for (const f of this.reachNamed.get(n) ?? []) {
        out.push(f);
        if (out.length > MAX_OPEN) return [out[0]];
      }
    }
    return out;
  }

  // An expression is read in two steps (twin of flow._JsProgram): compile()
  // finds its structure once, run() evaluates it against the current
  // summaries as often as the fixpoint needs.

  /** [calls, reads request data, words that may be tainted, holds a name] of code[a, b) (twin of flow.compile). */
  compile(rec, a, b, depth = 0) {
    const code = rec.code;
    const calls = [], spans = [];
    const lp = bisectLeft(rec.parens, a);
    if (depth < EVAL_DEPTH && lp < rec.parens.length && rec.parens[lp] < b) {
      const table = rec.table;
      const base = a > 0 ? a - 1 : 0;
      CALL_SCAN_RE.lastIndex = a - base;
      const it = code.slice(base, b).matchAll(CALL_SCAN_RE);
      CALL_SCAN_RE.lastIndex = 0;
      let pos = a;
      for (const m of it) {
        const start = m.index + base;
        if (start < pos) continue;
        const call = jsCallAt(code, m[1], start, start + m[0].length - 1, table, a);
        if (call === null) continue;
        const [name, recv, cstart, paren, close] = call;
        if (close >= b) continue;
        const callee = recv === null ? name : recv ? recv + "." + name : null;
        let san = null;
        let [fid, names] = this.bind(rec, name, recv, start);
        if (fid === null) {
          names = names.filter((n) => this.byName.has(n));
          if (!names.length && callee !== null) san = jsSanitizer(callee);
        }
        if (san !== null) {
          if (san !== true) calls.push(["san", san, this.compile(rec, paren + 1, close, depth + 1)]);
          spans.push([cstart, close + 1]);
          pos = close + 1;
        } else if (fid !== null) {
          const args = jsSplitSpans(code, paren + 1, close, table.pairs).map(([x, y]) => this.value(rec, x, y, depth + 1));
          calls.push(["fn", fid, args, jsAfterNew(code, cstart, a)]);
          spans.push([cstart, close + 1]);
          pos = close + 1;
        } else if (names.length) {
          calls.push(["open", names]);
        }
      }
    }
    let text;
    if (spans.length) {
      const pieces = [];
      let last = a;
      for (const [s, e] of spans) { pieces.push(code.slice(last, s), " "); last = e; }
      pieces.push(code.slice(last, b));
      text = pieces.join("");
    } else text = code.slice(a, b);
    const words = [];
    let opaque = false;
    for (const m of text.matchAll(WORD_RE)) {
      const w = m[0];
      if (rec.targets.has(w) && !jsMember(text, m.index)) words.push(w);
      if (!opaque && !LITERAL_WORDS.has(w)) opaque = true;
    }
    return [calls, JS_SOURCE_RE.test(text), words, opaque];
  }

  /** compile() of an argument; a function value by what it returns (twin of flow.value). */
  value(rec, a, b, depth) {
    const res = jsFnResult(rec.code, a, b, rec.table);
    if (res === null) return this.compile(rec, a, b, depth);
    let node = EMPTY_NODE;
    for (const [x, y] of res) node = nodeMerge(node, this.compile(rec, x, y, depth));
    return node;
  }

  /** The categories (and ALL) the value of a compiled expression is free of its function's inputs for (twin of flow.free). */
  free(node) {
    const [calls, direct, , opaque] = node;
    if (opaque || direct) return EMPTY;
    let out = UNIVERSE;
    for (const call of calls) {
      if (call[0] === "san") out = intersection(out, union(call[1], this.free(call[2])));
      else if (call[0] === "fn" && !call[3]) out = intersection(out, this.clean[call[1]]);
      else return EMPTY;
      if (!out.size) break;
    }
    return out;
  }

  /** The provenance of a compiled expression, or null (twin of flow._JsProgram.run). */
  run(node, rec, tainted, cats) {
    const [calls, direct, words] = node;
    const provs = [];
    const add = (prov, extra = EMPTY) => {
      const clean = union(prov.at(-1), extra);
      if (!intersects(clean, cats)) provs.push([...prov.slice(0, -1), clean]);
    };
    for (const call of calls) {
      if (call[0] === "san") {
        const sub = this.run(call[2], rec, tainted, cats);
        if (sub !== null) add(sub, call[1]);
      } else if (call[0] === "fn") {
        const fid = call[1];
        const src = this.retSrc.get(fid);
        if (src !== undefined) add(["ret", ...src, this.funcs[fid].name, this.retSrcClean.get(fid)]);
        const clean = call[3] ? EMPTY : this.clean[fid];
        if (!clean.has(ALL)) {
          for (const arg of call[2]) {
            const sub = this.run(arg, rec, tainted, cats);
            if (sub !== null) add(sub, clean);
          }
        }
      } else {
        // one returned value sanitized for nothing decides the merge
        let done = false;
        for (const n of call[1]) {
          for (const fid of this.retNamed.get(n) ?? []) {
            const clean = this.retSrcClean.get(fid);
            if (intersects(clean, cats)) continue;
            add(["ret", ...this.retSrc.get(fid), this.funcs[fid].name, clean]);
            if (!clean.size) { done = true; break; }
          }
          if (done) break;
        }
      }
    }
    if (direct) add(["direct", EMPTY]);
    for (const w of words) {
      const prov = tainted.get(w);
      if (prov !== undefined) add(prov);
    }
    return jsMerge(provs);
  }

  /** Add the assignments numbered `which` to tainted, in order (twin of flow._JsProgram._fill). */
  fill(rec, tainted, which) {
    const nodes = rec.assignNodes;
    for (const k of which) {
      const src = this.run(nodes[k], rec, tainted, EMPTY);
      if (src !== null) {
        const name = rec.assigns[k][0];
        tainted.set(name, tainted.has(name) ? jsMerge([tainted.get(name), src]) : src);
      }
    }
    return tainted;
  }

  /** Variable -> provenance for all of rec's assignments (twin of flow._JsProgram.taint_map). */
  taintMap(rec) {
    return this.fill(rec, new Map(), rec.assigns.map((_, k) => k));
  }

  /** The tainted variables scope k (null: the module) sees (twin of flow._JsProgram.scope_map). */
  scopeMap(rec, k, cache) {
    const key = (j) => rec.idx + ":" + (j === null ? "m" : j);
    const chain = [];
    while (k !== null && !cache.has(key(k))) { chain.push(k); k = rec.parent[k]; }
    let base = cache.get(key(k));
    if (base === undefined) { base = this.fill(rec, new Map(), rec.top); cache.set(key(null), base); }
    for (let i = chain.length - 1; i >= 0; i--) {
      base = this.fill(rec, new Map(base), rec.own[chain[i]]);
      cache.set(key(chain[i]), base);
    }
    return base;
  }

  /** The functions fn's returns and own assignments call (twin of flow._JsProgram._deps). */
  deps(fn) {
    const out = [];
    const stack = fn.returnNodes.map(([node]) => node);
    for (const k of fn.rec.own[fn.scope]) stack.push(fn.rec.assignNodes[k]);
    while (stack.length) {
      for (const call of stack.pop()[0]) {
        if (call[0] === "san") stack.push(call[2]);
        else if (call[0] === "fn") {
          out.push(call[1]);
          for (const arg of call[2]) stack.push(arg);
        } else {
          for (const n of call[1]) {
            const fids = this.byName.get(n) ?? [];
            if (fids.length <= MAX_OPEN_EDGES) for (const f of fids) out.push(f);
          }
        }
      }
    }
    return out;
  }

  /** Every fid, callees first (twin of flow._JsProgram.order). */
  order() {
    const deps = this.funcs.map((fn) => this.deps(fn));
    const order = [], seen = new Array(deps.length).fill(false);
    for (let root = 0; root < deps.length; root++) {
      if (seen[root]) continue;
      seen[root] = true;
      const stack = [[root, 0]];
      while (stack.length) {
        const top = stack[stack.length - 1];
        const [f, i] = top;
        if (i < deps[f].length) {
          top[1] = i + 1;
          const g = deps[f][i];
          if (!seen[g]) { seen[g] = true; stack.push([g, 0]); }
        } else {
          stack.pop();
          order.push(f);
        }
      }
    }
    return order;
  }

  /** this.clean, the least fixpoint (twin of flow._JsProgram.settle_clean). */
  settleClean(order) {
    for (let round = 0; round < RET_ROUNDS; round++) {
      let changed = false;
      for (const fid of order) {
        let c = UNIVERSE;
        for (const [node] of this.funcs[fid].returnNodes) {
          c = intersection(c, this.free(node));
          if (!c.size) break;
        }
        if (!sameSet(c, this.clean[fid])) { this.clean[fid] = c; changed = true; }
      }
      if (!changed) return;
    }
  }

  /** retSrc, to a fixpoint; false when RET_ROUNDS rounds did not settle it (twin of flow._JsProgram.settle_returns). */
  settleReturns(order) {
    for (let round = 0; round < RET_ROUNDS; round++) {
      let changed = false;
      const cache = new Map();
      for (const fid of order) {
        const fn = this.funcs[fid];
        if (!fn.returnNodes.length) continue;
        const rec = fn.rec;
        const tainted = this.scopeMap(rec, fn.scope, cache);
        for (const [node, line] of fn.returnNodes) {
          const src = this.run(node, rec, tainted, EMPTY);
          if (src === null) continue;
          if (!this.retSrc.has(fid)) {
            this.retSrc.set(fid, src[0] === "ret" ? src.slice(1, 4) : [rec.path, line, fn.name]);
            this.retSrcClean.set(fid, src.at(-1));
            if (!this.retNamed.has(fn.name)) this.retNamed.set(fn.name, []);
            const named = this.retNamed.get(fn.name);
            let lo = 0, hi = named.length;           // kept descending
            while (lo < hi) { const mid = (lo + hi) >> 1; if (named[mid] > fid) lo = mid + 1; else hi = mid; }
            named.splice(lo, 0, fid);
            changed = true;
          } else if (!subset(this.retSrcClean.get(fid), src.at(-1))) {
            this.retSrcClean.set(fid, intersection(this.retSrcClean.get(fid), src.at(-1)));
            changed = true;
          }
        }
      }
      if (!changed) return true;
    }
    return false;
  }

  /** reachNamed, once every function's reach is known (twin of flow._JsProgram.index_reach). */
  indexReach() {
    for (const [name, fids] of this.byName) {
      const reach = fids.filter((f) => this.funcs[f].reach.size);
      if (reach.length) this.reachNamed.set(name, reach);
    }
  }

  /**
   * [parameters, locals] scope k of rec sees: Map name -> Map "fid,index" ->
   * [fid, index, built, clean] (twin of flow._JsProgram.param_map). A scope
   * that adds or hides nothing shares its enclosing scope's maps; copying them
   * is read within the file's budget.
   */
  paramMap(rec, k, cache) {
    if (rec.over) return NO_PARAMS;
    const chain = [];
    while (k !== null && !cache.has(k)) { chain.push(k); k = rec.parent[k]; }
    let [seeds, locs] = k !== null ? cache.get(k) : NO_PARAMS;
    for (let c = chain.length - 1; c >= 0; c--) {
      const j = chain[c];
      const decl = rec.decl[j], fids = rec.scopeFns.get(j) ?? [], own = rec.own[j];
      if (!fids.length && !own.length && disjoint(seeds, decl) && disjoint(locs, decl)) {
        cache.set(j, [seeds, locs]);
        continue;
      }
      const cost = seeds.size + locs.size + 1;
      if (cost > rec.budget) { rec.over = true; return NO_PARAMS; }
      rec.budget -= cost;
      seeds = new Map([...seeds].filter(([n]) => !decl.has(n)));
      locs = new Map([...locs].filter(([n]) => !decl.has(n)));
      for (const fid of fids) {
        this.funcs[fid].pnames.forEach((names, i) => {
          for (const n of names) {
            const ent = new Map(seeds.get(n) ?? []);
            ent.set(fid + "," + i, [fid, i, false, EMPTY]);
            seeds.set(n, ent);
          }
        });
      }
      for (const a of own) {
        const name = rec.assigns[a][0];
        const val = this.carry(rec.assignNodes[a], seeds, locs);
        const old = locs.get(name);
        const plus = rec.plus[a];
        if (!val.size && !(plus && old !== undefined)) continue;
        const ent = new Map();
        if (old !== undefined) for (const [key, [f, i, bt, cl]] of old) ent.set(key, [f, i, bt || plus, cl]);
        const joins = rec.joins[a];
        for (const [key, [f, i, bt, cl]] of val) carryAdd(ent, key, f, i, bt || joins, cl);
        locs.set(name, ent);
      }
      cache.set(j, [seeds, locs]);
    }
    return [seeds, locs];
  }

  /** Map "fid,index" -> [fid, index, built, clean]: the parameters a compiled expression's value may hold (twin of flow.carry). */
  carry(node, seeds, locs) {
    const [calls, , words] = node;
    const out = new Map();
    for (const call of calls) {
      if (call[0] === "san") {
        for (const [key, [f, i, bt, cl]] of this.carry(call[2], seeds, locs)) carryAdd(out, key, f, i, bt, union(cl, call[1]));
      } else if (call[0] === "fn") {
        const clean = call[3] ? EMPTY : this.clean[call[1]];
        if (!clean.has(ALL)) {
          for (const arg of call[2]) {
            for (const [key, [f, i, bt, cl]] of this.carry(arg, seeds, locs)) carryAdd(out, key, f, i, bt, union(cl, clean));
          }
        }
      }
    }
    for (const w of words) {
      for (const table of [seeds, locs]) {
        const ent = table.get(w);
        if (ent !== undefined) for (const [key, [f, i, bt, cl]] of ent) carryAdd(out, key, f, i, bt, cl);
      }
    }
    return out;
  }
}

/** Do map's names and the set decl share none (iterating the smaller)? */
function disjoint(map, decl) {
  if (map.size <= decl.size) { for (const n of map.keys()) if (decl.has(n)) return false; return true; }
  for (const n of decl) if (map.has(n)) return false;
  return true;
}

/** Offsets of the '{' that open a function body (twin of flow._js_function_bodies). */
function jsFunctionBodies(code, opens, opener, named) {
  const bodies = new Set(named);
  for (const b of opens) {
    const p = jsBack(code, b);
    if (p < 0) continue;
    if (code[p] === ">") {
      if (p >= 1 && code[p - 1] === "=") bodies.add(b);
    } else if (code[p] === ")") {
      const o = opener.get(p);
      if (o === undefined || code[o] !== "(") continue;
      const q = jsBack(code, o);
      if (q < 0) continue;
      const word = wordBefore(code, q)[1];
      if (word && !CONTROL_WORDS.has(word)) bodies.add(b);
    }
  }
  return bodies;
}

/** Map body '{' -> [[start, end, line] of each returned expression] (twin of flow._js_returns). */
function jsReturns(code, bodies, matchClose, line, table) {
  const order = [...bodies].sort((a, b) => a - b);
  const out = new Map(), stack = [];
  let k = 0;
  for (const rm of code.matchAll(RETURN_RE)) {
    const r = rm.index;
    while (k < order.length && order[k] < r) stack.push(order[k++]);
    while (stack.length && (matchClose.get(stack[stack.length - 1]) ?? code.length) < r) stack.pop();
    if (stack.length) {
      const a = r + rm[0].length;
      const top = stack[stack.length - 1];
      if (!out.has(top)) out.set(top, []);
      out.get(top).push([a, argEndAt(code, a, true, table), line(r)]);
    }
  }
  return out;
}

/** [scopes sorted enclosing first, enclosing scope of each or null] (twin of flow._js_scope_tree). */
function jsScopeTree(spans) {
  const scopes = [...spans].sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const parent = [], stack = [];
  scopes.forEach(([a], k) => {
    while (stack.length && scopes[stack[stack.length - 1]][1] <= a) stack.pop();
    parent.push(stack.length ? stack[stack.length - 1] : null);
    stack.push(k);
  });
  return [scopes, parent];
}

/** The innermost scope around each of the ascending positions, or null (twin of flow._js_innermost). */
function jsInnermost(scopes, positions) {
  const out = [], stack = [];
  let k = 0;
  for (const pos of positions) {
    while (k < scopes.length && scopes[k][0] <= pos) stack.push(k++);
    while (stack.length && scopes[stack[stack.length - 1]][1] <= pos) stack.pop();
    out.push(stack.length ? stack[stack.length - 1] : null);
  }
  return out;
}

/**
 * fn.reach for the functions of rec (twin of flow._js_sink_reach): a
 * parameter reaches a sink when a name it binds is written in the sink's
 * arguments (for SQL, joined into them), or when a local the sink reads holds
 * it (paramMap; for SQL, in the query text and joined into a string on the way
 * or there). A later sink kind's category wins; within one category the first
 * sink call is reported. The locals are read within the file's budget.
 */
function jsSinkReach(prog, rec) {
  const funcs = prog.funcs;
  const mine = rec.fns.map((fid) => funcs[fid]);
  if (!mine.length) return;
  const code = rec.code, table = rec.table, pairs = table.pairs, cache = new Map();
  const spans = mine.map((fn, k) => [fn.span[0], fn.span[1], k]);
  rec.sinks.forEach(([cat, matches], c) => {
    const byStart = [...spans].sort((a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2]);
    let active = [];
    let addIdx = 0;
    matches.forEach(([pos, send], m) => {
      while (addIdx < byStart.length && byStart[addIdx][0] <= pos) active.push(byStart[addIdx++]);
      active = active.filter((sp) => sp[1] > pos);
      if (!active.length) return;
      const [a, b] = jsSinkSpan(code, pos, send, table);
      const seg = code.slice(a, b);
      const hits = [];
      for (const [, , k] of active) {
        const fn = mine[k];
        fn.pnames.forEach((names, i) => {
          for (const p of names) {
            if (jsParamDangerous(seg, p, cat)) { hits.push([fn, fn.params[i]]); break; }
          }
        });
      }
      const sc = rec.sinkScopes[c][m];
      if (sc !== null && !rec.over) {
        const locs = prog.paramMap(rec, sc, cache)[1];
        if (locs.size) {
          const n = cpSpanOf(code, a, b, table);
          if (n > rec.budget) rec.over = true;
          else {
            rec.budget -= n;
            let args = jsSplitSpans(code, a, b, pairs);
            if (cat === "SQL injection") args = args.slice(0, 1);      // the query text; parameters are bound
            if (args.some(([x, y]) => (code.slice(x, y).match(WORD_RE) ?? []).some((w) => locs.has(w)))) {
              let node = EMPTY_NODE;
              for (const [x, y] of args) node = nodeMerge(node, prog.value(rec, x, y, 0));
              const joins = cat === "SQL injection" && args.some(([x, y]) => jsJoins(code, x, y));
              for (const [f, i, built, clean] of prog.carry(node, EMPTY_MAP, locs).values()) {
                if (clean.has(cat) || (cat === "SQL injection" && !(built || joins))) continue;
                hits.push([funcs[f], funcs[f].params[i]]);
              }
            }
          }
        }
      }
      if (hits.length) {
        const line = rec.line(pos);
        for (const [fn, key] of hits) {
          // a later sink kind's category wins; within one category the first call is reported
          const prev = fn.reach.get(key);
          if (prev === undefined || prev[0] !== cat) fn.reach.set(key, [cat, line]);
        }
      }
    });
  });
}

function analyzeJs(files, findings) {
  const jsFiles = files.filter((f) => f.lang === "js");
  const recs = [], funcs = [];
  for (const f of jsFiles) {
    const content = jsText(f.content);
    const size = cpLen(content);
    if (size > JS_MAX_FILE) {
      findings.push({
        rule: "X-FLOW-SKIPPED", name: "JS flow analysis skipped (size)",
        type: "HOTSPOT", sev: "INFO",
        msg: `${f.path} is ${size} bytes; interprocedural JS taint analysis is skipped above ${JS_MAX_FILE} bytes.`,
        why: "The heuristic JS engine scales poorly on minified or machine-generated files of this size; " +
          "a full analysis would risk a multi-minute scan.",
        fix: "Split or deminify the file, or exclude it from the scan explicitly if the code is generated.",
        ref: "Scalability",
        file: f.path, line: 1, snippet: [], snipStart: 1,
      });
      continue;
    }
    const literals = new Map();
    const rec = new JsFile(f, content, jsMask(content, literals), literals);
    rec.idx = recs.length;
    recs.push(rec);
    const code = rec.code, table = rec.table, pairs = table.pairs;
    const braces = jsBraces(code);
    const heads = [];
    const found = jsFunctions(content, code, braces, table, heads);
    const first = funcs.length;
    found.forEach(([name, params, [s, e]], k) => {
      const fn = new JsFunction(funcs.length, rec, name, params, [s, e], s >= code.length || code[s] !== "{", heads[k]);
      // parameters from the whole list: `(a = f(1, 2), { b })` is two, the second binding b
      const plist = jsHeaderParams(code, heads[k], s, pairs);
      if (plist !== null) {
        fn.params = plist.map(([key]) => key);
        fn.pnames = plist.map(([, names]) => names);
      }
      funcs.push(fn);
      rec.fns.push(fn.fid);
    });
    const mine = funcs.slice(first);
    // what an expression holds is read by name: parameters too
    for (const fn of mine) for (const names of fn.pnames) for (const n of names) rec.targets.add(n);
    // what each function returns: an arrow function's expression, else the
    // `return`s of its own body (not of a function inside it)
    const [opens, matchClose] = braces;
    const opener = new Map();
    for (const [o, c] of pairs) opener.set(c, o);
    const named = mine.filter((fn) => !fn.expr).map((fn) => fn.span[0]);
    const bodies = jsFunctionBodies(code, opens, opener, named);
    const owned = jsReturns(code, bodies, matchClose, (p) => rec.line(p), table);
    for (const fn of mine) {
      fn.returns = fn.expr ? [[fn.span[0], fn.span[1], rec.line(fn.span[0])]] : owned.get(fn.span[0]) ?? [];
    }
    // scopes: every function body; a function is visible in the scope that
    // defines it, an assignment belongs to the innermost scope around it (a
    // bare one to the scope that declares its name, else to the module)
    const spanSet = new Map();
    const bodySpan = (b) => [b, (matchClose.get(b) ?? code.length) + 1];
    for (const b of bodies) { const sp = bodySpan(b); spanSet.set(sp.join(","), sp); }
    for (const fn of mine) if (fn.expr) spanSet.set(fn.span.join(","), fn.span);
    [rec.scopes, rec.parent] = jsScopeTree(spanSet.values());
    const where = new Map(rec.scopes.map((sp, k) => [sp.join(","), k]));
    const decl = rec.scopes.map(() => new Set());
    for (const b of bodies) {
      const k = where.get(bodySpan(b).join(","));
      for (const p of jsBodyParams(code, b, opener, pairs)) decl[k].add(p);
    }
    for (const fn of mine) {
      fn.scope = where.get(fn.span.join(","));
      if (!rec.scopeFns.has(fn.scope)) rec.scopeFns.set(fn.scope, []);
      rec.scopeFns.get(fn.scope).push(fn.fid);
      if (fn.expr) {                          // `const f = (a, { b }) => …`: before its `=>`
        const q = jsBack(code, fn.head[1] - 2);
        const o = q >= 0 ? opener.get(q) : undefined;
        if (o !== undefined) for (const p of jsBindingNames(code, o + 1, q, pairs)) decl[fn.scope].add(p);
      }
      if (!rec.defs.has(fn.name)) rec.defs.set(fn.name, []);
      rec.defs.get(fn.name).push(fn.fid);
      rec.defsAt.set(fn.name + SEP + rec.parent[fn.scope], fn.fid);
      if (!rec.heads.has(fn.name)) rec.heads.set(fn.name, []);
      rec.heads.get(fn.name).push(fn.head);
    }
    const dms = [...code.matchAll(DECL_RE)];
    jsInnermost(rec.scopes, dms.map((m) => m.index)).forEach((sc, k) => {
      const at = dms[k].index + dms[k][0].length;
      const names = sc === null ? rec.topDecl : decl[sc];
      for (const n of jsBindingNames(code, at, windowStop(code, at, table), pairs, true)) names.add(n);
    });
    // an assignment rebinds the definition of its name it resolves to (-1: too deep to tell)
    const defined = new Set(mine.map((fn) => fn.name + SEP + rec.parent[fn.scope]));
    const wms = [...code.matchAll(WRITE_RE)];
    jsInnermost(rec.scopes, wms.map((m) => m.indices[1][0])).forEach((sc0, k) => {
      const name = wms[k][1];
      let sc = sc0;
      if (!rec.defs.has(name) || rec.inHead(name, wms[k].indices[1][0])) return;
      let steps = 0;
      while (sc !== null && !decl[sc].has(name) && !defined.has(name + SEP + sc)) {
        steps++;
        sc = steps <= SCOPE_WALK ? rec.parent[sc] : -1;
        if (sc === -1) break;
      }
      rec.reassigned.add(name + SEP + sc);
    });
    rec.starts = rec.scopes.map((sp) => sp[0]);
    const cps = [...code.matchAll(CALL_RE)].map((m) => m.index);
    const cs = jsInnermost(rec.scopes, cps);
    cps.forEach((p, k) => rec.callScope.set(p, cs[k]));
    rec.decl = decl;
    rec.own = rec.scopes.map(() => []);
    jsInnermost(rec.scopes, rec.assigns.map((a) => a[3])).forEach((sc0, k) => {
      const name = rec.assigns[k][0];
      let sc = sc0;
      if (rec.assigns[k][4]) {
        let steps = 0;
        while (sc !== null && !decl[sc].has(name)) {
          steps++;
          sc = steps <= SCOPE_WALK ? rec.parent[sc] : null;
        }
      }
      (sc === null ? rec.top : rec.own[sc]).push(k);
      rec.assignScope.push(sc);
    });
    rec.sinkScopes = rec.sinks.map(([, matches]) => jsInnermost(rec.scopes, matches.map(([pos]) => pos)));
  }
  if (!funcs.length) return;
  const prog = new JsProgram(recs, funcs);
  // assignments are always read: they don't overlap, and what is read of
  // the calls nested in one is bounded by EVAL_DEPTH
  for (const rec of recs) rec.assignNodes = rec.assigns.map(([, a, b]) => prog.compile(rec, a, b));
  // returned expressions can overlap: each file's are read within its budget
  for (const fn of funcs) {
    const rec = fn.rec;
    fn.returnNodes = fn.returns.map(([a, b, line]) => {
      const n = cpSpanOf(rec.code, a, b, rec.table);
      if (rec.over || n > rec.budget) { rec.over = true; return [OPAQUE_NODE, line]; }
      rec.budget -= n;
      return [prog.compile(rec, a, b), line];
    });
  }
  const order = prog.order();
  prog.settleClean(order);
  // which parameters reach a sink: written in its arguments, or held by a local it reads
  for (const rec of recs) jsSinkReach(prog, rec);
  prog.indexReach();
  // the call-site pass's file-wide map holds request data read directly;
  // what functions return is read through the scopes
  for (const rec of recs) rec.tainted = prog.taintMap(rec);
  const settled = prog.settleReturns(order);
  if (!settled) {
    findings.push(flowNote("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (iteration cap)", recs[0].path, 1,
      `What JavaScript functions return did not settle within ${RET_ROUNDS} rounds; flows through long chains ` +
        "of returned values may be missing.",
      "Return values are iterated to a fixpoint with a safety cap; hitting it means an unusually long chain of " +
        "functions returning each other's values.",
      "Report the pattern to the Lazaret maintainers."));
  }
  // call sites: request data passed into a function whose parameter reaches a sink
  if (prog.reachNamed.size) {
    for (const rec of recs) {
      const lines = rec.text.split("\n");
      const code = rec.code, table = rec.table, hard = rec.hard, cache = new Map();
      for (const m of code.matchAll(CALL_RE)) {
        const call = jsCallAt(code, m[1], m.index, m.index + m[0].length - 1, table);
        if (call === null) continue;
        const [name, recv, , paren, close] = call;
        const cands = prog.reachCandidates(rec, name, recv, m.index);
        if (!cands.length) continue;
        if (bisectLeft(hard, paren + 1) !== bisectLeft(hard, close)) {
          // a nested call or statement in the arguments: a budgeted read
          const n = cpSpanOf(code, paren + 1, close, table);
          if (rec.over || n > rec.budget) { rec.over = true; continue; }
          rec.budget -= n;
        }
        const args = jsSplitSpans(code, paren + 1, close, table.pairs);
        const tainted = new Layers(prog.scopeMap(rec, rec.scopeAt(m.index), cache), rec.tainted);
        let hit = false;
        for (const fid of cands) {
          const fn = funcs[fid];
          for (let idx = 0; idx < fn.params.length; idx++) {
            const pname = fn.params[idx];
            if (!fn.reach.has(pname) || idx >= args.length) continue;
            const [cat, sline] = fn.reach.get(pname);
            const node = prog.value(rec, args[idx][0], args[idx][1], 0);
            if (prog.run(node, rec, tainted, new Set([cat])) !== null) {   // sink-category sanitizers
              const line = rec.line(m.index);
              findings.push(flowIssue(cat, rec.path, line, lines, `${rec.path}:${line}`,
                `${fn.rec.path}:${sline} (in ${fn.name}())`, `the call to ${name}()`));
              hit = true;
              break;
            }
          }
          if (hit) break;
        }
      }
    }
  }
  // sinks fed by a value another function read from the request and returned
  if (prog.retSrc.size) {
    for (const rec of recs) {
      const lines = rec.text.split("\n");
      const code = rec.code, table = rec.table, cache = new Map();
      rec.sinks.forEach(([cat, matches], c) => {
        const cats = new Set([cat]);
        for (let k = 0; k < matches.length; k++) {
          const [pos, send] = matches[k];
          const sc = rec.sinkScopes[c][k];
          const [a, b] = jsSinkSpan(code, pos, send, table);
          const n = cpSpanOf(code, a, b, table);
          if (rec.over || n > rec.budget) { rec.over = true; break; }
          rec.budget -= n;
          let args = jsSplitSpans(code, a, b, table.pairs);
          if (cat === "SQL injection") args = args.slice(0, 1);      // the query text; parameters are bound
          let node = EMPTY_NODE;
          for (const [x, y] of args) node = nodeMerge(node, prog.value(rec, x, y, 0));
          const src = prog.run(node, rec, prog.scopeMap(rec, sc, cache), cats);
          if (src !== null && src[0] === "ret") {
            const line = rec.line(pos);
            findings.push(flowIssue(cat, rec.path, line, lines, `${src[1]}:${src[2]} (in ${src[3]}())`,
              `${rec.path}:${line}`, `the value returned by ${src[4]}()`));
          }
        }
      });
    }
  }
  for (const rec of recs) {
    if (rec.over) {
      findings.push(flowNote("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)", rec.path, 1,
        `The JavaScript cross-file pass stopped following returned values and nested calls in ${rec.path} ` +
          `after reading ${READ_BUDGET} times its size; calls whose arguments hold no nested call were still ` +
          "checked, but flows through returned values in the rest of it may be missing.",
        "Deeply nested code makes the expressions the pass reads overlap; each file has a budget so a scan " +
          "cannot run unbounded.",
        "Split or deminify the file, or exclude it from the scan explicitly if the code is generated."));
    }
  }
}

/**
 * Cross-function / cross-file taint findings for the JavaScript files of a
 * scan (twin of flow.analyze for JavaScript). Never throws: an internal
 * error ends the pass with a Q-FLOW-INCOMPLETE note. Dependency files are
 * not analyzed.
 */
export function analyzeFlows(files) {
  const findings = [];
  let js = [];
  try {
    js = files.filter((f) => f && typeof f === "object" && f.lang === "js" && !f.dep && typeof f.path === "string");
  } catch { js = []; }
  try {
    analyzeJs(js, findings);
  } catch (e) {
    findings.push(flowNote("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (internal error)",
      js.length ? js[0].path : "?", 1,
      `The JavaScript cross-file taint pass stopped on an internal error (${e?.name ?? "Error"}); ` +
        "findings it had already produced are kept.",
      "An unexpected input made the interprocedural engine fail; the rest of the scan is unaffected.",
      "Please report the file that triggers this to the Lazaret maintainers."));
  }
  const sorted = findings.map((f, k) => [f, k])
    .sort((a, b) => cmpCodePoints(String(a[0].file), String(b[0].file)) || a[0].line - b[0].line || a[1] - b[1]);
  const seen = new Set(), unique = [];
  for (const [i] of sorted) {
    const key = JSON.stringify([i.rule, i.file, i.line, i.msg]);
    if (!seen.has(key)) { seen.add(key); unique.push(i); }
  }
  return unique;
}

/**
 * Give flow findings their file's redaction (twin of core.redact_file_issues
 * for the findings this module builds from raw lines): a snippet line that is
 * still its file line's raw text becomes the line as a file scan shows it
 * (PEM blocks, the file's entropy literals, credential patterns); msg gets
 * the file's literals. In place.
 */
export function redactFlowIssues(issues, files) {
  if (!REDACT.on) return issues;
  const byPath = new Map(files.map((f) => [f.path, f]));
  const groups = new Map();
  for (const i of issues) {
    if (!byPath.has(i.file)) continue;
    if (!groups.has(i.file)) groups.set(i.file, []);
    groups.get(i.file).push(i);
  }
  for (const [path, group] of groups) {
    const f = byPath.get(path);
    const lines = splitLines(f.content, f.lang);
    const ctx = registerScanContext(lines, SECRET_SKIP_RE);
    for (const i of group) {
      for (const key of ["msg", "cmd"]) {
        const v = i[key];
        if (typeof v === "string") {
          const nv = redactText(v, contextSecrets(ctx));
          if (nv !== v) i[key] = nv;
        }
      }
      const snip = i.snippet, start = i.snipStart;
      if (!Array.isArray(snip) || !Number.isInteger(start)) continue;
      let out = null;
      snip.forEach((line, k) => {
        const j = start - 1 + k;
        if (typeof line === "string" && j >= 0 && j < lines.length && line === lines[j]) {
          const shown = contextRedacted(ctx, j);
          if (shown !== line) { out ??= [...snip]; out[k] = shown; }
        }
      });
      if (out !== null) i.snippet = out;
    }
  }
  return issues;
}
