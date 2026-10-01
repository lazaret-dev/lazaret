// Cross-file received code — twin of lazaret.scanner.core's
// _cross_file_received_issues (see the section comment there: what the
// follower reads of a package's modules, what holds a received value, what
// it seeds, the bounds). A dropper can split the download and the code that
// runs it across two files of a package, so neither file shows the shape
// alone; the follower reads the package's files as modules and gives the
// single-file detector (the native engine's receivedCodeKind) the names that carry the value
// from one file into another.
//
// Results are core's for every input. The patterns are core's text (the
// parity test, tests/architecture/test_js_parity_crossfile.py, holds them to
// it), compiled with Python `re` semantics by pyRe; re.M's ^ and $ anchor at
// "\n" only, as Python's do. The rows this module reads are masked by UTF-16
// unit, so a masked row keeps its source row's length in units and offsets
// move between them unchanged; where core counts a length (a row too long to
// read), it is counted in code points on the source row, as core counts it.

import { sep } from "node:path";
import { pyRe, pyStrip, pyLstrip, cpLen, isPySpace, isWordChar, cmpCodePoints } from "./pycompat.js";
import { receivedCodeKind, importCode, readsOwnSource, importTimeSeverity, packValues } from "./native.js";
import { commentSpans } from "./lexer.js";
import { mkIssue } from "./issue.js";
import { registerScanContext, SECRET_SKIP_RE } from "./redact.js";

// core's pattern text and flags, verbatim (m = re.M)
const XF_PATTERNS = {
  _XF_CLASS_RE: ["^[ \\t]*class[ \\t]+(?P<name>[A-Za-z_]\\w*)", ""],
  _XF_DEF_RE: ["^[ \\t]*(?:async[ \\t]+)?def[ \\t]+(?P<name>[A-Za-z_]\\w*)[ \\t]*\\(", ""],
  _XF_ASSIGN_RE: ["^(?P<indent>[ \\t]*)(?P<name>[A-Za-z_]\\w*)[ \\t]*=(?![=])(?P<rhs>.*)$", ""],
  _XF_RETURN_RE: ["^[ \\t]*return[ \\t](?P<expr>.*)$", ""],
  _XF_FROM_RE: ["^[ \\t]*from[ \\t]+(?P<mod>\\.+[\\w.]*|[\\w.]+)[ \\t]+import[ \\t]+(?P<names>\\*|\\([^()]*\\)|.+?)[ \\t]*$", "m"],
  _XF_IMPORT_RE: ["^[ \\t]*import[ \\t]+(?P<names>[\\w.]+(?:[ \\t]+as[ \\t]+\\w+)?(?:[ \\t]*,[ \\t]*[\\w.]+(?:[ \\t]+as[ \\t]+\\w+)?)*)[ \\t]*$", "m"],
  _XF_STATIC_RE: ["^[ \\t]*@(?:staticmethod|classmethod)\\b", ""],
  _XF_DEF_END_RE: ["\\)[^():\\n]*:", ""],
  _XF_PY_QUOTE_RE: ["[#'\\\"]", ""],
  _XF_PY_ENV_WRITE_RE: ["\\b(?:os[ \\t]*\\.[ \\t]*)?environ[ \\t]*\\[[ \\t]*['\\\"](?P<var>[A-Za-z_][A-Za-z0-9_]{0,63})['\\\"][ \\t]*\\][ \\t]*=(?!=)(?P<rhs>[^\\n]*)", ""],
  _XF_PY_DYN_IMPORT_RE: ["(?<![\\w$.])(?P<local>[A-Za-z_]\\w*)[ \\t]*=[ \\t]*(?:importlib[ \\t]*\\.[ \\t]*)?(?P<fn>import_module|__import__)[ \\t]*\\([ \\t]*['\\\"](?P<mod>\\.{0,8}[A-Za-z_][\\w.]{0,200})['\\\"](?P<rest>[^\\n]*)", ""],
  _XF_MEMBER_WRITE_RE: ["(?<![\\w$.])(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*(?:\\[[^\\]\\n]*\\]|\\.[ \\t]*(?P<attr>[A-Za-z_$][\\w$]*))[ \\t]*=(?![=>])[ \\t]*(?P<rhs>[^;\\n]*)", ""],
  _XF_PARAMS_RE: ["\\((?P<params>[^()]*)\\)", ""],
  _XF_PARAM_NAME_RE: ["[ \\t]*(?:\\*{1,2}|\\.\\.\\.)?[ \\t]*(?P<name>[A-Za-z_$][\\w$]*)", ""],
  _XF_ARROW_ONE_RE: ["[ \\t]*(?:async[ \\t]+)?(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*=>", ""],
  _XF_PROMISE_RE: ["\\bnew[ \\t]+Promise[ \\t]*\\([ \\t]*(?:async[ \\t]+)?(?:function\\b[^(\\n]*\\([ \\t]*|\\([ \\t]*)?(?P<name>[A-Za-z_$][\\w$]*)", ""],
  _XF_CALL_NAME_RE: ["(?<![\\w$.])(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*\\(", ""],
  _XF_JS_FUNC_RE: ["\\bfunction[ \\t]*\\*?[ \\t]*(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*\\(", ""],
  _XF_JS_CONST_RE: ["\\b(?:const|let|var)[ \\t]+(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*=(?![=>])[ \\t]*(?P<rhs>.*)$", ""],
  _XF_JS_FN_VALUE_RE: ["(?:async[ \\t]+)?(?:function\\b[^(]*\\(|\\([^()]*\\)[ \\t]*=>|[A-Za-z_$][\\w$]*[ \\t]*=>)", ""],
  _XF_JS_CLASS_RE: ["\\bclass[ \\t]+(?P<name>[A-Za-z_$][\\w$]*)", ""],
  _XF_JS_METHOD_RE: ["(?:^|[ \\t;{}])(?P<static>static[ \\t]+)?(?:async[ \\t]+)?(?:\\*[ \\t]*)?(?:(?:get|set)[ \\t]+)?(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*\\([^()]*\\)[ \\t]*\\{", ""],
  _XF_JS_FIELD_RE: ["^[ \\t]*(?P<static>static[ \\t]+)?(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*=(?![=>])[ \\t]*(?P<rhs>[^;\\n]*)", ""],
  _XF_JS_RETURN_RE: ["\\breturn\\b[ \\t]*(?P<expr>[^;\\n]*)", ""],
  _XF_JS_LOCAL_RE: ["(?<![\\w$.])(?:(?:const|let|var)[ \\t]+)?(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*=(?![=>])[ \\t]*(?P<rhs>[^;\\n]*)", ""],
  _XF_JS_OBJECT_RE: ["(?:\\b(?:const|let|var)[ \\t]+(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*=|\\bmodule[ \\t]*\\.[ \\t]*exports[ \\t]*=|\\bexport[ \\t]+default)[ \\t]*\\{", ""],
  _XF_JS_MEMBER_RE: ["(?:async[ \\t]+(?=[*A-Za-z_$'\\\"]))?(?:\\*[ \\t]*)?(?:(?:get|set)[ \\t]+(?=[A-Za-z_$'\\\"]))?['\\\"]?(?P<name>[A-Za-z_$][\\w$]*)['\\\"]?[ \\t]*(?:(?P<method>\\()|(?P<colon>:)|(?=[,}]|$))", ""],
  _XF_JS_EXPORT_DECL_RE: ["\\bexport[ \\t]+(?:async[ \\t]+)?(?:function[ \\t]*\\*?[ \\t]*|(?:const|let|var)[ \\t]+|class[ \\t]+)(?P<name>[A-Za-z_$][\\w$]*)", ""],
  _XF_JS_EXPORT_DEFAULT_DECL_RE: ["\\bexport[ \\t]+default[ \\t]+(?:async[ \\t]+)?(?:function\\b[ \\t]*\\*?[ \\t]*(?P<fn>[A-Za-z_$][\\w$]*)?|class\\b[ \\t]*(?P<cls>[A-Za-z_$][\\w$]*)?)", ""],
  _XF_JS_EXPORT_LIST_RE: ["\\bexport[ \\t]*\\{(?P<names>[^{}]*)\\}(?![ \\t]*from\\b)", ""],
  _XF_JS_EXPORT_FROM_RE: ["\\bexport[ \\t]*\\{(?P<names>[^{}]*)\\}[ \\t]*from[ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"]", ""],
  _XF_JS_EXPORT_STAR_RE: ["\\bexport[ \\t]*\\*[ \\t]*(?:as[ \\t]+(?P<ns>[A-Za-z_$][\\w$]*)[ \\t]*)?from[ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"]", ""],
  _XF_JS_EXPORT_DEFAULT_RE: ["\\bexport[ \\t]+default[ \\t]+(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*;?[ \\t]*$", "m"],
  _XF_JS_MODEXP_OBJ_RE: ["\\bmodule\\s*\\.\\s*exports[ \\t]*=[ \\t]*\\{(?P<names>[^{}]*)\\}", ""],
  _XF_JS_MODEXP_PROP_RE: ["\\b(?:module\\s*\\.\\s*exports|exports)\\s*(?:\\.\\s*(?P<name>[A-Za-z_$][\\w$]*)|\\[\\s*['\\\"](?P<qname>[A-Za-z_$][\\w$]*)['\\\"]\\s*\\])[ \\t]*=(?![=>])[ \\t]*(?P<rhs>[^\\n]*)", ""],
  _XF_JS_MODEXP_ALL_RE: ["\\bmodule\\s*\\.\\s*exports[ \\t]*=[ \\t]*(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*;?[ \\t]*$", "m"],
  _XF_JS_MODEXP_CLASS_RE: ["\\bmodule\\s*\\.\\s*exports[ \\t]*=[ \\t]*class[ \\t]+(?P<name>[A-Za-z_$][\\w$]*)", ""],
  _XF_JS_MODEXP_REQ_RE: ["\\bmodule\\s*\\.\\s*exports[ \\t]*=[ \\t]*require\\([ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"][ \\t]*\\)", ""],
  _XF_JS_MODEXP_FN_RE: ["\\bmodule\\s*\\.\\s*exports[ \\t]*=[ \\t]*(?=(?:async[ \\t]+)?(?:function\\b|\\([^()]*\\)[ \\t]*=>|[A-Za-z_$][\\w$]*[ \\t]*=>))", ""],
  _XF_JS_DEFINE_RE: ["\\bObject\\s*\\.\\s*defineProperty\\(\\s*exports\\s*,\\s*['\\\"](?P<name>[A-Za-z_$][\\w$]*)['\\\"]\\s*,\\s*\\{[^{}]*?\\bget\\s*:\\s*function\\s*\\(\\s*\\)\\s*\\{\\s*return\\s+(?P<ref>[A-Za-z_$][\\w$]*(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)*)", ""],
  _XF_JS_REQ_DESTR_RE: ["\\b(?:const|let|var)[ \\t]*\\{(?P<names>[^{}]*)\\}[ \\t]*=[ \\t]*require\\([ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"][ \\t]*\\)", ""],
  _XF_JS_REQ_NS_RE: ["\\b(?:const|let|var)[ \\t]+(?P<ns>[A-Za-z_$][\\w$]*)[ \\t]*=[ \\t]*(?:(?:__importDefault|__importStar|_interopRequireDefault|_interopRequireWildcard)[ \\t]*\\([ \\t]*)?require\\([ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"][ \\t]*\\)(?![ \\t]*\\.)", ""],
  _XF_JS_REQ_MEMBER_RE: ["\\b(?:const|let|var)[ \\t]+(?P<local>[A-Za-z_$][\\w$]*)[ \\t]*=[ \\t]*require\\([ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"][ \\t]*\\)[ \\t]*\\.[ \\t]*(?P<name>[A-Za-z_$][\\w$]*)", ""],
  _XF_JS_IMP_NAMED_RE: ["\\bimport[ \\t]*(?:[A-Za-z_$][\\w$]*[ \\t]*,[ \\t]*)?\\{(?P<names>[^{}]*)\\}[ \\t]*from[ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"]", ""],
  _XF_JS_IMP_NS_RE: ["\\bimport[ \\t]*\\*[ \\t]*as[ \\t]+(?P<ns>[A-Za-z_$][\\w$]*)[ \\t]*from[ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"]", ""],
  _XF_JS_IMP_DEFAULT_RE: ["\\bimport[ \\t]+(?P<name>[A-Za-z_$][\\w$]*)[ \\t]*(?:,[ \\t]*\\{[^{}]*\\})?[ \\t]*from[ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"]", ""],
  _XF_JS_DYN_DESTR_RE: ["\\b(?:const|let|var)[ \\t]*\\{(?P<names>[^{}]*)\\}[ \\t]*=[ \\t]*(?:await[ \\t]+)?import\\([ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"][ \\t]*\\)", ""],
  _XF_JS_DYN_NS_RE: ["\\b(?:const|let|var)[ \\t]+(?P<ns>[A-Za-z_$][\\w$]*)[ \\t]*=[ \\t]*(?:await[ \\t]+)?import\\([ \\t]*['\\\"](?P<mod>[^'\\\"\\n]+)['\\\"][ \\t]*\\)", ""],
  _XF_JS_DIRNAME_RE: ["(?<![\\w$])(?:path[ \\t]*\\.[ \\t]*)?(?:join|resolve)[ \\t]*\\([ \\t]*__dirname[ \\t]*,[ \\t]*['\\\"](?P<a>[^'\\\"\\n]*)['\\\"][ \\t]*\\)|(?<![\\w$.])__dirname[ \\t]*\\+[ \\t]*['\\\"](?P<b>/[^'\\\"\\n]*)['\\\"]|`\\$\\{__dirname\\}(?P<c>/[^`$\\n]*)`", ""],
  _XF_JS_ENV_WRITE_RE: ["\\bprocess\\s*\\.\\s*env\\s*(?:\\.\\s*(?P<a>[A-Za-z_$][\\w$]*)|\\[\\s*['\\\"`](?P<b>[A-Za-z_$][\\w$]*)['\\\"`]\\s*\\])\\s*=(?![=>])(?P<rhs>[^\\n]*)", ""],
  _XF_SPACE_RE: ["\\s+", ""],
  _XF_BRACE_RE: ["[{}]", ""],
  _XF_JS_LINE_COMMENT_RE: ["(?:^|(?<=[\\s;,(){}]))//", ""],
  _XF_EMIT_RE: ["(?<![\\w$.])(?P<obj>[A-Za-z_$][\\w$]*)[ \\t]*\\.[ \\t]*emit[ \\t]*\\([ \\t]*(?P<q>['\\\"`])(?P<event>[^'\\\"`\\n]{1,100})\\2[ \\t]*,", ""],
  _XF_LISTEN_RE: ["(?<![\\w$.])(?P<obj>[A-Za-z_$][\\w$]*)[ \\t]*\\.[ \\t]*(?:on|once|addListener|prependListener|prependOnceListener)[ \\t]*\\([ \\t]*(?P<q>['\\\"`])(?P<event>[^'\\\"`\\n]{1,100})\\2[ \\t]*,[ \\t]*(?:(?:async[ \\t]+)?(?:function\\b[ \\t]*[\\w$]*[ \\t]*\\([ \\t]*(?P<fp>[A-Za-z_$][\\w$]*)|\\([ \\t]*(?P<ap>[A-Za-z_$][\\w$]*)[^)\\n]*\\)[ \\t]*=>|(?P<bp>[A-Za-z_$][\\w$]*)[ \\t]*=>)|(?P<handler>[A-Za-z_$][\\w$]*(?:[ \\t]*\\.[ \\t]*[A-Za-z_$][\\w$]*){0,3})[ \\t]*[,)])", ""],
  _XF_EMIT_AT_RE: ["\\.[ \\t]*emit[ \\t]*\\(", ""],
  _XF_LISTEN_AT_RE: ["\\.[ \\t]*(?:on|once|addListener|prependListener|prependOnceListener)[ \\t]*\\(", ""],
};

export const XF_LIMITS = {
  _XF_WINDOW: 25, _XF_MAX_FILES: 3000, _XF_MAX_SEEDS: 64, _XF_ROUNDS: 4, _XF_MAX_SYMBOLS: 5000, _XF_MAX_DEPTH: 8,
  _XF_LOCAL_DEPTH: 3, _XF_OBJECT_ROWS: 400, _XF_MAX_RUNNERS: 200, _XF_MAX_CHARS: 2_000_000, _XF_EMIT_MAX: 50,
};
const { _XF_WINDOW: WINDOW, _XF_MAX_FILES: MAX_FILES, _XF_MAX_SEEDS: MAX_SEEDS, _XF_ROUNDS: ROUNDS,
  _XF_MAX_SYMBOLS: MAX_SYMBOLS, _XF_MAX_DEPTH: MAX_DEPTH, _XF_LOCAL_DEPTH: LOCAL_DEPTH, _XF_OBJECT_ROWS: OBJECT_ROWS,
  _XF_MAX_RUNNERS: MAX_RUNNERS, _XF_MAX_CHARS: MAX_CHARS, _XF_EMIT_MAX: EMIT_MAX } = XF_LIMITS;
const EMIT_NEEDLE = "emit";                                          // a file without it emits nothing
const EMIT_GLOBALS = new Set(["process"]);                           // the emitters every file shares by name

// What the follower reads of the received-code detector's data (core's
// _DL_* values, from the native engine's rule pack; the detector itself,
// receivedCodeKind, is the engine's), read once, when first needed.
let dlData = null;
function DL() {
  if (dlData === null) {
    const [source, chain, str, name, space, needles, runNeedles, longRow, reasons] = packValues(
      "_DL_SOURCE", "_DL_CHAIN_RE", "_DL_STR_RE", "_DL_NAME_RE", "_XF_SPACE_RE", "_DL_NEEDLES", "_DL_RUN_NEEDLES",
      "_DL_LONG_ROW", "_DL_CATEGORY_REASON");
    dlData = {
      source: pyRe(source[0].re, source[0].flags),             // (the exact pattern of core's pair)
      chain: pyRe(chain.re, chain.flags + "g"),
      str: pyRe(str.re, str.flags + "g"),
      name: pyRe(`^(?:${name.re})$`, name.flags),
      space: pyRe(space.re, space.flags + "g"),
      needles, runNeedles, longRow, reasons,
    };
  }
  return dlData;
}
/** Does `expr` hold a value received over the network? (core._xf_has_source) */
const hasSource = (expr) => DL().source.test(expr);
/** The member chains named in `expr` (a, a.b.c), spaces taken out (core._xf_chains). */
function chainsOf(expr) {
  const { chain, space } = DL();
  const out = new Set();
  for (const m of expr.matchAll(chain)) out.add(m[0].replace(space, ""));
  return out;
}
/**
 * `row` with each string literal's contents blanked, its quotes kept
 * (core._xf_js_mask_line). Blanked by UTF-16 unit, so the row keeps its
 * length in units and offsets into it are the row's; core blanks by code
 * point — only a count of spaces differs, which no pattern read on it counts.
 */
const maskStrings = (row) =>
  row.replace(DL().str, (s) => (s.length >= 2 ? s[0] + " ".repeat(s.length - 2) + s[s.length - 1] : s));
/** Is `s` one identifier? (core: _DL_NAME_RE.fullmatch) */
const isName = (s) => DL().name.test(s);
const DEP_MARKERS = ["site-packages", "dist-packages", "vendor"];
const JS_KEYWORDS = new Set(["if", "for", "while", "switch", "catch", "function", "return", "do", "else", "with",
  "constructor", "class"]);
const NOT_PARAMS = new Set(["self", "cls", "this", "async"]);
const OBJECT_WORDS = ["const", "let", "var", "module", "export"];   // what _XF_JS_OBJECT_RE needs

/** The parity test's view of the twins: core's pattern text and flags, name sets and limits. */
export const XF_TWINS = {
  patterns: XF_PATTERNS,
  sets: { _XF_DEP_MARKERS: DEP_MARKERS, _XF_JS_KEYWORDS: [...JS_KEYWORDS], _XF_NOT_PARAMS: [...NOT_PARAMS],
    _XF_EMIT_GLOBALS: [...EMIT_GLOBALS] },
  limits: XF_LIMITS,
};

/** re.M's ^ and $ as Python reads them (at "\n" only; JavaScript's m flag also anchors at \r, U+2028 and U+2029). */
function multiline(src) {
  let out = "";
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === "\\") { out += c + src[++i]; continue; }
    if (c === "[") {                                    // a class: copied whole (] first is literal)
      let j = i + 1;
      if (src[j] === "^") j++;
      if (src[j] === "]") j++;
      while (j < src.length && src[j] !== "]") j += src[j] === "\\" ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j;
      continue;
    }
    out += c === "^" ? "(?<![^\\n])" : c === "$" ? "(?![^\\n])" : c;
  }
  return out;
}

/** A follower pattern, compiled with Python semantics; `extra` adds JS flags (g, y). */
function xfRe(name, extra = "") {
  const [src, flags] = XF_PATTERNS[name];
  const text = (flags.includes("m") ? multiline(src) : src).replaceAll("(?P<", "(?<");
  return pyRe(text, flags.replace("m", "") + extra);
}

const RX = Object.fromEntries(Object.keys(XF_PATTERNS).map((n) => [n, { g: xfRe(n, "g"), y: xfRe(n, "y") }]));

/** re.match(s, pos): a match starting at pos, else null. */
function match(name, s, pos = 0) {
  const rx = RX[name].y;
  rx.lastIndex = pos;
  return rx.exec(s);
}
/** re.search(s, pos). */
function search(name, s, pos = 0) {
  const rx = RX[name].g;
  rx.lastIndex = pos;
  return rx.exec(s);
}
/** re.finditer(s). (matchAll starts where the regex's lastIndex is: search() leaves it past its match.) */
function finditer(name, s) {
  const rx = RX[name].g;
  rx.lastIndex = 0;
  return s.matchAll(rx);
}

const end = (m) => m.index + m[0].length;

// Patterns whose group offsets core reads (m.start("rhs") and the like): compiled with the d flag.
const RXD = Object.fromEntries(["_XF_JS_CONST_RE", "_XF_JS_FIELD_RE", "_XF_JS_MODEXP_PROP_RE", "_XF_PY_ENV_WRITE_RE",
  "_XF_JS_ENV_WRITE_RE", "_XF_JS_METHOD_RE", "_XF_JS_MEMBER_RE"].map((n) => [n, { g: xfRe(n, "gd"), y: xfRe(n, "yd") }]));
function matchD(name, s, pos = 0) {
  const rx = RXD[name].y;
  rx.lastIndex = pos;
  return rx.exec(s);
}
function searchD(name, s, pos = 0) {
  const rx = RXD[name].g;
  rx.lastIndex = pos;
  return rx.exec(s);
}
function finditerD(name, s) {
  const rx = RXD[name].g;
  rx.lastIndex = 0;
  return s.matchAll(rx);
}

// ---- Python str details --------------------------------------------------

/** len(s) > n, in code points. */
const longer = (s, n) => s.length > n && (s.length > 2 * n || cpLen(s) > n);
/** str.split() (no argument): runs of Python whitespace, no empty strings. */
function pySplit(s) {
  const out = [];
  let word = "";
  for (const ch of s) {
    if (isPySpace(ch)) { if (word) out.push(word); word = ""; } else word += ch;
  }
  if (word) out.push(word);
  return out;
}
/** str.strip(chars). */
function stripChars(s, chars) {
  let a = 0, b = s.length;
  while (a < b && chars.includes(s[a])) a++;
  while (b > a && chars.includes(s[b - 1])) b--;
  return s.slice(a, b);
}
/** str.rstrip(chars). */
function rstripChars(s, chars) {
  let b = s.length;
  while (b > 0 && chars.includes(s[b - 1])) b--;
  return s.slice(0, b);
}
/** str.ljust(n): padded with spaces to n code points. */
const ljust = (s, n) => s + " ".repeat(Math.max(0, n - cpLen(s)));
/** str.count("\n", 0, end). */
function newlinesBefore(s, stop) {
  let n = 0;
  for (let i = s.indexOf("\n"); i >= 0 && i < stop; i = s.indexOf("\n", i + 1)) n++;
  return n;
}
/** re.escape for a name of the follower's (an identifier or a member chain); a backslash too, as re.escape does. */
const escapeName = (n) => n.replace(/[\\$.]/g, "\\$&");
const sortCp = (xs) => [...xs].sort(cmpCodePoints);
const posix = (p) => (sep === "/" ? p : p.split(sep).join("/"));    // core: path.replace(os.sep, "/")

// posixpath, for relative paths
function dirname(p) {
  let head = p.slice(0, p.lastIndexOf("/") + 1);
  if (head && !/^\/+$/.test(head)) head = head.replace(/\/+$/, "");
  return head;
}
function join(a, b) {
  if (b.startsWith("/")) return b;
  if (!a || a.endsWith("/")) return a + b;
  return a + "/" + b;
}
function normpath(path) {
  if (!path) return ".";
  let initial = path.startsWith("/") ? 1 : 0;
  if (initial && path.startsWith("//") && !path.startsWith("///")) initial = 2;
  const comps = [];
  for (const comp of path.split("/")) {
    if (comp === "" || comp === ".") continue;
    if (comp !== ".." || (!initial && !comps.length) || (comps.length && comps[comps.length - 1] === "..")) comps.push(comp);
    else if (comps.length) comps.pop();
  }
  return ("/".repeat(initial) + comps.join("/")) || ".";
}

// ---- what a body holds ----------------------------------------------------

/** {name: [source, refs]} of assignments [[name, rhs]], merged per name, each read when reached. core._XfLocals. */
class Locals {
  constructor(pairs) {
    this.rhs = new Map();
    this.done = new Map();
    for (const [name, rhs] of pairs) {
      if (!this.rhs.has(name)) this.rhs.set(name, []);
      this.rhs.get(name).push(rhs);
    }
  }
  has(name) { return this.rhs.has(name); }
  get(name) {
    let got = this.done.get(name);
    if (got === undefined) {
      let source = false;
      const refs = new Set();
      for (const rhs of this.rhs.get(name)) {
        source = source || hasSource(rhs);
        for (const c of chainsOf(rhs)) refs.add(c);
      }
      got = [source, refs];
      this.done.set(name, got);
    }
    return got;
  }
}
const localsOf = (pairs) => new Locals(pairs);

/** [source, refs] of expressions, their local names followed LOCAL_DEPTH deep. core._xf_follow. */
function follow(exprs, locals) {
  let source = false;
  const refs = new Set();
  for (const expr of exprs) {
    source = source || hasSource(expr);
    for (const c of chainsOf(expr)) refs.add(c);
  }
  let frontier = new Set([...refs].map((c) => c.split(".")[0]));
  const seen = new Set(frontier);
  for (let round = 0; round < LOCAL_DEPTH; round++) {
    const nxt = new Set();
    for (const name of frontier) {
      if (!locals.has(name)) continue;
      const got = locals.get(name);
      source = source || got[0];
      for (const c of got[1]) {
        refs.add(c);
        const head = c.split(".")[0];
        if (!seen.has(head)) nxt.add(head);
      }
    }
    for (const n of nxt) seen.add(n);
    frontier = nxt;
    if (!frontier.size) break;
  }
  return [source, refs];
}

/** Does a body that receives a value hand it to a callback: a parameter it calls, or a Promise's resolve? core._xf_delivers. */
function delivers(body, params) {
  if (!body.some((row) => DL().needles.some((n) => row.includes(n)) && hasSource(row))) return false;
  const names = new Set(params);
  for (const row of body) {
    if (row.includes("Promise")) for (const m of finditer("_XF_PROMISE_RE", row)) names.add(m.groups.name);
  }
  for (const n of NOT_PARAMS) names.delete(n);
  if (!names.size) return false;
  return body.some((row) => [...finditer("_XF_CALL_NAME_RE", row)].some((m) => names.has(m.groups.name)));
}

/** [source, refs] of a body (core._xf_ret). */
function ret(returns, localRows, body = [], params = []) {
  const got = follow(returns, localsOf(localRows));
  if (!got[0] && body.length && delivers(body, params)) got[0] = true;
  return got;
}

/** The parameter names of the function whose header starts at column `at` of `row`. core._xf_params. */
function paramsAt(row, at) {
  const one = match("_XF_ARROW_ONE_RE", row, at);
  if (one !== null) return [one.groups.name];
  const i = row.indexOf("(", at);
  const m = i >= 0 ? match("_XF_PARAMS_RE", row, i) : null;
  if (m === null) return [];
  const out = [];
  for (const item of m.groups.params.split(",")) {
    const p = match("_XF_PARAM_NAME_RE", item);
    if (p !== null) out.push(p.groups.name);
  }
  return out;
}

// ---- a module -------------------------------------------------------------

class XfModule {
  constructor(key, lang, path, text) {
    this.key = key; this.lang = lang; this.path = path; this.text = text;
    this.defs = new Map();          // name -> [source, refs]
    this.classes = new Map();       // class or object literal -> Map(member -> [[source, refs], static])
    this.imports = new Map();       // local name -> [module key|null, imported name|null, kind, label]
    this.exports = new Map();       // npm: exported name -> local name, or ["ref", chain]
    this.reexports = new Map();     // npm: exported name -> [module key|null, name|null]
    this.stars = [];                // npm: module keys of `export * from`
    this.default = null;            // npm: the default export's local name, or "<default>"
    this.defaultModule = null;      // npm: module.exports = require(…)'s module key
    this.env = new Map();           // environment variable -> [source, refs]
    this.bodies = new Map();        // symbol -> [params, body rows] of a function that names a code runner
  }
}

const merge = (a, b) => [a[0] || b[0], new Set([...a[1], ...b[1]])];
const setdefault = (map, k, v) => { if (!map.has(k)) map.set(k, v); };

/** Add (or merge into) member `name` of class or object literal `cls`. core._xf_member. */
function member(mod, cls, name, value, isStatic) {
  if (!mod.classes.has(cls)) mod.classes.set(cls, new Map());
  const meths = mod.classes.get(cls);
  const old = meths.get(name);
  meths.set(name, old === undefined ? [value, isStatic] : [merge(old[0], value), old[1]]);
}

/** Keep a function's body for the runner test when it names a code runner. core._xf_body. */
function keepBody(mod, sym, params, body) {
  if (params.length && !mod.bodies.has(sym) && body.some((row) => DL().runNeedles.some((n) => row.includes(n)))) {
    mod.bodies.set(sym, [params, body]);
  }
}

/** Is `cls` an object literal (its members are all static)? core._xf_is_object. */
function isObject(mod, cls) {
  const meths = mod.classes.get(cls);
  return meths !== undefined && meths.size > 0 && [...meths.values()].every(([, st]) => st);
}

/** The writes into a member of a module-level name or of an instance, read like assignments. core._xf_writes. */
function writes(mod, masked, orig, rowCls, lang) {
  const found = [];
  for (let k = 0; k < masked.length; k++) {
    const row = masked[k];
    if (!row.includes("=") || (!row.includes(".") && !row.includes("[")) || longer(orig[k], DL().longRow)) continue;
    for (const m of finditer("_XF_MEMBER_WRITE_RE", row)) {
      const { name, attr, rhs } = m.groups;
      if (name === "self" || name === "this" || name === "cls") {
        if (attr === undefined || rowCls[k] === null) continue;
        found.push([["member", rowCls[k], attr], rhs]);
      } else if (attr !== undefined && mod.classes.has(name)) {
        found.push([["member", name, attr], rhs]);
      } else if (mod.defs.has(name)) {
        found.push([["def", name], rhs]);
      }
    }
  }
  if (!found.length) return;
  const pairs = [];
  for (let k = 0; k < masked.length; k++) {
    const row = masked[k];
    if (!row.includes("=") || longer(orig[k], DL().longRow)) continue;
    if (lang === "py") {
      const a = match("_XF_ASSIGN_RE", row);
      if (a !== null) pairs.push([a.groups.name, a.groups.rhs]);
    } else {
      for (const m of finditer("_XF_JS_LOCAL_RE", row)) pairs.push([m.groups.name, m.groups.rhs]);
    }
  }
  const locals = localsOf(pairs);
  for (const [target, rhs] of found) {
    const value = follow([rhs], locals);
    if (target[0] === "member") member(mod, target[1], target[2], value, !mod.defs.has(target[1]) && isObject(mod, target[1]));
    else mod.defs.set(target[1], merge(mod.defs.get(target[1]), value));
  }
}

// ---- Python ---------------------------------------------------------------

// a string's body up to its closing quote, a backslash escaping (core._XF_PY_BODY_RE)
const PY_BODY = { "'": pyRe(String.raw`(?:[^\\']|\\.)*`, "y"), '"': pyRe(String.raw`(?:[^\\"]|\\.)*`, "y") };

/** `text`'s rows with string contents blanked and comments cut (core._xf_py_mask), by UTF-16 unit. */
function pyMask(text) {
  const out = [];
  let delim = null;
  for (const row of text.split("\n")) {
    const n = row.length;
    if (delim === null && !row.includes("#") && !row.includes("'") && !row.includes('"')) { out.push(row); continue; }
    const parts = [];
    let i = 0;
    if (delim !== null) {                               // inside a triple-quoted string
      const e = row.indexOf(delim);
      if (e < 0) { out.push(" ".repeat(n)); continue; }
      i = e + 3;
      parts.push(" ".repeat(i));
      delim = null;
    }
    while (i < n) {
      const m = search("_XF_PY_QUOTE_RE", row, i);
      if (m === null) { parts.push(row.slice(i)); break; }
      const j = m.index;
      parts.push(row.slice(i, j));
      const ch = row[j];
      if (ch === "#") { parts.push(" ".repeat(n - j)); break; }
      const three = row.slice(j, j + 3);
      if (three === "\'\'\'" || three === '"""') {
        const e = row.indexOf(three, j + 3);
        if (e < 0) { parts.push(" ".repeat(n - j)); delim = three; break; }
        parts.push(" ".repeat(e + 3 - j));
        i = e + 3;
        continue;
      }
      const body = PY_BODY[ch];
      body.lastIndex = j + 1;
      const k = j + 1 + body.exec(row)[0].length;
      if (k < n && row[k] === ch) { parts.push(ch + " ".repeat(k - j - 1) + ch); i = k + 1; }
      else { parts.push(ch + " ".repeat(n - j - 1)); break; }     // unterminated: to the end of the row
    }
    out.push(parts.join(""));
  }
  return out;
}

const indentOf = (row) => row.length - pyLstrip(row).length;

/** Fill `mod` from its Python text. core._xf_py_parse. */
function pyParse(mod, pkgParts) {
  if (longer(mod.text, MAX_CHARS)) return;
  const code = mod.text;
  const masked = pyMask(code);
  const orig = code.split("\n");
  const n = masked.length;
  const rowCls = new Array(n).fill(null);
  let cls = null, clsIndent = -1, bodyIndent = -1, k = 0;
  while (k < n) {
    const row = masked[k];
    if (!pyStrip(row)) { k++; continue; }
    const indent = indentOf(row);
    if (cls !== null && indent <= clsIndent) cls = null;
    if (cls !== null && bodyIndent < 0) bodyIndent = indent;
    const cm = row.includes("class") ? match("_XF_CLASS_RE", row) : null;
    if (cm !== null) {
      if (indent === 0) {
        cls = cm.groups.name; clsIndent = indent; bodyIndent = -1;
        if (!mod.classes.has(cls)) mod.classes.set(cls, new Map());
      }
      k++;
      continue;
    }
    const d = row.includes("def") ? match("_XF_DEF_RE", row) : null;
    if (d !== null && (indent === 0 || (cls !== null && indent > clsIndent))) {
      let j = k + 1;
      while (j < n && j - k <= WINDOW) {
        const r = masked[j];
        if (pyStrip(r) && indentOf(r) <= indent) break;
        j++;
      }
      const inline = search("_XF_DEF_END_RE", row, end(d));
      const tail = inline !== null ? row.slice(end(inline)) : "";
      const body = [...(inline !== null && pyStrip(tail) ? [tail] : []), ...masked.slice(k + 1, j)];
      const params = paramsAt(row, end(d) - 1);
      const returns = body.filter((r) => r.includes("return")).map((r) => match("_XF_RETURN_RE", r)).filter((m) => m !== null)
        .map((m) => m.groups.expr);
      const locals = body.filter((r) => r.includes("=")).map((r) => match("_XF_ASSIGN_RE", r)).filter((m) => m !== null)
        .map((m) => [m.groups.name, m.groups.rhs]);
      const value = ret(returns, locals, body, params);
      const name = d.groups.name;
      if (cls === null) {
        setdefault(mod.defs, name, value);
        keepBody(mod, name, params, body);
      } else {
        const isStatic = k > 0 && match("_XF_STATIC_RE", masked[k - 1]) !== null;
        member(mod, cls, name, value, isStatic);
        keepBody(mod, cls + "." + name, params, body);
        for (let t = k; t < j; t++) rowCls[t] = cls;
      }
      k = j;
      continue;
    }
    const a = row.includes("=") && (indent === 0 || (cls !== null && indent === bodyIndent)) ? match("_XF_ASSIGN_RE", row) : null;
    if (a !== null && !longer(orig[k].slice(a.index + a[0].length - a.groups.rhs.length), DL().longRow)) {
      const value = [hasSource(a.groups.rhs), chainsOf(a.groups.rhs)];
      if (indent === 0) setdefault(mod.defs, a.groups.name, value);
      else if (cls !== null && indent === bodyIndent) member(mod, cls, a.groups.name, value, true);
    }
    k++;
  }
  const joined = masked.join("\n");
  for (const m of finditer("_XF_FROM_RE", joined)) {
    const target = resolvePy(m.groups.mod, pkgParts);
    const names = pyStrip(m.groups.names);
    if (names === "*") {
      setdefault(mod.imports, "*" + (target ?? ""), [target, "*", "star", target]);
      continue;
    }
    for (const item of stripChars(names, "()").split(",")) {
      const parts = pySplit(item);
      if (!parts.length) continue;
      const local = parts.length === 3 && parts[1] === "as" ? parts[2] : parts[0];
      mod.imports.set(local, [target, parts[0], "name", target]);
    }
  }
  for (const m of finditer("_XF_IMPORT_RE", joined)) {
    for (const item of m.groups.names.split(",")) {
      const parts = pySplit(item);
      if (!parts.length) continue;
      const local = parts.length === 3 && parts[1] === "as" ? parts[2] : parts[0];
      mod.imports.set(local, [parts[0], null, "module", parts[0]]);
    }
  }
  if (code.includes("import_module") || code.includes("__import__")) {
    for (let r = 0; r < orig.length; r++) {
      const row = orig[r];
      if (!row.includes("import") || longer(row, DL().longRow)) continue;
      for (const m of finditer("_XF_PY_DYN_IMPORT_RE", row)) {
        if (masked[r][m.index] !== row[m.index]) continue;          // in a comment or a docstring
        const target = resolvePy(m.groups.mod, pkgParts);
        if (target === null) continue;
        const local = m.groups.local;
        const parts = target.split(".");
        if (m.groups.fn === "__import__" && !m.groups.rest.includes("fromlist") && parts.length > 1) {
          mod.imports.set(local, [parts[0], null, "module", parts[0]]);
          for (let i = 2; i <= parts.length; i++) {
            const sub = parts.slice(0, i).join(".");
            mod.imports.set(local + sub.slice(parts[0].length), [sub, null, "module", sub]);
          }
        } else {
          mod.imports.set(local, [target, null, "module", target]);
        }
      }
    }
  }
  for (let r = 0; r < orig.length; r++) {
    const row = orig[r];
    if (!row.includes("environ") || longer(row, DL().longRow)) continue;
    for (const m of finditerD("_XF_PY_ENV_WRITE_RE", row)) {
      if (masked[r][m.index] !== row[m.index]) continue;            // in a comment or a docstring
      const [a, b] = m.indices.groups.rhs;
      const rhs = masked[r].slice(a, b);
      const old = mod.env.get(m.groups.var) ?? [false, new Set()];
      mod.env.set(m.groups.var, [old[0] || hasSource(rhs), new Set([...old[1], ...chainsOf(rhs)])]);
    }
  }
  writes(mod, masked, orig, rowCls, "py");
}

// ---- JavaScript -----------------------------------------------------------

/** [rows, end]: the rows of the brace body that starts at the first "{" at or after column `at` of row k. core._xf_js_body. */
function jsBody(masked, k, at) {
  const first = masked[k].indexOf("{", at);
  if (first < 0) return [[], k];
  const rows = [];
  let depth = 0;
  const stop = Math.min(masked.length, k + WINDOW + 1);
  for (let j = k; j < stop; j++) {
    const row = j === k ? masked[j].slice(first) : masked[j];
    let cut = null;
    for (let i = 0; i < row.length; i++) {
      const c = row[i];
      if (c !== "{" && c !== "}") continue;
      depth += c === "{" ? 1 : -1;
      if (depth === 0) { cut = i + 1; break; }
    }
    rows.push(cut === null ? row : row.slice(0, cut));
    if (cut !== null) return [rows, j];
  }
  return [rows, stop - 1];
}

function jsRet(rows, params = []) {
  const returns = [], locals = [];
  for (const row of rows) for (const m of finditer("_XF_JS_RETURN_RE", row)) returns.push(m.groups.expr);
  for (const row of rows) for (const m of finditer("_XF_JS_LOCAL_RE", row)) locals.push([m.groups.name, m.groups.rhs]);
  return ret(returns, locals, rows, params);
}

/** [[source, refs], params, body rows] of the function whose header starts at column `at` of row k. core._xf_js_fn. */
function jsFn(masked, k, at) {
  const row = masked[k];
  const params = paramsAt(row, at);
  const arrow = row.indexOf("=>", at);
  const brace = row.indexOf("{", at);
  if (arrow >= 0 && (brace < 0 || arrow < brace)) {
    const rest = pyLstrip(row.slice(arrow + 2));
    if (!rest.startsWith("{")) return [ret([rest], [], [rest], params), params, [rest]];
    const [body] = jsBody(masked, k, arrow);
    return [jsRet(body, params), params, body];
  }
  const [body] = jsBody(masked, k, at);
  return [jsRet(body, params), params, body];
}

/** [[export/property name, local name]] for a `{ a, b as c, d: e, 'f': g }` list. core._xf_js_destr. */
function destr(names) {
  const out = [];
  for (const item of names.split(",")) {
    const parts = pySplit(item.replaceAll(":", " ").replaceAll(" as ", " ")).map((p) => stripChars(p, "'\"`")).filter((p) => p);
    if (parts.length === 1) out.push([parts[0], parts[0]]);
    else if (parts.length >= 2) out.push([parts[0], parts[1]]);
  }
  return out;
}

/** [rowClass, rowLevel] per masked row. core._xf_js_row_classes. */
function rowClasses(rows) {
  const rowClass = new Array(rows.length).fill(null), rowLevel = new Array(rows.length).fill(0);
  let depth = 0, pending = null;
  const stack = [];
  for (let k = 0; k < rows.length; k++) {
    const row = rows[k];
    if (stack.length) { rowClass[k] = stack[stack.length - 1][0]; rowLevel[k] = depth - stack[stack.length - 1][1]; }
    if (!row.includes("{") && !row.includes("}") && !row.includes("class")) continue;
    const events = [];
    for (const m of finditer("_XF_JS_CLASS_RE", row)) events.push([m.index, "c", m.groups.name]);
    for (let i = 0; i < row.length; i++) if (row[i] === "{" || row[i] === "}") events.push([i, row[i], null]);
    // Python sorts the tuples: position, then kind ("c" < "{" < "}")
    events.sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
    for (const [, kind, name] of events) {
      if (kind === "c") pending = name;
      else if (kind === "{") {
        if (pending !== null) { stack.push([pending, depth]); pending = null; }
        depth++;
      } else {
        depth--;
        if (stack.length && stack[stack.length - 1][1] === depth) stack.pop();
      }
    }
  }
  return [rowClass, rowLevel];
}

/** A package-relative JS path as a module key. core._xf_js_norm. */
function jsNorm(rel) {
  for (const ext of [".js", ".cjs", ".mjs", ".jsx", ".json"]) {
    if (rel.endsWith(ext)) { rel = rel.slice(0, -ext.length); break; }
  }
  return rel.endsWith("/index") ? rel.slice(0, -6) : rel;
}

/** The module key a relative import `spec` of the file `rel` names, else null. core._xf_js_key. */
function jsKey(rel, spec) {
  if (!spec.startsWith(".")) return null;
  const key = jsNorm(normpath(join(dirname(rel), spec)));
  return key === "." ? "index" : key;
}

/** [code rows, masked rows] of a JavaScript text (core._xf_js_views), by UTF-16 unit. */
function jsViews(text) {
  const code = [], masked = [];
  let inBlock = false;
  for (const src of text.split("\n")) {
    if (longer(src, DL().longRow)) { code.push(""); masked.push(""); continue; }
    let m = src.includes("'") || src.includes('"') || src.includes("`") ? maskStrings(src) : src, row = src;
    if (!inBlock && !m.includes("/")) { code.push(row); masked.push(m); continue; }   // (no comment starts on it)
    const spans = [];
    let i = 0;
    while (i <= m.length) {
      if (inBlock) {
        const e = m.indexOf("*/", i);
        if (e < 0) { spans.push([i, m.length]); break; }
        spans.push([i, e + 2]);
        i = e + 2; inBlock = false;
        continue;
      }
      const a = m.indexOf("/*", i);
      const lc = search("_XF_JS_LINE_COMMENT_RE", m, i);
      if (lc !== null && (a < 0 || lc.index < a)) { spans.push([lc.index, m.length]); break; }
      if (a < 0) break;
      const e = m.indexOf("*/", a + 2);
      if (e < 0) { spans.push([a, m.length]); inBlock = true; break; }
      spans.push([a, e + 2]);
      i = e + 2;
    }
    for (const [a, b] of spans) {
      m = m.slice(0, a) + " ".repeat(b - a) + m.slice(b);
      row = row.slice(0, a) + " ".repeat(b - a) + row.slice(b);
    }
    code.push(row);
    masked.push(m);
  }
  return [code, masked];
}

/** `code` with each path built from __dirname written as the relative specifier it is. core._xf_js_dirname_specs. */
function dirnameSpecs(code) {
  return code.replace(RX._XF_JS_DIRNAME_RE.g, (...args) => {
    const g = args[args.length - 1], whole = args[0];
    let rel = g.a !== undefined ? g.a : (g.b || g.c).slice(1);
    while (rel.startsWith("./")) rel = rel.slice(2);
    const fresh = "'./" + rel.replace(/^\/+/, "") + "'";
    return cpLen(fresh) <= cpLen(whole) ? fresh + " ".repeat(whole.length - fresh.length) : whole;
  });
}

/** Read the object literal whose "{" is at column `at` of row k as `cls`. core._xf_js_object. */
function jsObject(mod, rows, masked, k, at, cls) {
  let count = 0, depth = 0, expect = false;
  const stop = Math.min(masked.length, k + OBJECT_ROWS);
  for (let j = k; j < stop; j++) {
    const row = masked[j], codeRow = rows[j];
    const n = row.length;
    for (let i = j === k ? at : 0; i < n; i++) {
      const ch = row[i];
      if (expect && depth === 1 && ch !== " " && ch !== "\t") {
        expect = false;
        const m = matchD("_XF_JS_MEMBER_RE", codeRow, i);
        if (m !== null) {
          const name = m.groups.name;
          let value;
          if (m.groups.method !== undefined) {
            const [v, params, body] = jsFn(masked, j, m.indices.groups.name[0]);
            value = v;
            keepBody(mod, cls + "." + name, params, body);
          } else if (m.groups.colon !== undefined) {
            const rest = row.slice(end(m));
            if (match("_XF_JS_FN_VALUE_RE", pyLstrip(rest)) !== null) {
              const [v, params, body] = jsFn(masked, j, end(m));
              value = v;
              keepBody(mod, cls + "." + name, params, body);
            } else {
              const expr = rest.split(",")[0];
              value = [hasSource(expr), chainsOf(expr)];
            }
          } else {
            value = [false, new Set([name])];
          }
          member(mod, cls, name, value, true);
          count++;
        }
      }
      if (ch === "{" || ch === "(" || ch === "[") {
        depth++;
        if (depth === 1) expect = true;
      } else if (ch === "}" || ch === ")" || ch === "]") {
        depth--;
        if (depth <= 0) return count;
      } else if (ch === "," && depth === 1) {
        expect = true;
      }
    }
  }
  return count;
}

/** The 0-based row and column of offset `at` of `code`. */
function rowCol(code, at) {
  return [newlinesBefore(code, at), at - (code.lastIndexOf("\n", at - 1) + 1)];
}

/** Fill `mod` from its JavaScript text. core._xf_js_parse. */
function jsParse(mod, rel) {
  if (longer(mod.text, MAX_CHARS)) return;
  const [rows, masked] = jsViews(mod.text);
  let code = rows.join("\n");
  if (code.includes("__dirname")) code = dirnameSpecs(code);
  const [rowClass, rowLevel] = rowClasses(masked);
  const objects = new Map();                           // row -> the const an object literal there is read as
  for (let k = 0; k < masked.length; k++) {
    const row = masked[k];
    if (!row.includes("{") || rowClass[k] !== null || !OBJECT_WORDS.some((w) => row.includes(w))) continue;
    for (const m of finditer("_XF_JS_OBJECT_RE", row)) {
      const name = m.groups.name;
      const cls = name !== undefined ? name : m[0].includes("module") ? "<exports>" : "<default>";
      if (jsObject(mod, rows, masked, k, end(m) - 1, cls) && name !== undefined) objects.set(k, name);
    }
  }
  for (let k = 0; k < masked.length; k++) {
    const row = masked[k];
    const cls = rowClass[k];
    for (const m of row.includes("function") ? finditer("_XF_JS_FUNC_RE", row) : []) {
      if (!mod.defs.has(m.groups.name)) {
        const [value, params, body] = jsFn(masked, k, m.index);
        mod.defs.set(m.groups.name, value);
        keepBody(mod, m.groups.name, params, body);
      }
    }
    if (cls !== null) {
      for (const m of row.includes("{") && row.includes(")") ? finditerD("_XF_JS_METHOD_RE", row) : []) {
        const name = m.groups.name;
        if (JS_KEYWORDS.has(name)) continue;
        const [value, params, body] = jsFn(masked, k, m.indices.groups.name[0]);
        member(mod, cls, name, value, m.groups.static !== undefined);
        keepBody(mod, cls + "." + name, params, body);
      }
      if (rowLevel[k] === 1 && row.includes("=")) {
        const f = matchD("_XF_JS_FIELD_RE", row);
        if (f !== null && !JS_KEYWORDS.has(f.groups.name)) {
          const rhs = f.groups.rhs, name = f.groups.name;
          let value;
          if (match("_XF_JS_FN_VALUE_RE", pyLstrip(rhs)) !== null) {
            const [v, params, body] = jsFn(masked, k, f.indices.groups.rhs[0]);
            value = v;
            keepBody(mod, cls + "." + name, params, body);
          } else {
            value = [hasSource(rhs), chainsOf(rhs)];
          }
          member(mod, cls, name, value, f.groups.static !== undefined);
        }
      }
      continue;
    }
    const cm = row.includes("class") ? search("_XF_JS_CLASS_RE", row) : null;
    if (cm !== null && !mod.classes.has(cm.groups.name)) mod.classes.set(cm.groups.name, new Map());
    const m = row.includes("=") && (row.includes("const") || row.includes("let") || row.includes("var"))
      ? searchD("_XF_JS_CONST_RE", row) : null;
    if (m !== null && objects.get(k) !== m.groups.name) {
      const rhs = m.groups.rhs;
      if (match("_XF_JS_FN_VALUE_RE", pyLstrip(rhs)) !== null) {
        const [value, params, body] = jsFn(masked, k, m.indices.groups.rhs[0]);
        setdefault(mod.defs, m.groups.name, value);
        keepBody(mod, m.groups.name, params, body);
      } else {
        setdefault(mod.defs, m.groups.name, [hasSource(rhs), chainsOf(rhs)]);
      }
    }
  }
  // (each pattern is tried only where the words it needs are, as core's)
  const esm = ["export ", "export\t", "export{", "export*"].some((w) => code.includes(w));
  const when = (cond, name, d = false) => (cond ? (d ? finditerD(name, code) : finditer(name, code)) : []);
  for (const m of when(esm, "_XF_JS_EXPORT_DECL_RE")) mod.exports.set(m.groups.name, m.groups.name);
  for (const m of when(esm && code.includes("default"), "_XF_JS_EXPORT_DEFAULT_DECL_RE")) {
    const name = m.groups.fn || m.groups.cls;
    if (name) mod.default = name;
    else if (m[0].includes("function")) {
      const [k, at] = rowCol(code, m.index);
      const [value, params, body] = jsFn(masked, k, at);
      mod.defs.set("<default>", value);
      keepBody(mod, "<default>", params, body);
      mod.default = "<default>";
    }
  }
  for (const m of when(esm && code.includes("default"), "_XF_JS_EXPORT_DEFAULT_RE")) mod.default = m.groups.name;
  if (mod.classes.has("<default>") && mod.default === null) mod.default = "<default>";
  for (const m of when(esm, "_XF_JS_EXPORT_LIST_RE")) {
    for (const [local, exported] of destr(m.groups.names)) mod.exports.set(exported, local);
  }
  for (const m of when(esm && code.includes("from"), "_XF_JS_EXPORT_FROM_RE")) {
    const key = jsKey(rel, m.groups.mod);
    for (const [name, exported] of destr(m.groups.names)) mod.reexports.set(exported, [key, name]);
  }
  for (const m of when(esm && code.includes("from"), "_XF_JS_EXPORT_STAR_RE")) {
    const key = jsKey(rel, m.groups.mod);
    if (m.groups.ns) mod.reexports.set(m.groups.ns, [key, null]);
    else if (key !== null) mod.stars.push(key);
  }
  for (const name of (mod.classes.get("<exports>") ?? new Map()).keys()) setdefault(mod.exports, name, ["ref", "<exports>." + name]);
  const cjs = code.includes("module");
  for (const m of when(cjs, "_XF_JS_MODEXP_OBJ_RE")) {
    for (const [exported, local] of destr(m.groups.names)) mod.exports.set(exported, local);
  }
  for (const m of when(code.includes("exports"), "_XF_JS_MODEXP_PROP_RE", true)) {
    const name = m.groups.name || m.groups.qname;
    const rhs = pyStrip(rstripChars(pyStrip(m.groups.rhs), ";"));
    if (rhs === "void 0" || rhs === "undefined") continue;
    if (isName(rhs)) { mod.exports.set(name, rhs); continue; }
    const [k, at] = rowCol(code, m.indices.groups.rhs[0]);
    const local = "exports." + name;
    if (match("_XF_JS_FN_VALUE_RE", rhs) !== null) {
      const [value, params, body] = jsFn(masked, k, at);
      mod.defs.set(local, value);
      keepBody(mod, local, params, body);
    } else {
      const expr = k < masked.length ? masked[k].slice(at) : rhs;
      mod.defs.set(local, [hasSource(expr), chainsOf(expr)]);
    }
    mod.exports.set(name, local);
  }
  for (const m of when(cjs, "_XF_JS_MODEXP_ALL_RE")) mod.default = m.groups.name;
  for (const m of when(cjs && code.includes("class"), "_XF_JS_MODEXP_CLASS_RE")) mod.default = m.groups.name;
  for (const m of when(cjs && code.includes("require("), "_XF_JS_MODEXP_REQ_RE")) mod.defaultModule = jsKey(rel, m.groups.mod);
  for (const m of when(cjs, "_XF_JS_MODEXP_FN_RE")) {
    const [k, at] = rowCol(code, end(m));
    const [value, params, body] = jsFn(masked, k, at);
    mod.defs.set("<default>", value);
    keepBody(mod, "<default>", params, body);
    mod.default = "<default>";
  }
  for (const m of when(code.includes("defineProperty"), "_XF_JS_DEFINE_RE")) {
    setdefault(mod.exports, m.groups.name, ["ref", m.groups.ref.replace(RX._XF_SPACE_RE.g, "")]);
  }
  const req = code.includes("require("), dyn = code.includes("import("), imp = code.includes("import") && code.includes("from");
  for (const name of [...(req ? ["_XF_JS_REQ_DESTR_RE"] : []), ...(dyn ? ["_XF_JS_DYN_DESTR_RE"] : [])]) {
    for (const m of finditer(name, code)) {
      const key = jsKey(rel, m.groups.mod);
      for (const [exp, local] of destr(m.groups.names)) mod.imports.set(local, [key, exp, "name", m.groups.mod]);
    }
  }
  for (const name of [...(req ? ["_XF_JS_REQ_NS_RE"] : []), ...(dyn ? ["_XF_JS_DYN_NS_RE"] : [])]) {
    for (const m of finditer(name, code)) mod.imports.set(m.groups.ns, [jsKey(rel, m.groups.mod), null, "module", m.groups.mod]);
  }
  for (const m of when(req, "_XF_JS_REQ_MEMBER_RE")) {
    mod.imports.set(m.groups.local, [jsKey(rel, m.groups.mod), m.groups.name, "name", m.groups.mod]);
  }
  for (const m of when(imp, "_XF_JS_IMP_NAMED_RE")) {
    const key = jsKey(rel, m.groups.mod);
    for (const [exp, local] of destr(m.groups.names)) mod.imports.set(local, [key, exp, "name", m.groups.mod]);
  }
  for (const m of when(imp, "_XF_JS_IMP_NS_RE")) mod.imports.set(m.groups.ns, [jsKey(rel, m.groups.mod), null, "module", m.groups.mod]);
  for (const m of when(imp, "_XF_JS_IMP_DEFAULT_RE")) {
    mod.imports.set(m.groups.name, [jsKey(rel, m.groups.mod), "default", "default", m.groups.mod]);
  }
  for (let k = 0; k < rows.length; k++) {
    const row = rows[k];
    if (!row.includes("env")) continue;
    for (const m of finditerD("_XF_JS_ENV_WRITE_RE", row)) {
      const v = m.groups.a || m.groups.b;
      const [a, b] = m.indices.groups.rhs;
      const rhs = masked[k].slice(a, b);
      const old = mod.env.get(v) ?? [false, new Set()];
      mod.env.set(v, [old[0] || hasSource(rhs), new Set([...old[1], ...chainsOf(rhs)])]);
    }
  }
  writes(mod, masked, mod.text.split("\n"), rowClass, "js");
}

// ---- a package --------------------------------------------------------------

const symKey = (key, name) => key + "\u0000" + name;

class XfPackage {
  constructor(mods) { this.mods = mods; }

  resolveLocal(mod, name, depth = 0) {
    if (depth > MAX_DEPTH) return null;
    if (mod.defs.has(name)) return ["sym", [mod.key, name]];
    if (mod.classes.has(name)) return ["class", [mod.key, name]];
    const imp = mod.imports.get(name);
    if (imp !== undefined) return this.resolveImport(imp, depth + 1);
    return null;
  }

  resolveImport(imp, depth = 0) {
    const [key, name, kind] = imp;
    if (key === null) return null;
    if (!this.mods.has(key)) {                           // a namespace package: from . import mod
      const sub = kind === "name" && name ? `${key}.${name}` : null;
      return sub !== null && this.mods.has(sub) ? ["module", sub] : null;
    }
    if (kind === "module") return ["module", key];
    return this.resolveExport(key, name, depth + 1);
  }

  resolveExport(key, name, depth = 0) {
    const mod = this.mods.get(key);
    if (mod === undefined || depth > MAX_DEPTH) return null;
    if (mod.lang === "py") {
      const got = this.resolveLocal(mod, name, depth + 1);
      if (got !== null) return got;
      const sub = key + "." + name;
      return this.mods.has(sub) ? ["module", sub] : null;
    }
    if (name === "default") {
      if (mod.default !== null) return this.resolveLocal(mod, mod.default, depth + 1);
      if (mod.defaultModule !== null) return this.mods.has(mod.defaultModule) ? ["module", mod.defaultModule] : null;
    }
    const exp = mod.exports.get(name);
    if (Array.isArray(exp)) return this.resolveChain(mod, exp[1], null, depth + 1);
    if (exp !== undefined) return this.resolveLocal(mod, exp, depth + 1);
    const re = mod.reexports.get(name);
    if (re !== undefined) {
      if (re[0] === null) return null;
      return re[1] === null ? ["module", re[0]] : this.resolveExport(re[0], re[1], depth + 1);
    }
    for (const star of [...mod.stars, ...(mod.defaultModule ? [mod.defaultModule] : [])]) {
      const got = this.resolveExport(star, name, depth + 1);
      if (got !== null) return got;
    }
    if (mod.default !== null && name !== "default") return this.resolveChain(mod, mod.default + "." + name, null, depth + 1);
    return null;
  }

  resolveChain(mod, chain, cls, depth = 0) {
    const parts = chain.split(".");
    if (cls !== null && (parts[0] === "self" || parts[0] === "this" || parts[0] === "cls") && parts.length >= 2) {
      return (mod.classes.get(cls) ?? new Map()).has(parts[1]) ? ["sym", [mod.key, cls + "." + parts[1]]] : null;
    }
    let got = null, used = 0;
    for (let i = parts.length; i > 0; i--) {             // a dotted import (pkg._net) is one name
      const head = parts.slice(0, i).join(".");
      if (mod.imports.has(head) || (i === 1 && (mod.defs.has(head) || mod.classes.has(head)))) {
        got = this.resolveLocal(mod, head, depth + 1);
        used = i;
        break;
      }
    }
    let rest = parts.slice(used);
    while (got !== null && rest.length) {
      const [kind, val] = got;
      if (kind === "module") got = this.resolveExport(val, rest[0], depth + 1);
      else if (kind === "class") {
        const meths = this.mods.get(val[0]).classes.get(val[1]) ?? new Map();
        got = meths.has(rest[0]) ? ["sym", [val[0], val[1] + "." + rest[0]]] : null;
      } else return got;
      rest = rest.slice(1);
    }
    return got;
  }

  /** Map(symKey -> [mod, source, refs, cls, [key, name]]), at most MAX_SYMBOLS (per module, as core cuts). */
  symbols() {
    const out = new Map();
    for (const mod of this.mods.values()) {
      for (const [name, [source, refs]] of mod.defs) out.set(symKey(mod.key, name), [mod, source, refs, null, [mod.key, name]]);
      for (const [cls, meths] of mod.classes) {
        for (const [meth, [[source, refs]]] of meths) {
          out.set(symKey(mod.key, cls + "." + meth), [mod, source, refs, cls, [mod.key, cls + "." + meth]]);
        }
      }
      for (const [v, [source, refs]] of mod.env) {
        out.set(symKey(mod.key, "<env>." + v), [mod, source, refs, null, [mod.key, "<env>." + v]]);
      }
      if (out.size >= MAX_SYMBOLS) break;
    }
    return out;
  }

  /** Set of symKeys that hold a received value. core._XfPackage.tainted. */
  tainted() {
    const syms = this.symbols();
    const edges = new Map();
    for (const [sym, [mod, , refs, cls]] of syms) {
      const found = [];
      for (const chain of refs) {
        const got = this.resolveChain(mod, chain, cls);
        if (got !== null && got[0] === "sym") found.push(symKey(got[1][0], got[1][1]));
      }
      edges.set(sym, found);
    }
    const tainted = new Set([...syms].filter(([, v]) => v[1]).map(([s]) => s));
    for (let round = 0; round < ROUNDS; round++) {
      const grew = [...edges].filter(([sym, found]) => !tainted.has(sym) && found.some((f) => tainted.has(f))).map(([s]) => s);
      if (!grew.length) break;
      for (const s of grew) tainted.add(s);
    }
    return tainted;
  }

  /** Set of symKeys of the functions that run a parameter as code. core._XfPackage.runners. */
  runners() {
    const out = new Set();
    let count = 0;
    for (const mod of this.mods.values()) {
      for (const [sym, [params, body]] of mod.bodies) {
        const names = sortCp(new Set(params.filter((p) => !NOT_PARAMS.has(p))));
        if (!names.length) continue;
        count++;
        if (count > MAX_RUNNERS) return out;
        const res = receivedCodeKind(body.join("\n"), names);
        if (res !== null && res[1] === "run") out.add(symKey(mod.key, sym));
      }
    }
    return out;
  }

  namesOf(key, depth = 0) {
    const mod = this.mods.get(key);
    if (mod === undefined || depth > MAX_DEPTH) return new Set();
    if (mod.lang === "py") {
      return new Set([...mod.defs.keys(), ...mod.classes.keys(), ...[...mod.imports.keys()].filter((n) => !n.startsWith("*"))]);
    }
    const out = new Set([...mod.exports.keys(), ...mod.reexports.keys()]);
    for (const star of [...mod.stars, ...(mod.defaultModule ? [mod.defaultModule] : [])]) {
      for (const n of this.namesOf(star, depth + 1)) out.add(n);
    }
    return out;
  }
}

const INSTANCE_CACHE = new Map();
/** Local names (or self.c / this.c) assigned an instance of the class named by `expr`. core._xf_instances. */
function instances(text, expr, lang) {
  const key = lang + "\u0000" + expr;
  let rx = INSTANCE_CACHE.get(key);
  if (rx === undefined) {
    const nw = lang === "js" ? String.raw`(?:new[ \t]+)?` : "";
    rx = pyRe(String.raw`(?<![\w$.])(?<var>(?:(?:self|this)[ \t]*\.[ \t]*)?[A-Za-z_$][\w$]*)[ \t]*=[ \t]*` + nw
      + escapeName(expr) + String.raw`[ \t]*\(`, "g");
    if (INSTANCE_CACHE.size > 1000) INSTANCE_CACHE.clear();
    INSTANCE_CACHE.set(key, rx);
  }
  return new Set([...text.matchAll(rx)].map((m) => m.groups.var.replace(RX._XF_SPACE_RE.g, "")));
}

/** [Map(chain -> label), [[expr, member, label]]] for module `mod`. core._xf_seeds. */
function seedsOf(pkg, mod, marked, envs) {
  const seeds = new Map(), direct = [];
  const code = mod.text;
  const addClass = (expr, val, label) => {
    const [key, cls] = val;
    for (const [meth, [, isStatic]] of pkg.mods.get(key).classes.get(cls) ?? new Map()) {
      if (!marked.has(symKey(key, cls + "." + meth))) continue;
      if (isStatic) { seeds.set(expr + "." + meth, label); continue; }
      for (const v of sortCp(instances(code, expr, mod.lang))) seeds.set(v + "." + meth, label);
      direct.push([expr, meth, label]);
    }
  };
  const add = (expr, got, label, depth = 0) => {
    if (got === null || depth > 2) return;
    const [kind, val] = got;
    if (kind === "sym") {
      if (marked.has(symKey(val[0], val[1]))) seeds.set(expr, label);
    } else if (kind === "class") {
      addClass(expr, val, label);
    } else if (kind === "module") {
      for (const name of sortCp(pkg.namesOf(val)).slice(0, MAX_SEEDS * 4)) {
        const sub = pkg.resolveExport(val, name);
        if (sub !== null && sub[0] !== "module") add(expr + "." + name, sub, label, depth + 1);
      }
      if (pkg.mods.get(val)?.lang === "js") add(expr, pkg.resolveExport(val, "default"), label, depth + 1);
    }
  };
  for (const [local, imp] of mod.imports) {
    if (local.startsWith("*")) {
      if (pkg.mods.has(imp[0])) for (const name of sortCp(pkg.namesOf(imp[0]))) add(name, pkg.resolveExport(imp[0], name), imp[3]);
      continue;
    }
    let got = pkg.resolveImport(imp);
    if (got === null && mod.lang === "js" && imp[2] === "default" && pkg.mods.has(imp[0])) got = ["module", imp[0]];
    add(local, got, imp[3]);
  }
  for (const [v, label] of envs) {
    if (code.includes(v)) seeds.set((mod.lang === "py" ? "environ." : "process.env.") + v, label);
  }
  return [seeds, direct];
}

/** [code, Map(name -> label)]: each call of a method on a new instance read as one seeded name. core._xf_rewrite. */
function rewrite(code, direct, lang) {
  const names = new Map();
  direct.slice(0, MAX_SEEDS).forEach(([expr, meth, label], n) => {
    const nw = lang === "js" ? String.raw`(?:new[ \t]+)?` : "";
    const rx = pyRe(String.raw`(?<![\w$.])` + nw + escapeName(expr) + String.raw`[ \t]*\([^()\n]{0,200}\)[ \t]*\.[ \t]*`
      + escapeName(meth) + String.raw`(?![\w$])`, "g");
    const name = `_xf${n}`;
    let count = 0;
    code = code.replace(rx, (whole) => { count++; return ljust(name, cpLen(whole)); });
    if (count) names.set(name, label);
  });
  return [code, names];
}

// An event emitter between files (0.1.8): core's comment above _XF_EMIT_RE.
const reLiteral = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** What an emitter's name is in mod, the same in every file that names it (core._xf_emitter_of). */
function emitterOf(pkg, mod, name) {
  const imp = mod.imports.get(name);
  if (imp !== undefined) {
    const got = pkg.resolveImport(imp);
    return got !== null ? got : ["import", imp[0], imp[1]];
  }
  const got = pkg.resolveLocal(mod, name);
  if (got !== null) return got;
  return EMIT_GLOBALS.has(name) ? ["global", name] : null;       // this, a parameter: its file's own
}

const countNewlines = (s) => { let n = 0; for (let i = s.indexOf("\n"); i >= 0; i = s.indexOf("\n", i + 1)) n++; return n; };

/** finditer(name, text) for _XF_EMIT_RE (at: _XF_EMIT_AT_RE) and _XF_LISTEN_RE (_XF_LISTEN_AT_RE), read only where
 * `at` finds the member call a match makes: it starts where the identifier before that call's "." does, read by code
 * point as core reads [\w$] (core._xf_calls). */
function* calls(name, at, text) {
  let last = 0;
  for (const a of finditer(at, text)) {
    let k = a.index;
    while (k > 0 && (text[k - 1] === " " || text[k - 1] === "\t")) k--;
    let s = k;
    while (s > 0) {
      const c = text.charCodeAt(s - 1);
      const n = c >= 0xdc00 && c <= 0xdfff && s > 1 && (text.charCodeAt(s - 2) & 0xfc00) === 0xd800 ? 2 : 1;
      const ch = text.slice(s - n, s);
      if (ch !== "$" && !isWordChar(ch)) break;
      s -= n;
    }
    if (s === k || s < last) continue;                     // no identifier; inside the last match
    const m = match(name, text, s);
    if (m !== null) { last = end(m); yield m; }
  }
}

/** Map(module key -> [Map(name -> label), [rows], line]): the listeners given a received value another file emits
 * (core._xf_emitter_seeds). */
function emitterSeeds(pkg, tainted, envs) {
  const emits = new Map(), listens = new Map();
  for (const mod of pkg.mods.values()) {
    if (mod.lang !== "js" || !mod.text.includes(EMIT_NEEDLE)) continue;
    let k = 0;
    for (const m of calls("_XF_EMIT_RE", "_XF_EMIT_AT_RE", mod.text)) {
      if (k++ >= EMIT_MAX) break;
      const emitter = emitterOf(pkg, mod, m.groups.obj);
      if (emitter === null) continue;
      const chan = JSON.stringify([emitter, m.groups.event]);
      if (!emits.has(chan)) emits.set(chan, new Map());
      const byMod = emits.get(chan);
      if (!byMod.has(mod.key)) byMod.set(mod.key, []);
      byMod.get(mod.key).push(m);
    }
  }
  // a listener only matters for an event something emits: a file without any such event's name is not read
  const events = new Set([...emits.keys()].map((chan) => JSON.parse(chan)[1]));
  for (const mod of pkg.mods.values()) {
    if (mod.lang !== "js" || ![...events].some((event) => mod.text.includes(event))) continue;
    let k = 0;
    for (const m of calls("_XF_LISTEN_RE", "_XF_LISTEN_AT_RE", mod.text)) {
      if (k++ >= EMIT_MAX) break;
      const emitter = emitterOf(pkg, mod, m.groups.obj);
      if (emitter === null) continue;
      const chan = JSON.stringify([emitter, m.groups.event]);
      if (!listens.has(chan)) listens.set(chan, []);
      listens.get(chan).push([mod.key, m]);
    }
  }
  const comments = new Map(), codes = new Map();
  /** Is match m of module `key` code, not in a comment? (A file's comments are read once, and only where an emit
   * meets a listener.) Offsets are the text's own, in UTF-16 units, as its comments' are. */
  const isCode = (key, m) => {
    if (!comments.has(key)) {
      const text = pkg.mods.get(key).text;
      comments.set(key, readsOwnSource(text) ? [] : commentSpans(text, "js"));
    }
    const spans = comments.get(key);
    const e = end(m);
    let lo = 0, hi = spans.length;                               // the first comment that starts at or after m's end
    while (lo < hi) { const mid = (lo + hi) >> 1; if (spans[mid][0] < e) lo = mid + 1; else hi = mid; }
    return lo === 0 || spans[lo - 1][1] <= m.index;
  };
  const out = new Map();
  for (const [chan, byMod] of emits) {
    const event = JSON.parse(chan)[1];
    for (const key of sortCp(byMod.keys())) {
      let heard = (listens.get(chan) ?? []).filter((one) => one[0] !== key);
      const objs = heard.length ? new Set(byMod.get(key).filter((m) => isCode(key, m)).map((m) => m.groups.obj)) : new Set();
      heard = objs.size ? heard.filter(([lkey, m]) => isCode(lkey, m)) : [];
      if (!heard.length) continue;
      if (!codes.has(key)) codes.set(key, importCode(pkg.mods.get(key).text, "js"));
      let code = codes.get(key);
      for (const obj of sortCp(objs)) {
        const rx = pyRe(String.raw`(?<![\w$.])` + reLiteral(obj) + String.raw`[ \t]*\.[ \t]*emit[ \t]*\([ \t]*(['"` + "`" + String.raw`])`
          + reLiteral(event) + String.raw`\1[ \t]*,`, "g");
        code = code.replace(rx, (whole) => ljust("_xfe(", cpLen(whole)));
      }
      const seeds = tainted.size ? seedsOf(pkg, pkg.mods.get(key), tainted, envs)[0] : new Map();
      const res = receivedCodeKind(code, sortCp(seeds.keys()).slice(0, MAX_SEEDS), ["_xfe"]);
      if (res === null || res[1] !== "run") continue;
      for (const [lkey, m] of heard) {
        const param = m.groups.fp ?? m.groups.ap ?? m.groups.bp ?? null;
        const handler = m.groups.handler ?? null;
        const line = countNewlines(pkg.mods.get(lkey).text.slice(0, m.index)) + 1;
        if (!out.has(lkey)) out.set(lkey, [new Map(), [], line]);
        const entry = out.get(lkey);
        if (param !== null) entry[0].set(param, key);
        else if (handler !== null) { entry[0].set("_xfr", key); entry[1].push(`${handler}(_xfr)`); }
        entry[2] = Math.min(entry[2], line);
      }
    }
  }
  return out;
}

const XF_WHY = "A dropper can split what it downloads and the code that runs it across two files of a " +
  "package, so neither file shows the shape alone: one fetches, the other runs what the " +
  "first returns. Running code a server sends is the shape no library needs — whoever " +
  "controls the server chooses what runs.";

/** The follower's SC-IMPORT-RISK finding. core._xf_issue. */
function xfIssue(path, line, text, cat, srcs, who, runner = false) {
  const lines = text.split("\n");
  registerScanContext(lines, SECRET_SKIP_RE);        // the file's own entropy literals (core: _Redactor(lines))
  const where = srcs.join(", ");
  const tail = runner ? `the function that runs it is in another file of the package (${where})`
    : `the value is received in another file of the package (${where})`;
  return mkIssue({ id: "SC-IMPORT-RISK", name: "Risky import-time code", type: "HOTSPOT",
    sev: importTimeSeverity([DL().reasons[cat]]),
    msg: `${who} ${DL().reasons[cat]}; ${tail}.`, why: XF_WHY,
    fix: runner ? `Read both files: what does this file receive, and what does ${where} run?`
      : `Read both files: what does ${where} receive, and what runs it here?`,
    ref: "CWE-506 · Supply chain" }, path, line, lines);
}

/** [top package, dotted module, is package] for a dependency .py file, else null. core._xf_py_module. */
function pyModule(path) {
  const parts = posix(path).split("/");
  let idx = -1;
  for (const mark of DEP_MARKERS) idx = Math.max(idx, parts.lastIndexOf(mark));
  const rel = idx >= 0 && idx < parts.length - 1 ? parts.slice(idx + 1) : [];
  if (!rel.length || !rel[rel.length - 1].endsWith(".py")) return null;
  const stem = rel[rel.length - 1].slice(0, -3);
  const isPkg = stem === "__init__";
  const modParts = isPkg ? rel.slice(0, -1) : [...rel.slice(0, -1), stem];
  if (!modParts.length) return null;
  return [rel[0], modParts.join("."), isPkg];
}

/** An import's module spec resolved against the importing module's package parts. core._xf_resolve. */
function resolvePy(spec, pkgParts) {
  let dots = 0;
  while (dots < spec.length && spec[dots] === ".") dots++;
  const rest = spec.slice(dots);
  if (dots === 0) return rest || null;
  const keep = pkgParts.length - (dots - 1);
  if (keep < 0) return null;
  const target = [...pkgParts.slice(0, keep), ...(rest ? rest.split(".") : [])];
  return target.join(".") || null;
}

/** The npm package root a dependency file lives in, else null. core._xf_js_package. */
function jsPackage(path) {
  const parts = posix(path).split("/");
  for (let i = parts.length - 2; i >= 0; i--) {
    if (parts[i] === "node_modules") {
      if (parts[i + 1].startsWith("@") && i + 2 < parts.length) return parts.slice(0, i + 3).join("/");
      return parts.slice(0, i + 2).join("/");
    }
  }
  return null;
}

/** The follower's findings for one package's modules. core._xf_package_issues. */
function packageIssues(mods, skip, who) {
  const pkg = new XfPackage(mods);
  const tainted = pkg.tainted();
  const runners = pkg.runners();
  const envs = new Map();
  const envSyms = [...tainted].map((s) => s.split("\u0000")).filter(([, n]) => n.startsWith("<env>."));
  envSyms.sort((a, b) => cmpCodePoints(a[0], b[0]) || cmpCodePoints(a[1], b[1]));
  for (const [key, name] of envSyms) setdefault(envs, name.slice("<env>.".length), key);
  const heard = emitterSeeds(pkg, tainted, envs);
  if (!tainted.size && !runners.size && !heard.size) return [];
  const out = [];
  for (const mod of mods.values()) {
    if (skip.has(posix(mod.path))) continue;
    const [seeds, direct] = tainted.size ? seedsOf(pkg, mod, tainted, envs) : [new Map(), []];
    const runSeeds = runners.size ? seedsOf(pkg, mod, runners, new Map())[0] : new Map();
    const [given, rows, first] = heard.get(mod.key) ?? [new Map(), [], 0];
    if (!seeds.size && !direct.length && !runSeeds.size && !given.size) continue;
    let code = importCode(mod.text, mod.lang);
    if (receivedCodeKind(code) !== null) continue;       // the file shows it alone: the single-file test's
    let more;
    [code, more] = rewrite(code, direct, mod.lang);
    for (const [n, l] of more) seeds.set(n, l);
    const names = sortCp(seeds.keys()).slice(0, MAX_SEEDS);
    const whoHere = typeof who === "function" ? who(mod.path) : who;
    let res = names.length ? receivedCodeKind(code, names) : null;
    if (res !== null) {
      out.push(xfIssue(mod.path, res[0], mod.text, res[1], sortCp(new Set(names.map((n) => seeds.get(n)))), whoHere));
      continue;
    }
    if (given.size) {
      // the listeners' parameters seeded; a handler given by name called after the file
      const endLine = countNewlines(code) + 1;
      const both = new Map([...seeds, ...given]);
      const bothNames = sortCp(both.keys()).slice(0, MAX_SEEDS);
      res = receivedCodeKind(code + rows.map((r) => "\n" + r).join(""), bothNames);
      if (res !== null) {
        out.push(xfIssue(mod.path, res[0] > endLine ? first : res[0], mod.text, res[1],
          sortCp(new Set(bothNames.map((n) => both.get(n)))), whoHere));
        continue;
      }
    }
    if (runSeeds.size) {
      const runNames = sortCp(runSeeds.keys()).slice(0, MAX_SEEDS);
      res = receivedCodeKind(code, names, runNames);
      if (res !== null && res[1] === "run") {
        out.push(xfIssue(mod.path, res[0], mod.text, "run", sortCp(new Set(runNames.map((n) => runSeeds.get(n)))), whoHere, true));
      }
    }
  }
  return out;
}

/**
 * SC-IMPORT-RISK for each dependency file that runs a value received over
 * the network in another file of the same package, or receives one and hands
 * it to another file's function that runs it. `skipPaths` ("/"-separated):
 * the files already flagged single-file. `who(path)` may name the file.
 * Twin of lazaret.scanner.core._cross_file_received_issues.
 */
export function crossFileReceivedIssues(files, skipPaths = new Set(), who = "Dependency code", onePackage = false) {
  const skip = new Set(skipPaths);
  const groups = new Map();
  const group = (key) => { if (!groups.has(key)) groups.set(key, []); return groups.get(key); };
  for (const f of files) {
    if (!f.dep) continue;
    if (f.lang === "py") {
      const info = pyModule(f.path);
      if (info !== null) group("py\u0000" + (onePackage ? "" : info[0])).push([info[1], info[2], f]);
    } else if (f.lang === "js") {
      const root = jsPackage(f.path);
      if (root !== null) {
        const rel = posix(f.path).slice(root.length + 1);
        group("js\u0000" + root).push([jsNorm(rel), rel, f]);
      }
    }
  }
  const out = [];
  for (const [gkey, members] of groups) {
    const lang = gkey.split("\u0000")[0];
    if (members.length < 2 || members.length > MAX_FILES) continue;     // needs >= 2; a huge package is skipped
    if (!members.some(([, , f]) => DL().needles.some((n) => f.content.includes(n)))) continue;
    try {
      const mods = new Map();
      for (const [key, extra, f] of members) {
        const mod = new XfModule(key, lang, f.path, f.content);
        if (lang === "py") pyParse(mod, extra ? key.split(".") : key.split(".").slice(0, -1));
        else jsParse(mod, extra);
        mods.set(key, mod);
      }
      for (const i of packageIssues(mods, skip, who)) out.push(i);
    } catch {                                          // one package must never kill the scan
      continue;
    }
  }
  return out;
}
