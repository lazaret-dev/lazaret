// Code that runs what it receives over the network — twin of
// lazaret.scanner.core's runs_received_code (see the section comment there:
// what it follows, what counts, the bounds). The patterns are core's text,
// compiled with Python `re` semantics by pyRe; offsets and lengths are
// counted in code points where core's are (a row's length, the characters
// of a call's arguments and of an argument's value read, the look-back on a
// minified row), so the answer is core's for every text. A leaf module:
// lib/hooks.js uses it.

import { pyRe, pyStrip, pyLstrip, cpLen, isPySpace, isWordChar } from "./pycompat.js";

const DL_B = String.raw`\b`, DL_NOT_MEMBER = String.raw`(?<![\w$.])`;
/** pyRe for core's pattern text, whose named groups are Python's (?P<name>…). */
const pyReNamed = (src, flags = "") => pyRe(src.replaceAll("(?P<", "(?<"), flags);

/**
 * [exact, candidate] regexes (sticky, and global) from [assertion, body]
 * alternatives: the candidate leaves the leading assertions out (core's
 * _dl_alternatives), and an exact match starts where a candidate one does.
 */
function alternatives(pairs, tail = "") {
  const exactSrc = pairs.map(([a, b]) => a + b).join("|");
  const candSrc = pairs.map(([, b]) => b).join("|");
  const exact = tail ? `(?:${exactSrc})${tail}` : exactSrc;
  const cand = tail ? `(?:${candSrc})${tail}` : candSrc;
  return { exactSrc: exact, candSrc: cand, exact: pyRe(exact, "y"), cand: pyRe(cand, "g") };
}

/** The UTF-16 index after the code point that starts at index i. */
const nextCp = (s, i) => {
  const c = s.charCodeAt(i);
  return c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00 ? i + 2 : i + 1;
};

/**
 * The exact regex's matches in `row` that start in [pos, endpos), as
 * finditer gives them, found through the candidate regex (whose match must
 * end by endpos: Python's endpos is the end of the string). core._dl_finditer.
 * The candidate is searched in row[pos:endpos] (it has no look-behind), the
 * exact one at the candidate's start in the row.
 */
function* finditer(pair, row, pos = 0, endpos = null) {
  const whole = endpos === null && pos === 0;
  const base = whole ? 0 : pos;
  const text = whole ? row : row.slice(pos, endpos === null ? row.length : endpos);
  let p = pos;
  for (;;) {
    pair.cand.lastIndex = p - base;
    const m = pair.cand.exec(text);
    if (m === null) return;
    const at = m.index + base;
    pair.exact.lastIndex = at;
    const e = pair.exact.exec(row);
    if (e === null) { p = nextCp(row, at); continue; }
    yield e;
    const end = e.index + e[0].length;
    p = end > e.index ? end : nextCp(row, e.index);
  }
}

const firstMatch = (pair, row) => { for (const m of finditer(pair, row)) return m; return null; };

/** The UTF-16 index `n` code points after index i (at most the end). */
function cpForward(s, i, n) {
  for (let k = 0; k < n && i < s.length; k++) i = nextCp(s, i);
  return i;
}

/** The UTF-16 index `n` code points before index i (at least 0). */
function cpBack(s, i, n) {
  for (let k = 0; k < n && i > 0; k++) {
    const c = s.charCodeAt(i - 1);
    i -= c >= 0xdc00 && c <= 0xdfff && i >= 2 && (s.charCodeAt(i - 2) & 0xfc00) === 0xd800 ? 2 : 1;
  }
  return i;
}

/** len(s) > n, in code points, without counting a short string. */
const longer = (s, n) => s.length > n && (s.length > 2 * n || cpLen(s) > n);

/** Python's str.split() (no argument): runs of whitespace, no empty strings. */
function pySplit(s) {
  const out = [];
  let word = "";
  for (const ch of s) {
    if (isPySpace(ch)) { if (word) out.push(word); word = ""; } else word += ch;
  }
  if (word) out.push(word);
  return out;
}

/** bisect.bisect_left over a sorted array of numbers. */
function bisectLeft(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] < x) lo = mid + 1; else hi = mid; }
  return lo;
}

/** bisect.bisect_right over a sorted array of numbers. */
function bisectRight(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] <= x) lo = mid + 1; else hi = mid; }
  return lo;
}

/** Is one of the sorted offsets in [lo, hi)? core._dl_any. */
function anyIn(offsets, lo, hi) {
  const i = bisectLeft(offsets, lo);
  return i < offsets.length && offsets[i] < hi;
}

/** Is one of the spans (sorted, not overlapping) inside [lo, hi)? core._dl_within. */
function within(starts, ends, lo, hi) {
  const i = bisectLeft(starts, lo);
  return i < starts.length && ends[i] <= hi;
}

export const DL_NET_MODULES_SRC = String.raw`(?:node:)?(?:https?|net|tls|axios|got|node-fetch|undici|ws)`;
const DL_SOURCE = alternatives([
  // Python
  [DL_B, String.raw`urlopen\s*\(`], [DL_B, String.raw`requests\.(?:get|post|put|request|Session)\s*\(`],
  [DL_B, String.raw`httpx\.(?:get|post|request|stream|Client|AsyncClient)\s*\(`], [DL_B, String.raw`urllib3\.PoolManager\s*\(`],
  [DL_B, String.raw`HTTPS?Connection\s*\(`], [DL_B, String.raw`aiohttp\.ClientSession\s*\(`],
  [DL_B, String.raw`socket\.(?:socket|create_connection)\s*\(`],
  // JavaScript
  [DL_NOT_MEMBER, String.raw`fetch\s*\(`], [DL_B, String.raw`(?:window|globalThis|self|global)\.fetch\s*\(`],
  [DL_B, String.raw`https?\.(?:get|request|createServer)\s*\(`],
  [DL_B, String.raw`(?:net|tls)\.(?:connect|createConnection|createServer)\s*\(`],
  [DL_B, String.raw`new\s+(?:net\.Socket|WebSocket|XMLHttpRequest)\b`],
  [DL_B, String.raw`require\(\s*["']` + DL_NET_MODULES_SRC + String.raw`["']\s*\)`],
  [DL_B, String.raw`axios(?:\.(?:get|post|request))?\s*\(`], [DL_NOT_MEMBER, String.raw`got(?:\.(?:get|post))?\s*\(`],
  [DL_B, String.raw`undici\.(?:request|fetch)\s*\(`],
  // a download tool's output, captured
  [DL_B, String.raw`(?:execSync|execFileSync|spawnSync|check_output|getoutput|getstatusoutput|popen|run)` +
    String.raw`\s*\(\s*(?:\[\s*)?["'${"`"}]\s*(?:curl|wget)\b`],
]);
export const DL_SOURCE_SRC = DL_SOURCE.exactSrc;
const DL_SOURCE_RE = pyRe(DL_SOURCE_SRC, "g");
export const DL_NEEDLES = ["urlopen", "requests", "httpx", "urllib", "HTTPConnection", "HTTPSConnection", "aiohttp",
  "socket", "fetch", "http.", "https.", "net.", "tls.", "WebSocket", "XMLHttpRequest", "'http'", '"http"',
  "'https'", '"https"', "'net'", '"net"', "'tls'", '"tls"', "'ws'", '"ws"', "node:http", "node:net",
  "node:tls", "axios", "got", "undici", "curl", "wget"];
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
const DL_NEEDLE_RE = new RegExp([...DL_NEEDLES]
  .sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0)).map(escapeRe).join("|"), "gu");
export const DL_RUN_NEEDLES = ["eval", "exec", "Function", "runIn", "Script", "compileFunction", "_compile", "system",
  "popen", "getoutput", "getstatusoutput", "shell", "-e", "-c", "-p", "-r", "-E", "/c", "/C", "/k", "/K", "Command",
  "-enc"];
export const DL_MODULE_VALUE_SRC =
  String.raw`\s*(?:await\s+)?(?:require|import)\(\s*["']` + DL_NET_MODULES_SRC + String.raw`["']\s*\)\s*(?:;\s*)?$`;
const DL_MODULE_VALUE_RE = pyRe(DL_MODULE_VALUE_SRC, "y");
export const DL_FUNCTION_VALUE_SRC = String.raw`\s*(?:async\s*)?(?:function\b|\([^()]{0,200}\)\s*=>|[A-Za-z_$][\w$]*\s*=>)`;
const DL_FUNCTION_VALUE_RE = pyRe(DL_FUNCTION_VALUE_SRC, "y");
export const DL_IMPORT_SRC =
  String.raw`^[ \t]*import[ \t]+(?P<py>[\w.,]+(?:[ \t]+[\w.,]+)*)[ \t]*$` +
  String.raw`|^[ \t]*from[ \t]+(?:requests|httpx|urllib\.request|socket)[ \t]+import[ \t]+(?:\([ \t]*)?` +
  String.raw`(?P<pyfrom>[\w,]+(?:[ \t]+[\w,]+)*)[ \t]*\)?[ \t]*$` +
  String.raw`|\bimport\s+(?:\*\s+as\s+)?(?P<es>[A-Za-z_$][\w$]*)\s+from\s+["']` + DL_NET_MODULES_SRC + String.raw`["']` +
  String.raw`|\bimport\s*\{(?P<esn>[^{}]{0,200})\}\s*from\s+["']` + DL_NET_MODULES_SRC + String.raw`["']`;
const DL_IMPORT_RE = pyReNamed(DL_IMPORT_SRC, "g");
export const DL_PY_NET_MODULES = ["requests", "httpx", "urllib3", "urllib.request", "http.client", "aiohttp", "socket"];
const DL_PY_NET_MODULE_SET = new Set(DL_PY_NET_MODULES);
export const DL_LIMITS = { _DL_LONG_ROW: 1000, _DL_WINDOW: 50, _DL_ARG_SPAN: 400, _DL_LOOKBACK: 450,
  _DL_NAMED_SEARCHES: 64, _DL_PHASES: 8 };
const { _DL_LONG_ROW: LONG_ROW, _DL_WINDOW: WINDOW, _DL_ARG_SPAN: ARG_SPAN, _DL_LOOKBACK: LOOKBACK,
  _DL_NAMED_SEARCHES: NAMED_SEARCHES, _DL_PHASES: PHASES } = DL_LIMITS;
const BT = "`";
export const DL_CHAIN_SRC = String.raw`(?<![\w$.])[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*){0,50}`;
const DL_CHAIN_RE = pyRe(DL_CHAIN_SRC, "g");
export const DL_HEAD_SRC = String.raw`(?<![\w$.])[A-Za-z_$][\w$]*`;
const DL_HEAD_RE = pyRe(DL_HEAD_SRC, "g");
export const DL_WORD_RUN_SRC = String.raw`[\w$]+`;
const DL_WORD_RUN_RE = pyRe(DL_WORD_RUN_SRC, "g");
const DL_WORD_RUN_WHOLE_RE = pyRe(`^(?:${DL_WORD_RUN_SRC})$`);
export const DL_STR_SRC = String.raw`\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|${BT}(?:\\.|[^${BT}\\])*${BT}`;
const DL_STR_RE = pyRe(DL_STR_SRC, "g");
export const DL_TEMPLATE_HOLE_SRC = String.raw`\$\{([^{}]*)\}`;
const DL_TEMPLATE_HOLE_RE = pyRe(DL_TEMPLATE_HOLE_SRC, "g");
export const DL_FSTRING_HOLE_SRC = String.raw`(?<!\{)\{([^{}]*)\}`;
const DL_FSTRING_HOLE_RE = pyRe(DL_FSTRING_HOLE_SRC, "g");
export const DL_PREFIX_CHARS = [..."rRbBuUfF"];
const PREFIX_CHARS = new Set(DL_PREFIX_CHARS);
export const DL_BIND_SRC =
  String.raw`(?P<ann>(?<![\w$.])[A-Za-z_$][\w$]*)\s*:\s*[\w$.\[\], |]{1,80}?\s*=(?![=>])` +
  String.raw`|(?P<lhs>(?<![\w$.])[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*){0,8}(?:\s*,\s*[A-Za-z_$][\w$]*){0,8}` +
  String.raw`|\{[^{}()=;]{0,200}\}|\[[^\[\]()=;]{0,200}\])\s*(?:\+|\|\||\?\?)?=(?![=>])` +
  String.raw`|\bas\s+(?P<with>[A-Za-z_]\w*)\s*[:,)]` +
  String.raw`|\bfor\s*(?:\(\s*)?(?:(?:const|let|var)\s+)?(?P<for>[A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*){0,8}` +
  String.raw`|\{[^{}]{0,200}\}|\[[^\[\]]{0,200}\])\s+(?:of|in)\b` +
  String.raw`|\breturn\b(?P<ret>)`;
const DL_BIND_RE = pyReNamed(DL_BIND_SRC, "g");
export const DL_PARAMS_SRC =
  String.raw`\bfunction\b\s*(?:[\w$]+\s*)?\((?P<fp>[^()]{0,200})\)|\((?P<ap>[^()]{0,200})\)\s*=>` +
  String.raw`|(?<![\w$.])(?P<one>[A-Za-z_$][\w$]*)\s*=>|\blambda\b(?P<lp>[^:()]{0,200}):`;
const DL_PARAMS_RE = pyReNamed(DL_PARAMS_SRC, "g");
export const DL_FN_HEADER_SRC =
  String.raw`^\s*(?:async\s+)?def\s+(?P<py>\w+)|\bfunction\s*(?:\*\s*)?(?P<js>[A-Za-z_$][\w$]*)\s*\(` +
  String.raw`|\b(?:const|let|var)\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?` +
  String.raw`(?:function\b|\([^()]{0,200}\)\s*=>|[A-Za-z_$][\w$]*\s*=>)`;
const DL_FN_HEADER_RE = pyReNamed(DL_FN_HEADER_SRC);
export const DL_NAME_SRC = String.raw`[A-Za-z_$][\w$]*`;
const DL_NAME_RE = pyRe(DL_NAME_SRC, "g");
export const DL_DEFAULT_SRC = String.raw`=[^,]*`;
const DL_DEFAULT_RE = pyRe(DL_DEFAULT_SRC, "g");
export const DL_DOT_SRC = String.raw`\s*\??\.\s*`;
const DL_DOT_RE = pyRe(DL_DOT_SRC, "g");
export const DL_NOT_NAMES = ("const let var this self await async function return new typeof in of as for " +
  "with if else true false null None True False undefined str int float bytes bool list dict set tuple " +
  "object").split(" ");
const NOT_NAMES = new Set(DL_NOT_NAMES);
const DL_RUNNER_PAIRS = [
  [DL_NOT_MEMBER, String.raw`(?:eval|exec|execfile)\s*\(`], [DL_B, String.raw`(?:window|globalThis|global|self)\.eval\s*\(`],
  [DL_B, String.raw`new\s+Function\s*\(`], [DL_NOT_MEMBER, String.raw`Function\s*\(`],
  [DL_B, String.raw`runIn(?:This|New)?Context\s*\(`], [DL_B, String.raw`new\s+vm\.Script\s*\(`],
  [DL_B, String.raw`compileFunction\s*\(`], [String.raw`(?<=\.)`, String.raw`_compile\s*\(`], [DL_B, String.raw`execSync\s*\(`],
  [DL_B, String.raw`(?:child_process|childProcess|cp)\.exec\s*\(`],
  [DL_B, String.raw`require\(\s*["'](?:node:)?child_process["']\s*\)\.exec\s*\(`],
  [DL_B, String.raw`os\.(?:system|popen)\s*\(`], [DL_B, String.raw`__import__\(\s*["']os["']\s*\)\.(?:system|popen)\s*\(`],
  [DL_NOT_MEMBER, String.raw`(?:system|popen)\s*\(`], [DL_B, String.raw`(?:subprocess\.)?get(?:status)?output\s*\(`],
];
const DL_RUNNER = alternatives(DL_RUNNER_PAIRS);
export const DL_SHELL_TRUE_SRC = String.raw`\bshell\s*=\s*True\b`;
const DL_SHELL_TRUE_RE = pyRe(DL_SHELL_TRUE_SRC);
export const DL_SHELL_CALL_SRC = String.raw`(?:run|call|Popen|check_output|check_call)\s*\(`;
const DL_SHELL_CALL_WHOLE_RE = pyRe(`^(?:${DL_SHELL_CALL_SRC})$`);
export const DL_SHELL_ARG_SRC = String.raw`shell(?<!\wshell)\s*=\s*True`;
const DL_SHELL_ARG_RE = pyRe(DL_SHELL_ARG_SRC, "g");
const DL_RUNNER_SHELL = alternatives([...DL_RUNNER_PAIRS, [DL_B, DL_SHELL_CALL_SRC]]);
export const DL_DEFINING = ["def", "function", "async"];
const DL_INTERPRETERS = String.raw`(?:node|nodejs|bun|python[\d.]*|pythonw|(?:ba|z|da|k)?sh|perl|ruby|php|pwsh|` +
  String.raw`powershell|osascript|cmd)(?:\.exe)?`;
const DL_INLINE_FLAG = String.raw`(?:-(?:e|E|c|p|r|-eval|-print|Command|command|EncodedCommand|enc)|/[cCkK])`;
const DL_INTERP = alternatives([
  ["", String.raw`["'${BT}](?:[\w.:~-]*[/\\]){0,8}` + DL_INTERPRETERS + String.raw`["'${BT}]`],
  [DL_B, String.raw`process\.(?:execPath|argv\[0\])`], [DL_B, String.raw`sys\.executable`],
], String.raw`\s*,\s*(?:\[\s*)?(?:["'${BT}]-[^"'${BT}\n]{0,40}["'${BT}]\s*,\s*){0,4}?["'${BT}]` + DL_INLINE_FLAG +
  String.raw`["'${BT}]\s*,\s*`);
export const DL_EMBED_SRC = String.raw`\s*[rRbBuUfF]{0,2}["'${BT}]\s*(?:[\w.:~-]*[/\\]){0,8}` + DL_INTERPRETERS +
  String.raw`(?:\s+-[\w-]+){0,6}?\s+` + DL_INLINE_FLAG + String.raw`\b`;
const DL_EMBED_RE = pyRe(DL_EMBED_SRC, "y");
export const DL_LEAD_SRC = String.raw`\s*(?:(?:await|yield)\s+|\(\s*){0,50}`;
const DL_LEAD_RE = pyRe(DL_LEAD_SRC, "y");
export const DL_CALLEE_SRC =
  String.raw`(?:new\s+)?(?P<chain>[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*){0,50})\s*(?P<call>\()?`;
const DL_CALLEE_RE = pyReNamed(DL_CALLEE_SRC, "y");
export const DL_CALLEE_CHARS = [..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$."];
const CALLEE_CHAR_SET = new Set(DL_CALLEE_CHARS);
export const DL_BRACKET_SRC = String.raw`[()\[\]{},]`;

/** The names an assignment's left side binds (a member chain stays whole). core._dl_lhs_names. */
function lhsNames(lhs) {
  lhs = pyStrip(lhs);
  if (lhs.startsWith("{") || lhs.startsWith("[")) {
    return [...lhs.matchAll(DL_NAME_RE)].map((m) => m[0]).filter((n) => !NOT_NAMES.has(n));
  }
  const out = [];
  for (let part of lhs.split(",")) {
    part = pyStrip(part).replace(DL_DOT_RE, ".");
    if (part && !NOT_NAMES.has(part)) out.push(part);
  }
  return out;
}

/** Is the call at row[i] the name in a definition: def exec(…), function exec(…), async exec(…)? core._dl_defined_here. */
function definedHere(row, i) {
  let j = i;
  while (j > 0 && isPySpace(row[j - 1])) j--;
  if (j === i) return false;
  for (const word of DL_DEFINING) {
    const s = j - word.length;
    if (s >= 0 && row.startsWith(word, s) && (s === 0 || !isWordChar(String.fromCodePoint(row.codePointAt(cpBack(row, s, 1)))))) {
      return true;
    }
  }
  return false;
}

/**
 * The names holding a received value, with the row each was last bound on,
 * the names that carry the network wherever they are used, and their first
 * names (heads). core._DlTaint.
 */
class Taint {
  constructor(always) {
    this.always = new Set(always);
    this.at = new Map();
    this.heads = new Set([...this.always].map((n) => n.split(".")[0]));
  }

  nameLive(name, row) {
    if (this.always.has(name)) return true;
    const t = this.at.get(name);
    return t !== undefined && row - t <= WINDOW;
  }

  live(chain, row) {
    let acc = null;
    for (const part of chain.split(DL_DOT_RE)) {
      acc = acc === null ? part : `${acc}.${part}`;
      if (this.nameLive(acc, row)) return true;
    }
    return false;
  }
}

/** Does the row name one of the heads (as a chain starts)? */
function namesHead(row, heads) {
  if (!heads.size) return false;
  const found = row.match(DL_HEAD_RE);
  return found !== null && found.some((w) => heads.has(w));
}

/** The end of the whitespace, `await`s and parentheses at row[i]. */
function leadEnd(row, i) {
  DL_LEAD_RE.lastIndex = i;
  return i + DL_LEAD_RE.exec(row)[0].length;
}

/**
 * Does the value at row[i] begin with a received value (taint null: sources
 * only), read for ARG_SPAN code points after its lead? core._dl_carried.
 */
function carried(row, i, taint, k) {
  i = leadEnd(row, i);
  const base = cpBack(row, i, 1);                       // (the sources' look-behind reads one before)
  const text = row.slice(base, cpForward(row, i, ARG_SPAN));
  let j = i - base;
  for (let n = 0; n < 4; n++) {
    if (n) {
      DL_LEAD_RE.lastIndex = j;
      j += DL_LEAD_RE.exec(text)[0].length;
    }
    DL_CALLEE_RE.lastIndex = j;
    const m = DL_CALLEE_RE.exec(text);
    if (m === null) return false;
    const end = j + m[0].length;
    DL_SOURCE_RE.lastIndex = j;
    if (DL_SOURCE_RE.exec(end === text.length ? text : text.slice(0, end)) !== null) return true;
    if (taint !== null && taint.live(m.groups.chain, k)) return true;
    if (m.groups.call === undefined) return false;
    j = end;
  }
  return false;
}

/** The member chains of `code` (strings blanked) by the names they start with, as a Map. core._dl_chain_index. */
function chainIndex(code, lo = 0) {
  const by = new Map();
  const add = (name, s) => { const offs = by.get(name); if (offs === undefined) by.set(name, [s]); else offs.push(s); };
  for (const m of code.matchAll(DL_CHAIN_RE)) {
    const c = m[0], s = m.index + lo;
    if (!c.includes(".")) { add(c, s); continue; }
    let acc = null;
    for (const part of c.split(DL_DOT_RE)) {
      acc = acc === null ? part : `${acc}.${part}`;
      add(acc, s);
    }
  }
  return by;
}

/** Insert x into the sorted array a. */
function insort(a, x) {
  a.splice(bisectRight(a, x), 0, x);
}

const OPEN = new Set(["(", "[", "{"]), CLOSE = new Set([")", "]", "}"]);

/**
 * row[lo:hi] read as code: string literals' contents blanked, their spans,
 * and on demand the brackets, sources, chains and interpolating literals.
 * core._DlCode (offsets are UTF-16 indices of the row).
 */
class Code {
  constructor(row, lo, hi) {
    this.row = row; this.lo = lo; this.hi = hi;
    const text = row.slice(lo, hi);
    this.litS = []; this.litE = [];
    let out = "", at = 0;
    for (const m of text.matchAll(DL_STR_RE)) {
      const s = m.index, e = s + m[0].length;
      out += text.slice(at, s + 1) + " ".repeat(e - s - 2);
      at = e - 1;
      this.litS.push(s + lo); this.litE.push(e + lo);
    }
    this.code = out + text.slice(at);
    this.close = null; this.opener = null; this.commas = null;
    this.openParen = new Map(); this.es = new Map(); this.inner = new Map();
    this.by = null; this.liveOffs = []; this.holes = null;
  }

  literalAt(p) {
    const i = bisectRight(this.litS, p) - 1;
    return i >= 0 && this.litS[i] < p && p < this.litE[i] - 1 ? i : -1;
  }

  segmentAt(p) {
    const i = this.literalAt(p);
    if (i < 0) return this;
    let seg = this.inner.get(i);
    if (seg === undefined) {
      seg = new Code(this.row, this.litS[i] + 1, this.litE[i] - 1);
      this.inner.set(i, seg);
    }
    return seg.segmentAt(p);
  }

  brackets(queries = []) {
    if (this.close !== null) return;
    const close = new Map(), opener = new Map(), commas = new Map(), answers = this.openParen;
    const stack = [], parens = [];
    const { code, lo } = this;
    let qi = 0;
    for (let r = 0; r < code.length; r++) {
      const ch = code[r];
      if (ch !== "," && !OPEN.has(ch) && !CLOSE.has(ch)) continue;
      const q = r + lo;
      while (qi < queries.length && queries[qi] <= q) {
        answers.set(queries[qi], parens.length ? parens[parens.length - 1] : null);
        qi++;
      }
      if (ch === ",") {
        if (stack.length) {
          const top = stack[stack.length - 1];
          const list = commas.get(top);
          if (list === undefined) commas.set(top, [q]); else list.push(q);
        }
      } else if (OPEN.has(ch)) {
        stack.push(q);
        if (ch === "(") parens.push(q);
      } else if (stack.length) {
        const o = stack.pop();
        if (parens.length && parens[parens.length - 1] === o) parens.pop();
        close.set(o, q);
        opener.set(q, o);
      }
    }
    for (; qi < queries.length; qi++) answers.set(queries[qi], parens.length ? parens[parens.length - 1] : null);
    this.close = close; this.opener = opener; this.commas = commas;
  }

  exprStart(j) {
    const memo = this.es, { code, lo } = this, n = code.length;
    const path = [];
    let q = j, res;
    for (;;) {
      if (memo.has(q)) { res = memo.get(q); break; }
      path.push(q);
      const r = q - lo;
      if (r === 0) { res = q; break; }
      const ch = code[r - 1];
      if (CALLEE_CHAR_SET.has(ch)) q--;
      else if (ch === ")" || ch === "]") {
        const o = this.opener.get(q - 1);
        if (o === undefined) { res = null; break; }
        q = o;
      } else if ((ch === " " || ch === "\t") && ((r < n && code[r] === ".") || (r >= 2 && code[r - 2] === "."))) q--;
      else { res = q; break; }
    }
    for (const p of path) memo.set(p, res);
    return res;
  }

  index(taint, k) {
    this.by = chainIndex(this.code, this.lo);
    const offs = [];
    for (const [name, list] of this.by) if (taint.nameLive(name, k)) offs.push(...list);
    this.liveOffs = offs.sort((a, b) => a - b);
  }

  bound(name) {
    for (const s of this.by.get(name) ?? []) insort(this.liveOffs, s);
  }

  liveHoles(taint, k) {
    if (this.holes === null) {
      const starts = [], ends = [], row = this.row;
      for (let i = 0; i < this.litS.length; i++) {
        const s = this.litS[i], e = this.litE[i];
        let holes;
        if (row[s] === BT) holes = [...row.slice(s, e).matchAll(DL_TEMPLATE_HOLE_RE)].map((m) => m[1]);
        else {
          let pre = [...row.slice(Math.max(this.lo, cpBack(row, s, 2)), s)];
          while (pre.length && !PREFIX_CHARS.has(pre[0])) pre = pre.slice(1);
          if (!pre.includes("f") && !pre.includes("F")) continue;
          holes = [...row.slice(s, e).matchAll(DL_FSTRING_HOLE_RE)].map((m) => m[1]);
        }
        if (holes.length && [...holes.join(" ").matchAll(DL_CHAIN_RE)].some((c) => taint.live(c[0], k))) {
          starts.push(s); ends.push(e);
        }
      }
      this.holes = [starts, ends];
    }
    return this.holes;
  }
}

/**
 * One row (or a minified row's stretch) as runsReceivedCode reads it: its
 * code, and quotes paired from each runner's "(" for its arguments. core._DlRow.
 */
class Row {
  constructor(reader, k, row, lo, hi, taint, sources, top = true) {
    this.reader = reader; this.k = k; this.row = row; this.taint = taint; this.hi = hi;
    this.top = top ? new Code(row, lo, hi) : null;
    this.phases = top ? [this.top] : [];
    this.srcS = sources.map(([s]) => s);
    this.srcE = sources.map(([, e]) => e);
    this.dirty = false;
    this.indexed = [];
  }

  live(seg) {
    if (seg.by === null) {
      seg.index(this.taint, this.k);
      this.indexed.push(seg);
    }
    return seg.liveOffs;
  }

  bound(name) {
    for (const seg of this.indexed) seg.bound(name);
  }

  phaseAt(o) {
    for (const ph of this.phases) if (ph.lo <= o && o < ph.hi && ph.literalAt(o) < 0) return ph;
    if (this.phases.length - (this.top !== null ? 1 : 0) >= PHASES) return null;
    const ph = new Code(this.row, o, this.hi);
    this.phases.push(ph);
    return ph;
  }

  runs(r, taint) {
    const { row, k } = this;
    if (definedHere(row, r.index)) return false;                           // def exec(…), function exec(…)
    const rEnd = r.index + r[0].length;
    if (DL_SHELL_CALL_WHOLE_RE.test(r[0]) && !this.reader.shellWithin(k, row, rEnd)) return false;
    const o = rEnd - 1;
    if (o >= this.hi) return false;
    const ph = this.phaseAt(o);
    if (ph === null) return false;
    ph.brackets();
    const end = Math.min(ph.hi, cpForward(row, o + 1, ARG_SPAN));
    const c = ph.close.get(o);
    const close = c !== undefined && c < end ? c : null;
    if (close !== null && pyLstrip(row.slice(close + 1, close + 3)).startsWith("{")) return false;   // exec(x) {
    const starts = [o + 1], ends = [];
    for (const x of ph.commas.get(o) ?? []) {
      if (x >= end) break;
      ends.push(x);
      starts.push(x + 1);
    }
    ends.push(close === null ? end : close);
    const { srcS, srcE } = this;
    let live = [], holes = [[], []];
    if (taint !== null && this.dirty) { live = this.live(ph); holes = ph.liveHoles(taint, k); }
    const last = starts.length - 1;
    for (let i = 0; i < starts.length; i++) {
      const s = starts[i];
      const e = close === null && i === last ? Math.min(this.hi, cpForward(row, leadEnd(row, s), ARG_SPAN)) : ends[i];
      if ((anyIn(srcS, s, e) || anyIn(live, s, e)) && carried(row, s, taint, k)) return true;
    }
    const s = starts[0], e = ends[0];
    DL_EMBED_RE.lastIndex = 0;
    if (!DL_EMBED_RE.test(row.slice(s, e))) return false;
    return within(srcS, srcE, s, e) || anyIn(live, s, e) || within(holes[0], holes[1], s, e);
  }
}

/** The rows where a name stands whole ([\w$]+ runs are names). core._DlNamed. */
class Named {
  constructor(text, rows, starts) {
    this.text = text; this.rows = rows; this.starts = starts;
    this.searches = 0; this.index = null;
  }

  find(name) {
    const head = name.split(".")[0];
    if (!DL_WORD_RUN_WHOLE_RE.test(head)) return [];
    if (this.index === null && this.searches < NAMED_SEARCHES) {
      this.searches++;
      const esc = head.replaceAll("$", "\\$");
      const rx = pyRe(esc + String.raw`(?<![\w$]` + esc + String.raw`)(?![\w$])`, "g");
      const out = [], { text, starts } = this;
      rx.lastIndex = 0;
      for (let m = rx.exec(text); m !== null;) {
        const k = bisectRight(starts, m.index) - 1;
        out.push(k);
        if (k + 1 >= starts.length) break;
        rx.lastIndex = starts[k + 1];
        m = rx.exec(text);
      }
      return out;
    }
    if (this.index === null) {
      const index = new Map();
      this.rows.forEach((row, k) => {
        for (const word of new Set(row.match(DL_WORD_RUN_RE) ?? [])) {
          const list = index.get(word);
          if (list === undefined) index.set(word, [k]); else list.push(k);
        }
      });
      this.index = index;
    }
    return this.index.get(head) ?? [];
  }
}

/** The names a network module is imported under, on the rows `near`. core._dl_import_names. */
function importNames(rows, near) {
  const out = new Set();
  for (const k of [...near].sort((a, b) => a - b)) {
    const row = rows[k];
    if (!row.includes("import") || longer(row, LONG_ROW)) continue;
    for (const m of row.matchAll(DL_IMPORT_RE)) {
      const g = m.groups;
      if (g.py !== undefined) {
        for (const item of g.py.split(",")) {
          const parts = pySplit(item);
          if (parts.length && DL_PY_NET_MODULE_SET.has(parts[0])) {
            out.add(parts.length === 3 && parts[1] === "as" ? parts[2] : parts[0]);
          }
        }
        continue;
      }
      const items = g.pyfrom !== undefined ? g.pyfrom : g.esn;
      if (items === undefined) { out.add(g.es); continue; }
      for (const item of items.split(",")) {
        const parts = pySplit(item);
        if (parts.length) out.add(parts.length === 3 && parts[1] === "as" ? parts[2] : parts[0]);
      }
    }
  }
  return out;
}

/**
 * What a row says about the function a `return` below it belongs to: the
 * function's name on a header, "" on a minified row, null otherwise. core._dl_header.
 */
function header(row) {
  if (longer(row, LONG_ROW)) return "";
  const h = DL_FN_HEADER_RE.exec(row);
  return h === null ? null : h.groups.py || h.groups.js || h.groups.var || null;
}

/** The nearest non-blank row above k (in the window), unless minified. core._dl_row_above. */
function rowAbove(rows, k) {
  for (let j = k - 1; j > Math.max(-1, k - WINDOW - 1); j--) {
    if (pyStrip(rows[j])) return longer(rows[j], LONG_ROW) ? null : j;
  }
  return null;
}

/** runsReceivedCode's pass over the rows. core._DlReader. */
class Reader {
  constructor(rows, taint, sources, runners, named, seeds) {
    this.rows = rows; this.taint = taint; this.sources = sources; this.runners = runners;
    this.named = named; this.seeds = seeds;
    this.until = -1;
    this.headers = new Map();
    this.lastTop = [-1, null];                          // the row read last, and its code
    this.shellRow = -1; this.shell = [];
  }

  shellWithin(k, row, i) {
    if (this.shellRow !== k) {
      this.shellRow = k;
      this.shell = [...row.matchAll(DL_SHELL_ARG_RE)].map((m) => m.index);
    }
    return anyIn(this.shell, i, cpForward(row, i, ARG_SPAN) + 1);
  }

  shortRow(k, row) {
    const { taint, rows, sources } = this;
    const heads = taint.heads;
    const found = namesHead(row, heads);
    const hot = sources.has(k);
    const above = pyLstrip(row).startsWith(".") ? rowAbove(rows, k) : null;
    if (!(hot || found || (above !== null && (sources.has(above) || namesHead(rows[above], heads))))) return false;
    const srcs = hot ? [...finditer(DL_SOURCE, row)].map((m) => [m.index, m.index + m[0].length]) : [];
    const rd = new Row(this, k, row, 0, row.length, taint, srcs);
    rd.dirty = found;
    const top = rd.top;
    const facts = [];                                   // [kind, lo, hi, match or names, continued, code]
    let semi = -1;
    const bindable = row.includes("=") || row.includes("as") || row.includes("for") || row.includes("return");
    for (const m of bindable ? row.matchAll(DL_BIND_RE) : []) {
      const g = m.groups, seg = top.segmentAt(m.index), mEnd = m.index + m[0].length;
      let kind, lo, hi;
      if (g.ann !== undefined || g.lhs || g.ret !== undefined) {
        lo = mEnd;
        if (semi < lo) { semi = row.indexOf(";", lo); if (semi < 0) semi = row.length; }
        kind = g.ret !== undefined ? "return" : "bind"; hi = semi;
      } else if (g.with) { kind = "with"; lo = 0; hi = m.index; }
      else { kind = "for"; lo = mEnd; hi = row.length; }
      facts.push([kind, lo, hi, m, false, seg]);
    }
    const params = [], queries = new Map();
    const paramable = row.includes("=>") || row.includes("function") || row.includes("lambda");
    for (const m of paramable ? row.matchAll(DL_PARAMS_RE) : []) {
      const g = m.groups;
      const ps = g.fp || g.ap || g.one || g.lp || "";
      const names = [...ps.replace(DL_DEFAULT_RE, "").matchAll(DL_NAME_RE)].map((x) => x[0]).filter((n) => !NOT_NAMES.has(n));
      if (names.length) {
        const seg = top.segmentAt(m.index);
        params.push([m.index, names, seg]);
        const list = queries.get(seg);
        if (list === undefined) queries.set(seg, [m.index]); else list.push(m.index);
      }
    }
    for (const [seg, offsets] of queries) seg.brackets(offsets);
    const first = row.length - pyLstrip(row).length;
    for (const [p, names, seg] of params) {
      const j = seg.openParen.get(p);
      const start = j === null || j === undefined ? null : seg.exprStart(j);
      if (start === null) continue;
      const continued = seg === top && start <= first && first < j && row[first] === ".";
      facts.push(["param", start, j, names, continued, seg]);
    }
    // which facts hold a received value; binding their names can feed the others
    let aboveBy = null, aboveLive = false;
    if (above !== null && facts.some((f) => f[4])) {
      if (sources.has(above)) aboveLive = true;
      else {
        const [j, code] = this.lastTop;
        if (j === above && code.by !== null) aboveBy = code.by;         // (read just now: its chains are indexed)
        else {
          const aRow = rows[above];
          aboveBy = chainIndex(new Code(aRow, 0, aRow.length).code);
        }
        aboveLive = [...aboveBy.keys()].some((n) => taint.nameLive(n, k));
      }
    }
    const added = [];
    let pending = facts;
    for (let pass = 0; pass < 3; pass++) {
      let grew = false;
      const rest = [];
      for (const f of pending) {
        const [, lo, hi, , cont, seg] = f;
        if (!(within(rd.srcS, rd.srcE, lo, hi) || (cont && aboveLive) || (rd.dirty && anyIn(rd.live(seg), lo, hi)))) {
          rest.push(f);
          continue;
        }
        const [names, how] = this.names(f, row, k);
        for (const name of names) {
          if (how === "always") {
            if (taint.always.has(name)) continue;
            taint.always.add(name);
            added.push(name);
          } else if (taint.at.get(name) !== k) {
            taint.at.set(name, k);
            this.until = Math.max(this.until, k + WINDOW);
          } else continue;
          grew = true;
          rd.dirty = true;
          taint.heads.add(name.split(".")[0]);
          rd.bound(name);
          if (aboveBy !== null && aboveBy.has(name)) aboveLive = true;
        }
      }
      pending = rest;
      if (!grew) break;
    }
    for (const name of added) for (const r of this.named.find(name)) if (r > k) this.seeds[r] = 1;
    this.lastTop = [k, top];
    // its runners, with what it binds
    for (const r of finditer(this.runners, row)) if (rd.runs(r, taint)) return true;
    for (const r of finditer(DL_INTERP, row)) if (carried(row, r.index + r[0].length, taint, k)) return true;
    return false;
  }

  names(f, row, k) {
    const kind = f[0];
    if (kind === "param") return [f[3], "value"];
    const g = f[3].groups;
    if (kind === "bind") {
      const names = (g.ann !== undefined ? [g.ann] : lhsNames(g.lhs)).filter((n) => !NOT_NAMES.has(n));
      if (names.length === 1 && !names[0].includes(".")) {
        const value = row.slice(f[1], f[2]);
        DL_MODULE_VALUE_RE.lastIndex = 0;
        if (DL_MODULE_VALUE_RE.test(value)) return [names, "always"];
        DL_FUNCTION_VALUE_RE.lastIndex = 0;
        if (cpLen(names[0]) >= 3 && DL_FUNCTION_VALUE_RE.test(value)) return [names, "always"];
      }
      return [names, "value"];
    }
    if (kind === "with") return [[g.with], "value"];
    if (kind === "for") return [lhsNames(g.for), "value"];
    const fn = this.functionAbove(k);                   // return VALUE: the function nearest above carries it
    return [fn && cpLen(fn) >= 3 ? [fn] : [], "always"];
  }

  functionAbove(k) {
    const { headers, rows } = this;
    for (let j = k; j > Math.max(-1, k - WINDOW - 1); j--) {
      let h = headers.get(j);
      if (h === undefined) { h = header(rows[j]); headers.set(j, h); }
      if (h !== null) return h;
    }
    return null;
  }

  longRow(k, row) {
    const stretches = [];
    for (const n of row.matchAll(DL_NEEDLE_RE)) {
      const lo = cpBack(row, n.index, LOOKBACK);
      if (stretches.length && lo <= stretches[stretches.length - 1][1]) stretches[stretches.length - 1][1] = n.index;
      else stretches.push([lo, n.index]);
    }
    for (const [lo, hi] of stretches) {
      const end = cpForward(row, hi, 3 * ARG_SPAN);    // a runner's name, its arguments, the last one's value
      const searchEnd = Math.min(end, cpForward(row, hi, ARG_SPAN));
      let rd = null;
      for (const r of finditer(this.runners, row, lo, searchEnd)) {
        if (r.index >= hi) break;
        if (rd === null) {
          rd = new Row(this, k, row, lo, end, null,
            [...finditer(DL_SOURCE, row, lo, end)].map((m) => [m.index, m.index + m[0].length]), false);
        }
        if (rd.runs(r, null)) return true;
      }
      for (const r of finditer(DL_INTERP, row, lo, searchEnd)) {
        if (r.index >= hi) break;
        if (carried(row, r.index + r[0].length, null, k)) return true;
      }
    }
    return false;
  }
}

/**
 * The 1-based line where code runs what it received over the network as
 * code or as a shell command, else null. `text` has \n line endings.
 * Twin of lazaret.scanner.core.runs_received_code.
 */
export function runsReceivedCode(text) {
  if (!DL_NEEDLES.some((n) => text.includes(n)) || !DL_RUN_NEEDLES.some((n) => text.includes(n))) return null;
  const rows = text.split("\n");
  const starts = new Array(rows.length);
  for (let k = 0, at = 0; k < rows.length; k++) { starts[k] = at; at += rows[k].length + 1; }
  const near = new Set();                                              // rows holding a network name
  DL_NEEDLE_RE.lastIndex = 0;
  for (let m = DL_NEEDLE_RE.exec(text); m !== null;) {
    const k = bisectRight(starts, m.index) - 1;
    near.add(k);
    if (k + 1 >= starts.length) break;
    DL_NEEDLE_RE.lastIndex = starts[k + 1];
    m = DL_NEEDLE_RE.exec(text);
  }
  DL_NEEDLE_RE.lastIndex = 0;                                         // (matchAll starts from it)
  const taint = new Taint(text.includes("import") ? importNames(rows, near) : []);
  const sources = new Set([...near].filter((k) => longer(rows[k], LONG_ROW) || firstMatch(DL_SOURCE, rows[k]) !== null));
  if (!taint.always.size && !sources.size) return null;
  const named = new Named(text, rows, starts);
  const seeds = new Uint8Array(rows.length);                          // rows where a received value can start
  for (const r of sources) seeds[r] = 1;
  for (const name of taint.always) for (const r of named.find(name)) seeds[r] = 1;
  const runners = text.includes("shell") && DL_SHELL_TRUE_RE.test(text) ? DL_RUNNER_SHELL : DL_RUNNER;
  const reader = new Reader(rows, taint, sources, runners, named, seeds);
  let k = seeds.indexOf(1);
  if (k < 0) k = rows.length;
  while (k < rows.length) {
    const row = rows[k];
    if (longer(row, LONG_ROW)) {
      if (reader.longRow(k, row)) return k + 1;
    } else {
      if (seeds[k]) reader.until = Math.max(reader.until, k + WINDOW);
      if (reader.shortRow(k, row)) return k + 1;
    }
    let nk = k + 1;
    if (nk > reader.until) {
      nk = seeds.indexOf(1, nk);
      if (nk < 0) nk = rows.length;
    }
    k = nk;
  }
  return null;
}

/** core's pattern text for the twins above (held to core's by tests/architecture/test_js_parity_hooks.py). */
export const RECEIVED_TWINS = {
  _DL_SOURCE_RE: [DL_SOURCE_SRC, ""], _DL_SOURCE_CANDIDATE_RE: [DL_SOURCE.candSrc, ""],
  _DL_RUNNER_RE: [DL_RUNNER.exactSrc, ""], _DL_RUNNER_CANDIDATE_RE: [DL_RUNNER.candSrc, ""],
  _DL_RUNNER_SHELL_RE: [DL_RUNNER_SHELL.exactSrc, ""], _DL_RUNNER_SHELL_CANDIDATE_RE: [DL_RUNNER_SHELL.candSrc, ""],
  _DL_INTERP_RE: [DL_INTERP.exactSrc, ""], _DL_INTERP_CANDIDATE_RE: [DL_INTERP.candSrc, ""],
  _DL_MODULE_VALUE_RE: [DL_MODULE_VALUE_SRC, ""],
  _DL_FUNCTION_VALUE_RE: [DL_FUNCTION_VALUE_SRC, ""], _DL_IMPORT_RE: [DL_IMPORT_SRC, ""],
  _DL_CHAIN_RE: [DL_CHAIN_SRC, ""], _DL_HEAD_RE: [DL_HEAD_SRC, ""], _DL_WORD_RUN_RE: [DL_WORD_RUN_SRC, ""],
  _DL_STR_RE: [DL_STR_SRC, ""],
  _DL_TEMPLATE_HOLE_RE: [DL_TEMPLATE_HOLE_SRC, ""], _DL_FSTRING_HOLE_RE: [DL_FSTRING_HOLE_SRC, ""],
  _DL_BIND_RE: [DL_BIND_SRC, ""], _DL_PARAMS_RE: [DL_PARAMS_SRC, ""], _DL_FN_HEADER_RE: [DL_FN_HEADER_SRC, ""],
  _DL_NAME_RE: [DL_NAME_SRC, ""], _DL_DEFAULT_RE: [DL_DEFAULT_SRC, ""], _DL_DOT_RE: [DL_DOT_SRC, ""],
  _DL_SHELL_TRUE_RE: [DL_SHELL_TRUE_SRC, ""], _DL_SHELL_CALL_RE: [DL_SHELL_CALL_SRC, ""],
  _DL_SHELL_ARG_RE: [DL_SHELL_ARG_SRC, ""], _DL_BRACKET_RE: [DL_BRACKET_SRC, ""],
  _DL_EMBED_RE: [DL_EMBED_SRC, ""], _DL_LEAD_RE: [DL_LEAD_SRC, ""], _DL_CALLEE_RE: [DL_CALLEE_SRC, ""],
};
