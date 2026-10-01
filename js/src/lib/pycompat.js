// Python-compatibility helpers for the JS engine (zero-dependency leaf).
//
// The two engines must report the same findings for the same input, and the
// Python engine's regexes run with Python `re` semantics on `str`: \w, \d, \s
// and \b are Unicode-aware there, `.` matches everything except "\n", and
// re.I folds case the Unicode way. JavaScript's \w/\b are ASCII-only, so a
// rule written with the same source text silently diverged (a `café = …`
// assignment was invisible to the JS taint tracker). pyRe() compiles a
// Python pattern string into an equivalent JavaScript RegExp, so rule tables
// can carry the Python source text verbatim.

const W = "\\p{L}\\p{N}_";                 // Python str \w: isalnum() or "_"
// Python str \s: exactly the characters for which str.isspace() is true.
// (JS \s differs: it lacks \x1c-\x1f and \x85 and adds U+FEFF. For JS
// sources the scanner maps U+FEFF to a space before matching — spec 5.)
const WS = "\\t\\n\\v\\f\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
export const WORD_CLASS = `[${W}]`;
const BOUNDARY = `(?:(?<=[${W}])(?![${W}])|(?<![${W}])(?=[${W}]))`;
const NOT_BOUNDARY = `(?:(?<=[${W}])(?=[${W}])|(?<![${W}])(?![${W}]))`;
// `\b` right before a literal word character can only be the start of a
// word, so it is just "no word character before": the same matches, and V8
// no longer tries two lookarounds at every position of the input
// (SECRET_SKIP_RE over an 8 MB bundle: 7.1 s -> 0.1 s). The same holds
// before a `(?:…)` group whose every alternative starts with one. Not when
// the literal or the group may occur zero times (`\ba?`, `\b(?:a|b)*`).
const WORD_START = `(?<![${W}])`;
const WORD_LITERAL_RE = /[A-Za-z0-9_]/;
const OPTIONAL_RE = /[?*{]/;
/** Does the pattern at src[j] start with a word character in every match? */
function startsWithWordChar(src, j) {
  if (WORD_LITERAL_RE.test(src[j] ?? "")) return !OPTIONAL_RE.test(src[j + 1] ?? "");
  if (src.slice(j, j + 3) !== "(?:") return false;
  let depth = 0;
  for (let k = j + 3, alt = true; k < src.length; k++) {
    const c = src[k];
    if (alt) {                                          // the first token of an alternative
      if (!WORD_LITERAL_RE.test(c) || OPTIONAL_RE.test(src[k + 1] ?? "")) return false;
      alt = false;
      continue;
    }
    if (c === "\\") { k++; continue; }
    if (c === "[") {                                    // skip a class: ] first is literal
      k += src[k + 1] === "^" ? 2 : 1;
      if (src[k] === "]") k++;
      while (k < src.length && src[k] !== "]") k += src[k] === "\\" ? 2 : 1;
      continue;
    }
    if (c === "(") depth++;
    else if (c === ")") {
      if (depth === 0) return !OPTIONAL_RE.test(src[k + 1] ?? "");
      depth--;
    } else if (c === "|" && depth === 0) alt = true;
  }
  return false;
}
const SYNTAX = new Set("^$\\.*+?()[]{}|/");

// re.I folds U+0130 (İ) and U+0131 (ı) to i, as JavaScript's /iu does not
// (every other letter folds alike: ſ→s and K→k in both).
const DOTTED_I = "\u0130\u0131";
const FOLDS_I_RE = /^[iI]$/;

// A class repeated at least N times, `[…]{N,}`, is written `[…]{N}[…]*`: the
// same matches, but for N above 2 V8 keeps a backtrack entry per repetition
// and overflowed its stack ("Maximum call stack size exceeded") on runs of a
// few million characters (review B3: a base64 blob made a file's scan fail).
const AT_LEAST_RE = /\{(\d+),\}(\??)/y;

/**
 * Translate Python `re` pattern text into JavaScript (u-mode) pattern text.
 * ignoreCase: the pattern runs with re.I (JS flag i).
 */
export function pyRegexSource(src, { ignoreCase = false } = {}) {
  let out = "";
  let atom = null;                  // the last thing written, when it is one character class
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    const last = atom;
    atom = null;
    if (ch === "{" && last !== null) {
      AT_LEAST_RE.lastIndex = i;
      const m = AT_LEAST_RE.exec(src);
      if (m) { out += `{${m[1]}}${last}*${m[2]}`; i += m[0].length - 1; continue; }
    }
    if (ch === "\\") {
      const n = src[++i];
      if (n === undefined) { out += "\\\\"; break; }
      const set = { w: `[${W}]`, W: `[^${W}]`, d: "\\p{Nd}", D: "\\P{Nd}", s: `[${WS}]`, S: `[^${WS}]` }[n];
      if (set !== undefined) { out += set; atom = set; continue; }
      switch (n) {
        case "b":
          out += startsWithWordChar(src, i + 1) ? WORD_START : BOUNDARY;
          continue;
        case "B": out += NOT_BOUNDARY; continue;
        case "A": out += "^"; continue;
        case "Z": out += "$"; continue;
        case "U": out += `\\u{${src.slice(i + 1, i + 9)}}`; i += 8; continue;
        default: out += escapeOut(n); continue;
      }
    }
    if (ch === "[") { const [text, next] = translateClass(src, i, ignoreCase); out += text; atom = text; i = next; continue; }
    if (ch === ".") { out += "[^\\n]"; atom = "[^\\n]"; continue; }
    out += ignoreCase && FOLDS_I_RE.test(ch) ? `[iI${DOTTED_I}]` : ch;
  }
  return out;
}

function escapeOut(n) {
  if (/[A-Za-z0-9]/.test(n)) return "\\" + n;               // \n \t \x.. \u.... \1
  if (SYNTAX.has(n)) return "\\" + n;
  return n;                                                  // \" \' \- \# \  …
}

// Python class shorthands and their complements, as class contents.
const CLASS_SETS = { w: W, d: "\\p{Nd}", s: WS };
/**
 * Translate the character class starting at src[i] === "[". Returns
 * [js text, index of the closing "]"]. A negated shorthand inside a class
 * (\S, \W, \D — e.g. `[^\S\n]`) is rewritten with a look-ahead, since the
 * JS shorthands have different contents. ignoreCase: a class holding i or I
 * also holds İ and ı (re.I).
 */
function translateClass(src, i, ignoreCase = false) {
  let j = i + 1;
  let negated = false;
  if (src[j] === "^") { negated = true; j++; }
  const items = [];
  const negSets = [];
  let first = true;
  for (; j < src.length; j++) {
    const ch = src[j];
    if (ch === "]" && !first) break;
    first = false;
    if (ch === "\\") {
      const n = src[++j];
      if (n === "w" || n === "d" || n === "s") items.push(CLASS_SETS[n]);
      else if (n === "W" || n === "D" || n === "S") negSets.push(CLASS_SETS[n.toLowerCase()]);
      else if (n === "b") items.push("\\x08");
      else if (/[A-Za-z0-9]/.test(n) || SYNTAX.has(n) || n === "-") items.push("\\" + n);
      else items.push(n);
      continue;
    }
    if (ch === "[" || ch === "]") { items.push("\\" + ch); continue; }
    items.push(ch);
  }
  let rest = items.join("");
  if (ignoreCase && rest && new RegExp(`[${rest}]`, "iu").test("i")) rest += DOTTED_I;   // holds i or I
  if (!negSets.length) return [`[${negated ? "^" : ""}${rest}]`, j];
  if (negSets.length > 1) throw new Error("pyRe: several negated shorthands in one class are not supported");
  const c = negSets[0];
  // [^\S rest] = whitespace and not rest; [\S rest] = non-whitespace or rest
  const text = negated
    ? (rest ? `(?:(?=[${c}])[^${rest}])` : `[${c}]`)
    : (rest ? `(?:[^${c}]|[${rest}])` : `[^${c}]`);
  return [text, j];
}

/**
 * Compile a Python pattern (as written in lazaret/scanner/core.py) with
 * Python semantics. `flags` uses JS letters: i (re.I), s (re.S), m (re.M),
 * g (for iteration). The u flag is always added.
 */
export function pyRe(src, flags = "") {
  return new RegExp(pyRegexSource(src, { ignoreCase: flags.includes("i") }), [...new Set((flags + "u").split(""))].join(""));
}

// ---- strings -----------------------------------------------------------
// Characters for which Python's str.isspace() is true.
const PY_SPACE = "\t\n\v\f\r\x1c\x1d\x1e\x1f \x85\xa0\u1680\u2000\u2001\u2002\u2003" +
  "\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000";
const PY_SPACE_SET = new Set(PY_SPACE);
export const isPySpace = (ch) => PY_SPACE_SET.has(ch);
/** JS whitespace as the shared semantics define it: Python's set plus U+FEFF. */
export const isJsSpace = (ch) => PY_SPACE_SET.has(ch) || ch === "\ufeff";
export const isSpaceFor = (lang) => (lang === "js" ? isJsSpace : isPySpace);

/** Python str.strip() (not JS trim(), which also strips U+FEFF). */
export function pyStrip(s) {
  let a = 0, b = s.length;
  while (a < b && PY_SPACE_SET.has(s[a])) a++;
  while (b > a && PY_SPACE_SET.has(s[b - 1])) b--;
  return a === 0 && b === s.length ? s : s.slice(a, b);
}
/** Python str.strip(chars): the characters of `chars` (ASCII here) taken off both ends. A loop:
 * a regex like /^[T0]+|[T0]+$/ takes quadratic time on a long run of them. */
export function pyStripChars(s, chars) {
  let a = 0, b = s.length;
  while (a < b && chars.includes(s[a])) a++;
  while (b > a && chars.includes(s[b - 1])) b--;
  return a === 0 && b === s.length ? s : s.slice(a, b);
}
export function pyLstrip(s) {
  let a = 0;
  while (a < s.length && PY_SPACE_SET.has(s[a])) a++;
  return a ? s.slice(a) : s;
}
export function pyRstrip(s) {
  let b = s.length;
  while (b > 0 && PY_SPACE_SET.has(s[b - 1])) b--;
  return b === s.length ? s : s.slice(0, b);
}

const SURROGATE_RE = /[\ud800-\udbff][\udc00-\udfff]/g;
/** len(s) as Python counts it (code points, not UTF-16 units). */
export function cpLen(s) {
  if (!/[\ud800-\udbff]/.test(s)) return s.length;
  return s.length - (s.match(SURROGATE_RE) || []).length;
}
/** Code-point index of the UTF-16 offset `off` in s. */
/** The first n code points of s (Python's s[:n]). */
export function cpPrefix(s, n) {
  let i = 0;
  for (let k = 0; k < n && i < s.length; k++) {
    const c = s.charCodeAt(i);
    i += c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
  }
  return s.slice(0, i);
}
export function cpIndex(s, off) {
  return cpLen(s.slice(0, off));
}

const WORD_CHAR_RE = new RegExp(`^[${W}]$`, "u");
/** Python \w for one character (code point). */
export const isWordChar = (ch) => ch !== undefined && WORD_CHAR_RE.test(ch);

// ---- repr() -------------------------------------------------------------
const NONPRINTABLE_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;
/** Python str.isprintable() for one code point. */
export const isPrintable = (ch) => ch === " " || !NONPRINTABLE_RE.test(ch);

/** Python repr() of a str: messages quote source text exactly as Python does. */
export function pyRepr(s) {
  s = String(s);
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    if (ch === quote || ch === "\\") { out += "\\" + ch; continue; }
    if (ch === "\t") { out += "\\t"; continue; }
    if (ch === "\n") { out += "\\n"; continue; }
    if (ch === "\r") { out += "\\r"; continue; }
    const cp = ch.codePointAt(0);
    if (cp < 0x20 || cp === 0x7f || (cp >= 0x80 && !isPrintable(ch))) {
      if (cp < 0x100) out += "\\x" + cp.toString(16).padStart(2, "0");
      else if (cp < 0x10000) out += "\\u" + cp.toString(16).padStart(4, "0");
      else out += "\\U" + cp.toString(16).padStart(8, "0");
      continue;
    }
    out += ch;
  }
  return out + quote;
}

/** Python float repr() (shortest round-trip, Python's exponent thresholds). */
export function pyFloatRepr(x) {
  if (Number.isNaN(x)) return "nan";
  if (!Number.isFinite(x)) return x > 0 ? "inf" : "-inf";
  if (x === 0) return Object.is(x, -0) ? "-0.0" : "0.0";
  // the exponent of the shortest digits themselves (log10 misjudges values
  // next to a power of ten, e.g. 9999999999999998.0)
  const [m, e] = x.toExponential().split("e");
  const n = parseInt(e, 10);
  if (n >= 16 || n < -4) return `${m}e${n < 0 ? "-" : "+"}${String(Math.abs(n)).padStart(2, "0")}`;
  const s = String(x);
  return /[.e]/.test(s) ? s : s + ".0";
}

/** Python str() of a JSON-decoded value (dict/list use repr of members). */
export function pyStr(v) {
  if (typeof v === "string") return v;
  return pyReprValue(v);
}
function pyReprValue(v) {
  if (v === null || v === undefined) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (typeof v === "number") return Number.isInteger(v) && Math.abs(v) < 1e21 ? String(v) : pyFloatRepr(v);
  if (typeof v === "string") return pyRepr(v);
  if (Array.isArray(v)) return "[" + v.map(pyReprValue).join(", ") + "]";
  return "{" + Object.entries(v).map(([k, x]) => `${pyRepr(k)}: ${pyReprValue(x)}`).join(", ") + "}";
}

// ---- Python values of a parsed manifest ------------------------------------
// pyLiteralParse, and pyJsonParse with pyValues, keep Python's number kinds:
// an int is a BigInt (exact at any size: 12345678901234567890 is not
// 12345678901234567000), a float is a number (1.0 and -0.0 stay floats), a
// complex a PyComplex. pyLiteralParse also keeps a bytes literal apart from a
// str (PyBytes), marks the arrays it makes for tuples and sets (PY_TUPLE,
// PY_SET), and keeps each dict key that is not a str under "\0" + its repr(),
// the key itself in the dict's PY_KEYS map. A dict's keys in Python's order
// are its PY_ORDER (a JS object lists integer-like keys such as "1" first;
// pyEntries). pyLiteralStr renders such values as Python's str().
export const PY_TUPLE = Symbol("tuple");
export const PY_SET = Symbol("set");
export const PY_KEYS = Symbol("non-str keys");       // Map: property name → the key
export const PY_ORDER = Symbol("key order");         // property names in insertion order

/** [key, value] pairs of a parsed dict, in Python's order. */
export function pyEntries(obj) {
  const order = obj[PY_ORDER];
  return order ? order.map((k) => [k, obj[k]]) : Object.entries(obj);
}

/** A Python bytes value; `latin1` holds its bytes as U+0000-U+00FF. */
export class PyBytes {
  constructor(latin1) { this.latin1 = latin1; }
  toString() { return pyBytesRepr(this.latin1); }
}
function pyBytesRepr(b) {
  const quote = b.includes("'") && !b.includes('"') ? '"' : "'";
  let out = "b" + quote;
  for (const ch of b) {
    const c = ch.charCodeAt(0);
    if (ch === quote || ch === "\\") out += "\\" + ch;
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (c < 0x20 || c >= 0x7f) out += "\\x" + c.toString(16).padStart(2, "0");
    else out += ch;
  }
  return out + quote;
}

/** A Python complex number (literal_eval accepts `2j`, `-2j`, `1+2j`, `1.5-2j`). */
export class PyComplex {
  constructor(re, im) { this.re = re; this.im = im; }
  toString() { return pyComplexRepr(this); }
}

// Python's str() of an int refuses more than 4300 digits (ValueError: core
// then shows the int in hex, and so does pyIntStr).
const INT_STR_LIMIT = 10n ** 4300n;
/** str() of a Python int held as a BigInt. */
export function pyIntStr(v) {
  const a = v < 0n ? -v : v;
  if (a < INT_STR_LIMIT) return v.toString();
  return (v < 0n ? "-0x" : "0x") + a.toString(16);
}
// complex repr formats each part like a float repr without a trailing ".0"
const complexPart = (x) => { const r = pyFloatRepr(x); return r.endsWith(".0") ? r.slice(0, -2) : r; };
function pyComplexRepr(c) {
  if (c.re === 0 && !Object.is(c.re, -0)) return complexPart(c.im) + "j";
  const im = complexPart(c.im);
  return "(" + complexPart(c.re) + (im.startsWith("-") ? "" : "+") + im + "j)";
}

/** Python str() of a value from pyLiteralParse / pyJsonParse(…, {pyValues: true}). */
export function pyLiteralStr(v) {
  return typeof v === "string" ? v : pyLiteralRepr(v);
}
/** Python repr() of such a value. */
export function pyLiteralRepr(v) {
  if (v === null || v === undefined) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (typeof v === "bigint") return pyIntStr(v);
  if (typeof v === "number") return pyFloatRepr(v);
  if (typeof v === "string") return pyRepr(v);
  if (v instanceof PyComplex) return pyComplexRepr(v);
  if (v instanceof PyBytes) return pyBytesRepr(v.latin1);
  if (Array.isArray(v)) {
    const items = v.map(pyLiteralRepr);
    if (v[PY_TUPLE]) return items.length === 1 ? `(${items[0]},)` : `(${items.join(", ")})`;
    if (v[PY_SET]) return items.length ? `{${items.join(", ")}}` : "set()";   // (a set's order is Python's hash order)
    return `[${items.join(", ")}]`;
  }
  const keys = v[PY_KEYS];
  return "{" + pyEntries(v).map(([k, x]) => `${keys?.has(k) ? pyLiteralRepr(keys.get(k)) : pyRepr(k)}: ${pyLiteralRepr(x)}`).join(", ") + "}";
}

/** Python round(x, 1): round-half-even on the exact binary value. */
export function pyRound1(x) {
  const q = x * 4;
  if (Number.isInteger(q) && Math.abs(q % 2) === 1) {        // exact tie: x = odd/4
    const lo = Math.floor(x * 10) / 10, hi = Math.ceil(x * 10) / 10;
    const loDigit = Math.round(Math.abs(lo) * 10) % 2;
    return +(loDigit === 0 ? lo : hi).toFixed(1);
  }
  return +x.toFixed(1);
}

/** Compare two strings by code point (Python's str ordering). */
export function cmpCodePoints(a, b) {
  if (a === b) return 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.charCodeAt(i), y = b.charCodeAt(i);
    if (x === y) continue;
    const xs = x >= 0xd800 && x <= 0xdfff, ys = y >= 0xd800 && y <= 0xdfff;
    if (xs !== ys) return xs ? 1 : -1;       // a surrogate encodes a code point > U+FFFF
    return x - y;
  }
  return a.length - b.length;
}

/**
 * Nesting depth of a JSON text (brackets outside strings) — V8's JSON.parse
 * is iterative and never fails on depth, while Python's json.loads raises
 * RecursionError at an interpreter-dependent depth. Both engines check
 * depth > MAX_JSON_DEPTH explicitly before parsing a manifest (twin of
 * core.json_depth_exceeds / core.MAX_MANIFEST_DEPTH) and report
 * SC-MANIFEST-DEPTH.
 */
export const MAX_JSON_DEPTH = 500;
export function jsonDepthExceeds(text, limit = MAX_JSON_DEPTH) {
  let depth = 0, inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inStr) {
      if (c === 92) i++;              // backslash: skip the escaped char
      else if (c === 34) inStr = false;
      continue;
    }
    if (c === 34) inStr = true;
    else if (c === 91 || c === 123) { if (++depth > limit) return true; }
    else if (c === 93 || c === 125) depth--;
  }
  return false;
}
