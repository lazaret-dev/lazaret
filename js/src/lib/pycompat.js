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
const SYNTAX = new Set("^$\\.*+?()[]{}|/");

/** Translate Python `re` pattern text into JavaScript (u-mode) pattern text. */
export function pyRegexSource(src) {
  let out = "";
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === "\\") {
      const n = src[++i];
      if (n === undefined) { out += "\\\\"; break; }
      switch (n) {
        case "w": out += `[${W}]`; continue;
        case "W": out += `[^${W}]`; continue;
        case "d": out += "\\p{Nd}"; continue;
        case "D": out += "\\P{Nd}"; continue;
        case "s": out += `[${WS}]`; continue;
        case "S": out += `[^${WS}]`; continue;
        case "b": out += BOUNDARY; continue;
        case "B": out += NOT_BOUNDARY; continue;
        case "A": out += "^"; continue;
        case "Z": out += "$"; continue;
        case "U": out += `\\u{${src.slice(i + 1, i + 9)}}`; i += 8; continue;
        default: out += escapeOut(n); continue;
      }
    }
    if (ch === "[") { const [text, next] = translateClass(src, i); out += text; i = next; continue; }
    if (ch === ".") { out += "[^\\n]"; continue; }
    out += ch;
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
 * JS shorthands have different contents.
 */
function translateClass(src, i) {
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
  const rest = items.join("");
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
  return new RegExp(pyRegexSource(src), [...new Set((flags + "u").split(""))].join(""));
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
  const exp = Math.floor(Math.log10(Math.abs(x)));
  if (exp >= 16 || exp < -4) {
    let [m, e] = x.toExponential().split("e");
    const n = parseInt(e, 10);
    return `${m}e${n < 0 ? "-" : "+"}${String(Math.abs(n)).padStart(2, "0")}`;
  }
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
