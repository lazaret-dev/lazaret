// Python-compatible parsing of manifest text (zero-dependency leaf):
//  * pyJsonParse — json.loads semantics: NaN/Infinity accepted, and on
//    failure the exact error position CPython's decoder reports (so
//    "JSONDecodeError: line L column C" reads the same in both engines);
//    nesting deeper than MAX_JSON_DEPTH is reported as a depth failure
//    (Python: RecursionError), in document order.
//  * pyLiteralParse — ast.literal_eval for binding.gyp / .gypi files, which
//    gyp reads as Python literals (single quotes, comments, trailing commas).

import { MAX_JSON_DEPTH, PyComplex, PyBytes, PY_TUPLE, PY_SET, PY_KEYS, PY_ORDER, pyLiteralRepr } from "./pycompat.js";
import { pyCharByName } from "./pynames.js";

class JsonError extends Error { constructor(pos) { super("json"); this.pos = pos; } }
class DepthError extends Error {}
const WS = new Set([" ", "\t", "\n", "\r"]);
const ESC = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

/**
 * json.loads(text) → {ok, value} | {ok: false, depth: true} | {ok: false, pos} (pos in UTF-16 units).
 * onKey(obj, key, pos), if given, is called as each member is stored (pos: its key's opening quote).
 * pyValues: values as json.loads(parse_int=core._json_int) makes them: an integer literal of up
 * to 1000 characters is an int (a BigInt), any other number a float (a number), and an object
 * keeps its keys' order (PY_ORDER; see pycompat.js).
 */
export function pyJsonParse(text, { onKey = null, pyValues = false } = {}) {
  const s = String(text);
  const n = s.length;
  const skip = (i) => { while (i < n && WS.has(s[i])) i++; return i; };
  let depth = 0;
  function scanString(end) {                  // end: index after the opening quote
    const begin = end - 1;
    let out = "";
    for (;;) {
      let next = end, c = "";
      for (; next < n; next++) {
        c = s[next];
        if (c === '"' || c === "\\") break;
        if (c.charCodeAt(0) <= 0x1f) throw new JsonError(next);          // Invalid control character
      }
      if (next >= n) throw new JsonError(begin);                          // Unterminated string
      out += s.slice(end, next);
      next++;
      if (c === '"') return [out, next];
      if (next === n) throw new JsonError(begin);
      c = s[next];
      if (c !== "u") {
        end = next + 1;
        if (!(c in ESC)) throw new JsonError(end - 2);                    // Invalid \escape
        out += ESC[c];
        continue;
      }
      next++;
      end = next + 4;
      if (end >= n) throw new JsonError(next - 1);                        // Invalid \uXXXX escape
      const hex = s.slice(next, end);
      if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new JsonError(end - 5);
      let cp = parseInt(hex, 16);
      if (cp >= 0xd800 && cp <= 0xdbff && s[end] === "\\" && s[end + 1] === "u") {
        const h2 = s.slice(end + 2, end + 6);
        if (end + 6 >= n || !/^[0-9a-fA-F]{4}$/.test(h2)) throw new JsonError(end + 1);
        const lo = parseInt(h2, 16);
        if (lo >= 0xdc00 && lo <= 0xdfff) { out += String.fromCharCode(cp, lo); end += 6; continue; }
      }
      out += String.fromCharCode(cp);
    }
  }
  function number(start) {
    let i = start;
    if (s[i] === "-") { i++; if (i >= n) throw new JsonError(start, true); }
    if (s[i] >= "1" && s[i] <= "9") { i++; while (i < n && s[i] >= "0" && s[i] <= "9") i++; }
    else if (s[i] === "0") i++;
    else throw new JsonError(start);
    if (i < n - 1 && s[i] === "." && s[i + 1] >= "0" && s[i + 1] <= "9") { i += 2; while (i < n && s[i] >= "0" && s[i] <= "9") i++; }
    if (i < n - 1 && (s[i] === "e" || s[i] === "E")) {
      const e0 = i;
      i++;
      if (i < n - 1 && (s[i] === "-" || s[i] === "+")) i++;
      const d0 = i;
      while (i < n && s[i] >= "0" && s[i] <= "9") i++;
      if (i === d0) i = e0;
    }
    const lit = s.slice(start, i);
    if (pyValues && lit.length <= 1000 && !/[.eE]/.test(lit)) return [BigInt(lit), i];
    return [Number(lit), i];
  }
  function value(i) {                          // scan_once: value at i → [v, next]
    if (i >= n) throw new JsonError(i);
    const c = s[i];
    if (c === '"') return scanString(i + 1);
    if (c === "{" || c === "[") {
      if (++depth > MAX_JSON_DEPTH) throw new DepthError();
      const r = c === "{" ? object(i + 1) : array(i + 1);
      depth--;
      return r;
    }
    if (c === "n" && s.startsWith("null", i)) return [null, i + 4];
    if (c === "t" && s.startsWith("true", i)) return [true, i + 4];
    if (c === "f" && s.startsWith("false", i)) return [false, i + 5];
    if (c === "N" && s.startsWith("NaN", i)) return [NaN, i + 3];
    if (c === "I" && s.startsWith("Infinity", i)) return [Infinity, i + 8];
    if (c === "-" && s.startsWith("-Infinity", i)) return [-Infinity, i + 9];
    return number(i);
  }
  function object(i) {
    const obj = {};
    const order = pyValues ? [] : null;
    if (order) Object.defineProperty(obj, PY_ORDER, { value: order });
    i = skip(i);
    if (i >= n || s[i] !== "}") {
      for (;;) {
        if (i >= n || s[i] !== '"') throw new JsonError(i);               // Expecting property name
        const keyAt = i;
        const [key, k2] = scanString(i + 1);
        i = skip(k2);
        if (i >= n || s[i] !== ":") throw new JsonError(i);               // Expecting ':' delimiter
        i = skip(i + 1);
        const [v, v2] = value(i);
        if (order && !Object.prototype.hasOwnProperty.call(obj, key)) order.push(key);
        Object.defineProperty(obj, key, { value: v, enumerable: true, writable: true, configurable: true });
        if (onKey) onKey(obj, key, keyAt);
        i = skip(v2);
        if (i < n && s[i] === "}") break;
        if (i >= n || s[i] !== ",") throw new JsonError(i);               // Expecting ',' delimiter
        i = skip(i + 1);
      }
    }
    return [obj, i + 1];
  }
  function array(i) {
    const arr = [];
    i = skip(i);
    if (i >= n || s[i] !== "]") {
      for (;;) {
        const [v, v2] = value(i);
        arr.push(v);
        i = skip(v2);
        if (i < n && s[i] === "]") break;
        if (i >= n || s[i] !== ",") throw new JsonError(i);
        i = skip(i + 1);
      }
    }
    return [arr, i + 1];
  }
  try {
    const [v, end] = value(skip(0));
    const e = skip(end);
    if (e !== n) throw new JsonError(e);                                  // Extra data
    return { ok: true, value: v };
  } catch (e) {
    if (e instanceof DepthError) return { ok: false, depth: true };
    if (e instanceof JsonError) return { ok: false, pos: e.pos };
    if (e instanceof RangeError) return { ok: false, depth: true };
    throw e;
  }
}

/** JSONDecodeError's "line L column C" for a UTF-16 position (Python counts code points). */
export function jsonErrorWhere(text, pos) {
  const before = text.slice(0, pos);
  const lineno = (before.match(/\n/g) || []).length + 1;
  const lastNl = before.lastIndexOf("\n");
  const cp = (t) => t.length - (t.match(/[\ud800-\udbff][\udc00-\udfff]/g) || []).length;
  const colno = cp(before.slice(lastNl + 1)) + 1;
  return `line ${lineno} column ${colno}`;
}

// ---- ast.literal_eval (subset: what a gyp file can hold) -----------------------
const MAX_LITERAL_DEPTH = 200;       // CPython's tokenizer: "too many nested parentheses"
// Python's number tokens: hex/octal/binary integers; decimal integers,
// floats (`1.`, `.5`, `1.e5`, `01.5`) and imaginary literals (`2j`, `01j`).
const NUMBER_RE = /0[xX](?:_?[0-9a-fA-F])+|0[oO](?:_?[0-7])+|0[bB](?:_?[01])+|(?:[0-9](?:_?[0-9])*(?:\.(?:[0-9](?:_?[0-9])*)?)?|\.[0-9](?:_?[0-9])*)(?:[eE][-+]?[0-9](?:_?[0-9])*)?[jJ]?/y;
// the {NAME} of a \N{NAME} escape: words joined as in Unicode names (" ", "-", " -", "- ")
const CHAR_NAME_RE = /\{([A-Za-z0-9]+(?:(?: |-| -|- )[A-Za-z0-9]+)*)\}/y;
const SIMPLE_ESCAPES = { "\\": "\\", "'": "'", '"': '"', a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v" };
const mark = (arr, kind) => Object.defineProperty(arr, kind, { value: true });
/**
 * An id equal for keys Python's dict and set treat as the same (1 == 1.0 ==
 * True == 1+0j, -0.0 == 0, tuples item by item, str apart from bytes), or
 * null for an unhashable key (a list, dict or set: literal_eval's TypeError).
 */
function pyKeyId(v) {
  if (typeof v === "string") return "s" + v;
  if (v === null) return "N";
  if (typeof v === "boolean") return v ? "n1" : "n0";
  if (typeof v === "bigint") return "n" + v;
  if (typeof v === "number") return Number.isInteger(v) ? "n" + BigInt(v) : "f" + v;
  if (v instanceof PyComplex) return v.im === 0 ? pyKeyId(v.re) : `c${v.re},${v.im}`;
  if (v instanceof PyBytes) return "b" + v.latin1;
  if (Array.isArray(v) && v[PY_TUPLE]) {
    const ids = v.map(pyKeyId);
    return ids.includes(null) ? null : "t" + JSON.stringify(ids);
  }
  return null;
}
class LitError extends Error {}
class LitValueError extends Error {}

/**
 * ast.literal_eval(text.strip()): strings (all prefixes except f, escapes,
 * adjacent concatenation, triple quotes), numbers with Python's kinds and
 * token grammar (an int is a BigInt, a float a number, `2j` a PyComplex;
 * hex/octal/binary, underscores; a decimal int of more than 4300 digits is
 * refused, as Python's parser refuses it), a sign on a number literal (not
 * `--1`), a real plus or minus an imaginary literal (`1+2j`),
 * True/False/None, lists, tuples, dicts, sets, `set()`; comments and
 * trailing commas allowed. Read as Python's tokenizer reads source: \r\n and
 * \r end a line like \n (a comment, a line continuation, a line of a
 * triple-quoted string, which gets \n), \v is not whitespace, a NUL makes
 * the text invalid. A string may use \N{name} (see pynames.js); a bytes
 * literal, ASCII only and never concatenated with a str, is a PyBytes.
 * Dicts become objects in Python's key order (PY_ORDER), equal keys merged
 * as in Python, a non-str key under "\0" + its repr() (PY_KEYS); tuples and
 * sets become marked arrays, a set holding equal items once, in source
 * order. Returns {ok, value} or {ok: false}. onKey(obj, key, pos), if given,
 * is called as each string-keyed member is stored (pos: where the key's
 * first string token starts, as ast reports a Constant's position).
 */
export function pyLiteralParse(text, onKey = null) {
  const s = String(text);
  const n = s.length;
  let i = 0, depth = 0;
  // the length of the line break at s[k] (\r\n, \r or \n), else 0
  const lineBreak = (k) => (s[k] === "\n" ? 1 : s[k] === "\r" ? (s[k + 1] === "\n" ? 2 : 1) : 0);
  const ws = () => {
    for (;;) {
      while (i < n && " \t\n\r\f".includes(s[i])) i++;
      if (s[i] === "\\" && lineBreak(i + 1)) { i += 1 + lineBreak(i + 1); continue; }
      if (s[i] === "#") { while (i < n && s[i] !== "\n" && s[i] !== "\r") i++; continue; }
      break;
    }
  };
  const fail = () => { throw new LitError(); };
  let nonLiteral = false;              // a name/call where a literal belongs: ValueError once the syntax is fine
  let lastStr = -1;                    // start of the last string literal value() returned
  function str() {                     // one string token → [text, isBytes]
    const pm = /^([rRuUbB]{0,2})(['"])/.exec(s.slice(i, i + 3));
    if (!pm) fail();
    const pre = pm[1].toLowerCase();
    if (pre && !["r", "u", "b", "br", "rb"].includes(pre)) fail();
    const raw = pre.includes("r"), bytes = pre.includes("b");
    i += pre.length;
    const q = s[i];
    const triple = s.startsWith(q + q + q, i);
    const qs = triple ? q + q + q : q;
    i += qs.length;
    let out = "";
    for (;;) {
      if (i >= n) fail();
      if (s.startsWith(qs, i)) { i += qs.length; break; }
      const c = s[i];
      const nl = lineBreak(i);
      if (nl) {                          // a line break, read as \n; only a triple-quoted string spans one
        if (!triple) fail();
        out += "\n";
        i += nl;
        continue;
      }
      if (bytes && c.charCodeAt(0) > 0x7f) fail();                      // bytes: ASCII characters only
      if (c !== "\\") { out += c; i++; continue; }
      const d = s[i + 1];
      if (d === undefined) fail();
      if (bytes && d.charCodeAt(0) > 0x7f) fail();
      const cont = lineBreak(i + 1);
      if (raw) {                         // the backslash stays, and the character after it
        out += cont ? "\\\n" : c + d;
        i += 1 + (cont || 1);
        continue;
      }
      if (cont) { i += 1 + cont; continue; }                            // backslash-newline: nothing
      i += 2;
      if (d in SIMPLE_ESCAPES) { out += SIMPLE_ESCAPES[d]; continue; }
      if (/[0-7]/.test(d)) {
        let oct = d;
        while (oct.length < 3 && /[0-7]/.test(s[i])) oct += s[i++];
        const code = parseInt(oct, 8);
        out += bytes ? String.fromCharCode(code & 0xff) : String.fromCodePoint(code);
        continue;
      }
      const hexLen = d === "x" ? 2 : !bytes && d === "u" ? 4 : !bytes && d === "U" ? 8 : 0;
      if (hexLen) {
        const h = s.slice(i, i + hexLen);
        if (!new RegExp(`^[0-9a-fA-F]{${hexLen}}$`).test(h)) fail();
        const cp = parseInt(h, 16);
        if (cp > 0x10ffff) fail();
        out += String.fromCodePoint(cp);
        i += hexLen;
        continue;
      }
      if (!bytes && d === "N") {         // \N{NAME}: a character by name
        CHAR_NAME_RE.lastIndex = i;
        const m = CHAR_NAME_RE.exec(s);
        if (!m) fail();
        out += pyCharByName(m[1]);
        i += m[0].length;
        continue;
      }
      out += "\\" + d;                                                  // unknown escape kept
    }
    return [out, bytes];
  }
  function num() {                     // one number token, as Python's tokenizer reads it
    NUMBER_RE.lastIndex = i;
    const m = NUMBER_RE.exec(s);
    if (!m) fail();
    i += m[0].length;
    const t = m[0].replace(/_/g, "");
    if (/[jJ]$/.test(t)) return new PyComplex(0, Number(t.slice(0, -1)));
    if (/^0[xXoObB]/.test(t)) return BigInt(t);
    if (/[.eE]/.test(t)) return Number(t);
    if (/[1-9]/.test(t) && (t[0] === "0" || t.length > 4300)) fail();   // leading zeros; > 4300 digits
    return BigInt(t);
  }
  function numOperand() {              // a number token, possibly parenthesized: what a sign applies to
    ws();
    if (s[i] === "(") {
      if (++depth > MAX_LITERAL_DEPTH) fail();
      i++;
      const v = numOperand();
      ws();
      if (s[i] !== ")") fail();
      i++;
      depth--;
      return v;
    }
    if (!/[0-9.]/.test(s[i] ?? "")) fail();
    return num();
  }
  function complexSum(left) {          // `real + imag` / `real - imag`: a complex (literal_eval's BinOp)
    ws();
    const op = s[i];
    if ((op !== "+" && op !== "-") || (typeof left !== "bigint" && typeof left !== "number")) return left;
    i++;
    const right = numOperand();
    if (!(right instanceof PyComplex)) fail();
    const re = Number(left);
    if (!Number.isFinite(re) && typeof left === "bigint") fail();       // int too large to convert to float
    // the real becomes complex(re, 0.0), then part by part (Python 3.10-3.13;
    // 3.14 keeps the sign of the zero imaginary part in `x - 0j`)
    return op === "+" ? new PyComplex(re + right.re, 0 + right.im) : new PyComplex(re - right.re, 0 - right.im);
  }
  function seq(close) {
    const items = [];
    let sawComma = false;
    for (;;) {
      ws();
      if (s[i] === close) { i++; return [items, sawComma]; }
      items.push(value());
      ws();
      if (s[i] === ",") { i++; sawComma = true; continue; }
      if (s[i] === close) { i++; return [items, sawComma]; }
      fail();
    }
  }
  function value() {
    return complexSum(atom());
  }
  function atom() {
    ws();
    if (i >= n) fail();
    const c = s[i];
    if (c === "(" || c === "[" || c === "{") {
      if (++depth > MAX_LITERAL_DEPTH) fail();
      i++;
      let v;
      if (c === "[") v = seq("]")[0];
      else if (c === "(") {
        ws();
        if (s[i] === ")") { i++; v = mark([], PY_TUPLE); }
        else {
          const first = value();
          ws();
          if (s[i] === ")") { i++; v = first; }                          // parenthesized expression
          else if (s[i] === ",") { i++; const [rest] = seq(")"); v = mark([first, ...rest], PY_TUPLE); }
          else fail();
        }
      } else {
        ws();
        if (s[i] === "}") { i++; v = {}; }
        else {
          const k = value();
          const kAt = lastStr;
          ws();
          if (s[i] === ":") {
            i++;
            const obj = {};
            const names = new Map();                   // pyKeyId → property name
            const put = (key, at, val) => {
              const id = pyKeyId(key);
              if (id === null) fail();
              let name = names.get(id);                // an equal key: its first spelling stays
              if (name === undefined) {
                name = key;
                if (typeof key !== "string") {         // not a str: "\0" + its repr(), see PY_KEYS
                  name = "\0" + pyLiteralRepr(key);
                  if (!obj[PY_KEYS]) Object.defineProperty(obj, PY_KEYS, { value: new Map() });
                  obj[PY_KEYS].set(name, key);
                }
                names.set(id, name);
              }
              Object.defineProperty(obj, name, { value: val, enumerable: true, writable: true, configurable: true });
              if (!obj[PY_ORDER]) Object.defineProperty(obj, PY_ORDER, { value: [] });
              if (obj[PY_ORDER].length < names.size) obj[PY_ORDER].push(name);
              if (onKey && typeof key === "string") onKey(obj, key, at);
            };
            put(k, kAt, value());
            for (;;) {
              ws();
              if (s[i] === "}") { i++; break; }
              if (s[i] !== ",") fail();
              i++;
              ws();
              if (s[i] === "}") { i++; break; }
              const key = value();
              const at = lastStr;
              ws();
              if (s[i] !== ":") fail();
              i++;
              put(key, at, value());
            }
            v = obj;
          } else {
            const items = [k];
            ws();
            if (s[i] === ",") { i++; const [rest] = seq("}"); items.push(...rest); }
            else if (s[i] === "}") i++;
            else fail();
            const seen = new Set();                    // a set holds equal items once
            v = mark([], PY_SET);
            for (const x of items) {
              const id = pyKeyId(x);
              if (id === null) fail();
              if (!seen.has(id)) { seen.add(id); v.push(x); }
            }
          }
        }
      }
      depth--;
      return v;
    }
    if (c === "'" || c === '"' || (/[rRuUbB]/.test(c) && /^[rRuUbB]{1,2}['"]/.test(s.slice(i, i + 3)))) {
      const start = i;
      let [out, bytes] = str();
      for (;;) {                                                           // implicit concatenation
        ws();
        if (s[i] === "'" || s[i] === '"' || /^[rRuUbB]{1,2}['"]/.test(s.slice(i, i + 3))) {
          const [more, b] = str();
          if (b !== bytes) fail();                                         // bytes and str never mix
          out += more;
        } else {
          lastStr = start;
          return bytes ? new PyBytes(out) : out;
        }
      }
    }
    if (c === "-" || c === "+") {      // a sign applies to a number token only: not `--1`, `-True`, `-(1,)`
      i++;
      const v = numOperand();
      if (c === "+") return v;
      return v instanceof PyComplex ? new PyComplex(-v.re, -v.im) : -v;
    }
    if (/[0-9.]/.test(c)) return num();
    const w = /^[A-Za-z_]\w*/.exec(s.slice(i, i + 256));
    if (w && ["True", "False", "None"].includes(w[0])) { i += w[0].length; return w[0] === "True" ? true : w[0] === "False" ? false : null; }
    if (w && w[0] === "set") {                                             // `set()`: an empty set
      const at = i;
      i += 3;
      ws();
      if (s[i] === "(") {
        i++;
        ws();
        if (s[i] === ")") {
          i++;
          ws();
          if (s[i] !== "." && s[i] !== "(" && s[i] !== "[") return mark([], PY_SET);
        }
      }
      i = at;
    }
    if (w) {                                                               // name / attribute / call
      nonLiteral = true;
      i += w[0].length;
      for (;;) {
        ws();
        if (s[i] === ".") { i++; ws(); const a = /^[A-Za-z_]\w*/.exec(s.slice(i, i + 256)); if (!a) fail(); i += a[0].length; continue; }
        if (s[i] === "(") { i++; seq(")"); continue; }
        if (s[i] === "[") { i++; seq("]"); continue; }
        return null;
      }
    }
    fail();
  }
  try {
    i = 0;
    if (s.includes("\0")) fail();                                        // source code cannot hold NUL
    const v = value();
    ws();
    if (i !== n) fail();
    if (nonLiteral) return { ok: false, error: "ValueError" };
    const type = !Array.isArray(v) ? null : v[PY_TUPLE] ? "tuple" : v[PY_SET] ? "set" : null;
    return { ok: true, value: v, type };
  } catch (e) {
    if (e instanceof LitError || e instanceof RangeError) return { ok: false, error: "SyntaxError" };
    throw e;
  }
}
