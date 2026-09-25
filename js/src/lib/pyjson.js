// Python-compatible parsing of manifest text (zero-dependency leaf):
//  * pyJsonParse — json.loads semantics: NaN/Infinity accepted, and on
//    failure the exact error position CPython's decoder reports (so
//    "JSONDecodeError: line L column C" reads the same in both engines);
//    nesting deeper than MAX_JSON_DEPTH is reported as a depth failure
//    (Python: RecursionError), in document order.
//  * pyLiteralParse — ast.literal_eval for binding.gyp / .gypi files, which
//    gyp reads as Python literals (single quotes, comments, trailing commas).

import { MAX_JSON_DEPTH } from "./pycompat.js";

class JsonError extends Error { constructor(pos) { super("json"); this.pos = pos; } }
class DepthError extends Error {}
const WS = new Set([" ", "\t", "\n", "\r"]);
const ESC = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

/** json.loads(text) → {ok, value} | {ok: false, depth: true} | {ok: false, pos} (pos in UTF-16 units). */
export function pyJsonParse(text) {
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
    return [Number(s.slice(start, i)), i];
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
    i = skip(i);
    if (i >= n || s[i] !== "}") {
      for (;;) {
        if (i >= n || s[i] !== '"') throw new JsonError(i);               // Expecting property name
        const [key, k2] = scanString(i + 1);
        i = skip(k2);
        if (i >= n || s[i] !== ":") throw new JsonError(i);               // Expecting ':' delimiter
        i = skip(i + 1);
        const [v, v2] = value(i);
        Object.defineProperty(obj, key, { value: v, enumerable: true, writable: true, configurable: true });
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
class LitError extends Error {}
class LitValueError extends Error {}

/**
 * ast.literal_eval(text.strip()): strings (all prefixes except f, escapes,
 * adjacent concatenation, triple quotes), numbers (incl. hex/octal/binary,
 * underscores, unary +/-), True/False/None, lists, tuples, dicts, sets;
 * comments and trailing commas allowed. Dicts become objects, tuples and
 * sets arrays. Returns {ok, value} or {ok: false}.
 */
export function pyLiteralParse(text) {
  const s = String(text);
  const n = s.length;
  let i = 0, depth = 0;
  const ws = () => {
    for (;;) {
      while (i < n && " \t\n\r\f\v".includes(s[i])) i++;
      if (s[i] === "\\" && s[i + 1] === "\n") { i += 2; continue; }
      if (s[i] === "#") { while (i < n && s[i] !== "\n") i++; continue; }
      break;
    }
  };
  const fail = () => { throw new LitError(); };
  let nonLiteral = false;              // a name/call where a literal belongs: ValueError once the syntax is fine
  let topType = null;
  function str() {
    let raw = false, bytes = false;
    const pm = /^([rRuUbB]{0,2})(['"])/.exec(s.slice(i, i + 3));
    if (!pm) fail();
    const pre = pm[1].toLowerCase();
    if (pre && !["r", "u", "b", "br", "rb"].includes(pre)) fail();
    raw = pre.includes("r"); bytes = pre.includes("b");
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
      if (c === "\n" && !triple) fail();
      if (c === "\\") {
        const d = s[i + 1];
        if (d === undefined) fail();
        if (raw) { out += c + d; i += 2; continue; }
        i += 2;
        const simple = { "\n": "", "\\": "\\", "'": "'", '"': '"', a: "\x07", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v" };
        if (d in simple) { out += simple[d]; continue; }
        if (/[0-7]/.test(d)) {
          let oct = d;
          while (oct.length < 3 && /[0-7]/.test(s[i])) oct += s[i++];
          out += String.fromCodePoint(parseInt(oct, 8));
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
        if (!bytes && d === "N") fail();                                 // \N{...}: not needed for gyp
        out += "\\" + d;                                                 // unknown escape kept
        continue;
      }
      out += c;
      i++;
    }
    return out;
  }
  function num() {
    const m = /^(?:0[xX](?:_?[0-9a-fA-F])+|0[oO](?:_?[0-7])+|0[bB](?:_?[01])+|(?:\d(?:_?\d)*)?\.?\d(?:_?\d)*(?:[eE][-+]?\d(?:_?\d)*)?|\d(?:_?\d)*\.)[jJ]?/.exec(s.slice(i, i + 400));
    if (!m || !m[0]) fail();
    i += m[0].length;
    const t = m[0].replace(/_/g, "");
    if (/[jJ]$/.test(t)) return Number(t.slice(0, -1));                  // complex: magnitude only
    if (/^0[xX]/.test(t)) return parseInt(t.slice(2), 16);
    if (/^0[oO]/.test(t)) return parseInt(t.slice(2), 8);
    if (/^0[bB]/.test(t)) return parseInt(t.slice(2), 2);
    if (/^0\d/.test(t) && !/[.eE]/.test(t) && /[1-9]/.test(t)) fail();    // leading zeros
    return Number(t);
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
    ws();
    if (i >= n) fail();
    const c = s[i];
    if (topType === null) topType = c === "(" ? "tuple" : c === "[" ? "list" : c === "{" ? "brace" : "scalar";
    if (c === "(" || c === "[" || c === "{") {
      if (++depth > MAX_LITERAL_DEPTH) fail();
      i++;
      let v;
      if (c === "[") v = seq("]")[0];
      else if (c === "(") {
        ws();
        if (s[i] === ")") { i++; v = []; }
        else {
          const first = value();
          ws();
          if (s[i] === ")") { i++; v = first; }                          // parenthesized expression
          else if (s[i] === ",") { i++; const [rest] = seq(")"); v = [first, ...rest]; }
          else fail();
        }
      } else {
        ws();
        if (s[i] === "}") { i++; v = {}; }
        else {
          const k = value();
          ws();
          if (s[i] === ":") {
            i++;
            const obj = {};
            const put = (key, val) => Object.defineProperty(obj, String(key), { value: val, enumerable: true, writable: true, configurable: true });
            put(k, value());
            for (;;) {
              ws();
              if (s[i] === "}") { i++; break; }
              if (s[i] !== ",") fail();
              i++;
              ws();
              if (s[i] === "}") { i++; break; }
              const key = value();
              ws();
              if (s[i] !== ":") fail();
              i++;
              put(key, value());
            }
            v = obj;
          } else {
            const set = [k];
            ws();
            if (s[i] === ",") { i++; const [rest] = seq("}"); set.push(...rest); }
            else if (s[i] === "}") i++;
            else fail();
            v = set;
          }
        }
      }
      depth--;
      return v;
    }
    if (c === "'" || c === '"' || (/[rRuUbB]/.test(c) && /^[rRuUbB]{1,2}['"]/.test(s.slice(i, i + 3)))) {
      let out = str();
      for (;;) {                                                           // implicit concatenation
        ws();
        if (s[i] === "'" || s[i] === '"' || /^[rRuUbB]{1,2}['"]/.test(s.slice(i, i + 3))) out += str();
        else return out;
      }
    }
    if (c === "-" || c === "+") { i++; ws(); const v = value(); if (typeof v !== "number") fail(); return c === "-" ? -v : v; }
    if (/[0-9.]/.test(c)) return num();
    const w = /^[A-Za-z_]\w*/.exec(s.slice(i, i + 256));
    if (w && ["True", "False", "None"].includes(w[0])) { i += w[0].length; return w[0] === "True" ? true : w[0] === "False" ? false : null; }
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
    const v = value();
    ws();
    if (i !== n) fail();
    if (nonLiteral) return { ok: false, error: "ValueError" };
    let type = null;
    if (topType === "tuple" && Array.isArray(v)) type = "tuple";
    else if (topType === "brace" && Array.isArray(v)) type = "set";
    return { ok: true, value: v, type };
  } catch (e) {
    if (e instanceof LitError || e instanceof RangeError) return { ok: false, error: "SyntaxError" };
    throw e;
  }
}
