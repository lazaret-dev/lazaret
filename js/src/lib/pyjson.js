// Python-compatible parsing of JSON text (zero-dependency leaf): pyJsonParse,
// json.loads semantics (NaN/Infinity accepted, and on failure the exact error
// position CPython's decoder reports, so "JSONDecodeError: line L column C"
// reads the same in both packages; a trailing comma is reported at the comma,
// as Python 3.13+ does and core.json_error_where does on every version;
// nesting deeper than MAX_JSON_DEPTH is reported as a depth failure, Python's
// RecursionError, in document order). The baseline reads it. A manifest is
// the engine's to read since BR-7's step 3 (b) (its manifest/pyjson.rs and
// pylit.rs: json.loads and ast.literal_eval), as is its data (supplychain.js
// loadManifest).

import { MAX_JSON_DEPTH, PY_ORDER } from "./pycompat.js";

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
        const comma = i;
        i = skip(i + 1);
        if (i < n && s[i] === "}") throw new JsonError(comma);            // Illegal trailing comma (3.13+'s position)
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
        const comma = i;
        i = skip(i + 1);
        if (i < n && s[i] === "]") throw new JsonError(comma);            // Illegal trailing comma (3.13+'s position)
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
