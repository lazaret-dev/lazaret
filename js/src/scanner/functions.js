// extractFunctions — twin of lazaret.scanner.core.extract_functions (G4
// linear brace-walk for JS; indentation spans for Python).

import { pyRe, pyStrip, pyLstrip, isPySpace, isWordChar } from "../lib/pycompat.js";

const PY_DEF_RE = pyRe(String.raw`^(\s*)(?:async\s+)?def\s+(\w+)`);
const PY_CX_RE = pyRe(String.raw`\b(if|elif|for|while|and|or|except|case)\b`, "g");
const JS_CX_RE = pyRe(String.raw`\b(if|for|while|case|catch)\b|&&|\|\||\?[^.:]`, "g");
const count = (s, re) => { re.lastIndex = 0; let n = 0; while (re.exec(s)) n++; return n; };

const isW = (s, i) => {
  if (i < 0 || i >= s.length) return false;
  const c = s.charCodeAt(i);
  if (c < 128) return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95;
  return isWordChar(String.fromCodePoint(s.codePointAt(i)));
};
function wordEnd(s, i) {
  while (i < s.length && isW(s, i)) i += s.codePointAt(i) > 0xffff ? 2 : 1;
  return i;
}
function skipSpace(s, i) { while (i < s.length && isPySpace(s[i])) i++; return i; }
/** The first `n` code points of s. */
function cpSlice(s, n) {
  if (s.length <= n) return s;
  if (!/[\ud800-\udbff]/.test(s.slice(0, 2 * n))) return s.slice(0, n);
  return Array.from(s).slice(0, n).join("");
}

/**
 * First function header on a line — the language of the Python engine's
 *   (?:function\s+(\w+)
 *    |(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function|\([^()]*\)\s*=>|\w+\s*=>)
 *    |(?<!\w)(\w+)\s*\([^()]*\)\s*\{)
 * searched in the first FN_HEADER_SCAN_LIMIT characters of the line,
 * leftmost-first, in linear time. Returns the name or null.
 */
export const FN_HEADER_SCAN_LIMIT = 2000;
export function fnHeader(fullLine) {
  const line = cpSlice(fullLine, FN_HEADER_SCAN_LIMIT);
  const n = line.length;
  let parens = null;
  const closeAfter = (i) => {                      // first '(' or ')' at or after i: must be ')'
    if (parens === null) {
      parens = [];
      for (let k = 0; k < n; k++) { const c = line.charCodeAt(k); if (c === 40 || c === 41) parens.push(k); }
    }
    let lo = 0, hi = parens.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (parens[mid] < i) lo = mid + 1; else hi = mid; }
    return lo < parens.length && line[parens[lo]] === ")" ? parens[lo] : -1;
  };
  const arrowTail = (q) => {                        // function | \([^()]*\)\s*=> | \w+\s*=>
    if (line.startsWith("function", q)) return true;
    if (line[q] === "(") {
      const rp = closeAfter(q + 1);
      if (rp < 0) return false;
      const k = skipSpace(line, rp + 1);
      return line.startsWith("=>", k);
    }
    if (!isW(line, q)) return false;
    return line.startsWith("=>", skipSpace(line, wordEnd(line, q)));
  };
  for (let p = 0; p < n; p++) {
    // alternative 1: function\s+(\w+)
    if (line.startsWith("function", p)) {
      const s = skipSpace(line, p + 8);
      if (s > p + 8 && isW(line, s)) return line.slice(s, wordEnd(line, s));
    }
    // alternative 2: (?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(…)
    const kw = line.startsWith("const", p) ? 5 : (line.startsWith("let", p) || line.startsWith("var", p)) ? 3 : 0;
    if (kw) {
      const s = skipSpace(line, p + kw);
      if (s > p + kw && isW(line, s)) {
        const e = wordEnd(line, s);
        const eq = skipSpace(line, e);
        if (line[eq] === "=") {
          const q = skipSpace(line, eq + 1);
          let ok = false;
          if (line.startsWith("async", q)) ok = arrowTail(skipSpace(line, q + 5));
          if (!ok) ok = arrowTail(q);
          if (ok) return line.slice(s, e);
        }
      }
    }
    // alternative 3: (?<!\w)(\w+)\s*\([^()]*\)\s*\{
    if (isW(line, p) && (p === 0 || (!isW(line, p - 1)
        && !(p >= 2 && line.charCodeAt(p - 1) >= 0xdc00 && line.charCodeAt(p - 1) <= 0xdfff && isW(line, p - 2))))) {
      const e = wordEnd(line, p);
      const k = skipSpace(line, e);
      if (line[k] === "(") {
        const rp = closeAfter(k + 1);
        if (rp >= 0) {
          const b = skipSpace(line, rp + 1);
          if (line[b] === "{") return line.slice(p, e);
        }
      }
    }
  }
  return null;
}

/**
 * Functions with their length and cyclomatic complexity.
 */
export function extractFunctions(lines, lang) {
  const fns = [];
  if (lang !== "py" && lang !== "js") return fns;   // no function metrics for SQL
  if (lang === "py") {
    // A def ends at the first later line that is non-blank, not a comment
    // ('#' after stripping) and indented no deeper than the def — one pass
    // with a stack of open defs (twin of core.extract_functions).
    const cxPrefix = [0];
    for (const line of lines) cxPrefix.push(cxPrefix[cxPrefix.length - 1] + count(line, PY_CX_RE));
    const found = [], spans = new Map(), stack = [];
    for (let k = 0; k < lines.length; k++) {
      const l = lines[k];
      const m = l.includes("def") ? PY_DEF_RE.exec(l) : null;
      const t = pyStrip(l);
      if (t && !t.startsWith("#")) {
        const ind = m ? m[1].length : l.length - pyLstrip(l).length;
        while (stack.length && stack[stack.length - 1][0] >= ind) spans.set(stack.pop()[1], k);
      }
      if (m) { found.push([k, m[2]]); stack.push([m[1].length, k]); }
    }
    for (const [, k] of stack) spans.set(k, lines.length);
    for (const [i, name] of found) {
      const end = spans.get(i);
      fns.push({ name, line: i + 1, len: end - i, cx: 1 + cxPrefix[end] - cxPrefix[i] });
    }
    return fns;
  }
  // G4 (twin of the Python extract_functions fix): one linear brace walk.
  // Each header claims the first '{' at/after its LINE START, spans share a
  // brace exactly as the old independent scans did, the 800-line cap is
  // kept, and complexity comes from per-line counts instead of body copies.
  const content = lines.join("\n");
  const starts = [0];
  for (let j = 0; j < content.length; j++) if (content.charCodeAt(j) === 10) starts.push(j + 1);
  starts.push(content.length + 1);            // sentinel
  const headers = [];                          // {line, name}
  for (let i = 0; i < lines.length; i++) {
    const name = fnHeader(lines[i]);
    if (name !== null) headers.push({ line: i, name: name || "(anonymous)" });
  }
  const cxPrefix = [0];
  for (const line of lines) cxPrefix.push(cxPrefix[cxPrefix.length - 1] + count(line, JS_CX_RE));
  const opens = [];
  for (let j = 0; j < content.length; j++) if (content.charCodeAt(j) === 123) opens.push(j);
  const matched = new Map();                   // header idx -> [openPos, closePos]
  const stack = [];
  let waiting = [];
  let hi = 0;
  for (let bpos = 0; bpos < content.length; bpos++) {
    const c = content.charCodeAt(bpos);
    if (c !== 123 && c !== 125) continue;
    while (hi < headers.length && starts[headers[hi].line] <= bpos) waiting.push(hi++);
    if (c === 123) { stack.push([bpos, waiting]); waiting = []; }
    else if (stack.length) {
      const [openPos, owners] = stack.pop();
      for (const h of owners) matched.set(h, [openPos, bpos]);
    }
  }
  const n = lines.length;
  for (let h = 0; h < headers.length; h++) {
    const i = headers[h].line, name = headers[h].name;
    const windowEndOff = starts[Math.min(n, i + 800)];
    let lo = 0, hiB = opens.length;               // first '{' at/after the header's line start
    while (lo < hiB) { const mid = (lo + hiB) >> 1; if (opens[mid] < starts[i]) lo = mid + 1; else hiB = mid; }
    if (lo === opens.length || opens[lo] >= windowEndOff) continue;   // no '{' in window
    let end;
    if (matched.has(h) && matched.get(h)[1] < windowEndOff) {
      const closePos = matched.get(h)[1];
      let a = 0, b = starts.length;               // bisect_right(starts, closePos) - 1
      while (a < b) { const mid = (a + b) >> 1; if (starts[mid] <= closePos) a = mid + 1; else b = mid; }
      end = a - 1;
    } else {
      end = Math.min(n, i + 800) - 1;            // unclosed within window: old truncation
    }
    fns.push({ name, line: i + 1, len: end - i + 1, cx: 1 + cxPrefix[end + 1] - cxPrefix[i] });
  }
  return fns;
}
