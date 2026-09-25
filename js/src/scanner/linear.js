// Linear-time matchers for rule patterns that backtrack super-linearly on
// adversarial input (audit: a 547 KB .sql took 15.7 s in one regex; 2 MB
// files took minutes). Each function implements EXACTLY the language of the
// Python pattern it replaces (quoted above it) — same matches, so the
// engines agree — using head regexes plus precomputed delimiter positions
// instead of rescanning the line from every head.

import { pyRe, isPySpace as isWs, isWordChar } from "../lib/pycompat.js";

/** Sorted positions of every match of `re` (global) in s. */
function positions(s, re) {
  const out = [];
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(s))) { out.push(m.index); if (m[0].length === 0) re.lastIndex++; }
  return out;
}
/** Index of the first element >= x in the sorted array a (a.length if none). */
function lowerBound(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] < x) lo = mid + 1; else hi = mid; }
  return lo;
}
const firstAtOrAfter = (a, x) => { const k = lowerBound(a, x); return k < a.length ? a[k] : -1; };
function heads(s, re) {
  const out = [];
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(s))) {
    out.push([m.index, m.index + m[0].length]);
    re.lastIndex = m.index + 1;               // every head, even overlapping ones
  }
  return out;
}

// SQL-DYNAMIC (re.I) — the Python engine's linear form: each tempered scan
// stops at the next head of its own kind.
//   EXEC(?:UTE)?\s*\(\s*@?\w+\s*\+
//   |EXECUTE\s+IMMEDIATE\b(?:(?!EXECUTE\s+IMMEDIATE\b)[^;])*\|\|
//   |sp_executesql\b(?:(?!sp_executesql\b)[^;])*\+
//   |EXEC\s*\(\s*['\"][^']*['\"]\s*\+
//   |SET\s+@\w+\s*=(?:(?!SET\s+@)[^;'\"])*['\"](?:(?!SET\s+@)[^;])*(?:\+|\|\|)
const DYN_A1 = pyRe(String.raw`EXEC(?:UTE)?\s*\(\s*@?\w+\s*\+`, "i");
const DYN_A2 = pyRe(String.raw`EXECUTE\s+IMMEDIATE\b`, "gi");
const DYN_A3 = pyRe(String.raw`sp_executesql\b`, "gi");
const DYN_A4 = pyRe(String.raw`EXEC\s*\(\s*['\"]`, "gi");
const DYN_A5 = pyRe(String.raw`SET\s+@\w+\s*=`, "gi");
const SET_AT = pyRe(String.raw`SET\s+@`, "gi");
const none = (x) => x < 0 ? Infinity : x;
export function sqlDynamicFind(s) {
  if (!/exec|sp_executesql|set/i.test(s)) return -1;
  let best = -1;
  const take = (i) => { if (i >= 0 && (best < 0 || i < best)) best = i; };
  const m1 = DYN_A1.exec(s);
  if (m1) take(m1.index);
  let semis = null, pipes = null, pluses = null, quotes = null, setAt = null;
  const semiAfter = (i) => { semis ??= positions(s, /;/g); const x = firstAtOrAfter(semis, i); return x < 0 ? s.length : x; };
  const pipeAfter = (i) => { pipes ??= positions(s, /\|(?=\|)/g); return firstAtOrAfter(pipes, i); };
  const plusAfter = (i) => { pluses ??= positions(s, /\+/g); return firstAtOrAfter(pluses, i); };
  const setAfter = (i) => { setAt ??= positions(s, SET_AT); return none(firstAtOrAfter(setAt, i)); };
  const a2 = heads(s, DYN_A2), a2starts = a2.map((h) => h[0]);
  for (const [h, e] of a2) {                         // tempered [^;]* then \|\|
    const p = pipeAfter(e);
    if (p >= 0 && p < semiAfter(e) && p < none(firstAtOrAfter(a2starts, e))) { take(h); break; }
  }
  const a3 = heads(s, DYN_A3), a3starts = a3.map((h) => h[0]);
  for (const [h, e] of a3) {                         // tempered [^;]* then \+
    const p = plusAfter(e);
    if (p >= 0 && p < semiAfter(e) && p < none(firstAtOrAfter(a3starts, e))) { take(h); break; }
  }
  const a4 = heads(s, DYN_A4);
  if (a4.length) {                                   // [^']*['\"]\s*\+
    const n = s.length;
    const plusFrom = new Uint8Array(n + 1);          // s[i:] matches \s*\+
    for (let i = n - 1; i >= 0; i--) plusFrom[i] = s[i] === "+" || (isWs(s[i]) && plusFrom[i + 1]) ? 1 : 0;
    const goodDq = new Int32Array(n + 1);            // prefix count of `"` followed by \s*\+
    for (let i = 0; i < n; i++) goodDq[i + 1] = goodDq[i] + (s[i] === '"' && plusFrom[i + 1] ? 1 : 0);
    const sq = positions(s, /'/g);
    for (const [h, e] of a4) {
      const q0 = e - 1;                               // the opening quote
      let nsq = firstAtOrAfter(sq, q0 + 1);
      if (nsq < 0) nsq = n;
      if (goodDq[nsq] - goodDq[q0 + 1] > 0 || (nsq < n && plusFrom[nsq + 1])) { take(h); break; }
    }
  }
  for (const [h, e] of heads(s, DYN_A5)) {           // tempered, quote first, then + or ||
    const semi = semiAfter(e);
    quotes ??= positions(s, /['"]/g);
    const q = firstAtOrAfter(quotes, e);
    if (q < 0 || q >= semi || setAfter(e) < q) continue;
    const p = plusAfter(q + 1), d = pipeAfter(q + 1);
    const limit = Math.min(semi, setAfter(q + 1));
    if ((p >= 0 && p < limit) || (d >= 0 && d < limit)) { take(h); break; }
  }
  return best;
}

// SQL-GRANT-PUBLIC (re.I): \bGRANT\b(?:(?!\bGRANT\b)[^;])*\bTO\s+PUBLIC\b
const GRANT_HEAD = pyRe(String.raw`\bGRANT\b`, "gi");
const TO_PUBLIC = pyRe(String.raw`\bTO\s+PUBLIC\b`, "gi");
export function grantPublicFind(s) {
  if (!/grant/i.test(s)) return -1;
  const targets = positions(s, TO_PUBLIC);
  if (!targets.length) return -1;
  const semis = positions(s, /;/g);
  const grants = heads(s, GRANT_HEAD), starts = grants.map((g) => g[0]);
  for (const [h, e] of grants) {
    const t = firstAtOrAfter(targets, e);
    if (t < 0) break;
    const semi = firstAtOrAfter(semis, e);
    if ((semi < 0 || t < semi) && t < none(firstAtOrAfter(starts, e))) return h;
  }
  return -1;
}

// S-YAML: yaml\.load\s*\((?!(?:(?!yaml\.load)[^)])*(?:SafeLoader|safe_load))
// (the look-ahead stops at the next ')' and at the next yaml.load)
const YAML_HEAD = pyRe(String.raw`yaml\.load\s*\(`, "g");
const YAML_SAFE = /SafeLoader|safe_load/g;
export function yamlLoadFind(s) {
  if (!s.includes("yaml.load")) return -1;
  const safe = positions(s, YAML_SAFE);             // the words contain no ')'
  const parens = positions(s, /\)/g);
  const loads = positions(s, /yaml\.load/g);
  for (const [h, e] of heads(s, YAML_HEAD)) {
    const rp = none(firstAtOrAfter(parens, e));
    const a = firstAtOrAfter(safe, e);
    if (a < 0 || a >= rp || a >= none(firstAtOrAfter(loads, e))) return h;
  }
  return -1;
}

// S-CHMOD: chmod\s*\([^,()]*,\s*0o?7[67]7
const CHMOD_HEAD = pyRe(String.raw`chmod\s*\(`, "g");
const CHMOD_TAIL = pyRe(String.raw`^\s*0o?7[67]7`);
export function chmodFind(s) {
  if (!s.includes("chmod")) return -1;
  const delims = positions(s, /[,()]/g);
  for (const [h, e] of heads(s, CHMOD_HEAD)) {
    const c = firstAtOrAfter(delims, e);
    if (c < 0) break;
    if (s[c] === "," && CHMOD_TAIL.test(s.slice(c + 1, c + 64))) return h;
  }
  return -1;
}

// ---- TEXT_RULES over the whole file ----------------------------------------
// B-EMPTY-CATCH: catch\s*(\([^()]*\))?\s*\{\s*\}   (finditer: non-overlapping)
export function emptyCatchScan(content) {
  const out = [];
  if (!content.includes("catch")) return out;
  const parens = positions(content, /[()]/g);
  const n = content.length;
  const skipWs = (i) => { while (i < n && isWs(content[i])) i++; return i; };
  const tail = (k) => {                            // \s*\{\s*\}
    k = skipWs(k);
    if (content[k] !== "{") return -1;
    k = skipWs(k + 1);
    return content[k] === "}" ? k + 1 : -1;
  };
  let pos = 0, p;
  while ((p = content.indexOf("catch", pos)) !== -1) {
    const i = skipWs(p + 5);
    let end = -1;
    if (content[i] === "(") {
      const rp = firstAtOrAfter(parens, i + 1);        // [^()]*\) — the next paren must close
      if (rp >= 0 && content[rp] === ")") end = tail(rp + 1);
    } else {
      end = tail(i);
    }
    if (end >= 0) { out.push(p); pos = end; } else pos = p + 1;
  }
  return out;
}

// B-EXCEPT-PASS: except(?:(?!except)[^\n:])*:[^\S\n]*\n\s*pass\b   (finditer)
// ≡ an "except", then (same line, no ':' in between) the first ':', then a
// whitespace run containing a newline, then `pass` at a word boundary.
export function exceptPassScan(content) {
  const out = [];
  if (!content.includes("except")) return out;
  const stops = positions(content, /[:\n]/g);
  const n = content.length;
  const verdict = new Map();                       // colon offset → match end or -1
  const atColon = (c) => {
    if (verdict.has(c)) return verdict.get(c);
    let k = c + 1, sawNl = false;
    while (k < n && isWs(content[k])) { if (content[k] === "\n") sawNl = true; k++; }
    const ok = sawNl && content.startsWith("pass", k) && !isWordChar(String.fromCodePoint(content.codePointAt(k + 4) ?? 0x20));
    const end = ok ? k + 4 : -1;
    verdict.set(c, end);
    return end;
  };
  const excepts = positions(content, /except/g);
  let pos = 0, p;
  while ((p = content.indexOf("except", pos)) !== -1) {
    const c = firstAtOrAfter(stops, p + 6);
    const inner = firstAtOrAfter(excepts, p + 1);             // (?!except) inside the run
    const end = c >= 0 && content[c] === ":" && (inner < 0 || inner >= c) ? atColon(c) : -1;
    if (end >= 0) { out.push(p); pos = end; } else pos = p + 1;
  }
  return out;
}
