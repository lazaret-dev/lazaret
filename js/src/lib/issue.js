// Issue shape-builder — the one shared primitive every producer (scanner
// engine, SQL-sink analyzer, supply-chain manifest scanner) needs. Lives here
// so src/lib/supplychain.js can build issues without importing the scanner
// (RESTRUCTURE.md §5: src/lib/ imports nothing from src/scanner/); the
// scanner's engine.js re-exports it, so existing scanner-side imports keep
// working unchanged.
//
// Twin of lazaret.scanner.core.mk_issue / clip_snippet_line: snippets
// (spec 7) and redaction (spec 6) happen HERE, so library callers of
// scanFile never see a raw credential or a multi-megabyte snippet either.

import { cpIndex } from "./pycompat.js";
import {
  REDACT, SECRET_RULES, REDACTED, scanContext, contextSecrets, contextRedacted,
  pemBlockLines, redactContextLine, redactText, secretPlaceholder,
} from "./redact.js";

export const SNIPPET_MAX = 240;      // characters (code points) per snippet line
export const SNIPPET_LEAD = 60;      // context kept before the match on the flagged line
const ELLIPSIS = "…";

// Code-point offsets (Python's str indexing) into a long line, in O(log n)
// per finding: clipLine used to build Array.from(line) and mkIssue
// cpLen(line.slice(0, col)) for EVERY finding, so 10k findings on one 150 KB
// line took 12.6 s (20k: > 44 s). The view of a line — the UTF-16 offsets of
// its surrogate pairs, or null when it has none (then code-point and UTF-16
// offsets coincide) — is computed once and kept for the few most recent long
// lines; the output is exactly the code-point-based clipping of
// core.clip_snippet_line.
const CP_VIEW_CACHE = 8;
const cpViews = new Map();
const PAIR_RE = /[\ud800-\udbff][\udc00-\udfff]/g;
function surrogatePairs(s) {
  let v = cpViews.get(s);
  if (v !== undefined) return v;
  v = null;
  if (/[\ud800-\udbff]/.test(s)) {
    const at = [];
    PAIR_RE.lastIndex = 0;
    let m;
    while ((m = PAIR_RE.exec(s))) at.push(m.index);
    if (at.length) v = at;
  }
  if (cpViews.size >= CP_VIEW_CACHE) cpViews.delete(cpViews.keys().next().value);
  cpViews.set(s, v);
  return v;
}
/** UTF-16 offset of code point `c` (pair j starts at code point pairs[j] - j). */
function unitAt(pairs, c) {
  if (!pairs) return c;
  let lo = 0, hi = pairs.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (pairs[mid] - mid < c) lo = mid + 1; else hi = mid; }
  return c + lo;
}
/** cpIndex(s, off) — the code-point index of UTF-16 offset `off` — for any line length. */
export function cpIndexOf(s, off) {
  if (s.length <= SNIPPET_MAX || off < 0) return cpIndex(s, off);
  const u = Math.min(off, s.length);
  const pairs = surrogatePairs(s);
  if (!pairs) return u;
  let lo = 0, hi = pairs.length;                  // pairs wholly before u
  while (lo < hi) { const mid = (lo + hi) >> 1; if (pairs[mid] + 2 <= u) lo = mid + 1; else hi = mid; }
  return u - lo;
}

/**
 * Clip one snippet line to SNIPPET_MAX characters. The flagged line is
 * windowed around the match (`col`, a code-point offset): the window starts
 * SNIPPET_LEAD characters before it (never past the point where it would
 * run off the end) and "…" marks each side that was cut. Other lines keep
 * their start. O(window) per call once the line's view is cached.
 */
export function clipLine(text, col = null) {
  if (typeof text !== "string" || text.length <= SNIPPET_MAX) return text;
  const pairs = surrogatePairs(text);
  const n = text.length - (pairs ? pairs.length : 0);
  if (n <= SNIPPET_MAX) return text;
  let start = col == null ? 0 : Math.max(0, col - SNIPPET_LEAD);
  start = Math.min(start, n - (SNIPPET_MAX - 1));
  const head = start > 0 ? ELLIPSIS : "";
  const end = start + SNIPPET_MAX - head.length;
  const from = unitAt(pairs, start);
  if (end < n) return head + text.slice(from, unitAt(pairs, end - 1)) + ELLIPSIS;
  return head + text.slice(from);
}

/**
 * Build a finding. `rule` is a table row or a hand-built row with
 * {id, name, type, sev, msg, why, fix, ref}; `file` is {name} / {path} or
 * the name. Snippet is ±2 lines around the finding line. `col` is the
 * UTF-16 offset of the match on the flagged line (optional).
 */
export function mkIssue(rule, file, line, lines, col = null) {
  const name = typeof file === "string" ? file : (file.name ?? file.path);
  const start = Math.max(0, line - 3);
  const stop = Math.min(lines.length, line + 2);
  const flag = line - 1;
  const ctx = REDACT.on ? scanContext(lines) : null;
  const msg = REDACT.on ? redactText(rule.msg, ctx ? contextSecrets(ctx) : null) : rule.msg;
  const redact = REDACT.on && flag >= 0 && flag < lines.length;
  const pem = redact && !ctx ? pemBlockLines(lines) : null;
  const cpCol = col != null && typeof lines[flag] === "string" ? cpIndexOf(lines[flag], col) : null;
  const snippet = [];
  for (let k = start; k < stop; k++) {
    let l = lines[k];
    if (typeof l !== "string") { snippet.push(l); continue; }
    if (redact) {
      if (k === flag && SECRET_RULES.has(rule.id)) l = secretPlaceholder(rule.id, l);
      else if (ctx) l = contextRedacted(ctx, k);
      else l = pem.has(k) ? REDACTED : redactContextLine(l);
    }
    snippet.push(clipLine(l, k === flag ? cpCol : null));
  }
  return {
    rule: rule.id, name: rule.name, type: rule.type, sev: rule.sev, msg,
    why: rule.why, fix: rule.fix, ref: rule.ref, file: name, line,
    snippet, snipStart: start + 1,
  };
}

/** File-level synthetic finding with an empty snippet (walker/truncation). */
export function fileIssue(rule, file, line = 1) {
  return {
    rule: rule.id, name: rule.name, type: rule.type, sev: rule.sev,
    msg: REDACT.on ? redactText(rule.msg) : rule.msg,
    why: rule.why, fix: rule.fix, ref: rule.ref, file, line,
    snippet: [], snipStart: 1,
  };
}
