// Issue shape-builder — the one shared primitive every producer (scanner
// engine, SQL-sink analyzer, supply-chain manifest scanner) needs. Lives here
// so src/lib/supplychain.js can build issues without importing the scanner
// (RESTRUCTURE.md §5: src/lib/ imports nothing from src/scanner/); the
// scanner's engine.js re-exports it, so existing scanner-side imports keep
// working unchanged.
//
// core.mk_issue / clip_snippet_line: the engine makes the snippets (spec 7)
// and redacts them (spec 6) for the findings this package still builds, as it
// does its own (BR-7 step 3 c, 0.1.9: redact.rs), so library callers of
// scanFile never see a raw credential or a multi-megabyte snippet either.

import { cpIndex } from "./pycompat.js";
import { call } from "./native.js";
import { REDACT, isScanContext, linesText, redactText } from "./redact.js";

export const SNIPPET_MAX = 240;      // characters (code points) per snippet line
export const SNIPPET_LEAD = 60;      // context kept before the match on the flagged line

// Code-point offsets (Python's str indexing) into a long line, in O(log n)
// per finding: mkIssue's `col` is a UTF-16 offset, the engine's a code-point
// one, and cpLen(line.slice(0, col)) for EVERY finding made 10k findings on
// one 150 KB line take seconds. The view of a line — the UTF-16 offsets of
// its surrogate pairs, or null when it has none (then code-point and UTF-16
// offsets coincide) — is computed once and kept for the few most recent long
// lines.
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
 * Clip one snippet line to SNIPPET_MAX characters (core.clip_snippet_line, the engine's). The flagged line is
 * windowed around the match (`col`, a code-point offset): the window starts SNIPPET_LEAD characters before it (never
 * past the point where it would run off the end) and "…" marks each side that was cut. Other lines keep their start.
 */
export function clipLine(text, col = null) {
  if (typeof text !== "string" || text.length <= SNIPPET_MAX) return text;
  return call("clip_line", { col: Number.isInteger(col) ? col : null }, text);
}

const RULE_TEXTS = ["id", "name", "type", "sev", "msg", "why", "fix", "ref"];

/**
 * Build a finding (mkIssues, for one). `rule` is a table row or a hand-built row with {id, name, type, sev, msg, why,
 * fix, ref}; `file` is {name} / {path} or the name. Snippet is ±2 lines around the finding line. `col` is the UTF-16
 * offset of the match on the flagged line (optional).
 */
export function mkIssue(rule, file, line, lines, col = null) {
  return mkIssues(file, lines, [[rule, line, col]])[0];
}

/**
 * A finding for each of `rows` ([rule, line, col]: mkIssue's) of the file `file` whose lines are `lines`, made by the
 * engine (core.mk_issues; the lines handed over once). With redaction on, a secret rule's flagged line is the
 * placeholder and the other lines and the message are redacted: with the file's entropy literals too when `lines`
 * are a registered file's (registerScanContext; core's _Redactor).
 */
export function mkIssues(file, lines, rows) {
  if (!rows.length) return [];
  const name = typeof file === "string" ? file : (file.name ?? file.path);
  const items = rows.map(([rule, line, col = null]) => {
    const flagged = lines[line - 1];
    const cp = col != null && typeof flagged === "string" ? cpIndexOf(flagged, col) : null;
    return [Object.fromEntries(RULE_TEXTS.map((k) => [k, rule[k]])), line, cp];
  });
  const got = call("issue_make", { items, redact: REDACT.on, context: isScanContext(lines), neumaier: false },
    linesText(lines)).issues;
  return rows.map(([rule, line], k) => ({
    rule: rule.id, name: rule.name, type: rule.type, sev: rule.sev,
    msg: typeof rule.msg === "string" ? got[k][4] : rule.msg,
    why: rule.why, fix: rule.fix, ref: rule.ref, file: name, line,
    snippet: got[k][9], snipStart: got[k][10],
  }));
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

/** SC-TRUNCATED for a file not fully scanned (core.truncated_issue): `detail` says why. */
export function truncatedIssue(path, detail) {
  return fileIssue({ id: "SC-TRUNCATED", name: "Scan truncated", type: "HOTSPOT", sev: "CRITICAL",
    msg: `File not fully scanned: ${detail}.`,
    why: "Scanning stopped early, so a clean verdict for this file is not evidence of anything — the unscanned bytes are exactly where a hostile artifact would put its payload (audit C2/G16: declared sizes and entry counts are attacker-controlled and were used to skip files with zero signal).",
    fix: "Review the file manually or raise the limit and re-scan.",
    ref: "CWE-506 · Supply chain" }, path);
}

/**
 * SC-TRUNCATED for a file (or directory) whose scan threw (twin of
 * core.scan_error_issue): the run goes on without its findings, and like any
 * file not fully scanned it fails the gate. It was an INFO note
 * (Q-SCAN-ERROR), so a file whose scan died took its CRITICAL findings with
 * it and the gate passed (review B3: a 6 MB string line overflowed V8's
 * regex stack).
 */
export function scanErrorIssue(path, err) {
  const issue = truncatedIssue(path, `its scan failed (${(err && err.name) || "Error"}), so its findings are missing`);
  issue.why = "An internal error stopped this scan; the rest of the project is still scanned and reported, but nothing in this file was checked, so the result can't clear it.";
  issue.fix = "Review the file manually and report the error (re-run with LAZARET_DEBUG=1 for a traceback).";
  return issue;
}
