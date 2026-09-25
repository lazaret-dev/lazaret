// Obfuscation/entropy/suppression helpers — twins of lazaret.scanner.core
// (B64_BLOB_RE, OBF_IDENT_RE, SECRET_SKIP_RE, SUPPRESS_RE, is_suppressed).
// mkIssue itself lives in the leaf ../lib/issue.js and is re-exported here so
// scanner-side imports stay as they were (scanner→lib is the allowed direction;
// lib must never import scanner).

import { pyRe } from "../lib/pycompat.js";
import { lexLines } from "./lexer.js";

export { shannonEntropy, ENTROPY_VALUE_RE, entropySecretish } from "../lib/redact.js";
export { mkIssue } from "../lib/issue.js";
export { isComment } from "./lexer.js";

export const B64_BLOB_RE = pyRe(String.raw`[\"'][A-Za-z0-9+/]{200,}={0,2}[\"']`);
export const OBF_IDENT_RE = pyRe(String.raw`\b_0x[0-9a-f]{4,}\b`, "g");
export const CHARCODE_RE = /String\.fromCharCode/;
// Verdict integrity (audit C2/G2): no bare `test`, word-bounded tokens, so
// `latest` / `attested` / `# example_user` no longer suppress a real secret.
export const SECRET_SKIP_RE = pyRe(String.raw`environ|process\.env|getenv|\bplaceholder\b|\bexample\b|\bdummy\b|\bsample\b|\bmock\b|\bredacted\b|\bxxxx+\b`, "i");

// ---------------- Inline suppression (shared semantics spec 2) --------------
// Marker grammar (twin of core.SUPPRESS_RE): `#`, `//` or `--`, optional
// spaces/tabs, then nosec / NOSONAR / lazaret-ignore (case-insensitive, whole
// word). If what follows (after optional spaces and ':') is a comma-separated
// list of rule IDs, the marker suppresses only those rules; anything else —
// nothing, trailing whitespace, or a free-text reason such as "- reviewed by
// bob" — makes it a blanket marker for the line. The marker counts only when
// its introducer lies inside a real comment as the per-file lexer sees it
// (so `--` works in .sql comments, `#` in Python ones, and nothing inside a
// string, a template literal or code such as `x --nosec` or a JS `#private`
// field does). It applies to its own line, or to the next line when it sits
// on a standalone comment line.
const RULE_ID = String.raw`(?:S|T|SC|X|SQL|B|Q)-[A-Z0-9]+(?:-[A-Z0-9]+)*`;
export const SUPPRESS_RE = pyRe(String.raw`(?:#|//|--)[ \t]*(?:nosec|NOSONAR|lazaret-ignore)\b`
  + String.raw`(?:[ \t]*:?[ \t]*(` + RULE_ID + String.raw`(?:[ \t]*,[ \t]*` + RULE_ID + String.raw`)*))?`, "gi");

/** Findings from these families are never suppressible by markers in scanned code. */
export const UNSUPPRESSIBLE_PREFIXES = ["SC-", "X-"];

const NO_MARKER = Symbol("none");
/** Parsed marker of line i: NO_MARKER, null (blanket) or a Set of rule IDs. */
function markerOn(lines, lex, i) {
  const line = lines[i];
  if (!lex.spans.has(i) || !/nosec|nosonar|lazaret-ignore/i.test(line)) return NO_MARKER;
  SUPPRESS_RE.lastIndex = 0;
  let m;
  while ((m = SUPPRESS_RE.exec(line))) {
    if (!lex.inComment(i, m.index)) continue;
    return m[1] ? new Set(m[1].split(",").map((x) => x.trim().toUpperCase())) : null;
  }
  return NO_MARKER;
}

/**
 * Suppression filter for one file. SC-* and X-* findings are never
 * suppressed, and nothing is suppressed in dependency files (no reviewer
 * vouches for a marker there).
 */
export function makeSuppressor(lines, lang, { dep = false, lex = null } = {}) {
  if (dep) return () => false;
  lex ??= lexLines(lines, lang);
  const cache = new Map();
  const marker = (i) => {
    if (!cache.has(i)) cache.set(i, markerOn(lines, lex, i));
    return cache.get(i);
  };
  return (issue) => {
    const rule = String(issue.rule ?? "");
    if (UNSUPPRESSIBLE_PREFIXES.some((p) => rule.startsWith(p))) return false;
    const ln = issue.line - 1;
    for (const k of [ln, ln - 1]) {
      if (k < 0 || k >= lines.length) continue;
      if (k !== ln && !lex.comment[k]) continue;   // the line above counts only as a standalone comment
      const ids = marker(k);
      if (ids === NO_MARKER) continue;
      if (ids === null || ids.has(rule.toUpperCase())) return true;
    }
    return false;
  };
}

/** Back-compatible single-issue form: isSuppressed(issue, lines, lang?, dep?). */
export function isSuppressed(issue, lines, lang = "js", dep = false) {
  return makeSuppressor(lines, lang, { dep })(issue);
}
