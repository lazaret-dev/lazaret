// Obfuscation/entropy/suppression helpers + mkIssue — verbatim from the dashboard (lazaret/web/lazaret.html).
// mkIssue itself lives in the leaf ../lib/issue.js and is re-exported here so
// scanner-side imports stay as they were (scanner→lib is the allowed direction;
// lib must never import scanner).

/* ---------------- Obfuscation / entropy / suppression ---------------- */
export function shannonEntropy(s){
  const f={}; for(const ch of s) f[ch]=(f[ch]||0)+1;
  return -Object.values(f).reduce((a,n)=>a+(n/s.length)*Math.log2(n/s.length),0);
}
export const ENTROPY_VALUE_RE = /[=:]\s*["']([A-Za-z0-9+\/=_\-]{20,})["']/;
export const B64_BLOB_RE = /["'][A-Za-z0-9+\/]{200,}={0,2}["']/;
export const OBF_IDENT_RE = /\b_0x[0-9a-f]{4,}\b/g;
export const SECRET_SKIP_RE = /environ|process\.env|getenv|placeholder|example|test|dummy|sample/i;
export const SUPPRESS_RE = /(?:#|\/\/|--)\s*(?:nosec|NOSONAR|lazaret-ignore)\b(?::?\s*([\w,\s-]+))?/i;

export function isSuppressed(issue, lines){
  for(const ln of [issue.line-1, issue.line-2]){
    if(ln<0 || ln>=lines.length) continue;
    if(ln===issue.line-2 && !/^\s*(#|\/\/|--)/.test(lines[ln])) continue;
    const m = lines[ln].match(SUPPRESS_RE);
    if(m && (!m[1] || m[1].split(",").map(s=>s.trim().toUpperCase()).includes(issue.rule.toUpperCase())))
      return true;
  }
  return false;
}

export { mkIssue } from "../lib/issue.js";

// isComment lives here (not in scan.js) so metrics.js can import it without
// a scan ↔ metrics cycle.
export function isComment(line, lang){
  const t = line.trim();
  if(lang==="py") return t.startsWith("#");
  if(lang==="sql") return t.startsWith("--")||t.startsWith("/*")||t.startsWith("*");
  return t.startsWith("//")||t.startsWith("*")||t.startsWith("/*");
}
