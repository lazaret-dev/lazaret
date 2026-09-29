// Metrics & ratings — twin of lazaret.scanner.core compute_metrics /
// worst_sev_rating / maintainability_rating.

import { lexLines, jsxReading } from "../lib/lexer.js";
import { pyStrip, pyRound1 } from "../lib/pycompat.js";
import { normalizeNewlines } from "../lib/fs.js";
import { pinUnicode } from "../lib/unicode13.js";

export function computeMetrics(files) {
  let ncloc = 0, comments = 0;
  const nonDep = files.filter((f) => !f.dep);   // deps excluded from quality metrics
  const depFiles = files.length - nonDep.length;
  const winMap = new Map();
  for (const f of nonDep) {
    const key = f.path ?? f.name;                // CLI files carry `path`, library callers `name`
    const lines = pinUnicode(normalizeNewlines(String(f.content ?? ""))).split("\n");   // (no U+2028 split: core.compute_metrics)
    let lex = null;
    try { lex = lexLines(lines, f.lang, null, { jsx: jsxReading(key) }); }
    catch { /* its scan failed the same way (SC-TRUNCATED): count its lines as code rather than lose the report (review B3) */ }
    const code = [];
    for (let i = 0; i < lines.length; i++) {
      const t = pyStrip(lines[i]);
      if (!t) continue;
      if (lex && lex.comment[i]) { comments++; continue; }
      ncloc++;
      code.push([t, i]);
    }
    for (let i = 0; i + 6 <= code.length; i++) {
      let k = code[i][0];
      for (let j = i + 1; j < i + 6; j++) k += code[j][0];
      let occ = winMap.get(k);
      if (!occ) { occ = []; winMap.set(k, occ); }
      occ.push([key, i, code]);
    }
  }
  const dupSet = new Set();
  for (const occ of winMap.values()) {
    if (occ.length < 2) continue;
    for (const [key, i, code] of occ) for (let j = i; j < i + 6; j++) dupSet.add(`${key}\u0000${code[j][1]}`);
  }
  const dupPct = ncloc ? pyRound1(100 * dupSet.size / ncloc) : 0;
  return { files: nonDep.length, depFiles, ncloc, comments, dupPct };
}

export function worstSevRating(issues, types) {
  const sevs = new Set(issues.filter((i) => types.includes(i.type)).map((i) => i.sev));
  if (sevs.has("BLOCKER")) return "E";
  if (sevs.has("CRITICAL")) return "D";
  if (sevs.has("MAJOR")) return "C";
  if (sevs.has("MINOR")) return "B";
  return "A";
}
/**
 * INFO scan-coverage notes: typed SMELL for display, but they describe what
 * the scanner could not look at, not the code, so they do not count toward
 * the maintainability rating (twin of core.COVERAGE_RULES). The Q-FLOW notes
 * come from the JavaScript cross-file pass (0.1.7: a file its reader rejects
 * is one); Q-FLOW-RECURSION and Q-TAINT-CONFIG are only Python's to write.
 */
export const COVERAGE_RULES = new Set(["Q-SKIPPED-TREE", "Q-SYMLINK", "Q-UNREADABLE", "Q-SKIPPED-CONFIG",
  "Q-FLOW-SKIPPED", "Q-FLOW-INCOMPLETE", "Q-FLOW-RECURSION", "Q-TAINT-CONFIG"]);
/**
 * How many code smells a SMELL finding counts for: one, except a Q-CAPPED
 * note, which counts the findings it stands for when they are smells (and
 * nothing when they are bugs), so the rating is what it would be without the
 * cap (twin of core._rated_smells).
 */
function ratedSmells(i) {
  if (i.rule === "Q-CAPPED" && Number.isInteger(i.omitted)) return i.omittedType === "SMELL" ? i.omitted : 0;
  return 1;
}
export function maintainabilityRating(issues, ncloc) {
  let smells = 0;
  for (const i of issues) if (i.type === "SMELL" && !COVERAGE_RULES.has(i.rule)) smells += ratedSmells(i);
  const per100 = ncloc ? 100 * smells / ncloc : 0;
  return per100 <= 5 ? "A" : per100 <= 10 ? "B" : per100 <= 20 ? "C" : per100 <= 40 ? "D" : "E";
}
