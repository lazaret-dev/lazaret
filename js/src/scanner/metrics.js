// Metrics & ratings — twin of lazaret.scanner.core compute_metrics /
// worst_sev_rating / maintainability_rating.

import { jsxReading } from "../lib/lexer.js";
import { pyStrip, pyRound1 } from "../lib/pycompat.js";
import { normalizeNewlines } from "../lib/fs.js";
import { pinUnicode } from "../lib/unicode13.js";
import { fileMetrics } from "../lib/native.js";

// The languages whose duplication is measured (twin of core.DUP_LANGS): a
// project's Go and Rust files count in the files, lines of code and
// comments, not yet in the duplication.
export const DUP_LANGS = new Set(["py", "js", "sql"]);

/**
 * Files, lines of code, comment lines and duplication of a project's own files (its dependencies' left out), as
 * core.compute_metrics: each file's part is the engine's (Q-1 step 4, metrics.rs), and the windows of six lines of
 * code that occur twice or more are found here, across the files. A file the engine could not answer counts its
 * non-blank lines as code (review B3), and its windows are not compared.
 */
export function computeMetrics(files) {
  let ncloc = 0, comments = 0, measured = 0;
  const nonDep = files.filter((f) => !f.dep);   // deps excluded from quality metrics
  const depFiles = files.length - nonDep.length;
  const starts = new Map();                      // a window's key -> where each occurrence starts
  for (const f of nonDep) {
    const key = f.path ?? f.name;                // CLI files carry `path`, library callers `name`
    const text = normalizeNewlines(String(f.content ?? ""));   // (no U+2028 split: core.compute_metrics)
    let got = null;
    try { got = fileMetrics(text, f.lang, { jsx: jsxReading(key) }); } catch { /* every non-blank line is code */ }
    if (!got) {
      const lines = pinUnicode(text).split("\n").filter((l) => pyStrip(l));
      ncloc += lines.length;
      if (f.lang == null || DUP_LANGS.has(f.lang)) measured += lines.length;
      continue;
    }
    ncloc += got.ncloc;
    comments += got.comments;
    for (let k = 0; k < got.windows.length; k += 16) {
      const w = got.windows.slice(k, k + 16);
      const at = starts.get(w);
      if (at) at.push(measured + k / 16); else starts.set(w, [measured + k / 16]);
    }
    measured += got.measured;
  }
  const dup = new Set();
  for (const at of starts.values()) {
    if (at.length < 2) continue;
    for (const a of at) for (let j = a; j < a + 6; j++) dup.add(j);
  }
  const dupPct = measured ? pyRound1(100 * dup.size / measured) : 0;
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
 * come from the cross-file passes (a file a reader rejects is one; since
 * phase 3 of the Rust-first refactor the Python pass runs here too, and
 * writes Q-FLOW-RECURSION); Q-TAINT-CONFIG is only Python's to write.
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
