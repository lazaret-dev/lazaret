// A project's metrics (BR-7 step 4 (a)): each file's line metrics are asked of the engine (metrics.rs), and the
// rest is the engine's too (result.rs): the duplication across the files, the lines it leaves out, the counts.

import { jsxReading } from "../lib/lexer.js";
import { normalizeNewlines } from "../lib/fs.js";
import { call, fileMetrics } from "../lib/native.js";

/**
 * Each file as the engine's result reads it: [dep, lang, [ncloc, comments, measured, windows]], or the file's text
 * in place of its metrics when the engine could not give them (its non-blank lines then count as code: review B3).
 */
export function metricsFiles(files) {
  return files.map((f) => {
    const lang = f.lang ?? null;
    if (f.dep) return [true, lang, ""];
    const key = f.path ?? f.name;                // CLI files carry `path`, library callers `name`
    const text = normalizeNewlines(String(f.content ?? ""));   // (no U+2028 split: core's lines)
    let got = null;
    try { got = fileMetrics(text, f.lang, { jsx: jsxReading(key) }); } catch { /* the text instead */ }
    return [false, lang, got ? [got.ncloc, got.comments, got.measured, got.windows] : text];
  });
}

/**
 * Files, lines of code, comment lines and duplication of a project's own files, its dependencies' left out (the
 * engine's: result.rs): the share of measured lines of code in a window of six consecutive ones that occurs twice or
 * more across them, and `dupLeftOut`, the lines of code of the languages it does not measure (Go, Rust: N-13).
 */
export function computeMetrics(files) {
  return call("project_metrics", { files: metricsFiles(files) });
}
