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

import { cpLen, cpIndex } from "./pycompat.js";
import {
  REDACT, SECRET_RULES, REDACTED, scanContext, contextSecrets, contextRedacted,
  pemBlockLines, redactContextLine, redactText, secretPlaceholder,
} from "./redact.js";

export const SNIPPET_MAX = 240;      // characters (code points) per snippet line
export const SNIPPET_LEAD = 60;      // context kept before the match on the flagged line
const ELLIPSIS = "…";

/**
 * Clip one snippet line to SNIPPET_MAX characters. The flagged line is
 * windowed around the match (`col`, a code-point offset): the window starts
 * SNIPPET_LEAD characters before it (never past the point where it would
 * run off the end) and "…" marks each side that was cut. Other lines keep
 * their start.
 */
export function clipLine(text, col = null) {
  if (typeof text !== "string" || text.length <= SNIPPET_MAX) return text;
  const n = cpLen(text);
  if (n <= SNIPPET_MAX) return text;
  const cps = Array.from(text);
  let start = col == null ? 0 : Math.max(0, col - SNIPPET_LEAD);
  start = Math.min(start, n - (SNIPPET_MAX - 1));
  const head = start > 0 ? ELLIPSIS : "";
  const end = start + SNIPPET_MAX - head.length;
  if (end < n) return head + cps.slice(start, end - 1).join("") + ELLIPSIS;
  return head + cps.slice(start).join("");
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
  const cpCol = col != null && typeof lines[flag] === "string" ? cpIndex(lines[flag], col) : null;
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
