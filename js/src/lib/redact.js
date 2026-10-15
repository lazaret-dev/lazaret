// Secret redaction (audit L1, shared semantics spec 6) — leaf module.
//
// The flagged line of a SECRET-rule finding is replaced by a deterministic
// placeholder, and every other snippet line (and the issue msg, and any
// field that copies source text such as an install hook's `cmd`) has
// credential-shaped substrings replaced by "[redacted]": the matches of the
// line patterns, the lines of a PEM private key's block whole, and for a
// file's own findings its entropy literals (the strings S-ENTROPY would
// flag, wherever they appear). The redaction is the engine's (BR-7 step 3 c,
// 0.1.9: redact.rs and findings.rs), as it is the Python package's; this
// module hands it the text. mkIssue() applies all of it, so the library API
// (`import { scanFile } from "lazaret"`) is covered too.

import { call } from "./native.js";

export const SECRET_RULES = new Set(["S-SECRET", "S-TOKEN", "SQL-CRED", "S-ENTROPY"]);
export const REDACT_PLACEHOLDER = "[redacted: secret rule {RULE}]";
export const REDACT_FINGERPRINT = "[redacted: secret rule ";
export const REDACTED = "[redacted]";

/** Global switch (--no-redact-secrets turns it off for the run). */
export const REDACT = { on: true };
export function setRedactSecrets(on) { REDACT.on = !!on; }

// The lines of the files whose findings this package builds outside the
// engine's scan of them (the walker's encoding findings, the dependency
// checks'), registered so mkIssue redacts their snippets and messages with
// the file's entropy literals too (core's _Redactor): each array, with its
// lines joined as the engine reads them, once.
const CONTEXTS = new WeakMap();
export function registerScanContext(lines) {
  if (Array.isArray(lines) && !CONTEXTS.has(lines)) CONTEXTS.set(lines, null);
  return lines;
}
/** Are `lines` a registered file's (registerScanContext)? */
export function isScanContext(lines) {
  return Array.isArray(lines) && CONTEXTS.has(lines);
}
/** `lines` joined as the engine reads a file's lines (anything that is not a string reads as an empty line). */
export function linesText(lines) {
  if (isScanContext(lines)) {
    let text = CONTEXTS.get(lines);
    if (text === null) CONTEXTS.set(lines, (text = joinLines(lines)));
    return text;
  }
  return joinLines(lines);
}
function joinLines(lines) {
  return lines.map((l) => (typeof l === "string" ? l : "")).join("\n");
}

/** Replace credential-shaped substrings in one line (core._redact_context_line). */
export function redactContextLine(line) {
  if (typeof line !== "string" || !line) return line;
  return call("redact_text", { mode: "line" }, line);
}

/** Redaction for free text that may copy source (issue msg, hook cmd): the PEM blocks whole, then the line patterns,
 * and with `context` (a file's lines) the file's entropy literals (core._redact_text). */
export function redactText(text, context = null) {
  if (typeof text !== "string") return text;
  const args = { mode: "text", neumaier: false };
  if (context !== null) args.context = linesText(context);
  return call("redact_text", args, text);
}

/** The engine's [snippet, msg, cmd] for each of `issues` put in place where they changed. */
function applyRedaction(issues, got) {
  issues.forEach((i, k) => {
    const [snip, msg, cmd] = got[k];
    if (typeof msg === "string" && msg !== i.msg) i.msg = msg;
    if (typeof cmd === "string" && cmd !== i.cmd) i.cmd = cmd;
    if (Array.isArray(snip) && Array.isArray(i.snippet)) i.snippet = snip;
  });
}

const strOrNull = (v) => (typeof v === "string" ? v : null);

/**
 * The findings of one file (`lines`: its scan lines) built outside the engine's scan of it, given the file's redaction
 * in place (core.redact_file_issues for one file): every snippet line that is still the raw text of its file line
 * becomes that line as the file's own findings show it, and msg / cmd get the file's entropy literals.
 */
export function redactFileIssues(issues, lines) {
  if (!REDACT.on || !issues.length) return issues;
  const raw = issues.map((i) => {
    const snip = i.snippet, start = i.snipStart;
    if (!Array.isArray(snip) || !Number.isInteger(start)) return [];
    const at = [];                                          // [k, j]: snippet line k is still file line j's raw text
    snip.forEach((line, k) => {
      const j = start - 1 + k;
      if (typeof line === "string" && j >= 0 && j < lines.length && line === lines[j]) at.push([k, j]);
    });
    return at;
  });
  const rows = issues.map((i, n) => [raw[n].map(([, j]) => j), strOrNull(i.msg), strOrNull(i.cmd)]);
  const got = call("redact_file", { issues: rows, neumaier: false }, lines.join("\n")).issues;
  issues.forEach((i, n) => {
    const [shown, msg, cmd] = got[n];
    let snip = null;
    if (raw[n].length) {
      snip = [...i.snippet];
      raw[n].forEach(([k], m) => { snip[k] = shown[m]; });
    }
    applyRedaction([i], [[snip, msg, cmd]]);
  });
  return issues;
}

/**
 * Belt-and-braces sweep over a whole result (core.redact_result): msg and cmd redacted, a secret rule's flagged line
 * that is not yet the placeholder replaced by it, every other snippet line redacted, and every line clipped
 * (SNIPPET_MAX). Without redaction (--no-redact-secrets), the lines are clipped only. One engine call for the result.
 */
export function redactResult(res) {
  const issues = (res.issues ?? []).filter((i) => i !== null && typeof i === "object");
  if (!issues.length) return res;
  const rows = issues.map((i) => [i.rule ?? null, Number.isInteger(i.line) ? i.line : null,
    Number.isInteger(i.snipStart) ? i.snipStart : null, Array.isArray(i.snippet) ? i.snippet : null,
    strOrNull(i.msg), strOrNull(i.cmd)]);
  applyRedaction(issues, call("redact_issues", { issues: rows, redact: REDACT.on }).issues);
  return res;
}
