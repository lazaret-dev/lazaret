// Report assembly — the lazaret report format. Mirrors lazaret.py's build_result:
// {generatedBy (FIRST key), project, scannedAt, pass, conditions, metrics,
// counts, ratings, supplyChain, crossFile, perFile, issues}; and the reports'
// forms (JSON, terminal, HTML, SARIF), which the engine makes (report.rs,
// BR-7 step 4 c), as it makes the Python package's: the same bytes.

import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { gradeResult, localIso } from "./result.js";
import { ENGINE_VERSION, ENGINE_MARKER } from "./lib/fs.js";
import { call, loadError } from "./lib/native.js";
import { REDACT } from "./lib/redact.js";
import { splitLines } from "./scanner/lines.js";
import { reportSignature, SIGNATURE_FIELD } from "./baseline.js";

export { regrade, CROSS_FILE_LABEL } from "./result.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const WINDOWS = process.platform === "win32";

/**
 * A scan's result (the engine's: result.rs, as core.build_result's) with the version, the project's path and the
 * time this package's: generatedBy, project, scannedAt, then gradeResult's (result.js).
 */
export function buildResult(root, files, issues) {
  return { generatedBy: ENGINE_VERSION, project: resolve(root), scannedAt: localIso(), ...gradeResult(files, issues) };
}

// ---- in pieces ------------------------------------------------------------------
// V8 caps a string at about 2^29 characters, so a report with a million or so
// findings could not be rendered as one string: JSON.stringify threw "Invalid
// string length" and the scan ended with exit 3 and no report (the Python
// engine wrote it). So the engine makes each form in pieces, a frame and its
// findings a batch at a time, which writeReport writes as they come.
const BATCH = 2000;                // findings per engine call, at most
const BATCH_CHARS = 1 << 23;       // and characters of their JSON (a call's request and answer are strings too)

/** [start, end) ranges of `items` for the engine's calls: BATCH of them, or fewer when they are large. */
function* batches(items) {
  let start = 0, chars = 0;
  for (let k = 0; k < items.length; k++) {
    const n = (JSON.stringify(items[k]) ?? "null").length;
    if (k > start && (k - start >= BATCH || chars + n > BATCH_CHARS)) {
      yield [start, k];
      start = k;
      chars = 0;
    }
    chars += n;
  }
  if (start < items.length) yield [start, items.length];
}

/**
 * A report in pieces: the engine's frame (`name` with `args`, `res` with its findings left out in their place),
 * then items(batch, first) for each batch of its findings, then the rest of the frame (core's reports.framed).
 */
function* framed(name, res, args, items) {
  const issues = res && Array.isArray(res.issues) ? res.issues : [];
  const doc = res && Array.isArray(res.issues) ? { ...res, issues: [] } : res;
  const got = call(name, { ...args, doc, count: issues.length, perFileOrder: res && res.perFile ? perFileKeys(res) : null });
  yield got.head;
  for (const [a, b] of batches(issues)) yield items(issues.slice(a, b), a === 0);
  yield got.tail;
}

/**
 * JSON report, in pieces: Python's json.dumps(…, indent=2) of the result with the marker as key #1 and, when a
 * baseline key is given ($LAZARET_BASELINE_KEY), the baseline signature as key #2 (the engine's: report.rs).
 */
export function* jsonReportChunks(res, { key = null } = {}) {
  const prefix = [[ENGINE_MARKER, ENGINE_VERSION]];
  const sig = key ? reportSignature(res, key) : null;
  if (sig) prefix.push([SIGNATURE_FIELD, sig]);
  yield* framed("report_json", res, { prefix },
    (items, first) => call("report_items", { items, level: 2, first }).text);
}

/** res.perFile's keys in the order of the first issue in each file. */
function perFileKeys(res) {
  const keys = Object.keys(res.perFile);
  if (!keys.some((k) => /^(?:0|[1-9][0-9]*)$/.test(k))) return keys;   // no key an object reorders
  const order = new Set();
  for (const i of Array.isArray(res.issues) ? res.issues : []) {
    const f = String(i?.file);
    if (Object.hasOwn(res.perFile, f)) order.add(f);
  }
  for (const k of keys) order.add(k);
  return [...order];
}

/** JSON report text (jsonReportChunks joined). */
export function jsonRenderer(res, opts = {}) {
  return [...jsonReportChunks(res, opts)].join("");
}

// ---- terminal ---------------------------------------------------------------
// Terminal escape-sequence injection (audit H1): every string derived from
// scanned content — file names, messages, excerpts, the project path — passes
// through sanitizeTerm()/safeExcerpt() before it reaches a terminal: the C0
// controls but TAB and LF, CR, DEL, the C1 controls (0x9b is a one-byte CSI)
// and the bidi controls become '·' (the engine's: report.rs, as core's).
export function sanitizeTerm(text) {
  return term("text", text);
}

/**
 * The engine's term call; without an engine (a checkout that has not built native/lazaret.wasm: the CLI says so,
 * its own message with this package's path in it) every character but printable ASCII (and TAB and LF in "text"
 * mode) is '·'.
 */
function term(mode, text, args = {}) {
  if (loadError() !== null) return String(text).replace(mode === "text" ? /[^\x20-\x7e\t\n]/g : /[^\x20-\x7e]/g, "·");
  return call("term", { mode, ...args }, String(text)).text;
}
/**
 * sanitizeTerm for a value printed inside one line of output (a path, a link
 * target, a message): line breaks become '·' too, so the value cannot start
 * a line of its own (review: a file named "zz\n\n  Quality gate:  PASSED
 * \n::notice::…\n  x.py" printed a fake PASSED line and a GitHub workflow
 * command at column 0). The engine's, as core.sanitize_term_line.
 */
export function sanitizeTermLine(text) {
  return term("line", text);
}

export let EXCERPT_WIDTH = 100;
export function setExcerptWidth(n) { EXCERPT_WIDTH = n; }

/** Sanitized, trimmed, truncated source excerpt (the engine's, as core.safe_excerpt). */
export function safeExcerpt(text, width = EXCERPT_WIDTH) {
  return term("excerpt", text, { width });
}

export const SHOW_SECRETS_NOT_A_TERMINAL = "note: --show-secrets shows credentials on a terminal only, and the output "
  + "is not one: they stay redacted";

/** --show-secrets (core.show_secrets_on): true when asked for and the output is a terminal (`isTTY`); asked for
 * elsewhere (a pipe, a file, a CI log), a note on `err` says the credentials stay redacted. */
export function showSecretsOn(asked, isTTY, err) {
  if (!asked) return false;
  if (!isTTY) err(SHOW_SECRETS_NOT_A_TERMINAL);
  return !!isTTY;
}

/** flaggedLines' key of an issue's line. */
export const shownKey = (file, line) => `${line}\u0000${file}`;

/**
 * Each of `issues`' flagged line as read, unredacted (core.flagged_lines), for the files of `entries` ([{path,
 * content, lang?}]: their scan lines, splitLines): what --show-secrets prints in place of the redacted excerpt. Kept
 * apart from the result, for the terminal alone: it never reaches a report or the baseline.
 */
export function flaggedLines(issues, entries) {
  const byPath = new Map();
  for (const e of entries) if (typeof e.content === "string") byPath.set(e.path, e);
  const linesOf = new Map(), out = new Map();
  for (const i of issues) {
    const e = byPath.get(i.file);
    if (!e || !Number.isInteger(i.line) || i.line < 1) continue;
    let lines = linesOf.get(i.file);
    if (!lines) linesOf.set(i.file, (lines = splitLines(e.content, e.lang ?? null)));
    if (i.line <= lines.length) out.set(shownKey(i.file, i.line), lines[i.line - 1]);
  }
  return out;
}

/** Sanitized excerpt of an issue's flagged source line ("" if unavailable); `shown` (flaggedLines') gives the line as
 * read, unredacted, where it has it (--show-secrets, for the terminal alone). The engine's, as core.issue_excerpt. */
export function issueExcerpt(issue, width = EXCERPT_WIDTH, shown = null) {
  const raw = shown ? shown.get(shownKey(issue.file, issue.line)) : undefined;
  return call("issue_excerpt", { issue, width, redact: REDACT.on, shown: raw ?? null }).text;
}

/**
 * The terminal summary, in pieces (the engine's, as core.print_report): the gate, the ratings and the counts, then
 * (unless `quiet`) the findings by file, each with its flagged line (`rawLines`: --show-secrets' lines as read).
 */
export function* reportTextChunks(res, { quiet = false, rawLines = null, color = false } = {}) {
  const issues = Array.isArray(res.issues) ? res.issues : [];
  const frame = call("text_frame", { doc: { ...res, issues: [] }, count: issues.length, quiet, color });
  yield frame.head;
  if (!quiet && issues.length) {
    const { order } = call("text_order", { rows: issues.map((i) => [i.file, i.sev, i.line]) });
    let file = null;
    const ordered = order.map((n) => issues[n]);
    for (const [a, b] of batches(ordered)) {
      const batch = ordered.slice(a, b);
      const got = call("text_items", { issues: batch, file, color, width: EXCERPT_WIDTH, redact: REDACT.on,
        shown: batch.map((i) => (rawLines ? rawLines.get(shownKey(i.file, i.line)) ?? null : null)) });
      file = got.file;
      yield got.text;
    }
  }
  yield frame.tail;
}

/** Terminal summary. `out` receives lines (injectable for tests); `color` on a terminal. */
export function printReport(res, { out = console.log, quiet = false, rawLines = null, color = false } = {}) {
  let pending = "";
  for (const piece of reportTextChunks(res, { quiet, rawLines, color })) {
    const lines = (pending + piece).split("\n");
    pending = lines.pop();
    for (const line of lines) out(line);
  }
  if (pending) out(pending);
}

// ---- HTML ----------------------------------------------------------------------
/** HTML report, in pieces (the engine's, as core.html_report): with the provenance meta tag in its <head>. */
export function* htmlReportChunks(res) {
  yield* framed("html_frame", res, { windows: WINDOWS, marker: [ENGINE_MARKER, ENGINE_VERSION] },
    (issues, first) => call("html_items", { issues, first }).text);
}

/** HTML report text (htmlReportChunks joined). */
export function htmlRenderer(res) {
  return [...htmlReportChunks(res)].join("");
}

// ---- SARIF 2.1.0 (the engine's, as core.sarif_report) -----------------------------
/**
 * The SARIF log of a scan result, in pieces: the rules in the order of their first finding, each finding's location
 * below %SRCROOT% (the scan root: `root`, res.project by default); `marked`: with the marker in a top-level property
 * bag, first.
 */
export function* sarifChunks(res, root = null, { marked = true } = {}) {
  const issues = (Array.isArray(res.issues) ? res.issues : []).filter((i) => i !== null && typeof i === "object");
  const rules = [], known = [];
  const ranges = [...batches(issues)];
  for (const [a, b] of ranges) {
    const got = call("sarif_rules", { issues: issues.slice(a, b), known }).rules;
    for (const r of got) { rules.push(r); known.push(r.id); }
  }
  const frame = call("sarif_frame", { rules, root: resolve(root ?? res.project), windows: WINDOWS,
    version: pkg.version, source: res.source ?? null, marker: marked ? [ENGINE_MARKER, ENGINE_VERSION] : null,
    count: issues.length });
  yield frame.head;
  for (const [a, b] of ranges) {
    yield call("sarif_items", { issues: issues.slice(a, b), rules: known, windows: WINDOWS, first: a === 0 }).text;
  }
  yield frame.tail;
}

/** SARIF log text (sarifChunks joined). */
export function sarifRenderer(res, root = null) {
  return [...sarifChunks(res, root)].join("");
}

/** The SARIF log of a scan result, as an object (without the marker). */
export function sarifReport(res, root = null) {
  return JSON.parse([...sarifChunks(res, root, { marked: false })].join(""));
}
