// Report assembly — the lazaret report format. Mirrors lazaret.py's build_result:
// {generatedBy (FIRST key), project, scannedAt, pass, conditions, metrics,
// counts, ratings, supplyChain, crossFile, perFile, issues}; plus the terminal,
// HTML and SARIF renderers.

import { resolve, isAbsolute } from "node:path";
import { readFileSync } from "node:fs";
import { SEV_ORDER } from "./scanner/rules.js";
import { computeMetrics, worstSevRating, maintainabilityRating } from "./scanner/metrics.js";
import { ENGINE_VERSION, ENGINE_MARKER, HTML_ENGINE_MARKER } from "./lib/fs.js";
import { cmpCodePoints, pyStrip, isPrintable, pyFloatRepr } from "./lib/pycompat.js";
import { REDACT, SECRET_RULES } from "./lib/redact.js";
import { reportSignature, SIGNATURE_FIELD } from "./baseline.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

/** Local time, seconds precision, no zone — datetime.now().isoformat(timespec="seconds"). */
function localIso(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function buildResult(root, files, issues) {
  issues.sort((a, b) =>
    (SEV_ORDER[a.sev] - SEV_ORDER[b.sev]) ||
    cmpCodePoints(String(a.file), String(b.file)) ||
    (a.line - b.line));
  const metrics = computeMetrics(files);
  const counts = { VULN: 0, HOTSPOT: 0, BUG: 0, SMELL: 0 };
  for (const i of issues) counts[i.type]++;
  const ratings = {
    security: worstSevRating(issues, ["VULN"]),
    reliability: worstSevRating(issues, ["BUG"]),
    maintainability: maintainabilityRating(issues, metrics.ncloc),
  };
  const conds = [
    { label: "No blocker issues", ok: !issues.some((i) => i.sev === "BLOCKER") },
    { label: "No critical vulnerabilities",
      ok: !issues.some((i) => i.type === "VULN" && (i.sev === "CRITICAL" || i.sev === "BLOCKER")) },
    { label: "Duplication < 10%", ok: metrics.dupPct < 10 },
    { label: "Maintainability ≥ C", ok: "ABC".includes(ratings.maintainability) },
  ];
  // Keys are file names: one named __proto__ is an ordinary key here (an
  // assignment set the object's prototype instead, losing the count).
  const perFile = {};
  for (const i of issues) {
    const f = String(i.file);
    Object.defineProperty(perFile, f, { value: (Object.hasOwn(perFile, f) ? perFile[f] : 0) + 1,
      enumerable: true, writable: true, configurable: true });
  }
  let supply = 0, crossFile = 0;
  // INFO supply-chain entries are inventory (a project's own prepare hook,
  // shared semantics 3), not indicators.
  for (const i of issues) { if (i.rule.startsWith("SC-") && i.sev !== "INFO") supply++; if (i.rule.startsWith("X-")) crossFile++; }
  conds.push({ label: "No supply-chain indicators", ok: supply === 0 });
  conds.push({ label: "No cross-file taint flows", ok: crossFile === 0 });
  return {
    generatedBy: ENGINE_VERSION,
    project: resolve(root),
    scannedAt: localIso(),
    pass: conds.every((c) => c.ok),
    conditions: conds,
    metrics,
    counts,
    ratings,
    supplyChain: supply,
    crossFile,
    perFile,
    issues,
  };
}

// ---- JSON, in pieces --------------------------------------------------------------
// V8 caps a string at about 2^29 characters, so a report with a million or so
// findings could not be rendered as one string: JSON.stringify threw "Invalid
// string length" and the scan ended with exit 3 and no report (the Python
// engine wrote it). The renderers below yield their text in pieces, one per
// finding, which writeReport writes as they come; joined, the pieces are
// exactly the text JSON.stringify(value, null, 2) gives.
const INDENT = "  ";
const splittable = (v) => v !== null && typeof v === "object" && typeof v.toJSON !== "function" && !JSON.isRawJSON(v)
  && !(v instanceof Number || v instanceof String || v instanceof Boolean || v instanceof BigInt);
const indented = (text, level) => (level && text.includes("\n") ? text.replaceAll("\n", "\n" + INDENT.repeat(level)) : text);

/**
 * JSON.stringify(value, null, 2) as a sequence of strings: arrays and objects
 * down to `depth` levels are split into their members, anything deeper is
 * one piece. keysOf(object) lists a split object's members (JSON.stringify's
 * order by default); `level` is the indentation the value starts at.
 */
export function* jsonChunks(value, depth = 2, keysOf = Object.keys, level = 0) {
  if (depth <= 0 || !splittable(value)) {
    const text = JSON.stringify(value, null, 2);
    if (text !== undefined) yield indented(text, level);
    return;
  }
  const inner = "\n" + INDENT.repeat(level + 1);
  const [open, close] = Array.isArray(value) ? ["[", "]"] : ["{", "}"];
  let first = true;
  const member = function* (prefix, v) {
    if (depth > 1 && splittable(v)) {
      yield (first ? open : ",") + inner + prefix;
      yield* jsonChunks(v, depth - 1, keysOf, level + 1);
    } else {
      const text = JSON.stringify(v, null, 2);
      if (text === undefined && prefix) return;                      // an object member JSON.stringify leaves out
      yield (first ? open : ",") + inner + prefix + indented(text ?? "null", level + 1);
    }
    first = false;
  };
  if (Array.isArray(value)) for (let k = 0; k < value.length; k++) yield* member("", value[k]);
  else for (const key of keysOf(value)) yield* member(JSON.stringify(key) + ": ", value[key]);
  yield first ? open + close : "\n" + INDENT.repeat(level) + close;
}

/**
 * JSON report, in pieces: the result dict with the marker as key #1 and, when
 * a baseline key is given ($LAZARET_BASELINE_KEY), the baseline signature as
 * key #2.
 */
export function* jsonReportChunks(res, { key = null } = {}) {
  const sig = key ? reportSignature(res, key) : null;
  const out = { [ENGINE_MARKER]: ENGINE_VERSION };
  if (sig) out[SIGNATURE_FIELD] = sig;
  for (const [k, v] of Object.entries(res)) if (k !== ENGINE_MARKER && k !== SIGNATURE_FIELD) out[k] = v;
  // As the Python engine writes them: dupPct is a float (0.0, 12.0, not 0,
  // 12), and perFile lists the files in the order they first appear in the
  // sorted issues (its dict's order; a JavaScript object puts integer-like
  // keys, a file named 7, first).
  const dup = out.metrics?.dupPct;
  if (typeof dup === "number" && Number.isFinite(dup)) out.metrics = { ...out.metrics, dupPct: JSON.rawJSON(pyFloatRepr(dup)) };
  yield* jsonChunks(out, 2, (o) => (o === res.perFile ? perFileKeys(res) : Object.keys(o)));
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
// through sanitizeTerm()/safeExcerpt() before it reaches a terminal. C0
// controls except TAB/LF, CR, DEL, the C1 controls (0x9b is a one-byte CSI)
// and the bidi controls become '·' — exactly the set of the Python engine's
// sanitize_term (python/tests/scanner/test_review_term_c1.py compares them).
const TERM_UNSAFE_RE = /[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g;
export function sanitizeTerm(text) {
  return String(text).replace(TERM_UNSAFE_RE, "·");
}
// Line breaks sanitizeTerm keeps (LF) or does not know (U+2028, U+2029); the
// other line breaks (CR, VT, FF, U+001C-U+001E, U+0085) are control
// characters it already maps.
const LINE_BREAK_RE = /[\n\u2028\u2029]/g;
/**
 * sanitizeTerm for a value printed inside one line of output (a path, a link
 * target, a message): line breaks become '·' too, so the value cannot start
 * a line of its own (review: a file named "zz\n\n  Quality gate:  PASSED
 * \n::notice::…\n  x.py" printed a fake PASSED line and a GitHub workflow
 * command at column 0). Twin of core.sanitize_term_line.
 */
export function sanitizeTermLine(text) {
  return sanitizeTerm(text).replace(LINE_BREAK_RE, "·");
}

export let EXCERPT_WIDTH = 100;
export function setExcerptWidth(n) { EXCERPT_WIDTH = n; }

/** Sanitized, trimmed, truncated source excerpt (twin of core.safe_excerpt). */
export function safeExcerpt(text, width = EXCERPT_WIDTH) {
  text = pyStrip(String(text).replace(/\t/g, " "));
  if (!text) return "";
  const cps = Array.from(text);
  let out = "";
  for (const ch of cps.slice(0, width)) {                       // text[:width], a negative width too
    const o = ch.codePointAt(0);
    out += ch === " " || (o >= 0x20 && o < 0x7f) || (o > 0xa0 && isPrintable(ch) && !/[\u202a-\u202e\u2066-\u2069]/.test(ch)) ? ch : "·";
  }
  return out + (cps.length > width ? "…" : "");
}

export function issueExcerpt(issue, width = EXCERPT_WIDTH) {
  const snip = Array.isArray(issue.snippet) ? issue.snippet : [];
  const idx = issue.line - (issue.snipStart ?? issue.line);
  if (!(idx >= 0 && idx < snip.length) || typeof snip[idx] !== "string") return "";
  if (REDACT.on && SECRET_RULES.has(issue.rule)) return "[redacted]";
  return safeExcerpt(snip[idx], width);
}

/** Terminal summary. `out` receives lines (injectable for tests). */
export function printReport(res, { out = console.log, quiet = false } = {}) {
  const m = res.metrics;
  out("");
  out(`Lazaret scan — ${sanitizeTermLine(res.project)}`);
  out(`  ${m.files} files · ${m.ncloc} lines of code · ${typeof m.dupPct === "number" ? pyFloatRepr(m.dupPct) : m.dupPct}% duplication`);
  out("");
  out(`  Quality gate: ${res.pass ? "PASSED" : "FAILED"}`);
  for (const cond of res.conditions) out(`  ${cond.ok ? "✓" : "✗"} ${sanitizeTermLine(cond.label)}`);
  out(`  Ratings: security ${res.ratings.security} · reliability ${res.ratings.reliability} · maintainability ${res.ratings.maintainability}`);
  out(`  Issues: ${res.counts.VULN} vulnerabilities · ${res.counts.HOTSPOT} hotspots · ${res.counts.BUG} bugs · ${res.counts.SMELL} smells · ${res.supplyChain} supply-chain`);
  if (m.depFiles) out(`  Dependency files scanned: ${m.depFiles}`);
  if ("newIssues" in res) out(`  New issues vs baseline: ${res.newIssues}`);
  if (!quiet) {
    const shown = res.issues.slice(0, 40);
    for (const i of shown) {
      out(`  ${i.sev} ${i.rule} ${sanitizeTermLine(i.file)}:${i.line} — ${safeExcerpt(i.msg, 90)}`);
      const ex = issueExcerpt(i);
      if (ex) out(`      » ${ex}`);
    }
    if (res.issues.length > shown.length)
      out(`  … ${res.issues.length - shown.length} more (use --quiet to suppress)`);
  }
  out("");
}

// ---- HTML ----------------------------------------------------------------------
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;" };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ESC[c]);

/** HTML report, in pieces: the JSON report in a minimal page carrying the provenance meta tag. */
export function* htmlReportChunks(res) {
  yield `<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n${HTML_ENGINE_MARKER}\n` +
    `<title>Lazaret report</title></head>\n<body><pre>`;
  for (const piece of jsonReportChunks(res)) yield esc(piece);      // esc maps single characters: piece by piece is the same
  yield "</pre></body></html>\n";
}

/** HTML report text (htmlReportChunks joined). */
export function htmlRenderer(res) {
  return [...htmlReportChunks(res)].join("");
}

// ---- SARIF 2.1.0 (twin of core.sarif_report) ------------------------------------
const SARIF_LEVEL = { BLOCKER: "error", CRITICAL: "error", MAJOR: "warning", MINOR: "note", INFO: "note" };
export const SARIF_SRCROOT = "%SRCROOT%";
export const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const quoteBytes = (bytes) => {
  let out = "";
  for (const b of bytes) {
    const c = String.fromCharCode(b);
    out += /[A-Za-z0-9_.~\/-]/.test(c) ? c : "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
};
/** urllib.parse.quote(path, safe="/") of a report path, '/' separators. */
export function sarifUri(path) {
  return quoteBytes(Buffer.from(String(path).replace(/\\/g, "/"), "utf8"));
}
/** An absolute path as a file: URI, as pathlib's as_uri() writes it on the
 * same OS: file:///C:/a%20b (the drive letter and its colon as-is) and
 * file://server/share/x for a UNC path on Windows, file:///a%20b on POSIX. */
export function fileUri(absPath) {
  const p = String(absPath).replace(/\\/g, "/");
  const q = (s) => quoteBytes(Buffer.from(s, "utf8"));
  const drive = /^[A-Za-z]:(?=\/|$)/.exec(p);
  if (drive) return "file:///" + drive[0] + q(p.slice(2));
  if (p.startsWith("//")) return "file:" + q(p);
  return "file://" + (p.startsWith("/") ? "" : "/") + q(p);
}
export function sarifReport(res, root = null) {
  const rules = new Map(), results = [];
  for (const i of res.issues) {
    if (!rules.has(i.rule)) rules.set(i.rule, { id: i.rule, name: i.name,
      shortDescription: { text: i.name }, fullDescription: { text: i.why }, help: { text: i.fix } });
    const file = String(i.file);
    const loc = isAbsolute(file) ? { uri: fileUri(file) } : { uri: sarifUri(file), uriBaseId: SARIF_SRCROOT };
    const line = Math.max(1, Math.trunc(Number(i.line)) || 1);
    results.push({ ruleId: i.rule, ruleIndex: [...rules.keys()].indexOf(i.rule), level: SARIF_LEVEL[i.sev] ?? "note",
      message: { text: i.msg }, locations: [{ physicalLocation: { artifactLocation: loc, region: { startLine: line } } }] });
  }
  let rootUri = fileUri(resolve(root ?? res.project));
  if (!rootUri.endsWith("/")) rootUri += "/";
  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "Lazaret", version: pkg.version, informationUri: "https://lazaret.dev",
      rules: [...rules.values()] } },
      originalUriBaseIds: { [SARIF_SRCROOT]: { uri: rootUri } },
      results }],
  };
}
/** SARIF log, in pieces (one per result), with the marker in a top-level property bag, first. */
export function* sarifChunks(sarif) {
  yield* jsonChunks({ properties: { [ENGINE_MARKER]: ENGINE_VERSION }, ...sarif }, 4);   // runs[0].results[i]
}

/** SARIF log text (sarifChunks joined). */
export function sarifRenderer(sarif) {
  return [...sarifChunks(sarif)].join("");
}
