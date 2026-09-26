// Report assembly — the lazaret report format. Mirrors lazaret.py's build_result:
// {generatedBy (FIRST key), project, scannedAt, pass, conditions, metrics,
// counts, ratings, supplyChain, crossFile, perFile, issues}; plus the terminal,
// HTML and SARIF renderers.

import { resolve, isAbsolute } from "node:path";
import { readFileSync } from "node:fs";
import { SEV_ORDER } from "./scanner/rules.js";
import { computeMetrics, worstSevRating, maintainabilityRating } from "./scanner/metrics.js";
import { ENGINE_VERSION, ENGINE_MARKER, HTML_ENGINE_MARKER } from "./lib/fs.js";
import { cmpCodePoints, pyStrip, isPrintable } from "./lib/pycompat.js";
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
  const perFile = {};
  for (const i of issues) perFile[i.file] = (perFile[i.file] ?? 0) + 1;
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

/**
 * JSON report text: the result dict with the marker as key #1 and, when a
 * baseline key is given ($LAZARET_BASELINE_KEY), the baseline signature as
 * key #2.
 */
export function jsonRenderer(res, { key = null } = {}) {
  const sig = key ? reportSignature(res, key) : null;
  const out = { [ENGINE_MARKER]: ENGINE_VERSION };
  if (sig) out[SIGNATURE_FIELD] = sig;
  for (const [k, v] of Object.entries(res)) if (k !== ENGINE_MARKER && k !== SIGNATURE_FIELD) out[k] = v;
  return JSON.stringify(out, null, 2);
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

export let EXCERPT_WIDTH = 100;
export function setExcerptWidth(n) { EXCERPT_WIDTH = n; }

/** Sanitized, trimmed, truncated source excerpt (twin of core.safe_excerpt). */
export function safeExcerpt(text, width = EXCERPT_WIDTH) {
  text = pyStrip(String(text).replace(/\t/g, " "));
  if (!text) return "";
  const cps = Array.from(text);
  let out = "";
  for (const ch of cps.slice(0, Math.max(0, width))) {
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
  out(`Lazaret scan — ${sanitizeTerm(res.project)}`);
  out(`  ${m.files} files · ${m.ncloc} lines of code · ${m.dupPct}% duplication`);
  out("");
  out(`  Quality gate: ${res.pass ? "PASSED" : "FAILED"}`);
  for (const cond of res.conditions) out(`  ${cond.ok ? "✓" : "✗"} ${sanitizeTerm(cond.label)}`);
  out(`  Ratings: security ${res.ratings.security} · reliability ${res.ratings.reliability} · maintainability ${res.ratings.maintainability}`);
  out(`  Issues: ${res.counts.VULN} vulnerabilities · ${res.counts.HOTSPOT} hotspots · ${res.counts.BUG} bugs · ${res.counts.SMELL} smells · ${res.supplyChain} supply-chain`);
  if (m.depFiles) out(`  Dependency files scanned: ${m.depFiles}`);
  if ("newIssues" in res) out(`  New issues vs baseline: ${res.newIssues}`);
  if (!quiet) {
    const shown = res.issues.slice(0, 40);
    for (const i of shown) {
      out(`  ${i.sev} ${i.rule} ${sanitizeTerm(i.file)}:${i.line} — ${safeExcerpt(i.msg, 90)}`);
      const ex = issueExcerpt(i);
      if (ex) out(`      » ${ex}`);
    }
    if (res.issues.length > shown.length)
      out(`  … ${res.issues.length - shown.length} more (use --quiet to suppress)`);
  }
  out("");
}

// ---- HTML ----------------------------------------------------------------------
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");

/** HTML report: the JSON report in a minimal page carrying the provenance meta tag. */
export function htmlRenderer(res) {
  return `<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n${HTML_ENGINE_MARKER}\n` +
    `<title>Lazaret report</title></head>\n<body><pre>${esc(jsonRenderer(res))}</pre></body></html>\n`;
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
/** SARIF log text with the marker in a top-level property bag, first. */
export function sarifRenderer(sarif) {
  return JSON.stringify({ properties: { [ENGINE_MARKER]: ENGINE_VERSION }, ...sarif }, null, 2);
}
