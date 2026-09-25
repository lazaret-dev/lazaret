// Report assembly — the new lazaret format. Mirrors lazaret.py's build_result:
// {generatedBy (FIRST key), project, scannedAt, pass, conditions, metrics,
// counts, ratings, supplyChain, crossFile, perFile, issues}.

import { SEV_ORDER, TYPES } from "./scanner/rules.js";
import { computeMetrics, worstSevRating, maintainabilityRating } from "./scanner/metrics.js";
import { ENGINE_VERSION } from "./lib/fs.js";

export function buildResult(root, files, issues) {
  issues.sort((a, b) =>
    (SEV_ORDER[a.sev] - SEV_ORDER[b.sev]) ||
    a.file.localeCompare(b.file) ||
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
  // INFO supply-chain entries are inventory (a project's own prepare hook,
  // spec 3), not indicators — as the Python engine's build_result.
  const supply = issues.filter((i) => i.rule.startsWith("SC-") && i.sev !== "INFO").length;
  conds.push({ label: "No supply-chain indicators", ok: supply === 0 });
  const crossFile = issues.filter((i) => i.rule.startsWith("X-")).length;
  conds.push({ label: "No cross-file taint flows", ok: crossFile === 0 });
  return {
    generatedBy: ENGINE_VERSION,
    project: root,
    scannedAt: new Date().toISOString().slice(0, 19),
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

/** JSON report text: the result dict with the marker as key #1. */
export function jsonRenderer(res) {
  return JSON.stringify(res, null, 2);
}

// Terminal excerpt sanitation (audit H1: terminal escape-sequence injection).
// Scanned code may be hostile: strip ESC/CR/BS/BEL/NUL, tabs→spaces, trim,
// truncate with an ellipsis.
export function safeExcerpt(text, width = 100) {
  text = text.replace(/\t/g, " ").trim();
  if (!text) return "";
  let out = "";
  for (const ch of text.slice(0, width)) {
    const c = ch.codePointAt(0);
    out += (c >= 32 && c !== 127) || ch === "·" ? ch : "·";
  }
  return out + (text.length > width ? "…" : "");
}

export function issueExcerpt(issue, width = 100) {
  const snip = issue.snippet ?? [];
  const idx = issue.line - (issue.snipStart ?? issue.line);
  if (!(idx >= 0 && idx < snip.length) || typeof snip[idx] !== "string") return "";
  return safeExcerpt(snip[idx], width);
}

const C = { BLOCKER: "41;97", CRITICAL: "31", MAJOR: "33", MINOR: "36", INFO: "34" };

/** Terminal summary. `io` receives lines (injectable for tests). */
export function printReport(res, { out = console.log, quiet = false } = {}) {
  const m = res.metrics;
  out("");
  out(`Lazaret scan — ${res.project}`);
  out(`  ${m.files} files · ${m.ncloc} lines of code · ${m.dupPct}% duplication`);
  out("");
  out(`  Quality gate: ${res.pass ? "PASSED" : "FAILED"}`);
  for (const cond of res.conditions) {
    out(`  ${cond.ok ? "✓" : "✗"} ${cond.label}`);
  }
  out(`  Ratings: security ${res.ratings.security} · reliability ${res.ratings.reliability} · maintainability ${res.ratings.maintainability}`);
  out(`  Issues: ${res.counts.VULN} vulnerabilities · ${res.counts.HOTSPOT} hotspots · ${res.counts.BUG} bugs · ${res.counts.SMELL} smells`);
  if (!quiet) {
    const shown = res.issues.slice(0, 40);
    for (const i of shown) {
      out(`  ${i.sev} ${i.rule} ${i.file}:${i.line} — ${safeExcerpt(i.msg, 90)}`);
    }
    if (res.issues.length > shown.length)
      out(`  … ${res.issues.length - shown.length} more (use --quiet to suppress)`);
  }
  out("");
}
