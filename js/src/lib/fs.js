// Zero-dependency leaf helpers. Never import from ../scanner/ (RESTRUCTURE.md §5).

import { readdirSync, readFileSync, statSync, lstatSync, writeFileSync, renameSync, unlinkSync, existsSync } from "node:fs";
import { join, relative, extname, sep } from "node:path";

export const EXTS = {
  ".py": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
  ".mjs": "js", ".cjs": "js", ".sql": "sql",
};

// G10: only .git and __pycache__ are skipped by default (VCS metadata and
// build cache — never source). Dependency dirs are opt-in via includeDeps.
export const SKIP_DIRS = new Set([".git", "__pycache__"]);
export const OPTIN_SKIP_DIRS = [
  "node_modules", "venv", ".venv", "env", "dist", "build", ".next",
  "coverage", "vendor", "site-packages", ".tox", ".mypy_cache",
  ".pytest_cache", "migrations",
];
export const DEP_MARKERS = new Set([
  "node_modules", "site-packages", "bower_components", "vendor", "venv", ".venv",
]);

export const MAX_FILE_BYTES = 2_000_000;   // files above this are flagged SC-TRUNCATED

function walk(dir, relDir, out) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    let st;
    try {
      st = lstatSync(full);
    } catch {
      continue;                       // unreadable entry: skip, never crash
    }
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(name) || name.startsWith(".git")) continue;
      walk(full, relDir ? `${relDir}${sep}${name}` : name, out);
    } else if (st.isFile()) {
      out.push(relDir ? `${relDir}${sep}${name}` : name);
    }
  }
  return out;
}

/**
 * Collect the files to scan under `root`.
 * Returns { files, manifests, binaryIssues } — files: [{path, content, lang,
 * dep}], manifests: package.json/binding.gyp entries, binaryIssues:
 * SC-TRUNCATED-style findings for oversize files.
 */
export function collectFiles(root, { includeDeps = false } = {}) {
  const rels = walk(root, "", []);
  const files = [], manifests = [], binaryIssues = [];
  for (const rel of rels) {
    const full = join(root, rel);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.size > MAX_FILE_BYTES) {
      // Verdict integrity (audit C2/G16): an oversize file is flagged, not
      // silently skipped — and NOT added to `files`, so metrics stay honest.
      binaryIssues.push({
        rule: "SC-TRUNCATED", name: "Scan truncated", type: "HOTSPOT", sev: "CRITICAL",
        msg: `File not fully scanned: ${st.size.toLocaleString("en-US")} bytes exceeds the 2,000,000-byte file limit.`,
        why: "Scanning stopped early, so a clean verdict for this file is not evidence of anything — the unscanned bytes are exactly where a hostile artifact would put its payload (audit C2/G16: declared sizes and entry counts are attacker-controlled and were used to skip files with zero signal).",
        fix: "Review the file manually or raise the limit and re-scan.",
        ref: "CWE-506 · Supply chain", file: rel, line: 1, snippet: [], snipStart: 1,
      });
      continue;
    }
    if (rel === "package.json" || rel.endsWith(`${sep}package.json`)) {
      manifests.push({ kind: "package.json", path: rel, content: readFileSync(full, "utf8") });
      continue;
    }
    if (rel === "binding.gyp" || rel.endsWith(`${sep}binding.gyp`)) {
      // G11: node-gyp actions run at install time (see scanManifests).
      manifests.push({ kind: "binding.gyp", path: rel, content: readFileSync(full, "utf8") });
      continue;
    }
    const ext = extname(rel).toLowerCase();
    const lang = EXTS[ext];
    if (!lang) continue;
    const inDep = rel.split(sep).some((p) => DEP_MARKERS.has(p));
    if (inDep && !includeDeps) continue;   // opt-in only
    files.push({
      path: rel, content: readFileSync(full, "utf8"), lang, dep: includeDeps ? inDep : false,
    });
  }
  return { files, manifests, binaryIssues };
}

// Provenance marker for our reports (first key of the JSON report).
export const ENGINE_MARKER = "generatedBy";
export const ENGINE_VERSION = "lazaret-cli-1";
export const JSON_REPORT_NAME = "lazaret-report.json";
export const HTML_REPORT_NAME = "lazaret-report.html";
export const EXIT_OUTPUT = 3;             // report-path errors (distinct from gate exit 1 / usage exit 2)

/**
 * Safe report-path handling (contract: "CLI writes reports into CWD"):
 * default reports resolve under the scan root (or --out-dir), never bare
 * CWD-relative names; writability is checked BEFORE scanning (fail fast with
 * EXIT_OUTPUT, not a post-scan error that throws away the results).
 */
export function reportPaths(scanRoot, { outDir = null, json = true, html = true } = {}) {
  const base = outDir ?? scanRoot;
  const paths = {};
  if (json) paths.json = join(base, JSON_REPORT_NAME);
  if (html) paths.html = join(base, HTML_REPORT_NAME);
  return paths;
}

/**
 * Write a report atomically (temp file + rename), refusing to clobber a
 * pre-existing destination that is not one of ours. A destination carrying
 * exactly our marker key/value is one of OUR reports (safe to overwrite —
 * that's the re-scan workflow); anything else is refused.
 */
export function writeReport(path, text, { marker = null } = {}) {
  if (existsSync(path)) {
    const head = readFileSync(path, "utf8").slice(0, 65536);
    if (!marker || !head.includes(`"${marker.key}": "${marker.value}"`) && !head.includes(`"${marker.key}":"${marker.value}"`)) {
      throw new ReportPathError(`${path} already exists and is not a lazaret report (refusing to overwrite; use --force-overwrite)`);
    }
  }
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tmp, text);
  try {
    renameSync(tmp, path);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* best effort */ }
    throw e;
  }
  return path;
}

export class ReportPathError extends Error {}
