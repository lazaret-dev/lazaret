// Zero-dependency leaf helpers. Never import from ../scanner/ (RESTRUCTURE.md §5).

import {
  readdirSync, readFileSync, statSync, lstatSync, openSync, readSync, closeSync, fstatSync, fsyncSync,
  writeSync, renameSync, unlinkSync, chmodSync, constants as C,
} from "node:fs";
import { join, extname, sep, resolve, dirname, isAbsolute } from "node:path";
import { randomBytes } from "node:crypto";
import { fileIssue } from "./issue.js";

export const EXTS = {
  ".py": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
  ".mjs": "js", ".cjs": "js", ".sql": "sql",
};

// G10: only .git and __pycache__ are skipped by default (VCS metadata and
// build cache — never source). Dependency dirs are opt-in via includeDeps.
/**
 * Line endings as Python's text mode reads them: \r\n and a lone \r both become \n.
 * Without this, a file with Windows line endings leaves "\r" at the end of every
 * line, which (for one) turns a bare "# nosec" into a suppression that matches no
 * rule. Twin of lazaret.scanner.core.normalize_newlines.
 */
export function normalizeNewlines(text) {
  return typeof text === "string" && text.includes("\r") ? text.replace(/\r\n?/g, "\n") : text;
}

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

/** SC-TRUNCATED: a file that was not (fully) scanned — never a silent skip. */
export function truncatedIssue(path, detail) {
  return fileIssue({ id: "SC-TRUNCATED", name: "Scan truncated", type: "HOTSPOT", sev: "CRITICAL",
    msg: `File not fully scanned: ${detail}.`,
    why: "Scanning stopped early, so a clean verdict for this file is not evidence of anything — the unscanned bytes are exactly where a hostile artifact would put its payload (audit C2/G16: declared sizes and entry counts are attacker-controlled and were used to skip files with zero signal).",
    fix: "Review the file manually or raise the limit and re-scan.",
    ref: "CWE-506 · Supply chain" }, path);
}

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
      manifests.push({ kind: "package.json", path: rel, content: normalizeNewlines(readFileSync(full, "utf8")) });
      continue;
    }
    if (rel === "binding.gyp" || rel.endsWith(`${sep}binding.gyp`)) {
      // G11: node-gyp actions run at install time (see scanManifests).
      manifests.push({ kind: "binding.gyp", path: rel, content: normalizeNewlines(readFileSync(full, "utf8")) });
      continue;
    }
    const ext = extname(rel).toLowerCase();
    const lang = EXTS[ext];
    if (!lang) continue;
    const inDep = rel.split(sep).some((p) => DEP_MARKERS.has(p));
    if (inDep && !includeDeps) continue;   // opt-in only
    files.push({
      path: rel, content: normalizeNewlines(readFileSync(full, "utf8")), lang, dep: includeDeps ? inDep : false,
    });
  }
  return { files, manifests, binaryIssues };
}

const O_NOFOLLOW = C.O_NOFOLLOW ?? 0;
const O_NONBLOCK = C.O_NONBLOCK ?? 0;
const O_NOCTTY = C.O_NOCTTY ?? 0;
class NotRegularFile extends Error {}
function specialKind(st) {
  if (st.isFIFO()) return "a named pipe (FIFO)";
  if (st.isSocket()) return "a socket";
  if (st.isCharacterDevice()) return "a character device";
  if (st.isBlockDevice()) return "a block device";
  return "not a regular file";
}

const coverage = (rule, name, path, msg, why, fix, ref = "Maintainability") => ({
  rule, name, type: "SMELL", sev: "INFO", msg, why, fix, ref, file: path, line: 1, snippet: [], snipStart: 1,
});
export function scanErrorIssue(path, err) {
  return coverage("Q-SCAN-ERROR", "File scan failed", path,
    `Scanning ${path} failed (${(err && err.name) || "Error"}); findings for this file are incomplete.`,
    "An internal error while scanning one file is reported here instead of aborting the whole run, so the rest of the project still gets a report. This file's result is not evidence that it is clean.",
    "Review the file manually and report the error (re-run with LAZARET_DEBUG=1 for a traceback).",
    "Scan coverage");
}
/** Read at most `limit` bytes of a REGULAR file (never follows links, never blocks on a FIFO). */
export function readBounded(path, limit) {
  const fd = openSync(path, C.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new NotRegularFile(specialKind(st));
    const chunks = [];
    let total = 0;
    while (total < limit) {
      const chunk = Buffer.allocUnsafe(Math.min(1 << 20, limit - total));
      const n = readSync(fd, chunk, 0, chunk.length, null);
      if (n === 0) break;
      chunks.push(n === chunk.length ? chunk : chunk.subarray(0, n));
      total += n;
    }
    return Buffer.concat(chunks, total);
  } finally {
    closeSync(fd);
  }
}

function lexists(p) { try { lstatSync(p); return true; } catch { return false; } }

// ---------------------------------------------------------------------------
// Report paths (twin of lazaret.scanner.reports)
// ---------------------------------------------------------------------------
export const ENGINE_MARKER = "generatedBy";
export const ENGINE_VERSION = "lazaret-cli-1";
export const HTML_ENGINE_MARKER = `<meta name="${ENGINE_MARKER}" content="${ENGINE_VERSION}">`;
export const JSON_REPORT_NAME = "lazaret-report.json";
export const HTML_REPORT_NAME = "lazaret-report.html";
export const EXIT_OUTPUT = 3;             // report-path errors (distinct from gate exit 1 / usage exit 2)
export const MARKER_READ_BYTES = 65536;

export class ReportPathError extends Error {}

/**
 * Final absolute paths for every report this run may write. Relative
 * --json/--html/--sarif paths resolve under --out-dir (default: the scan
 * root) — never bare CWD-relative names. `json`/`html`: true (default name),
 * a path, or false; `sarif`: a path or null.
 */
export function reportPaths(scanRoot, { outDir = null, json = true, html = true, sarif = null } = {}) {
  const base = resolve(outDir || scanRoot);
  const pick = (v, dflt) => (typeof v === "string" && v ? (isAbsolute(v) ? v : join(base, v)) : join(base, dflt));
  const paths = {};
  if (json) paths.json = pick(json, JSON_REPORT_NAME);
  if (html) paths.html = pick(html, HTML_REPORT_NAME);
  if (sarif) paths.sarif = isAbsolute(sarif) ? sarif : join(base, sarif);
  return paths;
}

function probeWritable(dir) {
  let fd = null, tmp = null;
  try {
    tmp = join(dir, `.lazaret-writecheck-${randomBytes(6).toString("hex")}`);
    fd = openSync(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | O_NOFOLLOW, 0o600);
    return true;
  } catch {
    tmp = null;
    return false;
  } finally {
    if (fd !== null) try { closeSync(fd); } catch { /* ignore */ }
    if (tmp !== null) try { unlinkSync(tmp); } catch { /* ignore */ }
  }
}

function isDir(p) { try { return statSync(p).isDirectory(); } catch { return false; } }

export function writabilityError(path) {
  const parent = dirname(resolve(path));
  if (!isDir(parent)) return `cannot write ${path}: directory ${parent} does not exist`;
  if (!probeWritable(parent)) return `cannot write ${path}: ${parent} is not writable (permission denied or read-only filesystem)`;
  return null;
}

const JSON_MARK_RE = /^\ufeff?\s*\{\s*"generatedBy"\s*:\s*"lazaret-cli-1"\s*[,}]/;
const SARIF_MARK_RE = /^\ufeff?\s*\{\s*"properties"\s*:\s*\{\s*"generatedBy"\s*:\s*"lazaret-cli-1"\s*[,}]/;

/**
 * True if `path` is an existing regular file this engine (either engine)
 * produced. lstat first: symlinks, FIFOs, devices and directories are never
 * opened. The provenance marker is matched in a bounded prefix (never a
 * full JSON parse of a truncated head).
 */
export function isOurReport(path, kind = "json") {
  let st;
  try { st = lstatSync(path); } catch { return false; }
  if (!st.isFile()) return false;
  let head;
  try { head = readBounded(path, MARKER_READ_BYTES); } catch { return false; }
  const text = new TextDecoder("utf-8").decode(head);
  if (kind === "html") {
    const idx = text.indexOf(HTML_ENGINE_MARKER);
    const end = text.toLowerCase().indexOf("</head>");
    return idx >= 0 && (end < 0 || idx < end);
  }
  return JSON_MARK_RE.test(text) || SARIF_MARK_RE.test(text);
}

function validatePath(path, kind, strict) {
  if (path.startsWith("/dev/")) {
    throw new ReportPathError(`report path ${path} is a device file — write a real file and cat it, or redirect stdout`);
  }
  let st = null;
  try { st = lstatSync(path); } catch { /* does not exist */ }
  if (st) {
    if (st.isSymbolicLink()) throw new ReportPathError(`report path ${path} is a symlink — refusing to write through it`);
    if (st.isDirectory()) throw new ReportPathError(`report path ${path} is a directory`);
    if (!st.isFile()) throw new ReportPathError(`report path ${path} is a special file — refusing to write it`);
    if (!strict && !isOurReport(path, kind)) {
      throw new ReportPathError(`refusing to overwrite ${path}: the existing file is not a Lazaret report from this engine — not produced by this or a previous lazaret run. Move it, pick another path, or pass --force-overwrite`);
    }
  }
  const err = writabilityError(path);
  if (err) throw new ReportPathError(err);
  return path;
}

/** Validate ALL report destinations before the scan starts (throws ReportPathError). */
export function validateReportPaths(paths, strict = false) {
  for (const kind of ["json", "html", "sarif"]) if (paths[kind]) validatePath(paths[kind], kind, strict);
  return paths;
}

/** Validate an explicit --out-dir before the scan (exists, real directory, writable). */
export function validateOutDir(outDir) {
  const path = resolve(outDir);
  let st = null;
  try { st = lstatSync(path); } catch { /* missing */ }
  if (st && st.isSymbolicLink()) throw new ReportPathError(`output directory ${path} is a symlink — refusing to write reports through it`);
  if (!st) throw new ReportPathError(`output directory ${path} does not exist (create it first, or drop --out-dir)`);
  if (!st.isDirectory()) throw new ReportPathError(`output directory ${path} is not a directory`);
  if (!probeWritable(path)) throw new ReportPathError(`output directory ${path} is not writable — reports would be lost after a full scan`);
  return path;
}

/**
 * Write a report atomically (temp file in the destination directory, fsync,
 * rename), re-checking the no-clobber rule at write time. An existing
 * report's file mode is preserved; a new report gets 0666 & ~umask.
 * `render` is the text or a function returning it.
 */
export function writeReport(path, render, { kind = "json", strict = false } = {}) {
  const text = typeof render === "function" ? render() : render;
  const data = Buffer.isBuffer(text) ? text : Buffer.from(String(text), "utf8");
  const parent = dirname(resolve(path));
  let prevMode = null;
  try { const st = lstatSync(path); if (st.isFile()) prevMode = st.mode & 0o7777; } catch { /* new file */ }
  let fd = null, tmp = null;
  for (let attempt = 0; fd === null; attempt++) {
    tmp = join(parent, `.lazaret-report-${randomBytes(6).toString("hex")}.tmp`);
    try { fd = openSync(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | O_NOFOLLOW, 0o666); } catch (e) {
      tmp = null;
      if (e.code !== "EEXIST" || attempt > 20) throw e;
    }
  }
  try {
    let off = 0;
    while (off < data.length) off += writeSync(fd, data, off, data.length - off);
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    if (!strict && lexists(path) && !isOurReport(path, kind)) {
      throw new ReportPathError(`refusing to overwrite ${path}: the existing file is not a Lazaret report from this engine. Move it, pick another path, or pass --force-overwrite`);
    }
    if (prevMode !== null) chmodSync(tmp, prevMode);
    renameSync(tmp, path);
    tmp = null;
    try { const dfd = openSync(parent, C.O_RDONLY); try { fsyncSync(dfd); } finally { closeSync(dfd); } } catch { /* best effort */ }
  } finally {
    if (fd !== null) try { closeSync(fd); } catch { /* ignore */ }
    if (tmp !== null) try { unlinkSync(tmp); } catch { /* ignore */ }
  }
  return path;
}
