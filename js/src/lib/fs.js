// Directory walking and report-path safety — zero-dependency leaf helpers.
// Never import from ../scanner/ (RESTRUCTURE.md §5).
//
// Twin of lazaret.scanner.core.collect_files (shared semantics specs 4, 8, 9,
// 11, 15) and lazaret.scanner.reports (validate_out_dir, _validate_path,
// is_our_report, write_report).

import {
  readdirSync, lstatSync, statSync, openSync, readSync, closeSync, fstatSync, fsyncSync, readlinkSync,
  writeSync, renameSync, unlinkSync, chmodSync, constants as C,
} from "node:fs";
import { join, extname, sep, resolve, dirname, isAbsolute } from "node:path";
import { randomBytes } from "node:crypto";
import { decodeSource, fsNameToString } from "./encoding.js";
import { classifyBinary, HEADER_SAMPLE, PYC_HEADER, pycIssues, pycModule } from "./binary.js";
import { mkIssue, fileIssue } from "./issue.js";
import { pthIssues } from "./pth.js";

export const EXTS = {
  ".py": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
  ".mjs": "js", ".cjs": "js", ".sql": "sql",
};

/**
 * Line endings as Python's text mode reads them: \r\n and a lone \r both become \n.
 * Without this, a file with Windows line endings leaves "\r" at the end of every
 * line, which (for one) turns a bare "# nosec" into a suppression that matches no
 * rule. Twin of lazaret.scanner.core.normalize_newlines.
 */
export function normalizeNewlines(text) {
  return typeof text === "string" && text.includes("\r") ? text.replace(/\r\n?/g, "\n") : text;
}

// Spec 8: `.git` (exactly that name) is always skipped; dependency trees are
// pruned unless --deps; __pycache__ is never source-scanned but its .pyc
// files are checked. Every pruned tree is reported (Q-SKIPPED-TREE).
export const SKIP_DIRS = new Set([".git", "__pycache__"]);
export const OPTIN_SKIP_DIRS = [
  "node_modules", "venv", ".venv", "env", "dist", "build", ".next",
  "coverage", "vendor", "site-packages", ".tox", ".mypy_cache",
  ".pytest_cache", "migrations",
];
// Name-based markers (is_dependency_manifest): a manifest under one of these
// belongs to an installed package.
export const DEP_MARKERS = new Set([
  "node_modules", "site-packages", "bower_components", "vendor", "venv", ".venv",
]);
const DEP_TREES = new Set(["node_modules", "bower_components", "site-packages"]);
const VENV_TREES = new Set(["venv", ".venv", "env"]);

export const MAX_FILE_BYTES = 2_000_000;   // source files/manifests above this: SC-TRUNCATED

const O_NOFOLLOW = C.O_NOFOLLOW ?? 0;
const O_NONBLOCK = C.O_NONBLOCK ?? 0;
const O_NOCTTY = C.O_NOCTTY ?? 0;
const SEP = Buffer.from(sep);
const APPLE_DOUBLE_MAGIC = [Buffer.from([0x00, 0x05, 0x16, 0x07]), Buffer.from([0x00, 0x05, 0x16, 0x00])];

/** The scan target is missing, not a directory, unreadable or empty: usage error (exit 2). */
export class ScanTargetError extends Error {}

// strerror() text for the errno codes a walk can meet (Python reports exc.strerror).
const STRERROR = {
  EACCES: "Permission denied", EPERM: "Operation not permitted", ENOENT: "No such file or directory",
  ELOOP: "Too many levels of symbolic links", EIO: "Input/output error", ENOTDIR: "Not a directory",
  EISDIR: "Is a directory", ENAMETOOLONG: "File name too long", EMFILE: "Too many open files",
  ENFILE: "Too many open files in system", EBUSY: "Device or resource busy", ENXIO: "No such device or address",
  ETXTBSY: "Text file busy", EAGAIN: "Resource temporarily unavailable", EINVAL: "Invalid argument",
  EOVERFLOW: "Value too large for defined data type", ENOMEM: "Cannot allocate memory",
  EROFS: "Read-only file system", ENODEV: "No such device", ESTALE: "Stale file handle",
};
export function strerror(e) {
  if (e && e.code && STRERROR[e.code]) return STRERROR[e.code];
  if (e instanceof NotRegularFile) return e.message;
  const m = /^[A-Z0-9]+: ([^,]+)/.exec(String(e && e.message));
  if (m) return m[1][0].toUpperCase() + m[1].slice(1);
  return (e && e.name) || "Error";
}
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
export function symlinkIssue(path, target) {
  target = String(target);
  if (Array.from(target).length > 200) target = Array.from(target).slice(0, 197).join("") + "...";
  return coverage("Q-SYMLINK", "Symbolic link (not followed)", path,
    `Symbolic link ${path} -> ${target} was not followed; its target was not scanned.`,
    "Following links would let a repository pull files from outside the scanned tree (host credentials, /dev/urandom) into the scan and its reports, or loop forever. The link target is not part of the tree under review.",
    "If the target belongs to the project, scan it directly.",
    "CWE-59 · Scan coverage");
}
export function unreadableIssue(path, reason) {
  return coverage("Q-UNREADABLE", "Unreadable entry (not scanned)", path,
    `${path} could not be read (${reason}); it was not scanned.`,
    "An entry the scanner cannot read is invisible to every rule. Special files (named pipes, sockets, devices) are never opened: reading one can hang or exhaust the scan.",
    "Fix the permissions (or remove the special file) and re-scan.",
    "Scan coverage");
}
export function scanErrorIssue(path, err) {
  return coverage("Q-SCAN-ERROR", "File scan failed", path,
    `Scanning ${path} failed (${(err && err.name) || "Error"}); findings for this file are incomplete.`,
    "An internal error while scanning one file is reported here instead of aborting the whole run, so the rest of the project still gets a report. This file's result is not evidence that it is clean.",
    "Review the file manually and report the error (re-run with LAZARET_DEBUG=1 for a traceback).",
    "Scan coverage");
}
export function skippedTreeIssue(rel, nFiles, nBytes) {
  return {
    rule: "Q-SKIPPED-TREE", name: "Skipped directory (not scanned)", type: "SMELL", sev: "INFO",
    msg: `Directory ${rel} was skipped (${nFiles} files, ${nBytes} bytes unread).`,
    why: "Skipped trees are invisible to every rule — the classic hiding places (dist, build, .git) hold published code and committed-then-deleted secrets. Generated trees you own are fine to skip on purpose; unexpected entries here are blind spots.",
    fix: "Only exclude generated trees you control; remove the exclusion otherwise so the tree is scanned.",
    ref: "Maintainability", file: rel, line: 1, snippet: [], snipStart: 1,
  };
}
export function truncatedIssue(path, detail) {
  return fileIssue({ id: "SC-TRUNCATED", name: "Scan truncated", type: "HOTSPOT", sev: "CRITICAL",
    msg: `File not fully scanned: ${detail}.`,
    why: "Scanning stopped early, so a clean verdict for this file is not evidence of anything — the unscanned bytes are exactly where a hostile artifact would put its payload (audit C2/G16: declared sizes and entry counts are attacker-controlled and were used to skip files with zero signal).",
    fix: "Review the file manually or raise the limit and re-scan.",
    ref: "CWE-506 · Supply chain" }, path);
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
function childPath(dirBuf, nameBuf) { return Buffer.concat([dirBuf, SEP, nameBuf]); }
const byName = (a, b) => (a.str < b.str ? -1 : a.str > b.str ? 1 : 0);

function listDir(dirBuf) {
  return readdirSync(dirBuf, { encoding: "buffer" })
    .map((nb) => ({ buf: nb, str: fsNameToString(nb) }))
    .sort(byName);
}
function readlinkText(p) {
  try { return fsNameToString(readlinkSync(p, { encoding: "buffer" })); } catch { return "?"; }
}

// name → (marker names directly inside, marker suffixes directly inside)
const DEP_TREE_MARKERS = {
  venv: [["pyvenv.cfg"], []], ".venv": [["pyvenv.cfg"], []], env: [["pyvenv.cfg"], []],
  vendor: [["modules.txt", "autoload.php", "package.json"], [".dist-info", ".egg-info"]],
};
/** Is directory `name` a dependency tree (always for node_modules & co; vendor/venv only with a marker)? */
function isDependencyTree(name, dirBuf) {
  if (DEP_TREES.has(name)) return true;
  const markers = DEP_TREE_MARKERS[name];
  if (!markers) return false;
  const [names, suffixes] = markers;
  let entries;
  try { entries = readdirSync(dirBuf, { encoding: "buffer" }); } catch { return false; }
  return entries.some((nb) => {
    const n = fsNameToString(nb);
    return names.includes(n) || suffixes.some((x) => n.endsWith(x));
  });
}

/** (file count, byte count) of a pruned tree — iterative, links not followed. */
function treeStats(dirBuf) {
  let nFiles = 0, nBytes = 0;
  const stack = [dirBuf];
  while (stack.length) {
    const d = stack.pop();
    let names;
    try { names = readdirSync(d, { encoding: "buffer" }); } catch { continue; }
    for (const nb of names) {
      const p = childPath(d, nb);
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.isDirectory()) { stack.push(p); continue; }
      nFiles++;
      if (st.isFile()) nBytes += st.size;
    }
  }
  return [nFiles, nBytes];
}

/**
 * Collect the files to scan under `root` (twin of core._collect).
 * Returns { files, manifests, pth, binaryIssues, skippedIssues } — files:
 * [{path, content, lang, dep}], manifests: package.json/binding.gyp entries
 * [{kind, path, content, dep}], pth: paths of the .pth files checked,
 * binaryIssues: collection findings (binary classification, SC-TRUNCATED,
 * Q-ENCODING/SC-UTF7, SC-PYC-*, SC-PTH-EXEC, Q-SYMLINK, Q-UNREADABLE,
 * Q-SCAN-ERROR), skippedIssues: Q-SKIPPED-TREE per pruned tree.
 * Throws ScanTargetError when the root itself cannot be listed.
 */
export function collectFiles(root, { includeDeps = false, exclude = [] } = {}) {
  const col = { files: [], manifests: [], pth: [], binaryIssues: [], skippedIssues: [] };
  const issues = col.binaryIssues;
  const excluded = new Set(exclude);
  const rootBuf = Buffer.from(resolve(root));
  const seen = new Set();
  const skipTree = (buf, rel) => { const [n, bytes] = treeStats(buf); col.skippedIssues.push(skippedTreeIssue(rel, n, bytes)); };
  const stack = [{ buf: rootBuf, rel: "", dep: false }];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = listDir(dir.buf);
      if (!dir.rel) { const st = statSync(dir.buf); if (st.ino) seen.add(`${st.dev}:${st.ino}`); }
    } catch (e) {
      if (!dir.rel) throw new ScanTargetError(`cannot read directory ${fsNameToString(rootBuf)}: ${strerror(e)}`);
      issues.push(unreadableIssue(dir.rel, strerror(e)));
      continue;
    }
    const names = new Set(entries.map((e) => e.str));
    const subdirs = [];
    for (const ent of entries) {
      const full = childPath(dir.buf, ent.buf);
      const rel = dir.rel ? `${dir.rel}${sep}${ent.str}` : ent.str;
      let st;
      try { st = lstatSync(full); } catch (e) { issues.push(unreadableIssue(rel, strerror(e))); continue; }
      if (st.isSymbolicLink()) issues.push(symlinkIssue(rel, readlinkText(full)));
      else if (st.isDirectory()) subdirs.push({ ent, full, rel, st });
      else if (!st.isFile()) issues.push(unreadableIssue(rel, specialKind(st)));
      else {
        try { collectFile(full, rel, ent.str, st, dir.dep, col); } catch (e) {
          if (e instanceof NotRegularFile || (e && e.code)) issues.push(unreadableIssue(rel, strerror(e)));
          else issues.push(scanErrorIssue(rel, e));
        }
      }
    }
    const push = [];
    for (const { ent, full, rel, st } of subdirs) {
      const name = ent.str;
      if (name === ".git" || excluded.has(name)) { skipTree(full, rel); continue; }
      if (name === "__pycache__") {
        try { checkPycache(full, rel, names, issues); } catch (e) { issues.push(scanErrorIssue(rel, e)); }
        continue;
      }
      const key = `${st.dev}:${st.ino}`;
      if (st.ino && seen.has(key)) { issues.push(unreadableIssue(rel, "directory already visited (filesystem loop)")); continue; }
      if (st.ino) seen.add(key);
      const dep = dir.dep || isDependencyTree(name, full);
      if (dep && !dir.dep && !includeDeps) { skipTree(full, rel); continue; }
      push.push({ buf: full, rel, dep });
    }
    for (let k = push.length - 1; k >= 0; k--) stack.push(push[k]);   // pop order = sorted, depth-first
  }
  return col;
}

function collectFile(full, rel, name, st, dep, col) {
  const ext = extname(name).toLowerCase();
  const kind = name === "package.json" || name === "binding.gyp" ? name : null;
  const pth = !kind && ext === ".pth";
  const lang = kind || pth ? null : EXTS[ext];
  const size = st.size;
  if (!kind && !pth && !lang) {
    // spec 9: every other regular file is classified by magic bytes
    const bi = classifyBinary(rel, readBounded(full, HEADER_SAMPLE), size, "repo");
    if (bi) col.binaryIssues.push(bi);
    return;
  }
  // spec 9: the size cap applies only to files that would be read whole
  if (size > MAX_FILE_BYTES) {
    col.binaryIssues.push(truncatedIssue(rel, `${size.toLocaleString("en-US")} bytes exceeds the 2,000,000-byte file limit`));
    return;
  }
  const data = readBounded(full, MAX_FILE_BYTES + 1);
  if (data.length > MAX_FILE_BYTES) {                 // grew between the lstat and the read
    col.binaryIssues.push(truncatedIssue(rel, "read exceeded the 2,000,000-byte file limit"));
    return;
  }
  if (kind) {
    const content = normalizeNewlines(new TextDecoder("utf-8", { ignoreBOM: true }).decode(data));
    col.manifests.push({ kind, path: rel, content, dep });
    return;
  }
  if (pth) {                // only the .pth check runs on it (decoded as the registry does: utf-8-sig)
    col.pth.push(rel);
    for (const i of pthIssues(rel, new TextDecoder("utf-8").decode(data))) col.binaryIssues.push(i);
    return;
  }
  if (APPLE_DOUBLE_MAGIC.some((m) => data.subarray(0, 4).equals(m))) {
    const bi = classifyBinary(rel, data.subarray(0, HEADER_SAMPLE), size, "repo");
    if (bi) col.binaryIssues.push(bi);
    return;
  }
  const dec = decodeSource(data, { py: lang === "py" });
  const content = normalizeNewlines(dec.text);
  if (dec.reported) {
    const lines = content.split("\n");
    col.binaryIssues.push(mkIssue({ id: "Q-ENCODING", name: "Non-UTF-8 source encoding",
      type: "SMELL", sev: "INFO",
      msg: `Source file is not UTF-8 (detected ${dec.encoding}); decoded explicitly.`,
      why: "A non-UTF-8 source read as UTF-8 decodes to mojibake, hiding every pattern-based finding — a UTF-16 eval() scans clean.",
      fix: "Re-save the file as UTF-8 so tooling reads it as written.",
      ref: "Maintainability" }, rel, 1, lines));
    if (dec.utf7) col.binaryIssues.push(mkIssue({ id: "SC-UTF7", name: "UTF-7 source encoding",
      type: "HOTSPOT", sev: "CRITICAL",
      msg: "Python source declares UTF-7; code can hide in comments.",
      why: "In UTF-7, '+AAo-' decodes to a newline: text that every editor, diff and reviewer shows as a comment becomes executable code when Python reads the file. No legitimate project needs a UTF-7 source file.",
      fix: "Re-save the file as UTF-8 and review the decoded text (the findings for this file are reported against it).",
      ref: "CWE-506 · Supply chain" }, rel, dec.cookieLine || 1, lines));
  }
  col.files.push({ path: rel, content, lang, dep });
}

/** __pycache__ is not source-scanned; every .pyc directly inside is checked. */
function checkPycache(dirBuf, rel, parentNames, issues) {
  let entries;
  try { entries = listDir(dirBuf); } catch (e) { issues.push(unreadableIssue(rel, strerror(e))); return; }
  for (const ent of entries) {
    const full = childPath(dirBuf, ent.buf);
    const prel = `${rel}${sep}${ent.str}`;
    let st;
    try { st = lstatSync(full); } catch (e) { issues.push(unreadableIssue(prel, strerror(e))); continue; }
    if (st.isSymbolicLink()) { issues.push(symlinkIssue(prel, readlinkText(full))); continue; }
    if (!st.isFile() || !ent.str.endsWith(".pyc")) continue;
    let header;
    try { header = readBounded(full, PYC_HEADER); } catch (e) { issues.push(unreadableIssue(prel, strerror(e))); continue; }
    const module = pycModule(ent.str);
    const hasSource = parentNames.has(`${module}.py`) || parentNames.has(`${module}.pyw`);
    for (const i of pycIssues(prel, header, hasSource)) issues.push(i);
  }
}

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
