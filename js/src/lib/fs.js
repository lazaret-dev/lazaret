// Directory walking and report-path safety — zero-dependency leaf helpers.
// Never import from ../scanner/ (RESTRUCTURE.md §5).
//
// The walk (collectFiles) on the disk: it lists folders and reads files for collect.js' walk (walkSteps, takeStep),
// whose steps the engine decides (collect.rs, BR-7 step 4 e), as for core's walk. Report paths: twin of
// lazaret.scanner.reports (validate_out_dir, _validate_path, is_our_report, write_report).

import {
  readdirSync, lstatSync, statSync, openSync, readSync, closeSync, fstatSync, fsyncSync, readlinkSync,
  writeSync, renameSync, unlinkSync, chmodSync, realpathSync, constants as C,
} from "node:fs";
import { join, sep, resolve, dirname, basename, isAbsolute } from "node:path";
import { randomBytes } from "node:crypto";
import { fsNameToString } from "./encoding.js";
import {
  MAX_FILE_BYTES, MAX_WALK_DEPTH, pathTooLong, skippedTreeIssue, symlinkIssue, takeStep, unreadableIssue, walkSteps,
} from "./collect.js";

export { skippedTreeIssue, symlinkIssue, unreadableIssue };

/** posixpath.normpath of a relative '/'-separated path. */
export function normpathRel(path) {
  const comps = [];
  for (const c of path.split("/")) {
    if (c === "" || c === ".") continue;
    if (c !== ".." || !comps.length || comps[comps.length - 1] === "..") comps.push(c);
    else comps.pop();
  }
  return comps.join("/") || ".";
}

const O_NOFOLLOW = C.O_NOFOLLOW ?? 0;
const O_NONBLOCK = C.O_NONBLOCK ?? 0;
const O_NOCTTY = C.O_NOCTTY ?? 0;
const SEP = Buffer.from(sep);

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

/** Read `length` bytes from `offset` of a REGULAR file (fewer at its end), as readBounded reads one. */
export function readRange(path, offset, length) {
  const fd = openSync(path, C.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new NotRegularFile(specialKind(st));
    const out = Buffer.allocUnsafe(length);
    let total = 0;
    while (total < length) {
      const n = readSync(fd, out, total, Math.min(1 << 20, length - total), offset + total);
      if (n === 0) break;
      total += n;
    }
    return out.subarray(0, total);
  } finally {
    closeSync(fd);
  }
}

/** A regular file met by the walk, as collectEntry reads it (lib/collect.js): by its first bytes, or by range (a zip
 * model file's directory and pickles, FP-MODEL-FILES). */
function fileEntry(full, rel, name, size, dep) {
  return {
    rel, name, size, dep,
    read: (limit) => readBounded(full, limit),
    range: (offset, length) => readRange(full, offset, length),
    sibling: (n, limit) => readSibling(siblingPath(full, n), limit),
    head: (limit) => {                // no bytes when it can't be read
      try {
        return readBounded(full, limit);
      } catch (e) {
        if (!ioError(e)) throw e;
        return Buffer.alloc(0);
      }
    },
  };
}
const ioError = (e) => e instanceof NotRegularFile || Boolean(e && e.code);

/** The path of the file `name` beside `full` (the walk's paths are bytes: a Buffer, its folders split at SEP). */
function siblingPath(full, name) {
  if (typeof full === "string") return join(dirname(full), name);
  return Buffer.concat([full.subarray(0, full.lastIndexOf(SEP) + 1), Buffer.from(name)]);
}

/** FP-GRADLE-WRAPPER: the first `limit` bytes of a regular file beside one (a Gradle wrapper jar's properties), or
 * null when there is none (core._read_sibling). */
function readSibling(path, limit) {
  try {
    return readBounded(path, limit);
  } catch (e) {
    if (e instanceof NotRegularFile || (e && (e.code === "ENOENT" || e.code === "ENOTDIR"))) return null;
    throw e;
  }
}

function lexists(p) { try { lstatSync(p); return true; } catch { return false; } }
/**
 * A directory's identity for the loop check, from a { bigint: true } stat,
 * or null when the filesystem has no inode numbers. Number stats are not
 * enough: a Windows file ID is 64 bits (NTFS: a 16-bit sequence number
 * above a 48-bit record number), a double keeps 53, and nearby directories
 * rounded to the same number, so a directory was skipped as "already
 * visited" (a 600-level test tree on windows-latest found no files).
 */
export function dirKey(st) {
  return st.ino ? `${st.dev}:${st.ino}` : null;
}
function childPath(dirBuf, nameBuf) { return Buffer.concat([dirBuf, SEP, nameBuf]); }
const byName = (a, b) => (a.str < b.str ? -1 : a.str > b.str ? 1 : 0);

// `link`: the listing's own entry type says link. On Windows that is every
// reparse point (symlink, junction, mount point, and also dedup/cloud files),
// and it is the only reliable signal there: the lstat of a file symlink can
// come back as a regular file (seen on the windows-latest runners).
function listDir(dirBuf) {
  return readdirSync(dirBuf, { encoding: "buffer", withFileTypes: true })
    .map((d) => ({ buf: d.name, str: fsNameToString(d.name), link: d.isSymbolicLink() }))
    .sort(byName);
}
/** A link the walk reports and never follows, as the Python engine decides:
 * a symlink, or a directory that is a reparse point (junction, mount point).
 * A file the listing flags counts only if it has a link target, so a Windows
 * dedup or cloud placeholder file is still scanned as a file. */
export function isLink(ent, full, st) {
  if (st.isSymbolicLink()) return true;
  if (!ent.link) return false;
  if (st.isDirectory()) return true;
  try { readlinkSync(full); return true; } catch { return false; }
}
function readlinkText(p) {
  try { return fsNameToString(readlinkSync(p, { encoding: "buffer" })); } catch { return "?"; }
}

/** [[name, is a folder]] of a folder's entries (no link followed), or null when it cannot be listed. */
function listing(dirBuf) {
  try {
    return readdirSync(dirBuf, { encoding: "buffer", withFileTypes: true })
      .map((d) => [fsNameToString(d.name), d.isDirectory()]);
  } catch { return null; }
}

/** The disk as collect.js' walk lists and reads it (walkSteps' and takeStep's `tree`): a node is a Buffer path. */
const DISK = {
  list(dirBuf, { pycache = false } = {}) {
    return listDir(dirBuf).map((ent) => {
      const node = childPath(dirBuf, ent.buf), name = ent.str;
      let st;
      try { st = lstatSync(node, { bigint: true }); } catch (e) {
        return { name, node, kind: "error", why: strerror(e), tooLong: pathTooLong(e) };
      }
      if (pycache) {                  // as core._check_pycache: any reparse point counts, file or directory
        if (st.isSymbolicLink() || ent.link) return { name, node, kind: "link", target: readlinkText(node) };
        if (st.isFile()) return { name, node, kind: "file", size: Number(st.size) };
        return { name, node, kind: "special", code: "other" };
      }
      if (isLink(ent, node, st)) return { name, node, kind: "link", target: readlinkText(node) };
      if (st.isDirectory()) return { name, node, kind: "dir", key: dirKey(st) };
      if (!st.isFile()) return { name, node, kind: "special", code: specialCode(st) };
      return { name, node, kind: "file", size: Number(st.size) };
    });
  },
  key: (dirBuf) => dirKey(statSync(dirBuf, { bigint: true })),
  names: listing,
  cargo: (dirBuf, dirs) => dirs.filter((d) => {
    try { return lstatSync(Buffer.concat([dirBuf, SEP, Buffer.from(d), SEP, Buffer.from(".cargo-checksum.json")])).isFile(); }
    catch { return false; }
  }),
  strerror,
  entry: fileEntry,
  head: readBounded,
  stats: treeStats,
};

/** "go" when the vendor directory `dirBuf` is Go's, "cargo" when it is cargo's, else null (the engine's: collect.rs).
 * The npm package's twin of core._dep_tree_kind for a vendor folder, for its tests. */
export function vendorKind(dirBuf) {
  const tree = { ...DISK, list: () => [{ name: "vendor", node: dirBuf, kind: "dir", key: null }], key: () => null };
  for (const step of walkSteps(tree, null, { includeDeps: true })) {
    if (step.walk) return Array.isArray(step.walk.dep) ? step.walk.dep[0] : null;
  }
  return null;
}

/** (file count, byte count) of a pruned tree `depth` folders below the root — iterative, links not followed, no
 * folder deeper than MAX_WALK_DEPTH listed (core._tree_stats_at). */
function treeStats(dirBuf, depth = 1) {
  let nFiles = 0, nBytes = 0;
  const stack = [[dirBuf, depth]];
  while (stack.length) {
    const [d, at] = stack.pop();
    if (at > MAX_WALK_DEPTH) continue;
    let names;
    try { names = readdirSync(d, { encoding: "buffer" }); } catch { continue; }
    for (const nb of names) {
      const p = childPath(d, nb);
      let st;
      try { st = lstatSync(p); } catch { continue; }
      if (st.isDirectory()) { stack.push([p, at + 1]); continue; }
      nFiles++;
      if (st.isFile()) nBytes += st.size;
    }
  }
  return [nFiles, nBytes];
}

/**
 * Collect the files to scan under `root` (core._collect's walk: collect.js' walkSteps on the disk; what each entry is:
 * the engine's, collect.rs). Returns { files, manifests, pth, configs, binaryIssues, skippedIssues } —
 * files: [{path, content, lang, dep}], manifests: package.json and gyp
 * entries [{kind, path, content, dep}] (kind "package.json", "binding.gyp",
 * or "gyp" for any other .gyp / .gypi file), pth: paths of the .pth files
 * checked, configs: [{path, content}] config and data files outside
 * dependency trees (scanConfigFile), binaryIssues: collection findings
 * (binary classification, SC-TRUNCATED, Q-ENCODING/SC-UTF7/SC-ESCAPE-CODEC,
 * SC-PYC-*, SC-PTH-EXEC, Q-SYMLINK, Q-UNREADABLE, Q-SKIPPED-CONFIG),
 * skippedIssues: Q-SKIPPED-TREE per pruned tree.
 * Throws ScanTargetError when the root itself cannot be listed.
 */
export function collectFiles(root, { includeDeps = false, exclude = [], maxFileBytes = MAX_FILE_BYTES } = {}) {
  const col = { files: [], manifests: [], pth: [], configs: [], binaryIssues: [], skippedIssues: [], models: [],
    tooDeep: [], tooLong: [], maxFileBytes };
  const rootBuf = Buffer.from(resolve(root));
  for (const step of walkSteps(DISK, rootBuf, { includeDeps, exclude })) {
    if (step.rootError) throw new ScanTargetError(`cannot read directory ${fsNameToString(rootBuf)}: ${strerror(step.rootError)}`);
    takeStep(step, col, DISK, { ioError, strerror });
  }
  return col;
}

const specialCode = (st) => (st.isFIFO() ? "fifo" : st.isSocket() ? "socket" : st.isCharacterDevice() ? "char"
  : st.isBlockDevice() ? "block" : "other");

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

/** os.path.realpath of a directory: its longest existing ancestor resolved, the rest kept. */
function realDir(dir) {
  const tail = [];
  for (let head = dir; ;) {
    try { return join(realpathSync(head), ...tail); } catch { /* not there: try its parent */ }
    const up = dirname(head);
    if (up === head) return dir;
    tail.unshift(basename(head));
    head = up;
  }
}

/**
 * What two spellings of one report destination have in common: the real
 * path of its directory ('..', relative parts and symlinks resolved) joined
 * with its name, case-folded on Windows (twin of reports.same_file_key).
 */
export function sameFileKey(path) {
  const abs = resolve(path);
  const key = join(realDir(dirname(abs)), basename(abs));
  return process.platform === "win32" ? key.toLowerCase() : key;
}

const REPORT_LABELS = { json: "JSON", html: "HTML", sarif: "SARIF" };
/**
 * Two reports resolving to one file are refused before the scan (review:
 * `--sarif lazaret-report.json` silently replaced the SARIF log with the JSON
 * report; `--json X --html X` failed only after the whole scan). Twin of
 * reports.check_distinct_paths.
 */
export function checkDistinctPaths(paths) {
  const seen = new Map();
  for (const kind of ["json", "html", "sarif"]) {
    if (!paths[kind]) continue;
    const key = sameFileKey(paths[kind]);
    if (seen.has(key)) {
      throw new ReportPathError(`the ${REPORT_LABELS[seen.get(key)]} and ${REPORT_LABELS[kind]} reports would both be written to ${paths[kind]} — give each report its own path`);
    }
    seen.set(key, kind);
  }
}

/** Validate ALL report destinations before the scan starts (throws ReportPathError): distinct files, then each one. */
export function validateReportPaths(paths, strict = false) {
  checkDistinctPaths(paths);
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

/** Write a string, a Buffer or an iterable of strings to fd as UTF-8, in writes of about 1 MiB. */
function writeText(fd, text) {
  const put = (data) => { let off = 0; while (off < data.length) off += writeSync(fd, data, off, data.length - off); };
  if (Buffer.isBuffer(text) || typeof text === "string" || typeof text?.[Symbol.iterator] !== "function") {
    put(Buffer.isBuffer(text) ? text : Buffer.from(String(text), "utf8"));
    return;
  }
  let batch = "";
  for (const piece of text) {
    batch += piece;
    if (batch.length >= 1 << 20) {
      const cut = /[\ud800-\udbff]$/.test(batch) ? batch.length - 1 : batch.length;   // never split a surrogate pair
      put(Buffer.from(batch.slice(0, cut), "utf8"));
      batch = batch.slice(cut);
    }
  }
  put(Buffer.from(batch, "utf8"));
}

/**
 * Write a report atomically (temp file in the destination directory, fsync,
 * rename), re-checking the no-clobber rule at write time. An existing
 * report's file mode is preserved; a new report gets 0666 & ~umask.
 * `render` is the text or a function returning it; the text may also be an
 * iterable of strings (a report too big for one string), written as it comes.
 */
export function writeReport(path, render, { kind = "json", strict = false } = {}) {
  const text = typeof render === "function" ? render() : render;
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
    writeText(fd, text);
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
