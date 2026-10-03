// Directory walking and report-path safety — zero-dependency leaf helpers.
// Never import from ../scanner/ (RESTRUCTURE.md §5).
//
// Twin of lazaret.scanner.core.collect_files (shared semantics specs 4, 8, 9,
// 11, 15) and lazaret.scanner.reports (validate_out_dir, _validate_path,
// is_our_report, write_report).

import {
  readdirSync, lstatSync, statSync, openSync, readSync, closeSync, fstatSync, fsyncSync, readlinkSync,
  writeSync, renameSync, unlinkSync, chmodSync, realpathSync, constants as C,
} from "node:fs";
import { join, sep, resolve, dirname, basename, isAbsolute } from "node:path";
import { randomBytes } from "node:crypto";
import { decodeSource, fsNameToString } from "./encoding.js";
import { classifyBinary, HEADER_SAMPLE, PYC_HEADER, pycIssues, pycModule, pyExt, looksBinary, mpegTs, MPEG_TS_EXTS,
  disguisedBinary, DISGUISE_SAMPLE } from "./binary.js";
import { shebangLang } from "./native.js";
import { mkIssue, fileIssue } from "./issue.js";
import { pthIssues } from "./pth.js";
import { registerScanContext, SECRET_SKIP_RE } from "./redact.js";
import { isConfigFile, ownReport, CONFIG_SCAN_CAP } from "./configsecrets.js";

export const EXTS = {
  ".py": "py", ".pyw": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
  ".mts": "js", ".cts": "js", ".mjs": "js", ".cjs": "js", ".sql": "sql",
};
// gyp files, whatever their name (twin of core.GYP_EXTS): binding.gyp pulls
// others in ('includes': ['build/common.gypi']) and node-gyp runs their
// actions and command expansions too, so every one goes to scanGyp.
export const GYP_EXTS = new Set([".gyp", ".gypi"]);

/**
 * Line endings as Python's text mode reads them: \r\n and a lone \r both become \n.
 * Without this, a file with Windows line endings leaves "\r" at the end of every
 * line, which (for one) turns a bare "# nosec" into a suppression that matches no
 * rule. Twin of lazaret.scanner.core.normalize_newlines.
 */
export function normalizeNewlines(text) {
  return typeof text === "string" && text.includes("\r") ? text.replace(/\r\n?/g, "\n") : text;
}

/** posixpath.normpath of a relative '/'-separated path. */
function normpathRel(path) {
  const comps = [];
  for (const c of path.split("/")) {
    if (c === "" || c === ".") continue;
    if (c !== ".." || !comps.length || comps[comps.length - 1] === "..") comps.push(c);
    else comps.pop();
  }
  return comps.join("/") || ".";
}

/**
 * A hook's `target` joined with the directory `base` (relative to the scan
 * root), normalized; null when it is absolute or leaves the scan root.
 * Twin of core._tree_join.
 */
export function treeJoin(base, target) {
  target = target.replaceAll("\\", "/");
  if (target.startsWith("/") || /^[A-Za-z]:/.test(target)) return null;
  const joined = normpathRel(`${base || "."}/${target}`);
  if (joined === "." || joined === ".." || joined.startsWith("../")) return null;
  return joined;
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

// Source files and manifests above this are not read: SC-TRUNCATED (twin of
// core.SOURCE_SIZE_CAP). The CLI takes --max-source-bytes or
// LAZARET_MAX_SOURCE_BYTES; collectFiles() takes `maxFileBytes`.
export const MAX_FILE_BYTES = 16_000_000;

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
/** Q-SKIPPED-CONFIG: a config or data file too large to check for credentials (core.config_skipped_issue). */
export function configSkippedIssue(path, detail) {
  return coverage("Q-SKIPPED-CONFIG", "Config file not checked (too large)", path,
    `${path} was not checked for credentials: ${detail}.`,
    "Config and data files are read only to look for credentials, and one this large is data rather than configuration: a credential in it would not be reported.",
    "Keep credentials out of large data files, and real configuration in files of its own.",
    "Scan coverage");
}
export function unreadableIssue(path, reason) {
  return coverage("Q-UNREADABLE", "Unreadable entry (not scanned)", path,
    `${path} could not be read (${reason}); it was not scanned.`,
    "An entry the scanner cannot read is invisible to every rule. Special files (named pipes, sockets, devices) are never opened: reading one can hang or exhaust the scan.",
    "Fix the permissions (or remove the special file) and re-scan.",
    "Scan coverage");
}
/**
 * SC-TRUNCATED for a file (or directory) whose scan threw (twin of
 * core.scan_error_issue): the run goes on without its findings, and like any
 * file not fully scanned it fails the gate. It was an INFO note
 * (Q-SCAN-ERROR), so a file whose scan died took its CRITICAL findings with
 * it and the gate passed (review B3: a 6 MB string line overflowed V8's
 * regex stack).
 */
export function scanErrorIssue(path, err) {
  const issue = truncatedIssue(path, `its scan failed (${(err && err.name) || "Error"}), so its findings are missing`);
  issue.why = "An internal error stopped this scan; the rest of the project is still scanned and reported, but nothing in this file was checked, so the result can't clear it.";
  issue.fix = "Review the file manually and report the error (re-run with LAZARET_DEBUG=1 for a traceback).";
  return issue;
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
 * Returns { files, manifests, pth, configs, binaryIssues, skippedIssues } —
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
  const col = { files: [], manifests: [], pth: [], configs: [], binaryIssues: [], skippedIssues: [], maxFileBytes };
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
      if (!dir.rel) { const key = dirKey(statSync(dir.buf, { bigint: true })); if (key) seen.add(key); }
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
      if (isLink(ent, full, st)) issues.push(symlinkIssue(rel, readlinkText(full)));
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
      let key = null;
      try { key = dirKey(lstatSync(full, { bigint: true })); } catch { /* no identity: walked, not loop-checked */ }
      if (key && seen.has(key)) { issues.push(unreadableIssue(rel, "directory already visited (filesystem loop)")); continue; }
      if (key) seen.add(key);
      const dep = dir.dep || isDependencyTree(name, full);
      if (dep && !dir.dep && !includeDeps) { skipTree(full, rel); continue; }
      push.push({ buf: full, rel, dep });
    }
    for (let k = push.length - 1; k >= 0; k--) stack.push(push[k]);   // pop order = sorted, depth-first
  }
  return col;
}

/** n with thousands separators, as Python's f"{n:,}" writes it. */
const withCommas = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");

/**
 * "js" or "py" for a file without a source extension whose leading bytes
 * make it a JavaScript or Python script by its #! line (bin/cli, a hook's
 * ./setup): it runs as code, so it is read as source. null otherwise —
 * shell scripts too. Twin of lazaret.scanner.core.script_source_lang.
 */
export function scriptSourceLang(head) {
  head = head.subarray(0, HEADER_SAMPLE);
  if (head.length < 2 || head[0] !== 0x23 || head[1] !== 0x21 || looksBinary(head)) return null;
  const lang = shebangLang(new TextDecoder("utf-8").decode(head));
  return lang === "js" || lang === "py" ? lang : null;
}

function collectFile(full, rel, name, st, dep, col) {
  const ext = pyExt(name).toLowerCase();       // os.path.splitext, as core
  const kind = name === "package.json" || name === "binding.gyp" ? name : GYP_EXTS.has(ext) ? "gyp" : null;
  const pth = !kind && ext === ".pth";
  let lang = kind || pth ? null : EXTS[ext];
  const size = st.size;
  if (!kind && !pth && !lang) {
    // spec 9: every other regular file is classified by magic bytes — unless
    // its #! line makes it a Node or Python script: then it is source
    const head = readBounded(full, HEADER_SAMPLE);
    lang = scriptSourceLang(head);
    if (!lang) {
      const bi = classifyBinary(rel, head, size, "repo");
      if (bi) col.binaryIssues.push(bi);
      else if (!dep && isConfigFile(name) && (utf16Bom(head) || !looksBinary(head))) collectConfig(full, rel, size, col);
      return;
    }
  }
  if (lang && MPEG_TS_EXTS.has(ext)) {
    const head = readBounded(full, HEADER_SAMPLE);
    if (mpegTs(head)) {                                // a video (a camera's .mts), not TypeScript
      const bi = classifyBinary(rel, head, size, "repo");
      if (bi) col.binaryIssues.push(bi);
      return;
    }
  }
  // spec 9: the size cap applies only to files that would be read whole
  const cap = col.maxFileBytes;
  if (size > cap) {
    col.binaryIssues.push(truncatedIssue(rel, `${withCommas(size)} bytes exceeds the ${withCommas(cap)}-byte file limit`));
    if (lang) {                     // its first bytes still tell a program (as in the registry)
      let head = Buffer.alloc(0);
      try {
        head = readBounded(full, DISGUISE_SAMPLE);
      } catch (e) {                 // not read: the SC-TRUNCATED stands alone, as before
        if (!(e instanceof NotRegularFile || (e && e.code))) throw e;
      }
      const dis = disguisedBinary(rel, head);
      if (dis) col.binaryIssues.push(dis);
    }
    return;
  }
  const data = readBounded(full, cap + 1);
  if (data.length > cap) {                            // grew between the lstat and the read
    col.binaryIssues.push(truncatedIssue(rel, `read exceeded the ${withCommas(cap)}-byte file limit`));
    const dis = lang ? disguisedBinary(rel, data) : null;
    if (dis) col.binaryIssues.push(dis);
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
  // read as the registry reads a member (0.1.8): bytes that don't decode to
  // anything text-like are SC-TRUNCATED, not mojibake no rule can read
  const [content, found] = decodeMember(rel, data, lang);
  for (const i of found) col.binaryIssues.push(i);
  const dis = disguisedBinary(rel, data);       // a program under a source file's name (0.1.8)
  if (dis) col.binaryIssues.push(dis);
  col.files.push({ path: rel, content, lang, dep });
}

/**
 * Read a config or data file for scanConfigFile (core._collect_config):
 * decoded like source but without the encoding notes, since it is not code;
 * over CONFIG_SCAN_CAP a Q-SKIPPED-CONFIG note instead.
 */
const utf16Bom = (b) => b.length >= 2 && ((b[0] === 0xff && b[1] === 0xfe) || (b[0] === 0xfe && b[1] === 0xff));
function collectConfig(full, rel, size, col) {
  const cap = CONFIG_SCAN_CAP;
  if (size > cap) {
    col.binaryIssues.push(configSkippedIssue(rel, `${withCommas(size)} bytes is over the ${withCommas(cap)}-byte limit for config files`));
    return;
  }
  const data = readBounded(full, cap + 1);
  if (data.length > cap) {                            // grew between the lstat and the read
    col.binaryIssues.push(configSkippedIssue(rel, `it grew past the ${withCommas(cap)}-byte limit for config files while it was read`));
    return;
  }
  const content = normalizeNewlines(decodeSource(data, { py: false }).text);
  if (!ownReport(content)) col.configs.push({ path: rel, content });   // a report of Lazaret's own is not config
}

/**
 * Q-ENCODING (and SC-UTF7, SC-ESCAPE-CODEC, SC-TRUNCATED) for a decoded
 * source file: `dec` is decodeSource's result, `content` its text with \n
 * line endings. Twin of lazaret.scanner.core.encoding_issues.
 */
/** Python's f"{x:.0%}": half-even on the exact binary value of x * 100. */
export function percent(x) {
  const y = x * 100;
  const f = Math.floor(y);
  return `${y - f === 0.5 ? (f % 2 === 0 ? f : f + 1) : Math.round(y)}%`;
}

/** core._undecodable_share: U+FFFD and control characters in the first 65,536 code points. */
export function undecodableShare(text) {
  let n = 0, bad = 0;
  for (const ch of text) {
    if (n === 65536) break;
    n++;
    const c = ch.codePointAt(0);
    if (c === 0xfffd || c <= 0x08 || (c >= 0x0e && c <= 0x1a) || (c >= 0x1c && c <= 0x1f) || c === 0x7f
        || (c >= 0xdc80 && c <= 0xdcff)) bad++;
  }
  return n ? bad / n : 0;
}

/**
 * Twin of core.decode_member: [text, findings] for a file read as `lang`
 * ("py" keeps its coding cookie): Q-ENCODING / SC-UTF7 (encodingIssues), and
 * SC-TRUNCATED when it does not decode to anything text-like (more than 30%
 * invalid bytes or control characters), so its scan proves nothing. A
 * directory scan reads every source file this way (0.1.8), as the registry does.
 */
export function decodeMember(path, data, lang) {
  const dec = decodeSource(data, { py: lang === "py" });
  const text = normalizeNewlines(dec.text);
  const out = encodingIssues(path, text, dec);
  const share = undecodableShare(text);
  if (share > 0.3 && !(MPEG_TS_EXTS.has(pyExt(path).toLowerCase()) && mpegTs(data.subarray(0, 512)))) {
    out.push(truncatedIssue(path, `content is not decodable as text (${percent(share)} invalid bytes or ` +
      "control characters), so no rule could read it"));
  }
  return [text, out];
}

export function encodingIssues(rel, content, dec) {
  const out = [];
  if (dec.reported) {
    const lines = content.split("\n");
    // the file's own entropy literals and PEM blocks, as scanFile's findings
    // have (twin of core.encoding_issues): the Q-ENCODING snippet of a
    // UTF-8-BOM settings.py showed the literal its S-ENTROPY redacted
    registerScanContext(lines, SECRET_SKIP_RE);
    out.push(mkIssue({ id: "Q-ENCODING", name: "Non-UTF-8 source encoding",
      type: "SMELL", sev: "INFO",
      msg: `Source file is not UTF-8 (detected ${dec.encoding}); decoded explicitly.`,
      why: "A non-UTF-8 source read as UTF-8 decodes to mojibake, hiding every pattern-based finding — a UTF-16 eval() scans clean.",
      fix: "Re-save the file as UTF-8 so tooling reads it as written.",
      ref: "Maintainability" }, rel, 1, lines));
    if (dec.utf7) out.push(mkIssue({ id: "SC-UTF7", name: "UTF-7 source encoding",
      type: "HOTSPOT", sev: "CRITICAL",
      msg: "Python source declares UTF-7; code can hide in comments.",
      why: "In UTF-7, '+AAo-' decodes to a newline: text that every editor, diff and reviewer shows as a comment becomes executable code when Python reads the file. No legitimate project needs a UTF-7 source file.",
      fix: "Re-save the file as UTF-8 and review the decoded text (the findings for this file are reported against it).",
      ref: "CWE-506 · Supply chain" }, rel, dec.cookieLine || 1, lines));
    if (dec.escapes) out.push(mkIssue({ id: "SC-ESCAPE-CODEC", name: "Escape-sequence source encoding",
      type: "HOTSPOT", sev: "CRITICAL",
      msg: `Python source declares ${dec.encoding}; code can hide in escape sequences.`,
      why: "Python decodes this file's escape sequences before it reads the code: '\\u000a' is a newline and '\\u0065' is 'e', so text that every editor, diff and reviewer shows as a comment or a string escape becomes executable code. No legitimate project needs this source encoding.",
      fix: "Re-save the file as UTF-8 and review the decoded text (the findings for this file are reported against it).",
      ref: "CWE-506 · Supply chain" }, rel, dec.cookieLine || 1, lines));
    if (dec.undecoded) out.push(truncatedIssue(rel,
      `its source encoding (${dec.encoding}) is not decoded by Lazaret; the file was read as UTF-8`));
  }
  return out;
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
    // as core._check_pycache: any reparse point counts, file or directory
    if (st.isSymbolicLink() || ent.link) { issues.push(symlinkIssue(prel, readlinkText(full))); continue; }
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
