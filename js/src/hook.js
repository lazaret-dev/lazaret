// `lazaret hook [FILE …]`: the commit-time gate (the Python package's lazaret.scanner.hook; H-1, and in this package
// since H-2).
//
// What a commit should not carry: credentials, vulnerabilities and supply-chain threats. The files named (pre-commit
// passes the ones being committed), or with none the files staged for commit, are scanned as `lazaret <dir> --deps`
// scans a project, in a temporary tree that keeps their paths: their staged content, read from git's index (a partly
// staged file is checked as it will be committed; a file git doesn't track, or any file outside a repository, as it
// is on disk). The gate is `--ci`'s security and supply-chain conditions: no BLOCKER finding, no CRITICAL
// vulnerability, no supply-chain indicator and no cross-file taint flow. Duplication and maintainability, which `--ci`
// gates too, are not a commit's business. What prints is what those conditions read: vulnerabilities of MAJOR and
// above, supply-chain indicators and cross-file flows, each under its path as git writes it: the Python package's lines.
//
// A file that can't be read is SC-TRUNCATED, which fails the gate, as in a project scan; so is one whose name is
// another's here (names that differ only in case, or by a backslash, are one file on some systems). A symbolic link
// or a submodule is not followed. Nothing is run but git, which is asked only to list the index and print its blobs
// (`cat-file`, so no filter runs, git-lfs's included); it is the git PATH names by an absolute path (lib/programs.js),
// never one in the repository's folder.
//
// Exit codes: 0 passed (or nothing to check), 1 the gate failed, 2 usage error, 5 internal error (cli.js). runHook
// returns a promise of the code: the blobs are streamed from git into the temporary tree.

import { spawn, spawnSync } from "node:child_process";
import {
  closeSync, constants as C, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync,
  realpathSync, rmSync, writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { fsNameToString } from "./lib/encoding.js";
import { MAX_FILE_BYTES, ScanTargetError, strerror, truncatedIssue } from "./lib/fs.js";
import { loadError } from "./lib/native.js";
import { findProgram } from "./lib/programs.js";
import { cmpCodePoints } from "./lib/pycompat.js";
import { setRedactSecrets } from "./lib/redact.js";
import { collectProject, scanCollected } from "./project.js";
import { buildResult, CROSS_FILE_LABEL, issueExcerpt, sanitizeTermLine } from "./report.js";
import { SEV_ORDER } from "./scanner/rules.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

/** build_result's conditions this gate keeps (the other two are quality). */
export const GATE = ["No blocker issues", "No critical vulnerabilities", "No supply-chain indicators", CROSS_FILE_LABEL];
/** git's empty tree: what a first commit's staged files are compared with. */
export const EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const CHUNK = 1 << 20;
const NEWLINE = 0x0a;
const SEP = Buffer.from(sep);
const O_NOFOLLOW = C.O_NOFOLLOW ?? 0;
const O_NONBLOCK = C.O_NONBLOCK ?? 0;

const USAGE = `lazaret hook v${pkg.version} — the commit-time gate

Usage:
  lazaret hook [FILE …] [options]

Credentials, vulnerabilities and supply-chain threats in the files being
committed (their staged content). Fails on --ci's security and supply-chain
conditions; duplication and maintainability are not checked.

  FILE           files to check (pre-commit passes them); default: the files
                 staged for commit
  --staged       check the files staged for commit (what no FILE means)
  -q, --quiet    print only what fails the gate, and the findings
  --version      print version
  -h, --help     show this help

Exit codes: 0 passed or nothing to check · 1 the gate failed · 2 usage error ·
5 internal error.`;

/** A usage error: the message says what to do (hook.HookError). */
export class HookError extends Error {}

/** A path in a repository: its bytes as git gives them (`buf`) and its text (`text`, fsNameToString's, as the project
 * scan shows a name). `key` is the bytes as a string, to look the path up by. */
function gitPath(buf) {
  return { buf, text: fsNameToString(buf), key: buf.toString("latin1") };
}

/**
 * Run git, reading only (no optional locks, pathspecs literal) -> its stdout (a Buffer), or null when it fails or
 * isn't installed. git is the one in PATH's absolute folders (findProgram), never a git.exe in the repository's own
 * folder, which Windows runs for a bare `git`.
 */
function git(root, args, env) {
  const prog = findProgram("git", { env });
  if (prog === null) return null;
  const done = spawnSync(prog, ["--no-optional-locks", "--literal-pathspecs", ...(root ? ["-C", root] : []), ...args],
    { stdio: ["ignore", "pipe", "ignore"], env, maxBuffer: Infinity, windowsHide: true });
  return done.error || done.status !== 0 ? null : done.stdout;
}

/** The top of the git work tree `cwd` is in, or null. */
export function repoRoot(cwd, env = process.env) {
  const out = git(cwd, ["rev-parse", "--show-toplevel"], env);
  if (!out || !out.length) return null;
  const top = out.toString("utf8").replace(/[\r\n]+$/, "");
  try { return realpathSync.native(top); } catch { return top; }
}

/** The files staged for commit (added, copied, modified, type-changed; a rename is its new path), relative to the
 * work tree's top, as gitPaths. */
export function stagedPaths(root, env = process.env) {
  const base = git(root, ["rev-parse", "--verify", "-q", "HEAD"], env) !== null ? "HEAD" : EMPTY_TREE;
  const out = git(root, ["diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=ACMT", base], env);
  if (out === null) throw new HookError("git could not list the staged files");
  return splitNul(out).map(gitPath);
}

/** Map of a path's key -> { mode, oid } of the index's merged (stage 0) entries. */
export function indexEntries(root, env = process.env) {
  const out = git(root, ["ls-files", "-s", "-z"], env);
  if (out === null) throw new HookError("git could not read the index");
  const entries = new Map();
  for (const rec of splitNul(out)) {
    const tab = rec.indexOf(0x09);
    if (tab === -1) continue;
    const fields = asciiFields(rec.subarray(0, tab));
    if (fields.length === 3 && fields[2] === "0") entries.set(rec.subarray(tab + 1).toString("latin1"), { mode: fields[0], oid: fields[1] });
  }
  return entries;
}

function splitNul(buf) {
  const out = [];
  let start = 0;
  for (let k = buf.indexOf(0); k !== -1; k = buf.indexOf(0, start)) {
    if (k > start) out.push(buf.subarray(start, k));
    start = k + 1;
  }
  if (start < buf.length) out.push(buf.subarray(start));
  return out;
}

/** bytes.split(): the fields between runs of ASCII whitespace, as text. */
function asciiFields(buf) {
  return buf.toString("latin1").split(/[ \t\n\r\v\f]+/).filter(Boolean);
}

/** dest/rel as a Buffer path ({ dir, file }: the folder it goes in and the file), refusing a path that would leave
 * dest (hook._target). A backslash separates folders too, as on Windows. */
function target(dest, path) {
  const parts = [];
  let start = 0;
  for (let k = 0; k <= path.buf.length; k++) {
    if (k < path.buf.length && path.buf[k] !== 0x2f && path.buf[k] !== 0x5c) continue;
    const part = path.buf.subarray(start, k);
    start = k + 1;
    if (part.length && !(part.length === 1 && part[0] === 0x2e)) parts.push(part);
  }
  if (!parts.length || parts.some((p) => p.length === 2 && p[0] === 0x2e && p[1] === 0x2e)) throw new OutsideError(path);
  const pieces = [Buffer.from(dest)];
  for (const part of parts.slice(0, -1)) pieces.push(SEP, part);
  const dir = Buffer.concat(pieces);
  return { dir, file: Buffer.concat([dir, SEP, parts.at(-1)]) };
}
class OutsideError extends Error {
  constructor(path) { super(`not a path inside the project: ${path.text}`); }
}

/** Where a path of the repository (a gitPath) is on disk, under `base`: a Buffer path. */
const onDisk = (base, path) => Buffer.concat([Buffer.from(base), SEP,
  Buffer.from(path.buf.toString("latin1").replaceAll("/", sep), "latin1")]);

/** Make the folders dest/rel goes in and create it, a new file -> its descriptor. Throws CollisionError when a file
 * written for this check is already at its name or one of its folders' (its name is another's here). */
function createFile(dest, path) {
  const { dir, file } = target(dest, path);
  try {
    mkdirSync(dir, { recursive: true });
    const real = realpathSync.native(dir), top = realpathSync.native(dest);
    if (real !== top && !real.startsWith(top + sep)) throw new OutsideError(path);
    return openSync(file, "wx");
  } catch (e) {
    if (e && (e.code === "EEXIST" || e.code === "ENOTDIR")) throw new CollisionError();
    throw e;
  }
}
class CollisionError extends Error {}

/** Why a blob or a file could not be copied for the scan, in the Python package's words. */
function notCopied(e) {
  if (e instanceof CollisionError) {
    return "its name is another file's on this system (they differ only in case, in their Unicode form or by a "
      + "backslash), so it could not be copied for the scan";
  }
  if (e instanceof OutsideError) return `it could not be copied for the scan (${e.message})`;
  return `it could not be copied for the scan (${strerror(e)})`;
}

/**
 * Write each { oid, path } blob of the index under dest -> [[path text, why]] for the ones not written. One
 * `git cat-file --batch` reads them all, raw (no filter runs), streamed to disk.
 */
function writeBlobs(root, wanted, dest, env) {
  if (!wanted.length) return Promise.resolve([]);
  const prog = findProgram("git", { env });
  if (prog === null) return Promise.resolve(wanted.map((w) => [w.path.text, "git could not be run (it is not on PATH)"]));
  return new Promise((done) => {
    const failed = [];
    let proc;
    try {
      proc = spawn(prog, ["--no-optional-locks", "-C", root, "cat-file", "--batch"],
        { stdio: ["pipe", "pipe", "ignore"], env, windowsHide: true });
    } catch (e) {
      done(wanted.map((w) => [w.path.text, `git could not be run (${strerror(e)})`]));
      return;
    }
    let k = 0;                  // the blob being read
    let state = "header";       // header -> body -> newline -> header …
    let header = [];            // the header line's bytes so far
    let left = 0;               // the body's bytes still to come
    let fd = null;              // where they go (null: dropped)
    let writing = false;        // the body is the blob's, being written
    let spawnError = null;
    const fail = (why) => failed.push([wanted[k].path.text, why]);
    const closeFd = () => {
      if (fd !== null) { try { closeSync(fd); } catch { /* (closed) */ } fd = null; }
    };
    const onHeader = (line) => {
      const fields = asciiFields(line);
      const size = fields.length === 3 ? Number(fields[2]) : NaN;
      if (fields.length === 3 && fields[1] === "blob" && Number.isSafeInteger(size) && size >= 0) {
        left = size;
        writing = true;
        try {
          fd = createFile(dest, wanted[k].path);
        } catch (e) {
          fail(notCopied(e));
          writing = false;
        }
      } else {
        fail("git could not print it from the index");
        if (!(fields.length === 3 && Number.isSafeInteger(size) && size >= 0)) {
          k++;                  // (missing or ambiguous: nothing follows the line)
          return;
        }
        left = size;            // (another kind of object: its bytes are not the next header)
        writing = false;
      }
      state = "body";
      if (left === 0) { closeFd(); state = "newline"; }
    };
    proc.on("error", (e) => { spawnError = e; });
    proc.stdin.on("error", () => { /* (git stopped reading) */ });
    proc.stdout.on("data", (chunk) => {
      let at = 0;
      while (at < chunk.length && k < wanted.length) {
        if (state === "header") {
          const nl = chunk.indexOf(NEWLINE, at);
          if (nl === -1) { header.push(chunk.subarray(at)); at = chunk.length; break; }
          header.push(chunk.subarray(at, nl));
          at = nl + 1;
          const line = Buffer.concat(header);
          header = [];
          onHeader(line);
        } else if (state === "body") {
          const n = Math.min(left, chunk.length - at);
          if (fd !== null) {
            try {
              for (let off = 0; off < n;) off += writeSync(fd, chunk, at + off, Math.min(n - off, CHUNK));
            } catch (e) {
              fail(notCopied(e));
              closeFd();
            }
          }
          at += n;
          left -= n;
          if (left === 0) { closeFd(); state = "newline"; }
        } else {                // the newline after each blob
          at += 1;
          k++;
          writing = false;
          state = "header";
        }
      }
    });
    proc.on("close", () => {
      if (spawnError && k === 0 && !failed.length) {
        done(wanted.map((w) => [w.path.text, `git could not be run (${strerror(spawnError)})`]));
        return;
      }
      if (k < wanted.length) {
        if (state === "body" && writing && fd !== null) {
          fail("it could not be copied for the scan (git stopped mid-file)");
          k++;
        } else if (state === "body" || state === "newline") {
          k++;                  // (its failure is said already, or it was written whole)
        }
        closeFd();
        for (; k < wanted.length; k++) fail("git could not print it from the index");
      }
      done(failed);
    });
    proc.stdin.end(wanted.map((w) => w.oid + "\n").join(""));
  });
}

/** Copy a file on disk (a Buffer path) to dest/rel -> why not, "" for a link (not followed: nothing to say), or
 * null. */
function copyFile(from, dest, path) {
  let st;
  try { st = lstatSync(from); } catch (e) { return `it could not be read (${strerror(e)})`; }
  if (st.isSymbolicLink()) return "";
  if (!st.isFile()) return "it is not a regular file";
  let src = null, out = null;
  try {
    src = openSync(from, C.O_RDONLY | O_NOFOLLOW | O_NONBLOCK);          // (what was read above, still)
    if (!fstatSync(src).isFile()) return "it is not a regular file";
    out = createFile(dest, path);
    const buf = Buffer.allocUnsafe(CHUNK);
    for (let n; (n = readSync(src, buf, 0, CHUNK, null)) > 0;) {
      for (let off = 0; off < n;) off += writeSync(out, buf, off, n - off);
    }
    return null;
  } catch (e) {
    return notCopied(e);
  } finally {
    for (const d of [src, out]) if (d !== null) try { closeSync(d); } catch { /* (closed) */ }
  }
}

const exists = (path) => { try { lstatSync(path); return true; } catch { return false; } };

/**
 * Put what the commit holds under dest -> { checked: [path text], failed: [[path text, why not]] }. `files`: the
 * paths named (relative to cwd), or [] for the staged files.
 */
async function gather(files, cwd, dest, env) {
  const root = repoRoot(cwd, env);
  if (root === null && !files.length) throw new HookError("not in a git repository: name the files to check");
  let base = root;
  if (root === null) {
    try { base = realpathSync.native(cwd); } catch { base = cwd; }
  }
  let paths, entries;
  if (files.length) {
    paths = [];
    for (const f of files) {
      const given = isAbsolute(f) ? f : cwd.replace(/[\\/]+$/, "") + sep + f;   // (its folder resolved, not a link it is)
      let folder = dirname(given);
      try { folder = realpathSync.native(folder); } catch { /* (missing: said below) */ }
      const full = join(folder, basename(given));
      const rel = relative(base, full);
      if (rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel)) {
        throw new HookError(`${f} is outside ${root !== null ? "the repository" : "this folder"}`);
      }
      let st = null;
      try { st = lstatSync(full); } catch { /* (missing) */ }
      if (st && st.isDirectory()) throw new HookError(`${f} is a folder: name files (lazaret <folder> scans a project)`);
      paths.push(gitPath(Buffer.from(rel.split(sep).join("/"), "utf8")));
    }
    entries = root !== null ? indexEntries(root, env) : new Map();
    const missing = files.find((f, n) => !entries.has(paths[n].key) && !exists(onDisk(base, paths[n])));
    if (missing !== undefined) throw new HookError(`${missing} does not exist`);
  } else {
    paths = stagedPaths(root, env);
    entries = indexEntries(root, env);
  }
  const blobs = [], failed = [], checked = [], seen = new Set();
  for (const path of paths) {
    if (seen.has(path.key)) continue;
    seen.add(path.key);
    const entry = entries.get(path.key);
    if (entry && (entry.mode === "100644" || entry.mode === "100755")) blobs.push({ oid: entry.oid, path });
    else if (entry) continue;                              // a link or a submodule: not followed
    else {
      const why = copyFile(onDisk(base, path), dest, path);
      if (why === "") continue;                            // (a link on disk)
      if (why !== null) failed.push([path.text, why]);
    }
    checked.push(path.text);
  }
  if (root !== null) for (const f of await writeBlobs(root, blobs, dest, env)) failed.push(f);
  return { checked, failed };
}

/** What the gate's conditions read: vulnerabilities of MAJOR and above, supply-chain indicators, cross-file flows. */
export function shown(issue) {
  if (issue.rule.startsWith("SC-")) return issue.sev !== "INFO";
  if (issue.rule.startsWith("X-")) return true;
  return issue.type === "VULN" && SEV_ORDER[issue.sev] <= SEV_ORDER.MAJOR;
}

/** A path as git writes it: "/" between folders, on Windows too (the project scan writes the system's separator). */
export const gitForm = (path) => (sep === "/" ? String(path) : String(path).split(sep).join("/"));

function report(checked, issues, failedConditions, quiet, out) {
  if (!quiet || issues.length) out(`lazaret hook: ${checked.length} file${checked.length !== 1 ? "s" : ""} checked`);
  let cur = null;
  const sorted = [...issues].sort((a, b) => cmpCodePoints(gitForm(a.file), gitForm(b.file))
    || (SEV_ORDER[a.sev] - SEV_ORDER[b.sev]) || (a.line - b.line));
  for (const i of sorted) {
    if (gitForm(i.file) !== cur) {
      cur = gitForm(i.file);
      out(`  ${sanitizeTermLine(cur)}`);
    }
    const prefix = `    L${String(i.line).padEnd(5)} ${i.sev.padEnd(8)} [${i.rule}] `;
    out(prefix + sanitizeTermLine(i.msg));
    const ex = issueExcerpt(i);
    if (ex && !quiet) out(" ".repeat(prefix.length) + "» " + ex);
  }
  if (failedConditions.length) {
    out("  Commit gate:  FAILED ");
    for (const label of failedConditions) out(`    ✗ ${sanitizeTermLine(label)}`);
  } else if (!quiet) {
    out("  Commit gate:  PASSED ");
  }
}

/**
 * Check `files` (or the staged files) -> a promise of the exit code (hook.run). `maxFileBytes`: the largest source
 * file or manifest read (env LAZARET_MAX_SOURCE_BYTES, as the CLI reads it).
 */
export async function check(files, { cwd = process.cwd(), quiet = false, out = console.log, env = process.env,
  maxFileBytes = MAX_FILE_BYTES } = {}) {
  const tmp = mkdtempSync(join(tmpdir(), "lazaret-hook-"));
  let checked, res;
  try {
    const dest = join(tmp, "commit");
    mkdirSync(dest);
    let failed;
    ({ checked, failed } = await gather(files, cwd, dest, env));
    const notRead = failed.map(([path, why]) => truncatedIssue(path, why));
    if (!checked.length) {
      if (!quiet) out("lazaret hook: nothing to check");
      return 0;
    }
    try {
      res = scanCollected(dest, collectProject(dest, { deps: true, maxFileBytes }), { env, extraIssues: notRead }).res;
    } catch (e) {
      if (!(e instanceof ScanTargetError)) throw e;
      res = buildResult(dest, [], notRead);                  // (nothing Lazaret reads: no finding but these)
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  const issues = res.issues.filter(shown);
  const failedConditions = res.conditions.filter((c) => GATE.includes(c.label) && !c.ok).map((c) => c.label);
  report(checked, issues, failedConditions, quiet, out);
  return failedConditions.length ? 1 : 0;
}

// ---- the command line (hook.main) -------------------------------------------------
const FLAGS = [
  { flag: "--staged", dest: "staged" },
  { flag: "--quiet", short: "-q", dest: "quiet" },
  { flag: "--version", dest: "version" },
  { flag: "--help", short: "-h", dest: "help" },
];

/** argv after `hook` -> { opts, files }; throws HookUsage for what argparse refuses (abbreviations allowed, `--`
 * ends the options). */
export function parseHookArgs(argv) {
  const opts = {}, files = [];
  let onlyFiles = false;
  for (const raw of argv) {
    const a = String(raw);
    if (onlyFiles || a === "-" || !a.startsWith("-")) { files.push(a); continue; }
    if (a === "--") { onlyFiles = true; continue; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = eq === -1 ? a : a.slice(0, eq);
      const hits = FLAGS.filter((o) => o.flag.startsWith(name));
      const o = hits.find((h) => h.flag === name) ?? (hits.length === 1 ? hits[0] : null);
      if (!o) {
        throw new HookUsage(hits.length > 1 ? `ambiguous option: ${name} could match ${hits.map((h) => h.flag).join(", ")}`
          : `unrecognized arguments: ${a}`);
      }
      if (eq !== -1) throw new HookUsage(`argument ${o.flag}: ignored explicit argument '${a.slice(eq + 1)}'`);
      opts[o.dest] = true;
      continue;
    }
    for (const ch of a.slice(1)) {
      const o = FLAGS.find((x) => x.short === `-${ch}`);
      if (!o) throw new HookUsage(`unrecognized arguments: ${a}`);
      opts[o.dest] = true;
    }
  }
  return { opts, files };
}
class HookUsage extends Error {}

/**
 * `lazaret hook …` (cli.js) -> the exit code, or a promise of it. `io` as run()'s; `maxFileBytes` as check()'s.
 */
export function runHook(argv, io = {}, { maxFileBytes = MAX_FILE_BYTES } = {}) {
  const out = io.out ?? ((s) => console.log(s));
  const err = io.err ?? ((s) => console.error(s));
  const env = io.env ?? process.env;
  let parsed;
  try {
    parsed = parseHookArgs(argv);
  } catch (e) {
    if (!(e instanceof HookUsage)) throw e;
    err(`error: ${sanitizeTermLine(e.message)}`);
    err("Run 'lazaret hook --help' for usage.");
    return 2;
  }
  const { opts, files } = parsed;
  if (opts.help) { out(USAGE); return 0; }
  if (opts.version) { out(`lazaret v${pkg.version}`); return 0; }
  if (opts.staged && files.length) {
    err("error: --staged checks the staged files: name no FILE with it");
    err("Run 'lazaret hook --help' for usage.");
    return 2;
  }
  const missing = loadError();
  if (missing) {
    err(`error: ${sanitizeTermLine(missing)}`);
    return 2;
  }
  setRedactSecrets(true);
  return check(files, { cwd: io.cwd ?? process.cwd(), quiet: !!opts.quiet, out, env, maxFileBytes }).catch((e) => {
    if (!(e instanceof HookError)) throw e;
    err(`error: ${sanitizeTermLine(e.message)}`);
    return 2;
  });
}
