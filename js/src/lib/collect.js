// Which files a scan reads, and how: the engine's (collect.rs, BR-7 step 4 e), as core's walk asks it. The walk of a
// folder (walkSteps: what each entry is to the scan, in the walk's order) and each step's taking (takeStep: a regular
// file handed to collectEntry, a pruned tree counted, a __pycache__ checked) are the CLI's (fs.js collectFiles, on the
// disk) and the browser dashboard's (a folder upload, BR-7 step 5); the engine says what it needs read of a file and,
// once it has it, what the file is to the scan. This module uses nothing of Node's.

import { call, bytesText, issuesOf } from "./native.js";
import { scanErrorIssue, truncatedIssue } from "./issue.js";
import { REDACT } from "./redact.js";
import { CONFIG_SCAN_CAP } from "./configsecrets.js";

/** The path separator of a file's rel ("\\" on Windows, as os.sep; "/" in a browser). */
const PATH_SEP = typeof process !== "undefined" && process.platform === "win32" ? "\\" : "/";
export const WINDOWS = PATH_SEP === "\\";

// Source files and manifests above this are not read: SC-TRUNCATED (core.SOURCE_SIZE_CAP). The CLI takes
// --max-source-bytes or LAZARET_MAX_SOURCE_BYTES; collectFiles() takes `maxFileBytes`.
export const MAX_FILE_BYTES = 16_000_000;

// The deepest folder the walk enters, in folders below the root: one nested deeper (a folder to walk, a __pycache__)
// is not read, SC-TRUNCATED, and the result incomplete. Twin of core.MAX_WALK_DEPTH, whose comment says why 512.
export const MAX_WALK_DEPTH = 512;
export const TOO_DEEP_WHY = `it is nested deeper than ${MAX_WALK_DEPTH} folders, so it was not read`;

/** Why a scan is incomplete when `n` folders were nested too deep to be read (core.tree_incomplete's words). */
export const tooDeepReason = (n) =>
  `${n} folder${n !== 1 ? "s" : ""} nested deeper than ${MAX_WALK_DEPTH} folders ${n !== 1 ? "were" : "was"} not read`;

// A folder or a file this package cannot reach because its path is longer than the system allows (ENAMETOOLONG:
// Linux's PATH_MAX is 4,096 bytes, macOS's 1,024; the walk and the --deps readers here go by path, where core's go
// beneath a folder's descriptor and have no such limit) is not read: SC-TRUNCATED, and the result incomplete, never a
// Q-UNREADABLE note in a complete result (LZ-03's re-check). Below the depth cap a tree with long names can be read
// whole by the Python CLI and not by this one: this one then says so.
export const TOO_LONG_WHY = "its path is longer than this system allows, so it was not read";
/** Is `e` the system's refusal of a path that is too long? */
export const pathTooLong = (e) => Boolean(e && e.code === "ENAMETOOLONG");
/** Why a scan is incomplete when `n` folders or files had paths too long to read. */
export const tooLongReason = (n) => `${n} folder${n !== 1 ? "s or files" : " or file"} ${n !== 1 ? "were" : "was"} not `
  + `read: ${n !== 1 ? "their paths are" : "its path is"} longer than this system allows`;

/** The engine's [[path, issue]] as this package's issues. */
export const pathIssues = (pairs) => pairs.map(([path, row]) => issuesOf(path, [row])[0]);

/**
 * Collect one regular file (core._collect_file's): the walk's (fs.js collectFiles) and the dashboard's, which hands
 * over its uploads. `entry`: {rel, name, size, dep, read(limit): its first `limit` bytes (throws when it can't be
 * read; `ioError(e)` says whether an error is one), head(limit): the same, or no bytes when it can't be read,
 * range(offset, length): optional, those bytes (fewer at its end; throws as read does)}; dep: false, true, or a Go or
 * cargo vendor tree's [kind, rel]. Adds the file to `col`'s files, manifests, configs or pth, and its findings to
 * col.binaryIssues; col.maxFileBytes is the size cap. An entry that reads by range has a zip model file (a
 * checkpoint, an .npz) of any size read for its pickles, by the ranges the engine asks for (FP-MODEL-FILES).
 */
export function collectEntry(entry, col, { ioError = () => false, strerror = (e) => String(e && e.message) } = {}) {
  const args = { rel: entry.rel, name: entry.name, size: entry.size, dep: entry.dep, cap: col.maxFileBytes,
    configCap: CONFIG_SCAN_CAP, windows: WINDOWS, neumaier: false, redact: REDACT.on,
    ranges: typeof entry.range === "function" };
  const answers = {};
  const pieces = [];
  let text = "";
  for (;;) {
    const got = call("collect_file", { ...args, answers }, text);
    if (!got.need) { addCollected(got, col, entry.rel, entry.dep); return; }
    const { read: what, limit } = got.need;
    if (what === "pth" || what === "media") {   // (a file too large to read whole, in chunks: a .pth file's lines
      try {                                       // pth_stream, another's structure media_stream)
        answers[what] = what === "pth" ? streamPth((off, len) => entry.range(off, len))
          : streamMedia((off, len) => entry.range(off, len), entry.size);
      } catch (e) {
        if (!ioError(e)) throw e;
        answers[what] = { error: strerror(e) };
      }
      continue;
    }
    if (what === "ranges") {               // (every range read so far, their bytes as the text: core's)
      try {
        for (const [off, len] of got.need.ranges) pieces.push([off, entry.range(off, len)]);
      } catch (e) {
        if (!ioError(e)) throw e;
        answers[what] = { error: strerror(e) };
        continue;
      }
      answers[what] = pieces.map(([off, b]) => [off, b.length]);
      answers.rounds = (answers.rounds ?? 0) + 1;
      text = bytesText(concatBytes(pieces.map(([, b]) => b)));
      continue;
    }
    if (what === "sample") { answers[what] = bytesText(entry.head(limit)); continue; }   // (none when unread)
    let data;
    try {
      data = bytesText(entry.read(limit));
    } catch (e) {
      if (!ioError(e)) throw e;
      answers[what] = { error: strerror(e) };
      continue;
    }
    if (what === "data") { answers[what] = true; text = data; } else answers[what] = data;   // (a whole file: the text)
  }
}

/** A .pth file too large to read whole is read this many bytes at a time (core.PTH_CHUNK). */
const PTH_CHUNK = 1 << 20;

/**
 * FP-MODEL-FILES (John's decision of Oct 21): the lines site.py runs of a .pth file too large to read whole, read to
 * its end through `range(offset, length)` PTH_CHUNK at a time -> {lines, cuts} (the engine's pth_stream; core's
 * pth_stream_file).
 */
export function streamPth(range) {
  let state = null, off = 0;
  const lines = [], cuts = [];
  for (;;) {
    const chunk = range(off, PTH_CHUNK);
    const got = call("pth_stream", { state, end: chunk.length === 0 }, bytesText(chunk));
    state = got.state;
    for (const l of got.lines) lines.push(l);
    for (const c of got.cuts) cuts.push(c);
    if (chunk.length === 0) return { lines, cuts };
    off += chunk.length;
  }
}

/** A file walked as its stream passes is read this many bytes at a time (core.MEDIA_CHUNK). */
const MEDIA_CHUNK = 1 << 20;

/**
 * FP-OPAQUE-MEDIA: a file too large to read whole walked by its structure, read through `range(offset, length)`
 * MEDIA_CHUNK at a time, passing over what the walk skips but never past its `size` (a part that runs past it is a
 * file cut short) -> the walk's end: {is}, {not, why} or {unknown} (the engine's media_stream; core's
 * media_stream_file).
 */
export function streamMedia(range, size) {
  let state = null, off = 0;
  for (;;) {
    const chunk = range(off, MEDIA_CHUNK);
    const got = call("media_stream", { state, offset: off, eof: chunk.length === 0 }, bytesText(chunk));
    if (got.end !== null) return got.end;
    state = got.state;
    const end = off + chunk.length, next = got.next;
    // (the file ends before where the walk goes on, its size given or its byte there read: it is cut short there)
    if (next > end && (size !== undefined ? next > size : range(next - 1, 1).length === 0)) {
      return call("media_stream", { state, offset: end, eof: true }, "").end;
    }
    off = Math.max(end, next);
  }
}

/** Byte arrays one after another. */
function concatBytes(parts) {
  const out = new Uint8Array(parts.reduce((n, b) => n + b.length, 0));
  let at = 0;
  for (const b of parts) { out.set(b, at); at += b.length; }
  return out;
}

/** What collect_file said a file is, added to `col`. */
function addCollected(got, col, rel, dep) {
  for (const i of pathIssues(got.issues)) col.binaryIssues.push(i);
  if (got.file) {
    const f = { path: got.file.path, content: got.file.content, lang: got.file.lang, dep: got.file.dep };
    if (got.file.vendor !== undefined) f.vendor = got.file.vendor;      // (its module or crate is read whole)
    if (got.file.goContent !== undefined) f.goContent = got.file.goContent;   // (F-06: the Go reader's text)
    col.files.push(f);
  }
  if (got.manifest) col.manifests.push(got.manifest);
  if (got.config) col.configs.push(got.config);
  if (got.pth) col.pth.push(rel);
  // (FP-MODEL-FILES) a model file read, the globals of no known kind it imports and the calls with text it holds:
  // modelOwnIssues'
  if (got.model) (col.models ??= []).push([rel, !!dep, got.model.imports, got.model.calls ?? []]);
}

/**
 * FP-MODEL-FILES, once the scan knows its files: SC-PICKLE-GLOBAL as INFO (listed, setting no verdict) for each global
 * of the scanned project's own modules, or a dependency's, that a model file imports (importing one runs that
 * module's code, which the scan reads, when the file is loaded), and SC-PICKLE-GLOBAL, MAJOR, for each call with text a
 * model file holds: `models` [[path, dep, imports, calls]] (addCollected's), `files` the collection's files. The
 * engine's (pickle::own_imports); core's model_own_issues.
 */
export function modelOwnIssues(models, files) {
  if (!models || !models.length) return [];
  return pathIssues(call("model_own", { models, files: files.map((f) => [f.path, !!f.dep]) }));
}

/** A coverage note the walk's I/O finds (collect_issue): "unreadable" (reason), "symlink" (target), "skipped_tree"
 * (files, bytes). */
export function collectIssue(kind, path, args = {}) {
  return issuesOf(path, [call("collect_issue", { ...args, kind, path })])[0];
}
export const symlinkIssue = (path, target) => collectIssue("symlink", path, { target: String(target) });
export const unreadableIssue = (path, reason) => collectIssue("unreadable", path, { reason: String(reason) });
export const skippedTreeIssue = (rel, nFiles, nBytes) => collectIssue("skipped_tree", rel, { files: nFiles, bytes: nBytes });

/**
 * A project scan's walk of the folder `root` (core._collect's; what each entry is to the scan: the engine's,
 * collect_dir), on the folders `tree` lists: each step, in the walk's order (each folder's entries by code point,
 * depth first). `tree`:
 *   list(node) -> the folder's entries, [{name, node, kind: "file" (size) | "dir" (key: its identity, or null) |
 *     "link" (target) | "special" (code: fifo, socket, char, block, other) | "error" (why)}]; throws when the folder
 *     cannot be listed;
 *   key(node) -> the root folder's identity (or null), asked once it is listed;
 *   names(node) -> [[name, is a folder]] of a folder's entries (no link followed), or null when it can't be listed;
 *   cargo(node, dirs) -> the names among `dirs` (folders in `node`) that hold a regular .cargo-checksum.json;
 *   strerror(e) -> why a folder could not be listed.
 * Steps: {issue}, {file: {node, rel, name, size, dep}}, {skip: {node, rel, depth}}, {pycache: {node, rel, names}},
 * {walk: {node, rel, dep}} (a folder the walk follows, with the dependency or vendor tree it is in: false, true or
 * [kind, rel]), {tooDeep: {node, rel}} (a folder to walk or a __pycache__ nested deeper than MAX_WALK_DEPTH below the
 * root: not entered), {tooLong: {node, rel}} (a folder or an entry whose path the system refused as too long:
 * pathTooLong; an entry of `list` says so with `tooLong: true`) and {rootError} (the root could not be listed: nothing
 * follows). `depth`: the folder's, in folders below the root.
 */
export function* walkSteps(tree, root, { includeDeps = false, exclude = [] } = {}) {
  const excluded = [...new Set(exclude)].sort();
  const seen = new Set();
  const stack = [{ node: root, rel: "", dep: false, depth: 0 }];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = tree.list(dir.node);
      if (!dir.rel) { const key = tree.key(dir.node); if (key !== null) seen.add(key); }
    } catch (e) {
      if (!dir.rel) { yield { rootError: e }; return; }
      yield pathTooLong(e) ? { tooLong: { node: dir.node, rel: dir.rel } }
        : { issue: unreadableIssue(dir.rel, tree.strerror(e)) };
      continue;
    }
    const listed = entries.map((e) => (e.kind === "dir" ? [e.name, "dir", e.key, e.key !== null && seen.has(e.key)]
      : [e.name, e.kind, e.kind === "file" ? e.size : e.kind === "link" ? e.target : e.kind === "special" ? e.code : e.why]));
    const answers = { lists: [], cargo: [] };
    let got;
    for (;;) {
      got = call("collect_dir", { dir: dir.rel, dep: dir.dep, entries: listed, excludes: excluded, includeDeps,
        windows: WINDOWS, answers });
      if (!got.need) break;
      // (the probes reach no folder deeper than MAX_WALK_DEPTH either, as core._Root's: an entry of the folder is one
      // deeper than it, the crates in a vendor entry two)
      const below = dir.depth + 1;
      for (const k of got.need.lists) answers.lists.push([k, below > MAX_WALK_DEPTH ? null : tree.names(entries[k].node)]);
      for (const [k, dirs] of got.need.cargo) {
        answers.cargo.push([k, below + 1 > MAX_WALK_DEPTH ? [] : tree.cargo(entries[k].node, dirs)]);
      }
    }
    for (const key of got.seen) seen.add(key);
    const names = entries.map((e) => e.name);
    const push = [];
    for (const [k, action, extra] of got.do) {
      const { node, name } = entries[k];
      const rel = dir.rel ? `${dir.rel}${PATH_SEP}${name}` : name;
      const depth = dir.depth + 1;
      if (action === "issue") yield entries[k].tooLong ? { tooLong: { node, rel } } : { issue: pathIssues([extra])[0] };
      else if (action === "file") yield { file: { node, rel, name, size: entries[k].size, dep: dir.dep } };
      else if (action === "skip") yield { skip: { node, rel, depth } };
      else if (depth > MAX_WALK_DEPTH) yield { tooDeep: { node, rel } };       // (a walk or a __pycache__)
      else if (action === "pycache") yield { pycache: { node, rel, names } };
      else {
        const walk = { node, rel, depth, dep: dir.dep || (Array.isArray(extra[1]) ? [extra[1][0], rel] : extra[1]) };
        push.push(walk);
        yield { walk };                 // (a folder followed: nothing to take)
      }
    }
    for (let k = push.length - 1; k >= 0; k--) stack.push(push[k]);   // pop order = the engine's, depth-first
  }
}

/**
 * Take a step of walkSteps into `col` (collectFiles' collection): a finding, a file collected (collectEntry), a
 * pruned tree counted (Q-SKIPPED-TREE), a __pycache__ checked, a folder too deep to enter (SC-TRUNCATED, and its rel
 * in col.tooDeep: the result is incomplete) or one whose path is too long to read (SC-TRUNCATED, its rel in
 * col.tooLong: the result is incomplete). `tree` as walkSteps', and:
 *   entry(node, rel, name, size, dep) -> collectEntry's entry for a file;
 *   stats(node, depth) -> [files, bytes] of a pruned tree `depth` folders below the root (no folder deeper than
 *     MAX_WALK_DEPTH listed);
 *   list(node, {pycache: true}) -> a __pycache__'s entries (any reparse point a link); head(node, n) -> a file's first
 *     n bytes (throws when it can't be read).
 * `ioError(e)`: whether an error is the I/O's (the file is Q-UNREADABLE; anything else: its scan failed).
 */
export function takeStep(step, col, tree, { ioError = () => false, strerror = (e) => String(e && e.message) } = {}) {
  if (step.issue) col.binaryIssues.push(step.issue);
  else if (step.file) {
    const { node, rel, name, size, dep } = step.file;
    try {
      collectEntry(tree.entry(node, rel, name, size, dep), col, { ioError, strerror });
    } catch (e) {
      col.binaryIssues.push(ioError(e) ? unreadableIssue(rel, strerror(e)) : scanErrorIssue(rel, e));
    }
  } else if (step.skip) {
    const [nFiles, nBytes] = tree.stats(step.skip.node, step.skip.depth);
    col.skippedIssues.push(skippedTreeIssue(step.skip.rel, nFiles, nBytes));
  } else if (step.tooDeep) {
    col.binaryIssues.push(truncatedIssue(step.tooDeep.rel, TOO_DEEP_WHY));
    (col.tooDeep ??= []).push(step.tooDeep.rel);
  } else if (step.tooLong) {
    tooLongIssue(col, step.tooLong.rel);
  } else if (step.pycache) {
    try { checkPycache(tree, step.pycache, col, strerror); } catch (e) {
      col.binaryIssues.push(scanErrorIssue(step.pycache.rel, e));
    }
  }
}

/** A folder or a file whose path is too long to read: SC-TRUNCATED, and its rel in col.tooLong (incomplete). */
function tooLongIssue(col, rel) {
  col.binaryIssues.push(truncatedIssue(rel, TOO_LONG_WHY));
  (col.tooLong ??= []).push(rel);
}

/** __pycache__ is not source-scanned; every .pyc directly inside is checked (the engine's: collect_pycache). One, or
 * the folder, whose path is too long to read is SC-TRUNCATED (col.tooLong). */
function checkPycache(tree, { node, rel, names }, col, strerror) {
  const issues = col.binaryIssues;
  let entries;
  try { entries = tree.list(node, { pycache: true }); } catch (e) {
    if (pathTooLong(e)) tooLongIssue(col, rel);
    else issues.push(unreadableIssue(rel, strerror(e)));
    return;
  }
  for (const e of entries) if (e.tooLong) tooLongIssue(col, `${rel}${PATH_SEP}${e.name}`);
  entries = entries.filter((e) => !e.tooLong);
  const listed = entries.map((e) => [e.name, e.kind, e.kind === "file" ? e.size : e.kind === "link" ? e.target
    : e.kind === "special" ? e.code : e.why]);
  const files = new Map(entries.filter((e) => e.kind === "file").map((e) => [e.name, e.node]));
  const headers = {};
  for (;;) {
    const got = call("collect_pycache", { dir: rel, entries: listed, parent: [...names].sort(), windows: WINDOWS,
      answers: { headers } });
    if (!got.need) { for (const i of pathIssues(got.issues)) issues.push(i); return; }
    for (const name of got.need) {
      try { headers[name] = bytesText(tree.head(files.get(name), 16)); } catch (e) { headers[name] = { error: strerror(e) }; }
    }
  }
}
