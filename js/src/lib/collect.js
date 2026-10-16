// Which files a scan reads, and how: the engine's (collect.rs, BR-7 step 4 e), as core's walk asks it. The
// directory walk (fs.js collectFiles) hands each regular file it meets to collectEntry, and so does the browser
// dashboard for each upload (BR-7 step 5); the engine says what it needs read of the file and, once it has it, what
// the file is to the scan. This module uses nothing of Node's.

import { call, bytesText, issuesOf } from "./native.js";
import { REDACT } from "./redact.js";
import { CONFIG_SCAN_CAP } from "./configsecrets.js";

/** The path separator of a file's rel ("\\" on Windows, as os.sep; "/" in a browser). */
const PATH_SEP = typeof process !== "undefined" && process.platform === "win32" ? "\\" : "/";
export const WINDOWS = PATH_SEP === "\\";

// Source files and manifests above this are not read: SC-TRUNCATED (core.SOURCE_SIZE_CAP). The CLI takes
// --max-source-bytes or LAZARET_MAX_SOURCE_BYTES; collectFiles() takes `maxFileBytes`.
export const MAX_FILE_BYTES = 16_000_000;

/** The engine's [[path, issue]] as this package's issues. */
export const pathIssues = (pairs) => pairs.map(([path, row]) => issuesOf(path, [row])[0]);

/**
 * Collect one regular file (core._collect_file's): the walk's (fs.js collectFiles) and the dashboard's, which hands
 * over its uploads. `entry`: {rel, name, size, dep, read(limit): its first `limit` bytes (throws when it can't be
 * read; `ioError(e)` says whether an error is one), head(limit): the same, or no bytes when it can't be read}; dep:
 * false, true, or a Go or cargo vendor tree's [kind, rel]. Adds the file to `col`'s files, manifests, configs or pth,
 * and its findings to col.binaryIssues; col.maxFileBytes is the size cap.
 */
export function collectEntry(entry, col, { ioError = () => false, strerror = (e) => String(e && e.message) } = {}) {
  const args = { rel: entry.rel, name: entry.name, size: entry.size, dep: entry.dep, cap: col.maxFileBytes,
    configCap: CONFIG_SCAN_CAP, windows: WINDOWS, neumaier: false, redact: REDACT.on };
  const answers = {};
  let text = "";
  for (;;) {
    const got = call("collect_file", { ...args, answers }, text);
    if (!got.need) { addCollected(got, col, entry.rel); return; }
    const { read: what, limit } = got.need;
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

/** What collect_file said a file is, added to `col`. */
function addCollected(got, col, rel) {
  for (const i of pathIssues(got.issues)) col.binaryIssues.push(i);
  if (got.file) {
    const f = { path: got.file.path, content: got.file.content, lang: got.file.lang, dep: got.file.dep };
    if (got.file.vendor !== undefined) f.vendor = got.file.vendor;      // (its module or crate is read whole)
    col.files.push(f);
  }
  if (got.manifest) col.manifests.push(got.manifest);
  if (got.config) col.configs.push(got.config);
  if (got.pth) col.pth.push(rel);
}

/** A coverage note the walk's I/O finds (collect_issue): "unreadable" (reason), "symlink" (target), "skipped_tree"
 * (files, bytes). */
export function collectIssue(kind, path, args = {}) {
  return issuesOf(path, [call("collect_issue", { ...args, kind, path })])[0];
}
