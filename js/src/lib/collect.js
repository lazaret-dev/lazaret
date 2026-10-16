// Which files a scan reads, and how: the collection's decisions for one file, given its bytes (core._collect's
// part for a file). The directory walk (fs.js collectFiles) hands each regular file it meets to collectEntry, and so
// does the browser dashboard for each upload (BR-7 step 5), so this module uses nothing of Node's.

import { decodeSource, decodeMember, normalizeNewlines } from "./encoding.js";
import { classifyBinary, HEADER_SAMPLE, pyExt, looksBinary, mpegTs, MPEG_TS_EXTS, disguisedBinary, DISGUISE_SAMPLE }
  from "./binary.js";
import { EXHAUSTED, NativeError, NativeExhausted, shebangLang } from "./native.js";
import { truncatedIssue, scanErrorIssue } from "./issue.js";
import { pthIssues } from "./pth.js";
import { isConfigFile, ownReport, CONFIG_SCAN_CAP } from "./configsecrets.js";

/** The path separator of a file's rel ("\\" on Windows, as os.sep; "/" in a browser). */
const PATH_SEP = typeof process !== "undefined" && process.platform === "win32" ? "\\" : "/";

export const EXTS = {
  ".py": "py", ".pyw": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
  ".mts": "js", ".cts": "js", ".mjs": "js", ".cjs": "js", ".sql": "sql",
  ".go": "go", ".rs": "rs",
};
// The languages a dependency tree's files (--deps) are read in (twin of
// core.DEP_LANGS): a project's own Go and Rust files are read; a package's
// are, in a Go or cargo vendor tree (VENDOR_CODE, 0.1.9: deps.js vendoredCode).
export const DEP_LANGS = new Set(["py", "js", "sql"]);
// A vendor tree's code (twin of core.VENDOR_CODE): Go's (vendor/modules.txt) and cargo's (a .cargo-checksum.json in
// each crate's directory).
export const VENDOR_CODE = { go: ".go", cargo: ".rs" };

/** Is `rel` ("/"-separated, below a Go module's root for "go", a crate's for "crate") a file no build of a dependent
 * compiles (twin of core.never_built): a Go *_test.go file, a name with "_" or "." first, one under testdata/ or
 * vendor/; a crate's tests/, benches/ and examples/. */
export function neverBuilt(kind, rel) {
  if (kind === "go") {
    const parts = rel.split("/");
    const name = parts[parts.length - 1];
    return name.startsWith("_") || name.startsWith(".") || name.toLowerCase().endsWith("_test.go")
      || parts.slice(0, -1).some((p) => p === "testdata" || p === "vendor");
  }
  if (kind === "crate") return ["tests", "benches", "examples"].includes(rel.split("/")[0]);
  return false;
}

/** "go" or "rs" for a file of a Go or cargo vendor tree (`vendor`: [its kind, its rel]) that a build compiles, else
 * null. Twin of core._vendor_lang. */
function vendorLang(vendor, rel, ext) {
  if (!vendor || ext !== VENDOR_CODE[vendor[0]]) return null;
  const below = rel.slice(vendor[1].length + 1).split(PATH_SEP).join("/");
  if (vendor[0] === "go") return neverBuilt("go", below) ? null : "go";
  const slash = below.indexOf("/");
  const inside = slash < 0 ? "" : below.slice(slash + 1);
  return !inside || neverBuilt("crate", inside) ? null : "rs";
}
// gyp files, whatever their name (twin of core.GYP_EXTS): binding.gyp pulls
// others in ('includes': ['build/common.gypi']) and node-gyp runs their
// actions and command expansions too, so every one goes to scanGyp.
export const GYP_EXTS = new Set([".gyp", ".gypi"]);

// Name-based markers (is_dependency_manifest): a manifest under one of these
// belongs to an installed package.
export const DEP_MARKERS = new Set([
  "node_modules", "site-packages", "bower_components", "vendor", "venv", ".venv",
]);

// Source files and manifests above this are not read: SC-TRUNCATED (twin of
// core.SOURCE_SIZE_CAP). The CLI takes --max-source-bytes or
// LAZARET_MAX_SOURCE_BYTES; collectFiles() takes `maxFileBytes`.
export const MAX_FILE_BYTES = 16_000_000;

const APPLE_DOUBLE_MAGIC = [[0x00, 0x05, 0x16, 0x07], [0x00, 0x05, 0x16, 0x00]];

/** Q-SKIPPED-CONFIG: a config or data file too large to check for credentials (core.config_skipped_issue). */
export function configSkippedIssue(path, detail) {
  return {
    rule: "Q-SKIPPED-CONFIG", name: "Config file not checked (too large)", type: "SMELL", sev: "INFO",
    msg: `${path} was not checked for credentials: ${detail}.`,
    why: "Config and data files are read only to look for credentials, and one this large is data rather than configuration: a credential in it would not be reported.",
    fix: "Keep credentials out of large data files, and real configuration in files of its own.",
    ref: "Scan coverage", file: path, line: 1, snippet: [], snipStart: 1,
  };
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

/**
 * Collect one regular file (core._collect's part for a file): the walk's (fs.js collectFiles) and the dashboard's,
 * which hands over its uploads. `entry`: {rel, name, size, dep, read(limit): its first `limit` bytes (throws when it
 * can't be read), head(limit): the same, or no bytes when it can't be read}; dep: false, true, or a Go or cargo
 * vendor tree's [kind, rel]. Adds the file to `col`'s files, manifests, configs or pth, and its findings to
 * col.binaryIssues; col.maxFileBytes is the size cap.
 */
export function collectEntry(entry, col) {
  const { rel, name, size, dep } = entry;
  const ext = pyExt(name).toLowerCase();       // os.path.splitext, as core
  const kind = name === "package.json" || name === "binding.gyp" ? name : GYP_EXTS.has(ext) ? "gyp" : null;
  const pth = !kind && ext === ".pth";
  const vendor = Array.isArray(dep) ? dep : null;      // (a vendor tree's kind, its rel)
  let lang = kind || pth ? null : EXTS[ext] ?? null;
  if (dep && lang !== null && !DEP_LANGS.has(lang)) lang = vendorLang(vendor, rel, ext);
  if (!kind && !pth && !lang) {
    // spec 9: every other regular file is classified by magic bytes — unless
    // its #! line makes it a Node or Python script: then it is source
    const head = entry.read(HEADER_SAMPLE);
    lang = scriptSourceLang(head);
    if (!lang) {
      const bi = classifyBinary(rel, head, size, "repo");
      if (bi) col.binaryIssues.push(bi);
      else if (!dep && isConfigFile(name) && (utf16Bom(head) || !looksBinary(head))) collectConfig(entry, col);
      return;
    }
  }
  if (lang && MPEG_TS_EXTS.has(ext)) {
    const head = entry.read(HEADER_SAMPLE);
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
      const head = entry.head(DISGUISE_SAMPLE);        // (not read: the SC-TRUNCATED stands alone, as before)
      const dis = disguisedBinary(rel, head);
      if (dis) col.binaryIssues.push(dis);
    }
    return;
  }
  const data = entry.read(cap + 1);
  if (data.length > cap) {                            // grew between the lstat and the read
    col.binaryIssues.push(truncatedIssue(rel, `read exceeded the ${withCommas(cap)}-byte file limit`));
    const dis = lang ? disguisedBinary(rel, data) : null;
    if (dis) col.binaryIssues.push(dis);
    return;
  }
  if (kind) {
    const content = normalizeNewlines(new TextDecoder("utf-8", { ignoreBOM: true }).decode(data));
    col.manifests.push({ kind, path: rel, content, dep: Boolean(dep) });
    return;
  }
  if (pth) {                // only the .pth check runs on it (decoded as the registry does: utf-8-sig)
    col.pth.push(rel);
    let found;
    try {
      found = pthIssues(rel, new TextDecoder("utf-8").decode(data));
    } catch (e) {
      if (!(e instanceof NativeError)) throw e;
      found = [e instanceof NativeExhausted ? truncatedIssue(rel, EXHAUSTED) : scanErrorIssue(rel, e)];
    }
    for (const i of found) col.binaryIssues.push(i);
    return;
  }
  if (APPLE_DOUBLE_MAGIC.some((m) => m.every((b, k) => data[k] === b))) {
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
  const file = { path: rel, content, lang, dep: Boolean(dep) };
  if (vendor && (lang === "go" || lang === "rs")) file.vendor = vendor[1];    // (its module or crate is read whole)
  col.files.push(file);
}

/**
 * Read a config or data file for scanConfigFile (core._collect_config):
 * decoded like source but without the encoding notes, since it is not code;
 * over CONFIG_SCAN_CAP a Q-SKIPPED-CONFIG note instead.
 */
const utf16Bom = (b) => b.length >= 2 && ((b[0] === 0xff && b[1] === 0xfe) || (b[0] === 0xfe && b[1] === 0xff));
function collectConfig(entry, col) {
  const { rel, size } = entry;
  const cap = CONFIG_SCAN_CAP;
  if (size > cap) {
    col.binaryIssues.push(configSkippedIssue(rel, `${withCommas(size)} bytes is over the ${withCommas(cap)}-byte limit for config files`));
    return;
  }
  const data = entry.read(cap + 1);
  if (data.length > cap) {                            // grew between the lstat and the read
    col.binaryIssues.push(configSkippedIssue(rel, `it grew past the ${withCommas(cap)}-byte limit for config files while it was read`));
    return;
  }
  const content = decodeSource(data).text;
  if (!ownReport(content)) col.configs.push({ path: rel, content });   // a report of Lazaret's own is not config
}
