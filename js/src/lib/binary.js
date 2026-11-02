// Binary / compiled-artifact detection and the __pycache__ bytecode checks: core.classify_binary,
// disguised_binary, looks_binary and pyc_issues, the engine's for both packages (BR-7 step 3 d, 0.1.9: binary.rs),
// used for every non-source regular file in a directory scan (shared semantics spec 9) and for bytecode (spec 8).
// A file's bytes go to the engine as latin-1 text, a character per byte. Zero-dependency leaf.

import { call, issuesOf, bytesText } from "./native.js";

/** Do paths use "\\" as a separator too (Windows, as os.path does there)? Not in a browser. */
const WINDOWS = typeof process !== "undefined" && process.platform === "win32";

/**
 * os.path.splitext(path)[1]: from the base name's last dot, but not when every
 * dot before it is leading (".bashrc", "..js", "...py" have no extension;
 * Node's extname says ".js" for "..js"). Separators as os.path uses them here:
 * "/", and on Windows "\\" too.
 */
export function pyExt(path) {
  const p = String(path);
  let s = p.lastIndexOf("/");
  if (WINDOWS) s = Math.max(s, p.lastIndexOf("\\"));
  const dot = p.lastIndexOf(".");
  if (dot <= s) return "";
  for (let i = s + 1; i < dot; i++) if (p[i] !== ".") return p.slice(dot);
  return "";
}

/** MPEG transport stream video: the extensions it shares with TypeScript, and .m2ts (core.MPEG_TS_EXTS). */
export const MPEG_TS_EXTS = new Set([".ts", ".mts", ".m2ts"]);

/** Bytes read from each non-source file for classification (spec 9). */
export const HEADER_SAMPLE = 512;
/** The leading bytes disguisedBinary reads (core.DISGUISE_SAMPLE_BYTES). */
export const DISGUISE_SAMPLE = 2048;
/** The leading bytes classifyBinary reads (its entropy's sample). */
const CLASSIFY_SAMPLE = 8192;
export const PYC_HEADER = 16;

/** MPEG transport stream: a sync byte every 188 bytes (core._mpeg_ts). */
export const mpegTs = (h) => call("binary_check", { check: "mpeg_ts" }, bytesText(h, 377));

/**
 * Heuristic text/binary classification from a leading byte sample (core.looks_binary): only bytes that cannot be
 * text count — bytes of invalid UTF-8 sequences and C0 controls other than whitespace and ESC (NUL included); more
 * than 30% of the sample → binary.
 */
export function looksBinary(sample) {
  if (!sample.length) return false;
  return call("binary_check", { check: "looks" }, bytesText(sample));
}

/**
 * Supply-chain issue for a suspicious non-source file, or null (core.classify_binary).
 * context: "sdist" | "npm" | "wheel" | "repo"; data: leading bytes; size: full size. FP-OPAQUE-MEDIA: with `whole`
 * (`data` is the whole file: by default, when it holds `size` bytes), a near-random file that is a sound, video, image or font to its end is quiet, and a
 * keystore read to its end is S-SECRET (an array of it and SC-OPAQUE-BLOB when it holds more bytes no structure reads
 * than a keystore does); without it, such a file is judged by its first bytes. FP-GRADLE-WRAPPER: a Gradle wrapper
 * jar is judged by its checksum with `props`, the bytes of the gradle-wrapper.properties beside it (its first
 * GRADLE_PROPERTIES_MAX_BYTES and one more; null: there are none; {error}: it is there and was not read; not given: as
 * null when `data` is the whole jar, else it is any jar).
 */
export function classifyBinary(path, data, size, context = "repo", { whole = data.length === size, props } = {}) {
  const args = { path, size, context, windows: WINDOWS, neumaier: false };
  // (props: its bytes, its first GRADLE_PROPERTIES_MAX_BYTES and one more; null: none; {error}: there, not read)
  if (props !== undefined) {
    args.props = props === null ? null : props instanceof Uint8Array ? bytesText(props) : { error: String(props.error ?? "") };
  }
  let got;
  if (whole && data.length > CLASSIFY_SAMPLE && props === undefined) {
    got = call("binary_classify", { ...args, more: true }, bytesText(data, CLASSIFY_SAMPLE));
    if (got !== null && got.need) got = call("binary_classify", { ...args, whole: true }, bytesText(data));
  } else {
    got = call("binary_classify", whole ? { ...args, whole: true } : args, whole ? bytesText(data) : bytesText(data, CLASSIFY_SAMPLE));
  }
  // (a Gradle wrapper jar its caller gave no properties for: judged with none)
  if (got !== null && got.need === "wrapper") got = call("binary_classify", { ...args, whole: true, props: null }, bytesText(data));
  // (a keystore that is an opaque blob too: both findings, an array of issues, each an array)
  if (Array.isArray(got) && Array.isArray(got[0])) return issuesOf(path, got);
  return got === null ? null : issuesOf(path, [got])[0];
}

/**
 * SC-BINARY, CRITICAL, for a program under a source file's name (0.1.8): an executable's or a compiled module's
 * bytes (a Windows PE among them) in a file named as source code. Unlike a binary named for what it is
 * (classifyBinary) it is a disguise. Else null (core.disguised_binary).
 */
export function disguisedBinary(path, data) {
  const got = call("binary_disguised", { path, windows: WINDOWS }, bytesText(data, DISGUISE_SAMPLE));
  return got === null ? null : issuesOf(path, [got])[0];
}

// ---- __pycache__ bytecode (spec 8) ----------------------------------------
/**
 * SC-PYC-UNCHECKED / SC-PYC-ORPHAN for one .pyc in a __pycache__ directory (core.pyc_issues). `header` is the first
 * bytes of the file; `hasSource` whether the matching <module>.py(w) sits next to __pycache__.
 */
export function pycIssues(path, header, hasSource) {
  return issuesOf(path, call("pyc_issues", { path, has_source: !!hasSource }, bytesText(header, PYC_HEADER)));
}

/** The module a __pycache__ entry was compiled from: "x.cpython-311.pyc" → "x". */
export function pycModule(name) {
  return String(name).split(".")[0];
}
