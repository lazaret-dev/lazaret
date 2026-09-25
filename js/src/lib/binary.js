// Binary / compiled-artifact detection — twin of
// lazaret.scanner.core.classify_binary (the registry's classifier), used for
// every non-source regular file in a directory scan (shared semantics spec 9),
// plus the __pycache__ bytecode checks (spec 8). Zero-dependency leaf.

import { extname } from "node:path";

const b = (s) => Buffer.from(s, "latin1");
export const EXEC_MAGIC = [
  [b("\x7fELF"), "ELF binary (Linux/Unix executable or shared object)"],
  [b("\xfe\xed\xfa\xce"), "Mach-O binary (macOS)"],
  [b("\xfe\xed\xfa\xcf"), "Mach-O 64-bit binary (macOS)"],
  [b("\xce\xfa\xed\xfe"), "Mach-O binary (macOS)"],
  [b("\xcf\xfa\xed\xfe"), "Mach-O 64-bit binary (macOS)"],
  [b("\xca\xfe\xba\xbe"), "Mach-O universal binary or Java .class"],
  [b("\x00asm"), "WebAssembly module"],
  [b("dex\n"), "Android DEX bytecode"],
];
export const COMPILED_EXTS = new Set([".so", ".pyd", ".dll", ".dylib", ".node", ".a", ".lib", ".o",
  ".obj", ".exe", ".pyc", ".pyo", ".class", ".wasm", ".dex", ".jar", ".msi", ".dmg"]);
const BENIGN_MAGIC = ["\x89PNG", "\xff\xd8\xff", "GIF8", "RIFF", "OggS", "BM", "\x00\x00\x01\x00",
  "wOFF", "wOF2", "ID3", "%PDF", "II*\x00", "MM\x00*", "\x1a\x45\xdf\xa3", "ftyp",
  "\xff\x4f\xff\x51", "\x00\x00\x00\x0cjP  ", "8BPS", "icns", "DDS ", "OTTO", "ttcf", "%!PS",
  "\xc5\xd0\xd3\xc6", "gimp xcf", "\x01\xda", "\x59\xa6\x6a\x95", "SIMPLE  =", "qoif", "#?RADIANCE",
  "fLaC", "\x00\x00\x02\x00"].map(b);
const CONTAINER_DOCUMENT_EXTS = new Set([".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".odg",
  ".epub", ".dia", ".svgz", ".ora", ".kmz", ".3mf", ".xmind", ".vsdx"]);
const FONT_EXTS = new Set([".ttf", ".otf", ".ttc", ".woff", ".woff2", ".eot", ".pfb", ".pcf", ".bdf"]);
const NESTED_ARCHIVE_MAGIC = [[b("PK\x03\x04"), "zip"], [b("\x1f\x8b"), "gzip"], [b("BZh"), "bzip2"],
  [b("\xfd7zXZ\x00"), "xz"], [b("7z\xbc\xaf\x27\x1c"), "7-zip"], [b("Rar!"), "rar"]];

/** Bytes read from each non-source file for classification (spec 9). */
export const HEADER_SAMPLE = 512;

const startsWith = (buf, sig) => buf.length >= sig.length && buf.subarray(0, sig.length).equals(sig);

function isBenignMedia(header, ext) {
  if (BENIGN_MAGIC.some((sig) => startsWith(header, sig)) || header.subarray(0, 16).includes(b("ftyp"))) return true;
  if (header.subarray(36, 40).equals(b("acsp"))) return true;                 // ICC color profile
  const h4 = header.subarray(0, 4);
  return FONT_EXTS.has(ext) && [b("\x00\x01\x00\x00"), b("true"), b("typ1")].some((s) => h4.equals(s));
}

export function byteEntropy(data) {
  if (!data.length) return 0;
  const freq = new Array(256).fill(0);
  for (const x of data) freq[x]++;
  let e = 0;
  for (const c of freq) if (c) e -= (c / data.length) * Math.log2(c / data.length);
  return e;
}

/**
 * Heuristic text/binary classification from a leading byte sample (twin of
 * core.looks_binary): only bytes that cannot be text count — bytes of
 * invalid UTF-8 sequences and C0 controls other than whitespace and ESC (NUL
 * included); more than 30% of the sample → binary.
 */
export function looksBinary(sample) {
  if (!sample.length) return false;
  let bad = 0;
  for (let i = 0; i < sample.length;) {
    const c = sample[i];
    if (c < 0x80) {
      if (c <= 0x08 || (c >= 0x0e && c <= 0x1a) || (c >= 0x1c && c <= 0x1f) || c === 0x7f) bad++;
      i++;
      continue;
    }
    const n = utf8Len(sample, i);
    if (n) { i += n; continue; }
    bad++;                                             // surrogateescape: one per invalid byte
    i++;
  }
  return bad / sample.length > 0.30;
}
function utf8Len(b, i) {
  const c = b[i];
  const cont = (k) => k < b.length && (b[k] & 0xc0) === 0x80;
  if (c >= 0xc2 && c <= 0xdf) return cont(i + 1) ? 2 : 0;
  if (c >= 0xe0 && c <= 0xef) {
    const c1 = b[i + 1];
    if (c1 === undefined || (c === 0xe0 && c1 < 0xa0) || (c === 0xed && c1 > 0x9f)) return 0;
    return cont(i + 1) && cont(i + 2) ? 3 : 0;
  }
  if (c >= 0xf0 && c <= 0xf4) {
    const c1 = b[i + 1];
    if (c1 === undefined || (c === 0xf0 && c1 < 0x90) || (c === 0xf4 && c1 > 0x8f)) return 0;
    return cont(i + 1) && cont(i + 2) && cont(i + 3) ? 4 : 0;
  }
  return 0;
}

function issue(path, rule, name, sev, msg, why, fix) {
  return { rule, name, type: "HOTSPOT", sev, msg, why, fix, ref: "CWE-506 · Supply chain",
    file: path, line: 1, snippet: [], snipStart: 1 };
}

/** Python's "{:.1f}" (round-half-even on the exact binary value). */
function fmt1(x) {
  const s = x.toFixed(1);
  const q = x * 20;                                   // exact tie: x = (2k+1)/20
  if (!Number.isInteger(q) || q % 2 === 0) return s;
  const lo = Math.floor(x * 10) / 10;
  return Math.round(lo * 10) % 2 === 0 ? lo.toFixed(1) : s;
}

/**
 * Supply-chain issue for a suspicious non-source file, or null.
 * context: "sdist" | "npm" | "wheel" | "repo"; data: leading bytes; size: full size.
 */
export function classifyBinary(path, data, size, context = "repo") {
  const header = data.subarray(0, 512);
  const ext = extname(String(path)).toLowerCase();
  const isBin = looksBinary(data.subarray(0, 2048));
  let desc = EXEC_MAGIC.find(([sig]) => startsWith(header, sig))?.[1] ?? null;
  if (desc === null && isBin && startsWith(header, b("MZ"))) desc = "Windows PE executable/DLL";
  if (desc === null && COMPILED_EXTS.has(ext)) desc = `compiled artifact (${ext})`;
  if (desc) {
    if (context === "wheel") {
      return issue(path, "SC-BINARY", "Binary artifact in package", "INFO", `Bundled binary: ${desc}.`,
        "Wheels legitimately ship compiled extensions. Listed for inventory; verify it matches the project's published, reproducible build.",
        "Cross-check against the upstream build; prefer building from source in sensitive contexts.");
    }
    const where = { sdist: "a source distribution", npm: "an npm package", repo: "the source tree" }[context] ?? "the package";
    return issue(path, "SC-BINARY", "Binary artifact in package", "MAJOR",
      `Executable/compiled binary in ${where}: ${desc}.`,
      "Prebuilt binaries can't be reviewed as source, and smuggled binaries are a known compromise vector. Many legitimate packages ship some (Windows launcher stubs, test fixtures), so on its own this is a capability to review, not evidence of malice.",
      "Confirm the binary's provenance; build from source instead of trusting a prebuilt blob.");
  }
  if (CONTAINER_DOCUMENT_EXTS.has(ext)) return null;
  if (header.subarray(257, 262).equals(b("ustar"))) {
    return issue(path, "SC-NESTED-ARCHIVE", "Nested archive in package", "MINOR",
      "Embedded tar archive inside the package.",
      "Nested archives can conceal second-stage payloads from source review.",
      "Extract and inspect the archive's contents.");
  }
  for (const [sig, kind] of NESTED_ARCHIVE_MAGIC) {
    if (startsWith(header, sig)) {
      if (context === "wheel" && kind === "zip") break;
      return issue(path, "SC-NESTED-ARCHIVE", "Nested archive in package", "MINOR",
        `Embedded ${kind} archive inside the package.`,
        "Nested archives can conceal second-stage payloads from source review (a known supply-chain evasion technique).",
        "Extract and inspect the archive's contents.");
    }
  }
  if (isBenignMedia(header, ext)) return null;
  if (isBin && size >= 1024) {
    const ent = byteEntropy(data.subarray(0, 8192));
    if (ent > 7.2) {
      return issue(path, "SC-OPAQUE-BLOB", "High-entropy binary blob", "MAJOR",
        `Opaque high-entropy file (${size} bytes, entropy ${fmt1(ent)}/8).`,
        "Encrypted or packed data shipped in a package can be a second-stage payload that is decoded and executed at runtime.",
        "Identify what this file is and why it ships; reject unexplained binary blobs.");
    }
  }
  return null;
}

// ---- __pycache__ bytecode (spec 8) ----------------------------------------
export const PYC_HEADER = 16;

function pycIssue(rule, name, sev, path, msg, why, fix) {
  return { rule, name, type: "HOTSPOT", sev, msg, why, fix, ref: "CWE-506 · Supply chain",
    file: path, line: 1, snippet: [], snipStart: 1 };
}

/**
 * SC-PYC-UNCHECKED / SC-PYC-ORPHAN for one .pyc in a __pycache__ directory
 * (twin of core.pyc_issues). `header` is the first bytes of the file;
 * `hasSource` whether the matching <module>.py(w) sits next to __pycache__.
 */
export function pycIssues(path, header, hasSource) {
  const out = [];
  if (header.length >= 8 && header[2] === 0x0d && header[3] === 0x0a && header.readUInt32LE(4) === 0b01) {
    out.push(pycIssue("SC-PYC-UNCHECKED", "Unchecked-hash bytecode", "CRITICAL", path,
      `${path} is an unchecked-hash .pyc (PEP 552): Python imports it without checking the source.`,
      "An unchecked-hash .pyc is loaded on import even when the .py next to it says something else, so code that was never reviewed runs while the reviewed source looks benign.",
      "Delete the __pycache__ directory, keep bytecode out of version control and rebuild from reviewed source."));
  }
  if (!hasSource) {
    out.push(pycIssue("SC-PYC-ORPHAN", "Bytecode without source", "MAJOR", path,
      `${path} has no matching source file.`,
      "Bytecode without its source cannot be reviewed, and a .pyc can be run directly (python file.pyc) or loaded by a custom importer.",
      "Delete the file, or restore the source it was compiled from and review it."));
  }
  return out;
}

/** The module a __pycache__ entry was compiled from: "x.cpython-311.pyc" → "x". */
export function pycModule(name) {
  return String(name).split(".")[0];
}
