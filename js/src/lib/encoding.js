// Source decoding (shared semantics specs 4 and 15) and file-name decoding
// (spec 11) — zero-dependency leaf.

import { PY_CODEC_ALIASES, SINGLE_BYTE_CODECS } from "./codecs.js";

// ---- BOM / NUL sniff (spec 4) --------------------------------------------
/**
 * Encoding sniff for a source file's leading bytes:
 *   FF FE → utf-16-le; FE FF → utf-16-be; EF BB BF → utf-8-sig;
 *   else a NUL in the first 4 bytes → utf-16-le when it sits at index 1 or
 *   3, utf-16-be otherwise; else plain utf-8.
 */
export function sniffEncoding(buf) {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return { encoding: "utf-16-le", bom: 2 };
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) return { encoding: "utf-16-be", bom: 2 };
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) return { encoding: "utf-8-sig", bom: 3 };
  const head = buf.subarray(0, 4);
  const nul = head.indexOf(0);
  if (nul !== -1) return { encoding: head[1] === 0 || head[3] === 0 ? "utf-16-le" : "utf-16-be", bom: 0 };
  return { encoding: "utf-8", bom: 0 };
}

/**
 * core._text_is_plausible: does a BOM-less UTF-16 guess (a NUL in the first
 * four bytes, no BOM) read as text? A UTF-8 file with a NUL near the top
 * (`/*\0*\/eval(…)`) decodes to CJK-looking garbage under UTF-16; real
 * UTF-16 source is mostly ASCII. Plausible when at least 70% of the first
 * 2048 characters (code points, as Python counts them) are ' '..'~' or
 * TAB / LF / CR.
 */
export function textIsPlausible(text) {
  if (!text) return false;
  let n = 0, plain = 0;
  for (const ch of text) {
    if (n === 2048) break;
    n++;
    const c = ch.codePointAt(0);
    if ((c >= 0x20 && c <= 0x7e) || c === 9 || c === 10 || c === 13) plain++;
  }
  return plain / n >= 0.70;
}

// ---- PEP 263 cookies (spec 15) --------------------------------------------
// core._PY_COOKIE_RE / _PY_BLANK_RE (bytes patterns: \w is ASCII).
const COOKIE_RE = /^[ \t\f]*#[^\n]*?coding[:=][ \t]*([-\w.]+)/;
const BLANK_RE = /^[ \t\f]*(?:#[^\n]*)?$/;

const PY_NAME_BY_ALIAS = new Map();
for (const [name, aliases] of Object.entries(PY_CODEC_ALIASES)) for (const a of aliases) PY_NAME_BY_ALIAS.set(a, name);
const normEnc = (name) => String(name).toLowerCase().replace(/[^a-z0-9.]+/g, "_").replace(/^_+|_+$/g, "");
/** codecs.lookup(name).name for a text encoding, or null (unknown / not a text codec). */
export function pythonCodecName(name) {
  const n = normEnc(name);
  return PY_NAME_BY_ALIAS.get(n) ?? PY_NAME_BY_ALIAS.get(n.replace(/\./g, "_")) ?? null;
}
/**
 * core._normal_codec: the codec a cookie name resolves to as the interpreter
 * does (utf-8-* and latin-1-* spellings fold to their base codec), or null.
 */
export function normalCodec(name) {
  const short = String(name).slice(0, 12).toLowerCase().replace(/_/g, "-");
  if (short === "utf-8" || short.startsWith("utf-8-")) return "utf-8";
  if (["latin-1", "iso-8859-1", "iso-latin-1"].includes(short)
      || ["latin-1-", "iso-8859-1-", "iso-latin-1-"].some((p) => short.startsWith(p))) return "iso8859-1";
  return pythonCodecName(name);
}

const UTF7_NAMES = new Set(["utf-7", "utf7", "u7", "unicode-1-1-utf-7"]);
/** Spec 15: utf-7 / utf7 / u7 / unicode-1-1-utf-7, case- and _-insensitive. */
export const isUtf7Name = (name) => UTF7_NAMES.has(String(name).toLowerCase().replace(/_/g, "-"));

/**
 * PEP 263 cookie of Python source bytes (core._python_cookie): line 1, or
 * line 2 when line 1 is blank or a comment. Returns {name, line} or null.
 */
export function findCookie(buf) {
  let end = 0, breaks = 0;                            // bytes through the second line break
  while (end < buf.length && breaks < 2) {
    const c = buf[end++];
    if (c === 13 && buf[end] === 10) end++;           // \r\n is one line break, as in core
    if (c === 10 || c === 13) breaks++;
  }
  const lines = buf.subarray(0, end).toString("latin1").split(/\r\n|\r|\n/, 2);
  for (let idx = 0; idx < lines.length; idx++) {
    const m = COOKIE_RE.exec(lines[idx]);
    if (m) return { name: m[1], line: idx + 1 };
    if (!BLANK_RE.test(lines[idx])) break;
  }
  return null;
}

// ---- decoders ---------------------------------------------------------------
const B64 = new Int16Array(128).fill(-1);
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split("")
  .forEach((c, i) => { B64[c.charCodeAt(0)] = i; });

/** RFC 2152 UTF-7 decoder (errors="replace"). */
export function decodeUtf7(buf) {
  const units = [];
  let i = 0;
  const n = buf.length;
  while (i < n) {
    const c = buf[i];
    if (c === 0x2b) {                                    // '+'
      if (buf[i + 1] === 0x2d) { units.push(0x2b); i += 2; continue; }   // "+-" → '+'
      if (i + 1 < n && !(buf[i + 1] < 128 && B64[buf[i + 1]] >= 0)) {     // ill-formed "+x"
        units.push(0xfffd); i += 2; continue;
      }
      i++;
      let bits = 0, nbits = 0;
      while (i < n && buf[i] < 128 && B64[buf[i]] >= 0) {
        bits = ((bits << 6) | B64[buf[i]]) & 0xffffff;
        nbits += 6;
        if (nbits >= 16) { nbits -= 16; units.push((bits >> nbits) & 0xffff); }
        i++;
      }
      if (nbits >= 6 || (bits & ((1 << nbits) - 1)) !== 0) units.push(0xfffd);   // partial / non-zero padding
      if (buf[i] === 0x2d) i++;                          // '-' ends the shift and is absorbed
      continue;
    }
    units.push(c < 0x80 ? c : 0xfffd);
    i++;
  }
  return fixSurrogates(units);
}
function fixSurrogates(units) {
  let out = "";
  for (let k = 0; k < units.length; k++) {
    const u = units[k];
    if (u >= 0xd800 && u <= 0xdbff && units[k + 1] >= 0xdc00 && units[k + 1] <= 0xdfff) {
      out += String.fromCharCode(u, units[++k]);
    } else if (u >= 0xd800 && u <= 0xdfff) out += "\ufffd";
    else out += String.fromCharCode(u);
  }
  return out;
}
function decodeAscii(buf) {
  let out = "";
  for (let k = 0; k < buf.length; k += 8192) {
    const part = buf.subarray(k, k + 8192);
    out += String.fromCharCode(...Array.from(part, (b) => (b < 0x80 ? b : 0xfffd)));
  }
  return out;
}
const UTF8 = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });
const decodeUtf8 = (buf) => UTF8.decode(buf);

// Multi-byte codecs: Python codec name → WHATWG TextDecoder label (twin of
// core._TEXTDECODER_CODECS). Single-byte codecs decode with Python's own
// tables (SINGLE_BYTE_CODECS); the TextDecoder's differ (cp1252's undefined
// bytes, cp866, no ISO-8859-16).
const WHATWG = {
  "utf-16": "utf-16le", "utf-16-le": "utf-16le", "utf-16-be": "utf-16be",
  "shift_jis": "shift_jis", "cp932": "shift_jis", "euc_jp": "euc-jp",
  "iso2022_jp": "iso-2022-jp", "gbk": "gbk", "gb2312": "gbk", "cp936": "gbk", "gb18030": "gb18030",
  "big5": "big5", "cp950": "big5", "euc_kr": "euc-kr", "cp949": "euc-kr",
};

/** Bytes through a single-byte table (128 characters: bytes 0x80..0xFF; else all 256). */
function decodeSingleByte(table, buf) {
  const low = table.length === 128 ? 128 : 0;
  let out = "";
  for (let k = 0; k < buf.length; k += 8192) {
    const part = buf.subarray(k, k + 8192);
    out += String.fromCharCode(...Array.from(part, (b) => (b < low ? b : table.charCodeAt(b - low))));
  }
  return out;
}

// ---- escape codecs (twin of core._decode_escapes) -----------------------
/** Codecs that decode escape sequences before Python reads the code (SC-ESCAPE-CODEC). */
export const ESCAPE_CODECS = new Set(["unicode-escape", "raw-unicode-escape"]);
const hexDigit = (b) => (b >= 0x30 && b <= 0x39 ? b - 0x30 : b >= 0x61 && b <= 0x66 ? b - 0x57
  : b >= 0x41 && b <= 0x46 ? b - 0x37 : -1);
const isOctal = (b) => b >= 0x30 && b <= 0x37;
// \\ \' \" \b \f \t \n \r \v \a
const SIMPLE_ESCAPES = new Map([[0x5c, "\\"], [0x27, "'"], [0x22, '"'], [0x62, "\b"], [0x66, "\f"],
  [0x74, "\t"], [0x6e, "\n"], [0x72, "\r"], [0x76, "\v"], [0x61, "\x07"]]);
function latin1Run(buf, start, end) {
  let out = "";
  for (let k = start; k < end; k += 8192) out += String.fromCharCode(...buf.subarray(k, Math.min(k + 8192, end)));
  return out;
}

/**
 * Python's unicode_escape (raw false) or raw_unicode_escape (raw true), as
 * bytes.decode(codec) decodes: any other byte is Latin-1. null where Python
 * raises (a short \x, \u or \U, a code point past U+10FFFF, unicode_escape's
 * backslash at the end: the interpreter would not run the file) and for a
 * \N{name} escape, which needs Unicode's name table (core._decode_escapes
 * gives up on it too). A surrogate code point is U+FFFD, as
 * core.decode_source writes it.
 */
export function decodeEscapes(buf, raw) {
  const parts = [];
  const n = buf.length;
  let i = 0, run = 0;
  while (i < n) {
    if (buf[i] !== 0x5c) { i++; continue; }
    if (i + 1 >= n) { if (raw) { i++; continue; } return null; }
    const e = buf[i + 1];
    if (raw && e !== 0x75 && e !== 0x55) { i += 2; continue; }   // not an escape: kept as written
    if (i > run) parts.push(latin1Run(buf, run, i));
    i += 2;
    let count = 0;
    if (e === 0x75) count = 4;                                   // \uXXXX
    else if (e === 0x55) count = 8;                              // \UXXXXXXXX
    else if (e === 0x78) count = 2;                              // \xXX
    else if (e === 0x4e) return null;                            // \N{name}
    else if (isOctal(e)) {                                       // \o, \oo, \ooo (up to 0o777)
      let ch = e - 0x30;
      if (i < n && isOctal(buf[i])) {
        ch = ch * 8 + buf[i++] - 0x30;
        if (i < n && isOctal(buf[i])) ch = ch * 8 + buf[i++] - 0x30;
      }
      parts.push(String.fromCharCode(ch));
    } else if (e !== 0x0a) {                                     // backslash-newline is removed
      const simple = SIMPLE_ESCAPES.get(e);
      parts.push(simple !== undefined ? simple : "\\" + String.fromCharCode(e));   // unknown: kept
    }
    if (count > 0) {
      let ch = 0;
      for (; count > 0; count--, i++) {
        const d = i < n ? hexDigit(buf[i]) : -1;
        if (d < 0) return null;
        ch = ch * 16 + d;
      }
      if (ch > 0x10ffff) return null;
      parts.push(ch >= 0xd800 && ch <= 0xdfff ? "\ufffd" : String.fromCodePoint(ch));
    }
    run = i;
  }
  if (n > run) parts.push(latin1Run(buf, run, n));
  return parts.join("");
}

/** Decode `buf` with a Python codec name; null when this engine cannot decode it as Python does. */
function decodeWith(codec, buf) {
  if (codec === "utf-8" || codec === "utf-8-sig") return decodeUtf8(codec === "utf-8-sig" && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf ? buf.subarray(3) : buf);
  if (codec === "utf-7") return decodeUtf7(buf);
  if (codec === "iso8859-1" || codec === "charmap") return buf.toString("latin1");
  if (codec === "ascii") return decodeAscii(buf);
  if (ESCAPE_CODECS.has(codec)) return decodeEscapes(buf, codec === "raw-unicode-escape");
  const table = SINGLE_BYTE_CODECS[codec];
  if (table !== undefined) return decodeSingleByte(table, buf);
  const label = WHATWG[codec];
  if (!label) return null;
  try { return new TextDecoder(label, { fatal: false, ignoreBOM: codec !== "utf-16" }).decode(buf); } catch { return null; }
}

/**
 * Decode a source file's bytes the way its interpreter reads them (twin of
 * core.decode_source). Returns {text, encoding, reported, utf7, cookieLine,
 * escapes, undecoded}: reported → Q-ENCODING ("detected <encoding>"); utf7 →
 * SC-UTF7 and escapes → SC-ESCAPE-CODEC at cookieLine; undecoded →
 * SC-TRUNCATED. BOM / NUL sniff first (spec 4; a
 * BOM-less UTF-16 guess only when textIsPlausible, else plain UTF-8); for
 * Python source without a BOM or NUL, a PEP 263 cookie naming a codec other
 * than UTF-8 decodes with that codec (spec 15); an unknown codec decodes as
 * UTF-8 with replacement, and so does one this engine cannot decode exactly
 * as Python does (undecoded: not fully scanned). Never throws on content.
 */
export function decodeSource(buf, { py = false } = {}) {
  let sniff = sniffEncoding(buf);
  if (sniff.bom === 0 && sniff.encoding.startsWith("utf-16")
      && !textIsPlausible(decodeWith(sniff.encoding, buf.subarray(0, 4096)))) {
    // A NUL near the top of a UTF-8 file (`/*\0*/eval(…)`) is not UTF-16:
    // decoded that way the payload turns into CJK-looking garbage that no
    // rule reads. Accept the BOM-less UTF-16 guess only when it reads as
    // text (real UTF-16 source is mostly ASCII) — as core.decode_source.
    sniff = { encoding: "utf-8", bom: 0 };
  }
  let codec = sniff.encoding;
  const body = buf.subarray(sniff.bom);
  const info = { encoding: codec, reported: codec !== "utf-8", utf7: false, cookieLine: null };
  if (py && !info.reported) {
    const cookie = findCookie(buf);
    if (cookie) {
      const real = normalCodec(cookie.name);
      if (real === null) {
        Object.assign(info, { encoding: cookie.name, reported: true, cookieLine: cookie.line });
      } else if (real !== "utf-8") {
        codec = real;
        Object.assign(info, { encoding: real, reported: true, cookieLine: cookie.line,
          utf7: real === "utf-7" || isUtf7Name(cookie.name) });
        if (ESCAPE_CODECS.has(real)) info.escapes = true;
      }
    }
  }
  let text = decodeWith(codec, body);
  if (text === null) {                              // read as UTF-8: not what Python reads
    text = decodeUtf8(body);
    info.undecoded = true;
  }
  return { text, ...info };
}

// ---- file names (spec 11) -----------------------------------------------
/**
 * Decode a file-name byte string the way the Python engine reports it:
 * valid UTF-8 as text, every byte of an invalid sequence as the literal
 * text "\xNN" (os.fsencode(name).decode("utf-8", "backslashreplace")), so
 * every report stays valid UTF-8 and the name is still recognizable.
 */
export function fsNameToString(bytes) {
  let out = "";
  let i = 0;
  const n = bytes.length;
  let runStart = 0;
  const flush = (end) => { if (end > runStart) out += bytes.subarray(runStart, end).toString("utf8"); };
  while (i < n) {
    const len = utf8SeqLen(bytes, i);
    if (len > 0) { i += len; continue; }
    flush(i);
    out += "\\x" + bytes[i].toString(16).padStart(2, "0");
    i++;
    runStart = i;
  }
  flush(n);
  return out;
}
function utf8SeqLen(b, i) {
  const c = b[i];
  if (c < 0x80) return 1;
  const cont = (k) => k < b.length && (b[k] & 0xc0) === 0x80;
  if (c >= 0xc2 && c <= 0xdf) return cont(i + 1) ? 2 : 0;
  if (c >= 0xe0 && c <= 0xef) {
    const c1 = b[i + 1];
    if (c1 === undefined) return 0;
    if (c === 0xe0 && (c1 < 0xa0 || c1 > 0xbf)) return 0;
    if (c === 0xed && (c1 < 0x80 || c1 > 0x9f)) return 0;
    return cont(i + 1) && cont(i + 2) ? 3 : 0;
  }
  if (c >= 0xf0 && c <= 0xf4) {
    const c1 = b[i + 1];
    if (c1 === undefined) return 0;
    if (c === 0xf0 && (c1 < 0x90 || c1 > 0xbf)) return 0;
    if (c === 0xf4 && (c1 < 0x80 || c1 > 0x8f)) return 0;
    return cont(i + 1) && cont(i + 2) && cont(i + 3) ? 4 : 0;
  }
  return 0;
}
