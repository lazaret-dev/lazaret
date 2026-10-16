// Source decoding (shared semantics specs 4 and 15), the engine's for both packages (BR-7 step 4 b, 0.1.9:
// decode/), and file-name decoding (spec 11).

import { call } from "./native.js";

/**
 * A source file's bytes decoded as its interpreter reads them (core.decode_source): {text, info}, the text with
 * its line endings normalized, info {encoding, reported, utf7, cookieLine, escapes?, undecoded?}. A BOM or a NUL
 * in the first four bytes (BOM-less UTF-16, kept only when it reads as text); for Python source ("py") without
 * either, a PEP 263 coding cookie, decoded with any text codec Python has, as Python decodes it.
 */
export function decodeSource(buf, lang) {
  return call("decode_source", lang ? { lang } : {}, bytesText(buf));
}

/** `buf`'s bytes as the engine reads them: latin-1 text, a character per byte. */
export function bytesText(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
  return b.toString("latin1");
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
