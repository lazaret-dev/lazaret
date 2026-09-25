// Line splitting shared by the scanner and the metrics (spec 1): \r\n and a
// lone \r are newlines (Python text mode), and in JavaScript sources U+2028
// and U+2029 are line terminators too.
import { normalizeNewlines } from "../lib/fs.js";

const JS_LINE_SEP_RE = /[\u2028\u2029]/g;

export function normalizeSource(content, lang) {
  let text = normalizeNewlines(String(content ?? ""));
  if (lang === "js" && (text.includes("\u2028") || text.includes("\u2029"))) text = text.replace(JS_LINE_SEP_RE, "\n");
  return text;
}

export function splitLines(content, lang) {
  return normalizeSource(content, lang).split("\n");
}
