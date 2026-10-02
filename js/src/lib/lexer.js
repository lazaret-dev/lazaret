// Comment lexer shared by rule skipping, suppression markers, taint and the
// metrics: the native engine's (`lex_comment_spans`: rust/crates/
// lazaret-engine/src/lexer.rs and lex/), as the Python package reads it
// (core._lex_comment_spans), here laid out per line.
//
// Comment state is tracked ACROSS lines; a line is a comment line only if it
// has non-whitespace text and all of it is inside comments, so `/**/eval(x)`
// is code and ` * foo` is a comment only while a block comment is open.
//
// Fail closed where the same text reads two ways: a character is a comment
// (or a literal) only if both readings of its language say so, so code some
// runtime executes is never hidden as a comment and a string never passes
// for a comment holding a suppression marker:
//   js : the tokens JavaScript reads (templates nested in templates' `${…}`,
//        which is code; a regular expression told from a division by what
//        comes before it; Annex B's `<!--` and `-->`, code in a module, read
//        as code), with JSX and without (not in .ts files);
//   py : the tokens Python 3.12+ reads (f-strings in pieces, their
//        replacement fields code), and as Python 3.11 read strings and
//        comments;
//   sql: as standard SQL and as MySQL reads it (backslash escapes in '…'
//        "…", `…` names, `/*! … */` executed code, not a comment);
//   any other text: `#` and `//` to the end of the line, `/* … */`, quotes.
// Offsets are the engine's code points, turned into UTF-16 offsets here.

import { pyStrip } from "./pycompat.js";
import { configCommentSpans } from "./configsecrets.js";
import { call } from "./native.js";

/** Is a JavaScript-family file also read as JSX? Every one but .ts, .mts and .cts (core.jsx_reading). */
export function jsxReading(path) {
  const p = String(path ?? "").toLowerCase();
  return !(p.endsWith(".ts") || p.endsWith(".mts") || p.endsWith(".cts"));
}

/** For a text holding surrogate pairs, the UTF-16 offset of each code-point offset; null when they are the same. */
function unitOffsets(s) {
  if (!/[\uD800-\uDBFF][\uDC00-\uDFFF]/.test(s)) return null;
  const units = [];
  for (let i = 0; i < s.length; i++) {
    units.push(i);
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
  }
  units.push(s.length);
  return units;
}

/**
 * Absolute [start, end) spans of every comment in `content`: the spans both
 * readings of the language agree on. When `strings` is an array, the '…' /
 * "…" literal spans are appended to it; when `literals` is, the spans of
 * every literal: strings, regular expressions, a template's or an f-string's
 * text (its replacement fields left out), JSX text. jsx: false for a .ts
 * file (no JSX reading).
 */
export function commentSpans(content, lang, strings = null, { jsx = true, literals = null } = {}) {
  if (lang === "cfg") return configCommentSpans(content);          // a config or data file
  const args = { jsx, strings: strings !== null, literals: literals !== null };
  if (lang === "py" || lang === "js" || lang === "sql") args.lang = lang;
  const got = call("lex_comment_spans", args, content);
  const units = unitOffsets(content);
  const at = units ? ([a, b]) => [units[a], units[b]] : ([a, b]) => [a, b];
  if (strings) for (const s of got.strings) strings.push(at(s));
  if (literals) for (const s of got.literals) literals.push(at(s));
  return got.comments.map(at);
}

export function lineStarts(content) {
  const starts = [0];
  let p = content.indexOf("\n");
  while (p !== -1) { starts.push(p + 1); p = content.indexOf("\n", p + 1); }
  return starts;
}

/**
 * Comment layout of a file's lines:
 *   comment[i] — 1 when line i is a comment line;
 *   spans.get(i) — comment spans of line i, relative to the line;
 *   code[i]   — line i with its comment text removed (strings kept);
 *   strings   — absolute spans of '…' / "…" literals (JavaScript only);
 *   literals  — with `literals: true`, absolute spans of every literal
 *               (JavaScript and Python; see commentSpans), else null;
 *   starts    — line start offsets in the joined content.
 * jsx: false for a .ts file (see jsxReading).
 */
export function lexLines(lines, lang, content = null, { jsx = true, literals = false } = {}) {
  content ??= lines.join("\n");
  const strings = lang === "js" ? [] : null;
  const lits = literals && (lang === "js" || lang === "py") ? [] : null;
  const all = commentSpans(content, lang, strings, { jsx, literals: lits });
  const n = lines.length;
  const comment = new Uint8Array(n);
  const spans = new Map();
  const starts = lineStarts(content);
  let code = lines;
  if (all.length) {
    let i = 0;
    for (const [s, e] of all) {
      while (i + 1 < n && starts[i + 1] <= s) i++;
      for (let j = i; j < n; j++) {
        const ls = starts[j], le = ls + lines[j].length;
        const a = Math.max(s, ls) - ls, b = Math.min(e, le) - ls;
        if (b > a) { let list = spans.get(j); if (!list) { list = []; spans.set(j, list); } list.push([a, b]); }
        if (e <= le + 1) break;
      }
    }
    code = lines.slice();
    for (const [j, list] of spans) {
      const line = lines[j];
      let c = "", p = 0;
      for (const [a, b] of list) { c += line.slice(p, a); p = b; }
      c += line.slice(p);
      code[j] = c;
      comment[j] = pyStrip(c) === "" && pyStrip(line) !== "" ? 1 : 0;
    }
  }
  // A line's spans are sorted and disjoint: binary search, not a scan of
  // every span per query (review: O(markers × spans), seconds on one line).
  const inComment = (j, p) => {
    const list = spans.get(j);
    if (!list) return false;
    let lo = 0, hi = list.length;                  // first span ending after p
    while (lo < hi) { const mid = (lo + hi) >> 1; if (list[mid][1] <= p) lo = mid + 1; else hi = mid; }
    return lo < list.length && list[lo][0] <= p;
  };
  return { comment, spans, code, strings, literals: lits, starts, content, inComment };
}

/**
 * Single-line form for callers without file context (no block comment or
 * template open at its start): Python lines are comments when they start
 * with '#'; other languages are lexed on their own.
 */
export function isComment(line, lang) {
  const t = pyStrip(line);
  if (!t) return false;
  if (lang === "py") return t.startsWith("#");
  return lexLines([line], lang).comment[0] === 1;
}
