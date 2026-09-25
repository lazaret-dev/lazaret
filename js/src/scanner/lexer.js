// Comment lexer shared by rule skipping, suppression markers, taint and the
// metrics — twin of lazaret.scanner.core._lex_comment_spans /
// _comment_layout (shared semantics, spec 1).
//
// Comment state is tracked ACROSS lines; a line is a comment line only if it
// has non-whitespace text and all of it is inside comments, so `/**/eval(x)`
// is code and ` * foo` is a comment only while a block comment is open.
//   py : '#' to end of line; '…' "…" end at end of line unless the newline is
//        backslash-escaped; '''…''' """…""" span lines; backslash escapes.
//        (The Python engine uses Python's own tokenizer when the file
//        tokenizes; this lexer is its fallback and agrees on valid code.)
//   js : '//' to end of line; '/* … */' spans lines; '…' "…" as in py;
//        `…` template literals span lines (${…} is not re-lexed); a '/' that
//        starts a regex literal (previous significant code character is
//        start-of-file or one of ( , = : [ ! & | ? { } ; + - * % < > ~ ^, or
//        the previous word is return/typeof/instanceof/in/of/new/delete/void/
//        throw/case/do/else/yield/await) consumes the literal /…/ up to its
//        closing '/' on the same line; with no closing '/' on the line it is a
//        plain division, and so is every later '/' on that line.
//   sql: '--' to end of line; '/* … */' spans lines; '…' and "…" span lines,
//        no backslash escapes.
// Unterminated block comments and multi-line strings run to end of file.

import { pyRstrip, pyStrip, isWordChar } from "../lib/pycompat.js";

const NEXT = {
  py: /[#'"]/g,
  js: /[/'"`]/g,
  sql: /--|\/\*|['"]/g,
  any: /#|\/[/*]|['"`]/g,
};
const lineStr = (q) => new RegExp(`${q}(?:[^${q}\\\\\\n]|\\\\[\\s\\S])*${q}?`, "y");
const LINE_STR = { "'": lineStr("'"), '"': lineStr('"'), "`": lineStr("`") };
const STR = {
  py: { "'": LINE_STR["'"], '"': LINE_STR['"'],
    "'''": /'''(?:[^'\\]|\\[\s\S]|'(?!''))*(?:'''|$)/y, '"""': /"""(?:[^"\\]|\\[\s\S]|"(?!""))*(?:"""|$)/y },
  js: { "'": LINE_STR["'"], '"': LINE_STR['"'], "`": /`(?:[^`\\]|\\[\s\S])*`?/y },
  sql: { "'": /'[^']*'?/y, '"': /"[^"]*"?/y },
  any: LINE_STR,
};
const JS_REGEX_LIT_RE = /\/(?![*/])(?:[^/\\[\n]|\\[^\n]|\[(?:[^\]\\\n]|\\[^\n])*\])+\//y;
const JS_REGEX_PREV = new Set("(,=:[!&|?{};+-*%<>~^");
const JS_REGEX_KEYWORDS = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete",
  "void", "throw", "case", "do", "else", "yield", "await"]);
const isJsWord = (ch) => ch === "$" || ch === "_" || isWordChar(ch);

function jsRegexAllowed(prev, tail) {
  if (prev === "" || JS_REGEX_PREV.has(prev)) return true;
  if (isJsWord(prev)) {
    let k = tail.length;
    while (k > 0 && isJsWord(tail[k - 1])) k--;
    if (k === 0 && tail.length >= 11) return false;          // word longer than any keyword
    return JS_REGEX_KEYWORDS.has(tail.slice(k));
  }
  return false;
}

/**
 * Absolute [start, end) spans of every comment in `content`. When `strings`
 * is an array, the spans of '…' and "…" literals are appended to it.
 */
export function commentSpans(content, lang, strings = null) {
  const L = lang === "py" || lang === "js" || lang === "sql" ? lang : "any";
  const next = NEXT[L];
  const spans = [];
  const n = content.length;
  let pos = 0, prev = "", tail = "", noRegexUntil = -1;
  while (pos < n) {
    next.lastIndex = pos;
    const m = next.exec(content);
    if (!m) break;
    const k = m.index;
    if (L === "js" && k > pos) {
      const seg = pyRstrip(content.slice(pos, k));
      if (seg) { prev = seg[seg.length - 1]; tail = seg.slice(-11); }
    }
    const ch = content[k];
    const two = content.slice(k, k + 2);
    if ((ch === "#" && (L === "py" || L === "any")) || (two === "//" && (L === "js" || L === "any"))
        || (two === "--" && L === "sql")) {
      let e = content.indexOf("\n", k);
      if (e < 0) e = n;
      spans.push([k, e]);
      pos = e;
      continue;
    }
    if (two === "/*" && L !== "py") {
      let e = content.indexOf("*/", k + 2);
      e = e < 0 ? n : e + 2;
      spans.push([k, e]);
      pos = e;
      continue;
    }
    if (ch === "/") {                          // js only: regex literal or division
      if (k >= noRegexUntil && jsRegexAllowed(prev, tail)) {
        JS_REGEX_LIT_RE.lastIndex = k;
        const rm = JS_REGEX_LIT_RE.exec(content);
        if (rm) { pos = k + rm[0].length; prev = '"'; tail = ""; continue; }
        noRegexUntil = content.indexOf("\n", k);
        if (noRegexUntil < 0) noRegexUntil = n;
      }
      pos = k + 1;
      prev = "/"; tail = "/";
      continue;
    }
    const key = L === "py" && content.startsWith(ch + ch + ch, k) ? ch + ch + ch : ch;
    const re = STR[L][key];
    re.lastIndex = k;
    const sm = re.exec(content);
    pos = Math.max(sm ? k + sm[0].length : k + 1, k + 1);
    prev = '"'; tail = "";
    if (strings && ch !== "`") strings.push([k, pos]);
  }
  return spans;
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
 *   starts    — line start offsets in the joined content.
 */
export function lexLines(lines, lang, content = null) {
  content ??= lines.join("\n");
  const strings = lang === "js" ? [] : null;
  const all = commentSpans(content, lang, strings);
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
  const inComment = (j, p) => (spans.get(j) || []).some(([a, b]) => a <= p && p < b);
  return { comment, spans, code, strings, starts, content, inComment };
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
