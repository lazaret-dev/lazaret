// Comment lexer shared by rule skipping, suppression markers, taint and the
// metrics — twin of lazaret.scanner.core._lex_comment_spans /
// _comment_layout (shared semantics, spec 1).
//
// Comment state is tracked ACROSS lines; a line is a comment line only if it
// has non-whitespace text and all of it is inside comments, so `/**/eval(x)`
// is code and ` * foo` is a comment only while a block comment is open.
//
// Fail closed where the same text reads two ways (review): a character is a
// comment only if BOTH readings of its language say so, so code some runtime
// executes is never hidden as a comment and a string never passes for a
// comment holding a suppression marker. Each file is lexed twice and the
// comment spans (for JavaScript also the '…' "…" string spans) intersected:
//   py : the lexer below, and again with f-strings (and t-strings) as Python
//        3.12+ reads them (PEP 701): a replacement field may hold strings in
//        the same quotes, comments and newlines; nothing in an f-string is a
//        comment. (The Python engine no longer uses Python's tokenizer, which
//        differs across the supported versions.)
//   js : the lexer below, and again reading JSX (not in .ts files): element
//        text and attribute strings hold no comments, `{…}` holds code again.
//        An element starts at `<` + a tag name (or `>`) where an expression
//        may start (the regex positions below, after `default`, `)` or `]`);
//        text no JSX toolchain accepts (`>` or `}` in element text, anything
//        but attributes in a tag) ends that reading there.
//   sql: the lexer below (standard SQL), and again as MySQL reads it:
//        backslash escapes in '…' "…", `…` names, `/*! … */` (`/*M! … */`) is
//        executed code, not a comment.
//
// Lexer semantics:
//   py : '#' to end of line; '…' "…" end at end of line unless the newline is
//        backslash-escaped; '''…''' """…""" span lines; backslash escapes.
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
// String and regex literals are measured with the loops below, each the
// exact match of the regular expression in its comment (the Python engine's
// twin, core._lex_comment_spans, uses those expressions). V8's backtracking
// regex engine keeps one stack entry per repetition of an alternation, so a
// literal of a few million characters threw "Maximum call stack size
// exceeded": the file's findings were lost, or the whole run (review B3).
// Each returns the end of the match, or -1 where there is none.
const BS = 92, NL = 10;
/** q(?:[^q\\\n]|\\[\s\S])*q? — '…' "…" (and `…` read as "any"): ends at the line's end. */
export function lineStrEnd(s, k) {
  const q = s.charCodeAt(k), n = s.length;
  for (let i = k + 1; i < n;) {
    const c = s.charCodeAt(i);
    if (c === q) return i + 1;
    if (c === NL) return i;
    if (c === BS) { if (i + 1 >= n) return i; i += 2; } else i++;
  }
  return n;
}
/** q(?:[^q\\]|\\[\s\S])*q? — a template literal; '…' "…" as MySQL reads them. */
export function spanStrEnd(s, k) {
  const q = s.charCodeAt(k), n = s.length;
  for (let i = k + 1; i < n;) {
    const c = s.charCodeAt(i);
    if (c === q) return i + 1;
    if (c === BS) { if (i + 1 >= n) return i; i += 2; } else i++;
  }
  return n;
}
/** qqq(?:[^q\\]|\\[\s\S]|q(?!qq))*(?:qqq|$) — Python's '''…''' """…"""; none when a lone backslash ends the text. */
export function tripleStrEnd(s, k) {
  const q = s.charCodeAt(k), n = s.length;
  for (let i = k + 3; i < n;) {
    const c = s.charCodeAt(i);
    if (c === q) {
      if (s.charCodeAt(i + 1) === q && s.charCodeAt(i + 2) === q) return i + 3;
      i++;
    } else if (c === BS) { if (i + 1 >= n) return -1; i += 2; } else i++;
  }
  return n;
}
/** q[^q]*q? — '…' "…" in standard SQL, `…` in MySQL. */
export function plainStrEnd(s, k) {
  const e = s.indexOf(s[k], k + 1);
  return e < 0 ? s.length : e + 1;
}
/** \/(?![*\/])(?:[^\/\\[\n]|\\[^\n]|\[(?:[^\]\\\n]|\\[^\n])*\])+\/ — a regex literal. */
export function jsRegexEnd(s, k) {
  const n = s.length;
  let i = k + 1, parts = 0;
  if (i >= n || s.charCodeAt(i) === 42 || s.charCodeAt(i) === 47) return -1;     // /* and //
  while (i < n) {
    const c = s.charCodeAt(i);
    if (c === 47 || c === NL) break;
    if (c === BS) {
      if (i + 1 >= n || s.charCodeAt(i + 1) === NL) break;
      i += 2;
    } else if (c === 91) {                                   // [ … ]: a '/' inside is literal
      let j = i + 1;
      while (j < n) {
        const d = s.charCodeAt(j);
        if (d === 93 || d === NL) break;
        if (d === BS) { if (j + 1 >= n || s.charCodeAt(j + 1) === NL) { j = n; break; } j += 2; } else j++;
      }
      if (j >= n || s.charCodeAt(j) !== 93) break;           // not closed on its line
      i = j + 1;
    } else i++;
    parts++;
  }
  return parts > 0 && i < n && s.charCodeAt(i) === 47 ? i + 1 : -1;
}
const STR = {
  py: { "'": lineStrEnd, '"': lineStrEnd, "'''": tripleStrEnd, '"""': tripleStrEnd },
  js: { "'": lineStrEnd, '"': lineStrEnd, "`": spanStrEnd },
  sql: { "'": plainStrEnd, '"': plainStrEnd },
  any: { "'": lineStrEnd, '"': lineStrEnd, "`": lineStrEnd },
};
// SQL as MySQL reads it
const MYSQL_NEXT = /--|\/\*|['"`]/g;
const MYSQL_STR = { "'": spanStrEnd, '"': spanStrEnd, "`": plainStrEnd };
const JS_REGEX_PREV = new Set("(,=:[!&|?{};+-*%<>~^");
const JS_REGEX_KEYWORDS = new Set(["return", "typeof", "instanceof", "in", "of", "new", "delete",
  "void", "throw", "case", "do", "else", "yield", "await"]);
const JSX_KEYWORDS = new Set([...JS_REGEX_KEYWORDS, "default"]);
const isJsWord = (ch) => ch === "$" || ch === "_" || isWordChar(ch);

function jsRegexAllowed(prev, tail, keywords = JS_REGEX_KEYWORDS) {
  if (prev === "" || JS_REGEX_PREV.has(prev)) return true;
  if (isJsWord(prev)) {
    let k = tail.length;
    while (k > 0 && isJsWord(tail[k - 1])) k--;
    if (k === 0 && tail.length >= 11) return false;          // word longer than any keyword
    return keywords.has(tail.slice(k));
  }
  return false;
}

/** The [start, end) spans covered by both a and b (each sorted, non-overlapping). */
function intersectSpans(a, b) {
  const out = [];
  let i = 0, j = 0;
  while (i < a.length && j < b.length) {
    const s = Math.max(a[i][0], b[j][0]), e = Math.min(a[i][1], b[j][1]);
    if (s < e) out.push([s, e]);
    if (a[i][1] < b[j][1]) i++; else j++;
  }
  return out;
}

/** Is a JavaScript-family file also read as JSX? Every one but .ts (core.jsx_reading). */
export function jsxReading(path) {
  return !String(path ?? "").toLowerCase().endsWith(".ts");
}

/**
 * Absolute [start, end) spans of every comment in `content`: the spans both
 * readings of the language agree on. When `strings` is an array, the '…' /
 * "…" literal spans both JavaScript readings agree on are appended to it.
 * jsx: false for a .ts file (no JSX reading).
 */
export function commentSpans(content, lang, strings = null, { jsx = true } = {}) {
  const L = lang === "py" || lang === "js" || lang === "sql" ? lang : "any";
  if (L === "any" || (L === "js" && !jsx)) return lexPass(content, L, strings);
  const sa = strings ? [] : null, sb = strings ? [] : null;
  const a = lexPass(content, L, sa);
  const b = L === "js" ? lexJsx(content, sb) : lexPass(content, L, sb, true);
  if (strings) for (const s of intersectSpans(sa, sb)) strings.push(s);
  return intersectSpans(a, b);
}

/** One reading: the lexer above, or with `second` the other reading of Python (PEP 701) or SQL (MySQL). */
function lexPass(content, L, strings = null, second = false) {
  const mysql = second && L === "sql";
  const fstrings = second && L === "py";
  const next = mysql ? MYSQL_NEXT : NEXT[L];
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
      if (mysql && (content.startsWith("!", k + 2) || content.startsWith("M!", k + 2))) {
        pos = k + 2;                               // MySQL executes /*! … */: its text is code
        continue;
      }
      let e = content.indexOf("*/", k + 2);
      e = e < 0 ? n : e + 2;
      spans.push([k, e]);
      pos = e;
      continue;
    }
    if (ch === "/") {                          // js only: regex literal or division
      if (k >= noRegexUntil && jsRegexAllowed(prev, tail)) {
        const e = jsRegexEnd(content, k);
        if (e >= 0) { pos = e; prev = '"'; tail = ""; continue; }
        noRegexUntil = content.indexOf("\n", k);
        if (noRegexUntil < 0) noRegexUntil = n;
      }
      pos = k + 1;
      prev = "/"; tail = "/";
      continue;
    }
    if (fstrings) {
      const [isF, raw] = pyFstringPrefix(content, k);
      if (isF) { pos = pyFstringEnd(content, k, raw); continue; }
    }
    const end = mysql ? MYSQL_STR[ch] : STR[L][L === "py" && content.startsWith(ch + ch + ch, k) ? ch + ch + ch : ch];
    pos = Math.max(end(content, k), k + 1);
    prev = '"'; tail = "";
    if (strings && ch !== "`") strings.push([k, pos]);
  }
  return spans;
}

// ---- Python f-strings as 3.12+ reads them (PEP 701); twin of core._py_fstring_end
const PY_FSTRING_PREFIXES = new Set(["f", "fr", "rf", "t", "tr", "rt"]);
const FSTR_TEXT_STOP = { "'": /[{}\\\n']/g, '"': /[{}\\\n"]/g };
const FSTR_FIELD_STOP = /[#'"(){}[\]:]/g;
/** A character that may continue a Python name, for prefix purposes: ASCII letters, digits, '_', any non-ASCII. */
function pyNameChar(c) {
  return c === 95 || c >= 0x80 || (c >= 48 && c <= 57) || ((c | 32) >= 97 && (c | 32) <= 122);
}
/** [is an f-/t-string, raw] for the string literal whose quote is at s[k]. */
function pyFstringPrefix(s, k) {
  let j = k;
  while (j > 0 && k - j <= 2 && pyNameChar(s.charCodeAt(j - 1))) j--;
  if (k - j > 2 || (j > 0 && pyNameChar(s.charCodeAt(j - 1)))) return [false, false];
  const p = s.slice(j, k).toLowerCase();
  return [PY_FSTRING_PREFIXES.has(p), p.includes("r")];
}
/** Index just past the f-string whose opening quote is at s[k] (core._py_fstring_end). */
function pyFstringEnd(s, k, raw) {
  const n = s.length;
  let q = s[k];
  let ql = s.startsWith(q + q + q, k) ? 3 : 1;
  // frames: ["S", quote, qlen, raw] text; ["P", …] a format spec; ["F", depth, quote, qlen, raw] a field
  const stack = [["S", q, ql, raw]];
  let i = k + ql, named = false;
  while (stack.length) {
    const fr = stack[stack.length - 1];
    if (fr[0] !== "F") {
      const rw = fr[3];
      q = fr[1]; ql = fr[2];
      const re = FSTR_TEXT_STOP[q];
      re.lastIndex = i;
      const m = re.exec(s);
      if (!m) return n;
      i = m.index;
      const c = s[i];
      if (c === q) {
        if (ql === 3 && !s.startsWith(q + q + q, i)) { i++; continue; }
        i += ql;
        while (stack.pop()[0] !== "S");            // its fields and specs end with it
        named = false;
      } else if (c === "\n") {
        if (fr[0] === "P") stack.pop();            // a newline ends a format spec
        else if (ql === 1) while (stack.pop()[0] !== "S");   // unterminated: ends at the newline
        else i++;
        named = false;
      } else if (c === "\\") {
        const nx = s.slice(i + 1, i + 2);
        if (nx === "{" || nx === "}") i += 1;     // the brace is read on its own
        else if (!rw && nx === "N" && s.startsWith("{", i + 2)) { i += 3; named = true; }
        else i += 2;
      } else if (c === "{") {
        if (fr[0] === "S" && s.startsWith("{", i + 1)) i += 2;   // '{{'
        else { stack.push(["F", 0, q, ql, rw]); i += 1; }
        named = false;
      } else if (named) { named = false; i += 1; }                // '}' closing \N{…}
      else if (fr[0] === "P") stack.pop();                       // the field reads this '}'
      else i += s.startsWith("}", i + 1) ? 2 : 1;                 // '}}', or a stray '}'
      continue;
    }
    FSTR_FIELD_STOP.lastIndex = i;
    const m = FSTR_FIELD_STOP.exec(s);
    if (!m) return n;
    i = m.index;
    const c = s[i];
    if (c === "#") {                                              // a comment: to end of line
      const e = s.indexOf("\n", i);
      if (e < 0) return n;
      i = e;
    } else if (c === "'" || c === '"') {
      const [isF, sraw] = pyFstringPrefix(s, i);
      const l3 = s.startsWith(c + c + c, i) ? 3 : 1;
      if (isF) { stack.push(["S", c, l3, sraw]); i += l3; }
      else {
        i = Math.max(STR.py[l3 === 3 ? c + c + c : c](s, i), i + 1);
      }
    } else if (c === "(" || c === "[" || c === "{") { fr[1]++; i++; }
    else if (c === ")" || c === "]") { fr[1] = Math.max(fr[1] - 1, 0); i++; }
    else if (c === "}") {
      i++;
      if (fr[1]) fr[1]--;
      else stack.pop();                                           // the field ends
    } else {                                                      // ':'
      if (!fr[1]) stack.push(["P", fr[2], fr[3], fr[4]]);
      i++;
    }
  }
  return i;
}

// ---- JavaScript read as JSX; twin of core._lex_js_jsx
const JSX_JS_NEXT = /[/'"`{}<]/g;
const JSX_FILE_NEXT = /[/'"`<]/g;                  // the file's own code: its braces need no count
const JSX_TEXT_NEXT = /[{}<>]/g;
const JSX_WS = /[ \t\n\r\f\v]*/y;
const JSX_NAME = /[A-Za-z0-9_$.:\-\u0080-￿]*/y;
const jsxNameStart = (c) => c >= 0x80 || c === 95 || c === 36 || ((c | 32) >= 97 && (c | 32) <= 122);
const skipWs = (s, j) => { JSX_WS.lastIndex = j; JSX_WS.exec(s); return JSX_WS.lastIndex; };
const skipName = (s, j) => { JSX_NAME.lastIndex = j; JSX_NAME.exec(s); return JSX_NAME.lastIndex; };
/** Where the tag name (or a fragment's '>') starts when a '<' ends just before s[j], else -1. */
function jsxTagAt(s, j) {
  j = skipWs(s, j);
  return j < s.length && (s[j] === ">" || jsxNameStart(s.charCodeAt(j))) ? j : -1;
}

function lexJsx(content, strings = null) {
  const spans = [];
  const n = content.length;
  let pos = 0, prev = "", tail = "", noRegexUntil = -1;
  // frames: ["js", depth] code (the bottom frame is the file, the others a
  // `{…}` inside JSX); ["tag"] an opening tag's attributes; ["text"] children
  const stack = [["js", 0]];
  const elementDone = () => { if (stack[stack.length - 1][0] === "js") { prev = '"'; tail = ""; } };
  while (pos < n) {
    const fr = stack[stack.length - 1];
    let abort;
    if (fr[0] === "js") {
      const next = stack.length > 1 ? JSX_JS_NEXT : JSX_FILE_NEXT;
      next.lastIndex = pos;
      const m = next.exec(content);
      if (!m) break;
      const k = m.index;
      if (k > pos) {
        const seg = pyRstrip(content.slice(pos, k));
        if (seg) { prev = seg[seg.length - 1]; tail = seg.slice(-11); }
      }
      const ch = content[k];
      const two = content.slice(k, k + 2);
      if (two === "//") {
        let e = content.indexOf("\n", k);
        if (e < 0) e = n;
        spans.push([k, e]);
        pos = e;
      } else if (two === "/*") {
        let e = content.indexOf("*/", k + 2);
        e = e < 0 ? n : e + 2;
        spans.push([k, e]);
        pos = e;
      } else if (ch === "/") {
        pos = k + 1;
        if (k >= noRegexUntil && jsRegexAllowed(prev, tail)) {
          const e = jsRegexEnd(content, k);
          if (e >= 0) { pos = e; prev = '"'; tail = ""; continue; }
          noRegexUntil = content.indexOf("\n", k);
          if (noRegexUntil < 0) noRegexUntil = n;
        }
        prev = "/"; tail = "/";
      } else if (ch === "{") {
        fr[1]++;
        pos = k + 1;
        prev = "{"; tail = "{";
      } else if (ch === "}") {
        pos = k + 1;
        if (fr[1]) fr[1]--;
        else if (stack.length > 1) { stack.pop(); continue; }      // a `{…}` inside JSX ends
        prev = "}"; tail = "}";
      } else if (ch === "<") {
        const t = prev === ")" || prev === "]" || jsRegexAllowed(prev, tail, JSX_KEYWORDS) ? jsxTagAt(content, k + 1) : -1;
        if (t >= 0) {
          stack.push(["tag"]);
          pos = skipName(content, t);
        } else {
          pos = k + 1;
          prev = "<"; tail = "<";
        }
      } else {                                                     // a string or template literal
        pos = Math.max(STR.js[ch](content, k), k + 1);
        prev = '"'; tail = "";
        if (strings && ch !== "`") strings.push([k, pos]);
      }
      continue;
    }
    if (fr[0] === "tag") {
      const j = skipWs(content, pos);
      if (j >= n) break;
      const c = content[j];
      const two = content.slice(j, j + 2);
      if (two === "/>") { stack.pop(); pos = j + 2; elementDone(); continue; }
      if (c === ">") { stack[stack.length - 1] = ["text"]; pos = j + 1; continue; }
      if (two === "//" || two === "/*") {                          // comments may sit between attributes
        let e = content.indexOf(two === "//" ? "\n" : "*/", j + 2);
        e = e < 0 ? n : (two === "//" ? e : e + 2);
        spans.push([j, e]);
        pos = e;
        continue;
      }
      if (c === "{") { stack.push(["js", 0]); pos = j + 1; prev = "{"; tail = "{"; continue; }
      if (c === '"' || c === "'") {                               // no escapes in JSX attribute strings
        let e = content.indexOf(c, j + 1);
        e = e < 0 ? n : e + 1;
        if (strings) strings.push([j, e]);
        pos = e;
        continue;
      }
      if (c === "=") { pos = j + 1; continue; }
      if (jsxNameStart(content.charCodeAt(j))) { pos = skipName(content, j); continue; }
      const t = c === "<" ? jsxTagAt(content, j + 1) : -1;
      if (t >= 0) { stack.push(["tag"]); pos = skipName(content, t); continue; }   // an element as a value
      abort = j;
    } else {                                                       // element text
      JSX_TEXT_NEXT.lastIndex = pos;
      const m = JSX_TEXT_NEXT.exec(content);
      if (!m) break;
      const k = m.index;
      const c = content[k];
      if (c === "{") { stack.push(["js", 0]); pos = k + 1; prev = "{"; tail = "{"; continue; }
      if (c === "<") {
        let j = skipWs(content, k + 1);
        if (content.startsWith("/", j)) {                          // a closing tag
          j = skipWs(content, skipName(content, skipWs(content, j + 1)));
          if (content.startsWith(">", j)) { stack.pop(); pos = j + 1; elementDone(); continue; }
        } else {
          const t = jsxTagAt(content, k + 1);
          if (t >= 0) { stack.push(["tag"]); pos = skipName(content, t); continue; }
        }
      }
      abort = k;
    }
    // not JSX after all: back to the code around it, from this character
    while (stack[stack.length - 1][0] !== "js") stack.pop();
    pos = abort;
    prev = "<"; tail = "<";
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
 * jsx: false for a .ts file (see jsxReading).
 */
export function lexLines(lines, lang, content = null, { jsx = true } = {}) {
  content ??= lines.join("\n");
  const strings = lang === "js" ? [] : null;
  const all = commentSpans(content, lang, strings, { jsx });
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
