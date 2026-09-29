// scanFile — twin of lazaret.scanner.core.scan_file / _scan_file,
// implementing the shared semantics (FIX-SPEC items 1, 2, 5, 6, 7, 12, 13, 14).
import { normalizeSource } from "./lines.js";
import { RULES, TEXT_RULES } from "./rules.js";
import {
  STRING_LIT_RE, TAINT_SOURCES, TAINT_SINKS, PARTIAL_SAN, neutralize, parseAssignment, AUG_ASSIGN_RE, taintCode,
  TAINT_JOIN_MAX_LINES, TAINT_JOIN_MAX_CHARS, BRACKET_DELTA, bracketDepth, cpHead, firstArg, sinkArgs,
  GUARD_IF_RE, guardedNames, guardExits, VIEW_RETURN_RE, VIEW_RETURN_SKIP_RE, viewBody, viewReturns, scopeOpener,
  literalContinuations, routeParams, TEMPLATE_SINK_RE, TEMPLATE_IMPORT_RE, NON_HTML_TYPE_RE, NON_HTML_CHAIN_RE, extent, containerWrite,
  KEYED_WRITE_RE, keyedReads, SAME_SITE_RE, allowGuard,
} from "./taint.js";
import { sqlSinkScan, scanSqlNowhere, parenCloseMap } from "./sql.js";
import {
  B64_BLOB_RE, OBF_IDENT_RE, SECRET_SKIP_RE, CHARCODE_RE, ENTROPY_VALUE_RE, entropySecretish,
  makeSuppressor, mkIssue,
} from "./engine.js";
import { lexLines, jsxReading } from "../lib/lexer.js";
import { extractFunctions } from "./functions.js";
import { cpLen, pyRe, pyRepr, pyRstrip, pyLstrip, pyStrip, isPySpace } from "../lib/pycompat.js";
import { findSecretToken, registerScanContext } from "../lib/redact.js";
import { truncatedIssue } from "../lib/fs.js";
import { assigned13, pinUnicode } from "../lib/unicode13.js";
import { runsDownloadThroughShell, EXEC_CALL_RE } from "../lib/shellpipe.js";
import { documentationToken, keyMaterial, secretCol, redactConfigValues } from "../lib/configsecrets.js";
import { configKind, ownerDir, entries as autorunEntries, localCommand } from "../lib/autorun.js";
import { isWorkflow, findings as workflowFindings } from "../lib/ghworkflow.js";
import { agentHijackInCommand, installScriptRisk, followHook, treeJoin, nodeCandidates, cpPrefix, selfPublishAt } from "../lib/hooks.js";
import { cpForward } from "../lib/received.js";
import { normalizeNewlines } from "../lib/fs.js";

export { isComment } from "./engine.js";

export const LONG_LINE = 160;
export const FN_LEN_LIMIT = 60;
export const FN_CX_LIMIT = 12;
/** Spec 7: per (file, rule) cap for every non-security rule (S-, T-, SC-, X-, SQL- are never capped). */
export const CAP_PER_RULE = 200;
export const FINDING_CAP = CAP_PER_RULE;
const NEVER_CAPPED_PREFIXES = ["S-", "T-", "SC-", "X-", "SQL-"];
/** Spec 14: per-file backstop for pattern rules (the regexes themselves are linear). */
export const SCAN_TIME_BUDGET_MS = 30_000;
let timeBudgetMs = SCAN_TIME_BUDGET_MS;
export function setScanTimeBudget(ms) { timeBudgetMs = ms ?? SCAN_TIME_BUDGET_MS; }

const DEP_RULE_PREFIXES = ["SC-", "S-TOKEN", "S-SECRET"];   // dependency mode: supply-chain + secret rules
const COMMENT_LINE_RULES = new Set(["Q-TODO", "S-TOKEN", "S-BIDI"]);

/* ---------------- Analyzers ---------------- */
export function detectLang(name, content) {
  if (/\.(py|pyw)$/i.test(name)) return "py";
  if (/\.(js|jsx|ts|tsx|mts|cts|mjs|cjs)$/i.test(name)) return "js";
  if (/\.sql$/i.test(name)) return "sql";
  // content heuristic: SQL keywords dominate and no JS/py structure
  if (/\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+(TABLE|PROCEDURE|USER)|GRANT|ALTER\s+TABLE)\b/i.test(content)
     && !/\b(function|=>|def |import )\b/.test(content)) return "sql";
  if (/^\s*(def |import |from \w+ import|class \w+.*:)/m.test(content) && !/[{};]\s*$/m.test(content)) return "py";
  return /\b(def |elif |None|self\.)/.test(content) && !/\b(const|let|=>|function)\b/.test(content) ? "py" : "js";
}

class ScanBudgetExceeded extends Error {}
const isBlank = (s) => { for (const ch of s) if (!isPySpace(ch)) return false; return true; };

// ---- match text (spec 5) --------------------------------------------------
// Rules match each line in the form the language runtime reads it:
//   py : a line containing non-ASCII is matched in its NFKC-normalized form;
//   js : identifier escapes \uXXXX and \u{X…} outside '…'/"…" string
//        literals are decoded when they denote an identifier character, and
//        U+FEFF (JavaScript whitespace Python's \s lacks) becomes a space.
// Line numbers never change; snippets still show the original text.
const NON_ASCII_RE = /[^\x00-\x7f]/;
const JS_UESC_RE = /\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})/g;
const ID_CONTINUE_RE = /^[\p{XID_Continue}$]$/u;
// identifier characters since Unicode 15.1 only (core._LATER_ID_CONTINUE)
const LATER_ID_CONTINUE = new Set([0x200c, 0x200d, 0x30fb, 0xff65]);
const pyMatchText = (t) => (NON_ASCII_RE.test(t) ? t.normalize("NFKC") : t);

class FileCtx {
  constructor(lines, lang, content, deadline, jsx = true) {
    this.lines = lines;
    this.lang = lang;
    this.content = content;
    this.lex = lexLines(lines, lang, content, { jsx, literals: true });
    this.cmask = this.lex.comment;
    this.deadline = deadline;
    this._mlines = null;
    this._mcode = new Map();
    this._strStarts = null;
    this._litEnds = null;
  }
  get mlines() {
    if (this._mlines === null) {
      if (this.lang === "py") this._mlines = this.lines.map(pyMatchText);
      else if (this.lang === "js") this._mlines = this.lines.map((_, i) => this.jsText(i, false));
      else this._mlines = this.lines;
    }
    return this._mlines;
  }
  /** Match text of line i with its comment text removed. */
  mcode(i) {
    if (this.lex.code === this.lines) return this.mlines[i];
    let v = this._mcode.get(i);
    if (v === undefined) {
      if (this.lang === "py") v = pyMatchText(this.lex.code[i]);
      else if (this.lang === "js") v = this.jsText(i, true);
      else v = this.lex.code[i];
      this._mcode.set(i, v);
    }
    return v;
  }
  /**
   * Line i as names are read in it (SC-HOMOGLYPH; core._FileCtx.names_code):
   * its match text with its comments removed and every literal blanked, by
   * the spans both readings of the file agree on: strings of any kind (a
   * template with its fields), regex literals.
   */
  namesCode(i) {
    const lits = this.lex.literals;
    if (!lits) return this.mcode(i);
    const line = this.lines[i];
    this._litEnds ??= lits.map((s) => s[1]);
    const base = this.lex.starts[i], end = base + line.length;
    let k = upperBound(this._litEnds, base);         // the first literal ending after base
    let out = "", p = 0, any = false;
    for (; k < lits.length && lits[k][0] < end; k++) {
      const a = Math.max(lits[k][0], base) - base, b = Math.min(lits[k][1], end) - base;
      out += line.slice(p, a) + " ".repeat(b - a);
      p = b;
      any = true;
    }
    if (!any) return this.mcode(i);
    out += line.slice(p);
    if (this.lang === "js") return this.jsText(i, true, out);
    return pyMatchText(cutSpans(out, this.lex.spans.get(i)));
  }
  /** Line i's match text; `line`: line i with some of its text blanked (the same length) to read instead. */
  jsText(i, dropComments, line = null) {
    let plain;
    if (line === null) {
      line = this.lines[i];
      plain = dropComments ? this.lex.code[i] : line;
    } else plain = dropComments ? cutSpans(line, this.lex.spans.get(i)) : line;
    if (!line.includes("\\u")) return plain.includes("\ufeff") ? plain.replaceAll("\ufeff", " ") : plain;
    if (this._strStarts === null) this._strStarts = this.lex.strings.map((s) => s[0]);
    const base = this.lex.starts[i];
    const cuts = dropComments ? (this.lex.spans.get(i) || []) : [];
    const edits = cuts.map(([a, b]) => [a, b, ""]);
    JS_UESC_RE.lastIndex = 0;
    let m, c = 0;                                  // cuts are sorted: one moving index
    while ((m = JS_UESC_RE.exec(line))) {
      const at = m.index;
      while (c < cuts.length && cuts[c][1] <= at) c++;
      if (c < cuts.length && cuts[c][0] <= at) continue;
      const k = upperBound(this._strStarts, base + at) - 1;
      if (k >= 0 && this.lex.strings[k][1] > base + at) continue;   // inside a '…' or "…" literal
      const cp = parseInt(m[1] ?? m[2], 16);
      if (cp > 0x10ffff) continue;
      const ch = String.fromCodePoint(cp);
      if (ch === "$" || LATER_ID_CONTINUE.has(cp) || (assigned13(cp) && ID_CONTINUE_RE.test(ch)))
        edits.push([at, at + m[0].length, ch]);
    }
    let out = plain;
    if (edits.length) {
      edits.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
      out = "";
      let p = 0;
      for (const [a, b, rep] of edits) {
        if (a < p) continue;
        out += line.slice(p, a) + rep;
        p = b;
      }
      out += line.slice(p);
    }
    return out.includes("\ufeff") ? out.replaceAll("\ufeff", " ") : out;
  }
  checkTime() {
    if (Date.now() > this.deadline) throw new ScanBudgetExceeded();
  }
}
/** `line` without the text of `spans` (sorted, disjoint, relative to it); core._cut_spans. */
function cutSpans(line, spans) {
  if (!spans || !spans.length) return line;
  let c = "", p = 0;
  for (const [a, b] of spans) { c += line.slice(p, a); p = b; }
  return c + line.slice(p);
}
function upperBound(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] <= x) lo = mid + 1; else hi = mid; }
  return lo;
}

// ---- Hex-escape decoding (SC-HEXSTR); twin of core.hex_hidden_text -------
const HEX_ESCAPE_RE = /\\x([0-9A-Fa-f]{2})/g;
const HEX_MIN_ESCAPES = 8;
const HEX_PRINTABLE_SHARE = 0.75;
const LETTER_RUN_RE = /[A-Za-z]{3}/;
export const HIDDEN_TEXT_DANGER_RE = pyRe(
  String.raw`https?://|\b(?:eval|exec|execSync|compile|__import__|import|require|child_process|` +
  String.raw`subprocess|system|popen|spawn|powershell|cmd\.exe|curl|wget|base64|b64decode|atob|` +
  String.raw`Function|fromCharCode|marshal|pickle)\b|/bin/(?:ba)?sh`, "i");

export function hexHiddenText(line) {
  if (!line.includes("\\x")) return null;
  let total = 0, text = "", letters = 0;
  HEX_ESCAPE_RE.lastIndex = 0;
  let m;
  while ((m = HEX_ESCAPE_RE.exec(line))) {
    total++;
    const c = parseInt(m[1], 16);
    if (c >= 0x20 && c < 0x7f) {
      text += String.fromCharCode(c);
      if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) letters++;
    }
  }
  if (total < HEX_MIN_ESCAPES) return null;
  if (text.length / total < HEX_PRINTABLE_SHARE) return null;
  if (!LETTER_RUN_RE.test(text) || letters / text.length < 0.4) return null;
  return text;
}

// Fewer escapes than HEX_MIN_ESCAPES still hide a name when the name is the
// point: a string literal in which a dangerous name (HIDDEN_TEXT_DANGER_RE)
// has a letter, digit or "_" written as an escape of a printable ASCII
// character is SC-HEXSTR, CRITICAL (twin of core.hex_hidden_name; see there).
const NAME_ESCAPE_RE = /\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|u\{([0-9A-Fa-f]{1,6})\}|U([0-9A-Fa-f]{8})|([0-7]{3}))/g;
const HIDDEN_TEXT_DANGER_ALL = new RegExp(HIDDEN_TEXT_DANGER_RE.source, HIDDEN_TEXT_DANGER_RE.flags + "g");
const NAME_CHAR_RE = /^[A-Za-z0-9_]$/;

/** [name, column] for the first string literal hiding part of a dangerous name in escapes, else null. */
export function hexHiddenName(line) {
  if (!line.includes("\\")) return null;
  const lits = new RegExp(STRING_LIT_RE.source, STRING_LIT_RE.flags);
  for (const lit of line.matchAll(lits)) {
    if (!lit[0].includes("\\")) continue;
    const found = hiddenNameIn(lit[0].slice(1, -1), lit.index + 1);
    if (found) return found;
  }
  return null;
}

function hiddenNameIn(seg, offset) {
  const escAt = [], escCol = [];
  let text = "", pos = 0, total = 0, printable = 0;
  NAME_ESCAPE_RE.lastIndex = 0;
  let m;
  while ((m = NAME_ESCAPE_RE.exec(seg))) {
    const start = m.index;
    let run = start;
    while (run > 0 && seg[run - 1] === "\\") run--;
    if ((start - run) % 2) continue;                 // "\\x65": an escaped backslash, then text
    total++;
    const digits = m[1] ?? m[2] ?? m[3] ?? m[4];
    const code = digits !== undefined ? parseInt(digits, 16) : parseInt(m[5], 8);
    if (code > 0x10ffff) continue;                   // no character: left as written
    const ch = String.fromCodePoint(code);
    text += seg.slice(pos, start);
    if (code >= 0x20 && code < 0x7f) {
      printable++;
      if (NAME_CHAR_RE.test(ch)) { escAt.push(text.length); escCol.push(offset + start); }
    }
    text += ch;                                      // every escape decoded
    pos = start + m[0].length;
  }
  if (!escAt.length || printable / total < HEX_PRINTABLE_SHARE) return null;
  text += seg.slice(pos);
  HIDDEN_TEXT_DANGER_ALL.lastIndex = 0;
  while ((m = HIDDEN_TEXT_DANGER_ALL.exec(text))) {
    let lo = 0, hi = escAt.length;                   // bisect_left(escAt, m.index)
    while (lo < hi) { const mid = (lo + hi) >> 1; if (escAt[mid] < m.index) lo = mid + 1; else hi = mid; }
    if (lo < escAt.length && escAt[lo] < m.index + m[0].length) return [m[0], escCol[lo]];
    if (!m[0]) HIDDEN_TEXT_DANGER_ALL.lastIndex++;
  }
  return null;
}

// SC-PIPE-SHELL: a project's own code that runs a download piped into a shell
// (twin of core._PIPE_SHELL_RULE; a dependency's code gets the import-time test)
const PIPE_SHELL_RULE = { id: "SC-PIPE-SHELL", name: "Download piped into a shell", type: "HOTSPOT", sev: "MAJOR",
  msg: "Code runs a downloaded script through a shell.",
  why: "Piping a download into a shell runs whatever the server sends at that moment, with the program's privileges: nothing pins or checks it, so the server, or anyone who can change what it serves, decides what runs. Installers publish the line for people to paste once, after reading the script; code that runs it hands every run to that server.",
  fix: "Download a pinned version, check its checksum or signature, and run that file; or drop the download.",
  ref: "CWE-494 · Supply chain" };

// ---- Look-alike identifiers (SC-HOMOGLYPH); twin of core.lookalike_name ----
// A name spelled with letters from another alphabet that look like Latin ones
// reads as a name it is not (`const \u0435val = eval`: a Cyrillic e; see
// core). The table, the targets and the name pattern are core's (the parity
// test compares them); every such character is written as an escape.
const LOOKALIKE_KEYS = "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0455\u0456\u0458\u04bb\u0501\u051b\u051d\u04cf\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0405\u0406\u0408\u04ae\u051a\u051c\u04c0\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7\u03dc\u03bf\u03f2\u03f3\u0585\u057d\u0251\u0261";
const LOOKALIKE_VALUES = "aeopcyxsijhdqwlABEKMHOPCTXSIJYQWIABEZHIKMNOPTYXFocjouag";
export const LOOKALIKES = new Map(Array.from(LOOKALIKE_KEYS, (ch, k) => [ch, LOOKALIKE_VALUES[k]]));
export const LOOKALIKE_TARGETS = new Set([
  "Buffer", "Function", "Popen", "__builtins__", "__import__", "atob", "b64decode", "builtins", "check_call",
  "check_output", "child_process", "compile", "eval", "exec", "execFile", "execFileSync", "execSync", "fetch",
  "fork", "fromCharCode", "getattr", "getoutput", "global", "globalThis", "import", "import_module", "marshal", "os",
  "pickle", "popen", "process", "require", "runInContext", "runInNewContext", "runInThisContext", "setInterval",
  "setTimeout", "socket", "spawn", "spawnSync", "subprocess", "system", "urlopen", "vm", "window"
]);
export const NAME_RUN_SRC = String.raw`[\w$\u200c\u200d]+`;
const NAME_RUN_RE = pyRe(NAME_RUN_SRC, "g");
const ASCII_WORD_RE = /[A-Za-z0-9_$]+/g;
const ASCII_LETTER_RE = /[A-Za-z]/;
const INVISIBLE_IN_NAMES = new Set(["\u200c", "\u200d"]);
const isAscii = (s) => !/[^\x00-\x7f]/.test(s);
const hexCp = (ch) => ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");

/**
 * [name, readsAs, severity, other, detail, column] for the first name in
 * `code` (a line as FileCtx.namesCode reads it: comments removed, literals
 * blanked) that reads as an ASCII name it is not, else null. `words()` gives
 * the file's ASCII words.
 */
export function lookalikeName(code, lang, words) {
  if (isAscii(code)) return null;
  NAME_RUN_RE.lastIndex = 0;
  let m;
  while ((m = NAME_RUN_RE.exec(code))) {
    const name = m[0];
    if (isAscii(name) || (m.index && code[m.index - 1] === "\\")) continue;   // after an escape left as written
    const seen = lang === "js" ? name.normalize("NFKC") : name;
    let skeleton = "";
    for (const ch of seen) if (!INVISIBLE_IN_NAMES.has(ch)) skeleton += LOOKALIKES.get(ch) ?? ch;
    if (!skeleton || skeleton === name || !isAscii(skeleton) || /^[0-9]/.test(skeleton)) continue;
    let severity, other = false;
    if (LOOKALIKE_TARGETS.has(skeleton)) severity = "CRITICAL";
    else if (skeleton.length >= 3 && words().has(skeleton)) { severity = "CRITICAL"; other = true; }
    else if (ASCII_LETTER_RE.test(name)) severity = "MAJOR";
    else continue;
    const parts = [];
    for (const ch of name) {
      if (ch.codePointAt(0) < 0x80) continue;
      let part;
      if (INVISIBLE_IN_NAMES.has(ch)) part = `an invisible U+${hexCp(ch)}`;
      else {
        const shown = lang === "js" ? ch.normalize("NFKC") : ch;
        let mapped = "";
        for (const c of shown) mapped += LOOKALIKES.get(c) ?? c;
        part = `U+${hexCp(ch)} for ${pyRepr(mapped)}`;
      }
      if (!parts.includes(part)) parts.push(part);
    }
    return [name, skeleton, severity, other, parts.join(", "), m.index];
  }
  return null;
}

const LOOKALIKE_WHY = "A name written with letters from another alphabet that look like Latin ones, or with an invisible character inside it, is not the name a reviewer reads: `const eval = eval` with a Cyrillic e (U+0435) makes a second eval that runs where no one sees eval called, and an isAdmin with a Cyrillic i is not isAdmin (CVE-2021-42694, the homoglyph half of Trojan Source).";
function lookalikeIssue(found, path, lineNo, lines) {
  const [name, skeleton, severity, other, detail, col] = found;
  return mkIssue({ id: "SC-HOMOGLYPH", name: "Look-alike identifier", type: "HOTSPOT", sev: severity,
    msg: `${pyRepr(name)} reads as ${pyRepr(skeleton)}${other ? ", another name in this file," : ""} but is spelled with ${detail}.`,
    why: LOOKALIKE_WHY,
    fix: "Rename it with the letters it appears to have, and find out why it was written this way.",
    ref: "CWE-1007 · CVE-2021-42694" }, path, lineNo, lines, col);
}


// ---- Invisible-character payload (SC-HIDDEN-UNICODE); twins of core ----
// Carrier chars in UTF-16: VS1 (BMP U+FE00-FE0F), or an astral char in
// U+E0000-E01EF, which all share the high surrogate 0xDB40 with a low
// surrogate 0xDC00-0xDDEF. Matching code units needs no `u` flag; the run
// length and columns are counted in code points, to match core.
const HIDDEN_RUN_RE = /(?:[\uFE00-\uFE0F]|\uDB40[\uDC00-\uDDEF]){2,}/g;
const FLAG_EMOJI_BASE = String.fromCodePoint(0x1F3F4);
const HIDDEN_TAG_START = 0xE0000, HIDDEN_TAG_END = 0xE007F;
const HIDDEN_EXEC_RE = pyRe(String.raw`(?<![\w$.])(?:eval|Function|execSync|exec|runInThisContext|runInNewContext|runInContext)\s*\(`);
const HIDDEN_UNICODE_WHY = "Invisible characters in source carry bytes that no review or diff shows: a variation selector or a tag character has no business in code. GlassWorm hid a payload in variation selectors and decoded it into eval; tag characters smuggle instructions past a reviewer and an AI reading the file. Only a flag emoji and a single emoji variation selector are ordinary.";

/** Is the run at UTF-16 `index` a flag emoji's tag sequence? Twin of core._hidden_flag_emoji. */
function hiddenFlagEmoji(line, index, run) {
  if (!(index >= 2 && line.slice(index - 2, index) === FLAG_EMOJI_BASE)) return false;
  const cps = [...run], last = cps[cps.length - 1].codePointAt(0);
  return last === HIDDEN_TAG_END && cps.every((c) => { const o = c.codePointAt(0); return o >= HIDDEN_TAG_START && o <= HIDDEN_TAG_END; });
}

/** [col, run] (col a UTF-16 index) for the first non-flag-emoji carrier run in `line`, else null. Twin of core.hidden_unicode_run. */
function hiddenUnicodeRun(line) {
  HIDDEN_RUN_RE.lastIndex = 0;
  let m;
  while ((m = HIDDEN_RUN_RE.exec(line))) {
    if (!hiddenFlagEmoji(line, m.index, m[0])) return [m.index, m[0]];
  }
  return null;
}

/** SC-HIDDEN-UNICODE at line lineNo. Twin of core._hidden_unicode_issue. */
function hiddenUnicodeIssue(path, lineNo, lines, col, run, runsCode) {
  const cps = [...run];
  const tags = cps.some((c) => { const o = c.codePointAt(0); return o >= HIDDEN_TAG_START && o <= HIDDEN_TAG_END; });
  const varsel = cps.some((c) => { const o = c.codePointAt(0); return !(o >= HIDDEN_TAG_START && o <= HIDDEN_TAG_END); });
  const what = tags && varsel ? "variation selectors and tag characters" : tags ? "tag characters" : "variation selectors";
  return mkIssue({ id: "SC-HIDDEN-UNICODE", name: "Invisible-character payload", type: "HOTSPOT",
    sev: runsCode ? "CRITICAL" : "MAJOR",
    msg: `A run of ${cps.length} invisible ${what} carries hidden data in the code` + (runsCode ? ", and the file runs code from a string." : "."),
    why: HIDDEN_UNICODE_WHY,
    fix: "Show the characters as escape sequences and decode what they spell; if it is a payload, do not run the file.",
    ref: "CWE-506 · Supply chain" }, path, lineNo, lines, col);
}

// ---- code hidden off-screen (SC-OFFSCREEN-CODE, 0.1.8); twin of core.offscreen_code ----
// Code after a run of at least OFFSCREEN_MIN blanks, standing in code (not in
// a string or a comment), that reads as code; CRITICAL when it loads or runs
// more code. See core's comment above _OFFSCREEN_SRC.
const OFFSCREEN_SRC = String.raw`(?<![ \t])[ \t]{150,}(?=\S)`;
const OFFSCREEN_CODE_SRC =
  String.raw`[;,(){}\[\]]|(?:const|let|var|function|async|class|def)\s+[A-Za-z_$(]|[A-Za-z_$][\w$]*\s*(?:[.(\[=;]|["'` + "`" + String.raw`])` +
  String.raw`|(?:import|from|exec|eval|require)\b`;
const OFFSCREEN_EXEC_SRC =
  String.raw`\b(?:require|import|exec|eval|Function|child_process|spawn|execSync|__import__|compile|b64decode` +
  String.raw`|fromCharCode|atob)\b|\bglobal\s*\[`;
const OFFSCREEN_RE = pyRe(OFFSCREEN_SRC);
const OFFSCREEN_CODE_Y = pyRe(OFFSCREEN_CODE_SRC, "y");
const OFFSCREEN_EXEC_RE = pyRe(OFFSCREEN_EXEC_SRC);
const OFFSCREEN_MIN = 150, OFFSCREEN_READ = 4000;
export const OFFSCREEN_TWINS = {
  patterns: { _OFFSCREEN_RE: [OFFSCREEN_SRC, ""], _OFFSCREEN_CODE_RE: [OFFSCREEN_CODE_SRC, ""],
    _OFFSCREEN_EXEC_RE: [OFFSCREEN_EXEC_SRC, ""] },
  limits: { _OFFSCREEN_MIN: OFFSCREEN_MIN, _OFFSCREEN_READ: OFFSCREEN_READ },
};
const OFFSCREEN_WHY = "A long run of blanks pushes code past the right edge of editors, diffs and code review, while " +
  "the interpreter runs it all the same: @react-native-aria/radio 0.2.14 hid its loader 731 columns right. No formatter puts code there.";

/** Does `prefix` close every string and comment it opens, and open no line comment? Twin of core._code_prefix. */
function codePrefix(prefix, lang) {
  let quote = null, i = 0;
  const n = prefix.length;
  while (i < n) {
    const ch = prefix[i];
    if (quote !== null) {
      if (ch === "\\") { i += 2; continue; }
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'" || (ch === "`" && lang === "js")) {
      quote = ch;
    } else if (lang === "py" && ch === "#") {
      return false;
    } else if (lang === "js" && ch === "/" && prefix.startsWith("//", i)) {
      return false;
    } else if (lang === "js" && ch === "/" && prefix.startsWith("/*", i)) {
      const end = prefix.indexOf("*/", i + 2);
      if (end < 0) return false;
      i = end + 2;
      continue;
    }
    i++;
  }
  return quote === null;
}

/** [UTF-16 column, blanks, hidden text, runs code] for code after a long run of blanks on `line`, else null. Twin of core.offscreen_code. */
export function offscreenCode(line, lang) {
  if (cpLen(line) <= OFFSCREEN_MIN || (!line.includes(" ".repeat(16)) && !line.includes("\t".repeat(16)))) return null;
  const m = OFFSCREEN_RE.exec(line);
  if (m === null) return null;
  const end = m.index + m[0].length;
  OFFSCREEN_CODE_Y.lastIndex = end;
  if (!OFFSCREEN_CODE_Y.test(line) || !codePrefix(line.slice(0, m.index), lang)) return null;
  const hidden = line.slice(end, cpForward(line, end, OFFSCREEN_READ));
  return [end, m[0].length, hidden, OFFSCREEN_EXEC_RE.test(hidden)];
}

function offscreenIssue(path, lineNo, lines, found) {
  const [col, blanks, hidden, runs] = found;
  const preview = cpLen(hidden) <= 60 ? hidden : cpPrefix(hidden, 57) + "...";
  return mkIssue({ id: "SC-OFFSCREEN-CODE", name: "Code hidden off-screen", type: "HOTSPOT", sev: runs ? "CRITICAL" : "MAJOR",
    msg: `Code after ${blanks} blanks on this line, where editors and review don't show it: ${pyRepr(preview)}.`,
    why: OFFSCREEN_WHY + (runs ? " This code loads or runs more code." : ""),
    fix: "Read the whole line (turn on word wrap) and review what it does.",
    ref: "CWE-506 · Supply chain" }, path, lineNo, lines, col);
}

// SC-SELF-PUBLISH (0.1.8): code that renames its package and publishes it (hooks.selfPublishAt; core._SELF_PUBLISH_RULE).
const SELF_PUBLISH_RULE = { id: "SC-SELF-PUBLISH", name: "Code that republishes its package", type: "HOTSPOT", sev: "CRITICAL",
  msg: "Renames its package (package.json's \"name\") and publishes it: the shape of registry spam and of packages that spread themselves.",
  why: "The 2025-26 registry floods shipped a script that gives package.json a new, random name and runs `npm publish` in a loop, " +
    "from the account of whoever runs it. Release tools publish too, but never rename what they publish.",
  fix: "Don't run it; report the package to the registry.",
  ref: "CWE-506 · Supply chain" };

// A "-----BEGIN ... PRIVATE KEY-----" header alone is not a key: libraries keep the
// header as a constant to recognize key files. Require base64 key material after it,
// on the same line or the next two. Twin of core._token_has_material.
const PEM_BODY_RE = /[A-Za-z0-9+/]{40}[A-Za-z0-9+/]*={0,2}/;   // {40}…*, not {40,}: see pycompat AT_LEAST_RE
function tokenHasMaterial(line, lines, i) {
  const t = findSecretToken(line);
  if (!t || !t.text.startsWith("-----BEGIN")) return true;
  return [line.slice(t.end), ...lines.slice(i + 1, i + 3)].some((x) => PEM_BODY_RE.test(x));
}

// ---- intra-file taint ------------------------------------------------------
const IDENT_RUN_RE = { py: /[\p{L}\p{N}_]+/gu, js: /[\p{L}\p{N}_$]+/gu };
/**
 * Taint tracking (twin of core.taint_scan): each line is matched with its
 * comment text removed; assignments from sources (or from tainted
 * variables) taint every bound name (spec 12), read over the lines of the
 * statement, with f-string and untagged template fields as code; a sink whose
 * injectable arguments carry a tainted variable (or a source) not cleansed
 * for that sink is reported, and so is a Flask view's tainted return value.
 * Taints live in the function body they were made in; a reassignment in the
 * same block, or an enclosing one, replaces the value, one in a nested or
 * sibling block adds to it; path guards that leave clear path traversal.
 */
export function taintScan(file, lines, lang, ctx = null) {
  const src = TAINT_SOURCES[lang];
  if (!src) return [];                   // SQL and others: pattern rules only
  if (!ctx || ctx.lines !== lines) {
    const content = lines.join("\n");
    ctx = new FileCtx(lines, lang, content, Infinity, jsxReading(file));
  }
  const issues = [];
  // var -> {line, clean:Set(suffix), order, scope, chain: [[indent, block id], …]}
  const tainted = new Map();
  let sinks = TAINT_SINKS[lang];
  if (lang === "py" && !TEMPLATE_IMPORT_RE.test(ctx.content)) sinks = sinks.filter((r) => r[1] !== TEMPLATE_SINK_RE);
  const partial = PARTIAL_SAN[lang] || {};
  const suffixes = [...new Set(sinks.map((r) => r[0]))];
  const identRe = IDENT_RUN_RE[lang];
  const views = lang === "py" && ctx.content.includes("@") ? viewReturns(ctx) : new Set();
  const routes = lang === "py" && ctx.content.includes("def") ? routeParams(ctx) : new Map();
  let pending = null;                    // [scope id, names, def line] of a route handler whose body is not yet seen
  const xssSink = sinks.find((r) => r[0] === "XSS") ?? null;
  const guardIf = GUARD_IF_RE[lang];
  const inside = literalContinuations(ctx);
  const levels = [];                     // open blocks: [indent, block id, scope id or null]
  let nextBlock = 0, nextScope = 0, nextOrder = 0;
  const inScope = new Map();             // scope id -> names tainted in it
  let opener = null;                     // [indent, scope id] of a function whose body is not yet seen
  let openDepth = 0, continued = 0;
  const carriers = (code, suf) => {
    if (!tainted.size) return [];
    const found = new Set();
    identRe.lastIndex = 0;
    let m;
    while ((m = identRe.exec(code))) {
      const t = tainted.get(m[0]);
      if (t && !(suf && t.clean.has(suf))) found.add(m[0]);
    }
    return [...found].sort((a, b) => tainted.get(a).order - tainted.get(b).order);
  };
  const statement = (i, line) => {
    let depth = bracketDepth(line);
    if (depth <= 0) return line;
    const parts = [line];
    let total = 0;
    for (let j = i + 1; depth > 0 && j < lines.length && j <= i + TAINT_JOIN_MAX_LINES
         && total < TAINT_JOIN_MAX_CHARS; j++) {
      if (ctx.cmask[j]) continue;
      const nxt = cpHead(ctx.mcode(j), TAINT_JOIN_MAX_CHARS - total);
      parts.push(nxt);
      total += cpLen(nxt);
      depth += bracketDepth(nxt);
    }
    return parts.join(" ");
  };
  const keyed = new Map();               // container -> Map(literal key -> clean Set, or null: no untrusted data)
  const allowed = [];                    // [indent, name, taint order, clean Set before] of the allowlist guards open
  // null when the value carries no untrusted data, else the sink suffixes it is clean for (core's value_clean)
  const valueClean = (rhs) => {
    rhs = keyedReads(rhs, keyed);
    const base = taintCode(neutralize(rhs, lang), lang);   // full sanitizers stripped
    if (!src.test(base) && !carriers(base, null).length) return null;
    const clean = new Set();
    for (const suf of suffixes) {
      const neut = partial[suf] ? taintCode(neutralize(rhs, lang, suf), lang) : base;
      if (!src.test(neut) && !carriers(neut, suf).length) clean.add(suf);
    }
    if (xssSink && xssSink[1].test(rhs)) clean.add("XSS");
    if (SAME_SITE_RE.test(rhs)) clean.add("REDIR");         // a path on this site, or a URL on a fixed host
    return clean;
  };
  const report = (suffix, cat, sev, cwe, fix, text, i, col) => {
    const restCode = taintCode(neutralize(keyedReads(text, keyed), lang, suffix), lang);
    const found = carriers(restCode, suffix);
    if (!found.length && !src.test(restCode)) return;
    const what = found.length ? `untrusted data via '${found[0]}' (tainted at line ${tainted.get(found[0]).line})` : "untrusted data";
    issues.push(mkIssue({ id: `T-${suffix}`, name: `Tainted flow → ${cat}`, type: "VULN", sev,
      msg: `Possible ${cat}: ${what} reaches this sink.`,
      why: "Data from user input or a decode function flows into a dangerous call without visible sanitization (lightweight intra-file taint tracking).",
      fix, ref: `${cwe} · Taint analysis` }, file, i + 1, lines, col));
  };
  for (let i = 0; i < lines.length; i++) {
    if (ctx.cmask[i]) continue;
    const line = ctx.mcode(i);
    if (!line || isBlank(line)) continue;
    if (!(i & 63)) ctx.checkTime();
    // ---- the structure ----
    let structural = false;
    if (!inside.has(i)) {
      let depth = 0;
      if (lang === "py") for (const ch of ctx.namesCode(i)) depth += BRACKET_DELTA[ch] ?? 0;
      if (openDepth > 0 && continued < TAINT_JOIN_MAX_LINES) {
        openDepth = Math.max(0, openDepth + depth);
        continued++;
      } else {
        structural = true;
        openDepth = Math.max(0, depth);
        continued = 0;
        const raw = lines[i];
        const indent = raw.length - pyLstrip(raw).length;
        while (allowed.length && indent <= allowed[allowed.length - 1][0]) {   // an allowlist guard's block ends
          const [, n, order, before] = allowed.pop();
          const tn = tainted.get(n);
          if (tn && tn.order === order) tn.clean = before;
        }
        while (levels.length && levels[levels.length - 1][0] > indent) {
          const gone = levels.pop()[2];
          if (gone !== null) {             // a function's body ends
            for (const n of inScope.get(gone) ?? []) if (tainted.get(n)?.scope === gone) tainted.delete(n);
            inScope.delete(gone);
          }
        }
        if (!levels.length || levels[levels.length - 1][0] < indent) {
          const scope = opener !== null && indent > opener[0] ? opener[1] : null;
          levels.push([indent, nextBlock++, scope]);
          if (pending !== null && scope === pending[0]) {
            // a route handler's body: the parameters it takes from the request
            const chain = levels.map((lv) => [lv[0], lv[1]]);
            for (const name of pending[1]) {
              keyed.delete(name);
              tainted.set(name, { line: pending[2] + 1, clean: new Set(), order: nextOrder++, scope, chain });
              if (!inScope.has(scope)) inScope.set(scope, []);
              inScope.get(scope).push(name);
            }
            pending = null;
          }
        }
        opener = null;
        if (scopeOpener(line, lang)) {
          pending = routes.has(i) ? [nextScope, routes.get(i), i] : null;
          opener = [indent, nextScope++];
        }
      }
    }
    let stmt = null;
    let a = parseAssignment(line, lang);
    const cw = a ? null : containerWrite(line, lang);
    if (a) {
      stmt = statement(i, line);
      a = parseAssignment(stmt, lang) ?? a;
      const clean = valueClean(a.rhs);
      const chain = levels.map((lv) => [lv[0], lv[1]]);
      let scope = null;
      for (let k = levels.length - 1; k >= 0; k--) if (levels[k][2] !== null) { scope = levels[k][2]; break; }
      const augmented = AUG_ASSIGN_RE[lang].test(stmt);
      const top = levels[levels.length - 1];
      for (const name of a.names) {
        if (!augmented) keyed.delete(name);
        const old = tainted.get(name);
        const replaces = !!old && structural && !augmented
          && old.chain.some(([ind, id]) => ind === top[0] && id === top[1]);
        if (!old || replaces) {
          if (clean === null) tainted.delete(name);
          else {
            tainted.set(name, { line: i + 1, clean, order: nextOrder++, scope, chain });
            if (scope !== null) {
              if (!inScope.has(scope)) inScope.set(scope, []);
              inScope.get(scope).push(name);
            }
          }
        } else if (clean !== null) {
          old.clean = new Set([...old.clean].filter((c) => clean.has(c)));
        }
      }
    } else if (cw !== null) {
      stmt = statement(i, line);
      const [container] = cw;
      let written = cw[1];
      const joined = containerWrite(stmt, lang);
      if (joined !== null && joined[0] === container) written = joined[1];
      const clean = valueClean(written);
      const km = KEYED_WRITE_RE.exec(stmt);
      if (km && km[1] === container) {
        if (!keyed.has(container)) keyed.set(container, new Map());
        keyed.get(container).set(km[3], clean);
      }
      if (clean !== null) {
        const old = tainted.get(container);
        if (old) old.clean = new Set([...old.clean].filter((c) => clean.has(c)));
        else {
          let scope = null;
          for (let k = levels.length - 1; k >= 0; k--) if (levels[k][2] !== null) { scope = levels[k][2]; break; }
          tainted.set(container, { line: i + 1, clean, order: nextOrder++, scope, chain: levels.map((lv) => [lv[0], lv[1]]) });
          if (scope !== null) {
            if (!inScope.has(scope)) inScope.set(scope, []);
            inScope.get(scope).push(container);
          }
        }
      }
    } else if (tainted.size && guardIf.test(line)) {
      stmt = statement(i, line);
      const guarded = guardedNames(stmt, lang).filter((n) => tainted.has(n));
      if (guarded.length && guardExits(ctx, i, stmt, lang)) {
        for (const n of guarded) tainted.get(n).clean = new Set([...tainted.get(n).clean, "PATH"]);
      }
      const guard = allowGuard(stmt, lang);
      if (guard !== null && tainted.has(guard[0])) {
        const code = taintCode(guard[1], lang);
        if (!src.test(code) && !carriers(code, null).length) {
          const entry = tainted.get(guard[0]);
          if (guard[2]) {                       // leaves when not a member: clean from here on
            if (guardExits(ctx, i, stmt, lang)) entry.clean = new Set(suffixes);
          } else {                              // a member inside the block
            const raw = lines[i];
            allowed.push([raw.length - pyLstrip(raw).length, guard[0], entry.order, entry.clean]);
            entry.clean = new Set(suffixes);
          }
        }
      }
    }
    let xssHere = false;
    for (const [suffix, sinkRe, cat, sev, cwe, fix] of sinks) {
      const sm = sinkRe.exec(line);
      if (!sm) continue;
      if (stmt === null) stmt = statement(i, line);
      xssHere = xssHere || suffix === "XSS";
      if (suffix === "XSS" && (lang === "py" ? NON_HTML_TYPE_RE.test(extent(stmt.slice(sm.index + sm[0].length)))
        : NON_HTML_CHAIN_RE.test(sm[0]))) continue;
      const args = sinkArgs(stmt.slice(sm.index + sm[0].length), sinkRe, lang, suffix);
      report(suffix, cat, sev, cwe, fix, args, i, sm.index);
    }
    if (views.has(i) && !xssHere && xssSink) {
      if (stmt === null) stmt = statement(i, line);
      const rm = VIEW_RETURN_RE.exec(stmt);
      const value = firstArg(stmt.slice(rm.index + rm[0].length));
      if (pyStrip(value) && !VIEW_RETURN_SKIP_RE.test(value) && viewBody(value)) {
        report(xssSink[0], xssSink[2], xssSink[3], xssSink[4], xssSink[5], value, i, rm.index + rm[0].length - 6);
      }
    }
  }
  return issues;
}

// ---- decode → execute across lines (spec 13) --------------------------------
// SC-EVAL-DECODE is matched per line, so `eval(\n  atob(…))` would be
// missed: when a line names a sink and leaves parentheses open (or ends
// with the sink's name), it is joined — comment text removed — with up to
// SC_JOIN_MAX_LINES following lines until the parentheses balance, and the
// rule is matched on the joined statement; a match must begin on the first
// line (twin of core._joined_eval_decode).
const SC_JOIN_MAX_LINES = 8;
const SC_JOIN_MAX_CHARS = 4000;
const SC_SINK_NAMES = ["eval", "exec", "execSync", "Function", "runInContext", "runInThisContext", "runInNewContext"];
// core._EVAL_BY_NAME: a computed member named 'eval' or 'Function' by a string
// literal, whole or cut into pieces joined with + (`window['eval']`, `self["Func" + "tion"]`)
const EVAL_BY_NAME = "\\[\\s*['\\\"`](?:e(?:['\\\"`]\\s*\\+\\s*['\\\"`])?v(?:['\\\"`]\\s*\\+\\s*['\\\"`])?a(?:['\\\"`]\\s*\\+\\s*['\\\"`])?l|F(?:['\\\"`]\\s*\\+\\s*['\\\"`])?u(?:['\\\"`]\\s*\\+\\s*['\\\"`])?n(?:['\\\"`]\\s*\\+\\s*['\\\"`])?c(?:['\\\"`]\\s*\\+\\s*['\\\"`])?t(?:['\\\"`]\\s*\\+\\s*['\\\"`])?i(?:['\\\"`]\\s*\\+\\s*['\\\"`])?o(?:['\\\"`]\\s*\\+\\s*['\\\"`])?n)['\\\"`]\\s*\\]";
const SC_SINK_WORD_RE = pyRe(String.raw`\b(?:eval|exec|execSync|Function|runIn(?:This|New)?Context)\b|` + EVAL_BY_NAME);
function parenBalance(code) {
  const t = code.replace(STRING_LIT_RE, "");
  let d = 0;
  for (const ch of t) { if (ch === "(") d++; else if (ch === ")") d--; }
  return d;
}
function joinedEvalDecode(ctx, i, ruleRe) {
  const code = ctx.mcode(i);
  if (!SC_SINK_WORD_RE.test(code)) return null;
  let depth = parenBalance(code);
  const trimmed = pyRstrip(code);
  if (depth <= 0 && !SC_SINK_NAMES.some((n) => trimmed.endsWith(n))) return null;
  const parts = [code];
  let added = 0;
  for (let k = i + 1; k < Math.min(ctx.lines.length, i + 1 + SC_JOIN_MAX_LINES); k++) {
    if (ctx.cmask[k]) continue;
    const nxt = ctx.mcode(k);
    parts.push(nxt);
    added += cpLen(nxt);
    depth += parenBalance(nxt);
    if ((depth <= 0 && !isBlank(nxt)) || added > SC_JOIN_MAX_CHARS) break;
  }
  const m = ruleRe.exec(parts.join(" "));
  return m && m.index < code.length ? m.index : null;
}

// Dependency mode also follows a decoded value through variables: a name
// assigned from a decode call (atob, Buffer.from(…, 'base64'), b64decode,
// bytes.fromhex, codecs.decode, unhexlify, zlib.decompress — member prefixes
// allowed), or from an expression naming such a variable, that later appears
// in the arguments of eval / exec / execSync / execFile(Sync) / spawn(Sync) /
// Function / new Function / vm.runIn*Context is SC-EVAL-DECODE at the sink
// (twin of core._dep_decode_flow). A decode call written directly in a
// sink's arguments counts too. `exec` / `eval` are sinks only when called
// bare, on a global object or Python's builtins, or on child_process (the
// module, a require("child_process") call or a name bound to one); any other
// method call (RegExp.prototype.exec, a database's .exec) is not code
// execution. The other sink names count on any receiver.
const DECODE_CALL_SRC = "(?:\\batob|\\bb64decode|\\.\\s*fromhex|\\bunhexlify|\\b(?:codecs|__import__\\(\\s*['\\\"]codecs['\\\"]\\s*\\)|importlib\\.import_module\\(\\s*['\\\"]codecs['\\\"]\\s*\\))\\s*\\.\\s*decode|\\b(?:zlib|__import__\\(\\s*['\\\"]zlib['\\\"]\\s*\\)|importlib\\.import_module\\(\\s*['\\\"]zlib['\\\"]\\s*\\))\\s*\\.\\s*decompress|\\.\\s*decrypt)\\s*\\(|\\bBuffer\\s*\\.\\s*from\\s*\\([^;\\n]{0,300}?['\\\"`]base64['\\\"`]";
const DECODE_CALL_RE = pyRe(DECODE_CALL_SRC);
// A decoder imported under another name (twin of core._decoder_aliases /
// _file_decode_re): `from base64 import b64decode as invoke` makes invoke(…)
// a decode call; `.decrypt(` is one of its own.
const DECODER_IMPORT_RE = pyRe(String.raw`^[ \t]*from[ \t]+(?:base64|binascii|codecs|zlib|marshal|bz2|lzma|gzip)[ \t]+import[ \t]+([^\n#]{1,300})`, "gm");
const DECODER_NAMES = new Set(["b64decode", "b32decode", "b85decode", "a85decode", "decodebytes", "standard_b64decode",
  "urlsafe_b64decode", "unhexlify", "a2b_base64", "a2b_hex", "decode", "decompress", "loads"]);
const PLAIN_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
function decoderAliases(text) {
  const out = [];
  if (!text.includes("import") || !text.includes(" as ")) return out;
  DECODER_IMPORT_RE.lastIndex = 0;
  for (let m; (m = DECODER_IMPORT_RE.exec(text)) !== null;) {
    for (const part of m[1].replaceAll("(", " ").replaceAll(")", " ").split(",")) {
      const bits = part.split(/[\t\n\x0b\x0c\r \x1c-\x1f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/).filter(Boolean);
      if (bits.length === 3 && bits[1] === "as" && DECODER_NAMES.has(bits[0]) && PLAIN_NAME_RE.test(bits[2])
          && !out.includes(bits[2])) out.push(bits[2]);
    }
  }
  return out.slice(0, 20);
}
function fileDecodeRe(content) {
  const aliases = decoderAliases(content);
  return aliases.length ? pyRe(DECODE_CALL_SRC + String.raw`|(?<![\w.])(?:` + aliases.join("|") + String.raw`)\s*\(`) : DECODE_CALL_RE;
}
// The receiver starts at an identifier boundary, (?<![\w$]): every position
// inside a long identifier used to retry the whole rest of it (quadratic).
const DECODE_SINK_RE = pyRe(String.raw`(?:(?<![\w$])(require\s*\(\s*['"\x60][ \w:]*['"\x60]\s*\)|[A-Za-z_$][\w$]*)\s*\.\s*)?`
  + String.raw`(?<![\w$])(eval|exec|execSync|execFile|execFileSync|spawn|spawnSync|Function`
  + String.raw`|runIn(?:This|New)?Context)\s*\(`, "gd");
const GLOBAL_EVAL_RECEIVERS = new Set(["window", "globalThis", "self", "global", "top", "parent",
  "frames", "builtins", "__builtins__"]);
// The indirect calls of eval / Function as sinks of the flow (twin of
// core._INDIRECT_SINK_RE): each match ends at the call's "(". Matched on the
// line as written, since a computed member's name is a string literal; a
// match must start outside one.
const INDIRECT_SINK_RE = pyRe("\\(\\s*(?:void\\s+)?[\\w$.]+\\s*,\\s*(?:(?:window|globalThis|self|global|top|parent|frames)\\s*\\.\\s*)?(?:eval|Function)\\s*\\)\\s*\\(|\\b(?:eval|Function)\\s*\\.\\s*(?:call|apply)\\s*\\(|\\b(?:eval|Function)\\s*\\.\\s*bind\\s*\\([^()]*\\)\\s*\\(|\\bReflect\\s*\\.\\s*apply\\s*\\((?=\\s*(?:(?:window|globalThis|self|global|top|parent|frames)\\s*\\.\\s*)?(?:eval|Function)\\s*,)|\\[\\s*['\\\"`](?:e(?:['\\\"`]\\s*\\+\\s*['\\\"`])?v(?:['\\\"`]\\s*\\+\\s*['\\\"`])?a(?:['\\\"`]\\s*\\+\\s*['\\\"`])?l|F(?:['\\\"`]\\s*\\+\\s*['\\\"`])?u(?:['\\\"`]\\s*\\+\\s*['\\\"`])?n(?:['\\\"`]\\s*\\+\\s*['\\\"`])?c(?:['\\\"`]\\s*\\+\\s*['\\\"`])?t(?:['\\\"`]\\s*\\+\\s*['\\\"`])?i(?:['\\\"`]\\s*\\+\\s*['\\\"`])?o(?:['\\\"`]\\s*\\+\\s*['\\\"`])?n)['\\\"`]\\s*\\]\\s*\\(", "g");
const CHILD_PROCESS_RE = pyRe(String.raw`['"\x60](?:node:)?child_process['"\x60]`);
const CP_ALIAS_RE = pyRe(String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:require|import)\s*\(\s*`
  + String.raw`['"\x60](?:node:)?child_process['"\x60]\s*\)`
  + String.raw`|\bimport\s+(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"\x60](?:node:)?child_process['"\x60]`, "g");
/** Names bound to the child_process module in this file (twin of core._child_process_aliases). */
function childProcessAliases(content) {
  const out = new Set();
  if (!content.includes("child_process")) return out;
  CP_ALIAS_RE.lastIndex = 0;
  let m;
  while ((m = CP_ALIAS_RE.exec(content))) out.add(m[1] ?? m[2]);
  return out;
}
/** Is this DECODE_SINK_RE match a call that runs code? (twin of core._is_code_sink) */
function isCodeSink(code, m, cpAliases) {
  const name = m[2];
  if (name !== "eval" && name !== "exec") return true;
  if (m[1] === undefined) {
    let j = m.indices[2][0] - 1;
    while (j >= 0 && (code[j] === " " || code[j] === "\t")) j--;
    return j < 0 || code[j] !== ".";
  }
  const recv = code.slice(m.indices[1][0], m.indices[1][1]);
  if (recv.startsWith("require")) return name === "exec" && CHILD_PROCESS_RE.test(recv);
  if (GLOBAL_EVAL_RECEIVERS.has(recv)) return name === "eval" || recv === "builtins" || recv === "__builtins__";
  return name === "exec" && (recv === "child_process" || cpAliases.has(recv));
}
const DEP_ASSIGN_RE = pyRe(String.raw`(?<![\w$])([A-Za-z_$][\w$]*)\s*=(?![=>])([^;]*)`, "gd");
const DEP_SINK_ARGS_MAX = 1000;
const blankStrings = (code) => code.replace(STRING_LIT_RE, (s) => s[0] + " ".repeat(s.length - 2) + s[s.length - 1]);
// A decoded value taints names for DEP_FLOW_WINDOW characters from the decode
// (twin of core.DEP_FLOW_WINDOW: unbounded, one ordinary decode in a large
// bundle spread through helper parameters to thousands of names).
const DEP_FLOW_WINDOW = 10000;
// `function exec(`, `function* exec(`, `def exec(`: a definition (on the 24 chars before the name)
const FN_DEF_BEFORE_RE = pyRe(String.raw`(?:^|[^\w$])(?:function\s*\*?|def)\s*$`);
function depDecodeFlow(path, ctx, issues, rule) {
  const identRe = IDENT_RUN_RE[ctx.lang] ?? IDENT_RUN_RE.js;
  const have = new Set(issues.filter((i) => i.rule === "SC-EVAL-DECODE").map((i) => i.line));
  const cpAliases = ctx.lang === "js" ? childProcessAliases(ctx.content) : new Set();
  const decoded = new Map();                 // name -> [line of the decode, its offset in the file]
  const decodeRe = ctx.lang === "py" ? fileDecodeRe(ctx.content) : DECODE_CALL_RE;
  const live = (text, at) => {               // decodes behind the decoded names in text, in reach at `at`
    const out = [];
    identRe.lastIndex = 0;
    let m;
    while ((m = identRe.exec(text))) {
      const d = decoded.get(m[0]);
      if (d && at - d[1] <= DEP_FLOW_WINDOW) out.push(d);
    }
    return out;
  };
  let offset = 0;                            // offset of line i in the file, in code points like core
  for (let i = 0; i < ctx.lines.length; i++) {
    const base = offset;
    offset += cpLen(ctx.lines[i]) + 1;
    if (ctx.cmask[i]) continue;
    const code = ctx.mcode(i);
    if (!code || isBlank(code)) continue;
    if (!(i & 63)) ctx.checkTime();
    const hasDecode = decodeRe.test(code);
    if (!decoded.size && !hasDecode) continue;
    const blank = blankStrings(code);
    const pairs = pairOffsets(code);         // blank keeps code's UTF-16 layout
    const events = [];
    DEP_ASSIGN_RE.lastIndex = 0;
    let m;
    while ((m = DEP_ASSIGN_RE.exec(blank))) events.push([m.index, 0, m]);
    DECODE_SINK_RE.lastIndex = 0;
    while ((m = DECODE_SINK_RE.exec(blank))) events.push([m.index, 1, m]);
    INDIRECT_SINK_RE.lastIndex = 0;
    while ((m = INDIRECT_SINK_RE.exec(code))) if (blank[m.index] === code[m.index]) events.push([m.index, 2, m]);
    events.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
    let close = null;
    for (let n = 0; n < events.length; n++) {
      if (n && !(n & 255)) ctx.checkTime();  // one long line can hold thousands of statements
      const [pos, kind, ev] = events[n];
      const at = base + cpAt(pairs, pos);
      if (kind === 0) {
        const [a, b] = ev.indices[2];
        if (decodeRe.test(code.slice(a, b))) { decoded.set(ev[1], [i + 1, at]); continue; }
        const src = live(blank.slice(a, b), at);
        if (src.length) decoded.set(ev[1], src.reduce((x, y) => (y[1] > x[1] ? y : x)));
        continue;
      }
      if (have.has(i + 1)) continue;
      if (kind === 1) {
        if (!isCodeSink(code, ev, cpAliases)) continue;
        const nameAt = ev.indices[2][0];
        if (FN_DEF_BEFORE_RE.test(blank.slice(Math.max(0, nameAt - 24), nameAt))) continue;  // a definition
      }
      close ??= parenCloseMap(blank);
      const argStart = ev.index + ev[0].length;
      const closed = close.get(argStart - 1);
      if (closed !== undefined && pyLstrip(blank.slice(closed + 1, cpAdvance(pairs, closed + 1, DEP_SINK_ARGS_MAX + 1)))
        .startsWith("{")) continue;          // `exec(a) {`: a method
      const end = Math.min(closed ?? blank.length, cpAdvance(pairs, argStart, DEP_SINK_ARGS_MAX));
      const src = live(blank.slice(argStart, end), at);
      let msg;
      if (src.length) msg = `Decoded payload (assigned at line ${Math.min(...src.map((d) => d[0]))}) reaches a code-execution sink.`;
      else if (decodeRe.test(code.slice(argStart, end))) msg = "Decoded payload reaches a code-execution sink in the same call.";
      else continue;
      have.add(i + 1);
      issues.push(mkIssue({ ...rule, msg }, path, i + 1, ctx.lines, ev.index));
    }
  }
}
const SC_EVAL_DECODE = RULES.find((r) => r.id === "SC-EVAL-DECODE");

// ---- findings cap (spec 7) -------------------------------------------------
// Findings identical on (rule, file, line, msg) are reported once (the first
// is kept): same line, same snippet text in every report. Then every rule
// that is not a security rule (S-, T-, SC-, X-, SQL-) is capped at
// CAP_PER_RULE findings per file, whatever its severity or type (review: a
// MAJOR B-EMPTY-CATCH gave 130,001 findings, an 87.7 MB report, for one
// 1.95 MB line). Twin of core.dedupe_issues / cap_issues.
function cappable(i) {
  return !NEVER_CAPPED_PREFIXES.some((p) => String(i.rule).startsWith(p));
}
/** `issues` without repeats of the same (rule, file, line, msg); the first of each is kept, in order. */
export function dedupeIssues(issues) {
  const seen = new Set(), out = [];
  for (const i of issues) {
    const key = JSON.stringify([i.rule, i.file, i.line, i.msg]);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(i);
  }
  return out;
}
/** Deduplicated; then at most CAP_PER_RULE findings per rule, in line order; one Q-CAPPED per capped rule at its first omitted line. */
export function capIssues(path, issues, lines) {
  issues = dedupeIssues(issues);
  const order = issues.map((_, k) => k).sort((a, b) => (issues[a].line ?? 0) - (issues[b].line ?? 0) || a - b);
  const counts = new Map(), dropped = new Set(), omitted = new Map();
  for (const k of order) {
    const i = issues[k];
    if (!cappable(i)) continue;
    const n = (counts.get(i.rule) ?? 0) + 1;
    counts.set(i.rule, n);
    if (n > CAP_PER_RULE) {
      dropped.add(k);
      const o = omitted.get(i.rule);
      if (o) o[0]++; else omitted.set(i.rule, [1, i.line, i.type]);
    }
  }
  if (!dropped.size) return issues;
  const out = issues.filter((_, k) => !dropped.has(k));
  for (const [rid, [n, first, type]] of omitted) {
    const note = mkIssue({ id: "Q-CAPPED", name: "Findings capped", type: "SMELL", sev: "INFO",
      msg: `${n} more ${rid} findings omitted`,
      why: "Findings of one rule that repeat hundreds of times in one file are capped so reports stay readable; security findings are never capped.",
      fix: `Fix or deliberately suppress the ${rid} pattern in this file, then re-scan to see the remaining occurrences.`,
      ref: "Maintainability" }, path, first, lines);
    // what the note stands for: the maintainability rating counts the
    // omitted findings, not the note (metrics.js maintainabilityRating)
    note.omitted = n;
    note.omittedType = type;
    out.push(note);
  }
  return out;
}

function lineStarts(content) {
  const starts = [0];
  let p = content.indexOf("\n");
  while (p !== -1) { starts.push(p + 1); p = content.indexOf("\n", p + 1); }
  return starts;
}

/**
 * Scan one file: {name|path, content, lang, dep}. dep → dependency mode:
 * only supply-chain and secret rules, no suppression markers honored.
 */
export function scanFile(file) {
  const path = file.name ?? file.path;
  const lang = file.lang ?? detectLang(String(path ?? ""), String(file.content ?? ""));
  const dep = !!file.dep;
  const content = pinUnicode(normalizeSource(file.content, lang));   // Unicode 13.0 (core._unicode13)
  const lines = content.split("\n");
  const ctx = new FileCtx(lines, lang, content, Date.now() + timeBudgetMs, jsxReading(path));
  registerScanContext(lines, SECRET_SKIP_RE);
  const issues = [];
  try {
    scanLines(path, content, lines, lang, dep, ctx, issues);
  } catch (e) {
    if (!(e instanceof ScanBudgetExceeded)) throw e;
    issues.push(truncatedIssue(path, "scan time budget exceeded"));
  }
  const suppressed = makeSuppressor(lines, lang, { dep, lex: ctx.lex });
  return capIssues(path, issues.filter((i) => !suppressed(i)), lines);
}

// ---- config and data files (credentials only; core.scan_config_file) -------
const TOKEN_RULE = RULES.find((r) => r.id === "S-TOKEN");
export const CONFIG_SECRET_RULE = {
  id: "S-SECRET", name: "Hardcoded credential", type: "VULN", sev: "BLOCKER",
  msg: "Credential appears to be hardcoded in a config file.",
  why: "Config files are committed, copied into images and shared: a credential in one leaks with every copy, and rotating it means finding them all.",
  fix: "Reference it instead (${VAR}, a secrets manager), and rotate this one now.",
  ref: "CWE-798 · OWASP A07",
};

/**
 * Column of the first S-TOKEN match on a config line that is reported: not a
 * documentation sample, and a private-key header only with key material after
 * it, on the line or the next two (core._config_token_col). -1 if none.
 */
function configTokenCol(line, lines, i) {
  let t, from = 0;
  while ((t = findSecretToken(line, from))) {
    from = t.end;
    if (documentationToken(t.text)) continue;
    if (t.text.startsWith("-----BEGIN")
        && ![line.slice(t.end), ...lines.slice(i + 1, i + 3)].some((x) => keyMaterial(x))) continue;
    return t.index;
  }
  return -1;
}

// ---- settings that run commands (SC-AUTORUN; core's section comment) ----
export const AUTORUN_SHOW = 200;           // code points of a command a message shows
const AUTORUN_WHY =
  "Editors and AI coding agents run these commands on their own — when the folder is opened, a " +
  "session starts or the agent uses a tool — with your privileges, without asking each time. The " +
  "2026 Shai-Hulud worms (Mini Shai-Hulud, the keyv wave) committed a Claude Code SessionStart hook " +
  "and a VS Code folder-open task to every repository they reached, so opening a checkout ran the " +
  "worm.";

const autorunRule = (sev, msg, why, fix) => ({
  id: "SC-AUTORUN", name: "Settings run a command automatically", type: "HOTSPOT", sev, msg, why, fix,
  ref: "CWE-506 · Supply chain",
});

const AGENT_SETTINGS_REASON = "writes an AI agent's or editor's auto-run settings";
/** installScriptRisk for what a settings file runs, but for writing an agent's settings (core._autorun_script_risk). */
const autorunScriptRisk = (text) => installScriptRisk(text).filter((r) => !r.startsWith(AGENT_SETTINGS_REASON));

/** [reasons, target] for a command a settings file runs (core._autorun_risk). */
function autorunRisk(command, base, read) {
  const reasons = [];
  const hijack = agentHijackInCommand(command);
  if (hijack !== null) reasons.push(`starts the AI agent "${hijack[0]}" with ${hijack[1]}`);
  reasons.push(...autorunScriptRisk(command));
  if (reasons.length || read === null) return [reasons, null];
  for (const target of followHook(localCommand(command))[0]) {
    const rel = treeJoin(base, target);
    const text = rel !== null ? read(rel) : null;
    if (text === null) continue;
    const found = autorunScriptRisk(text);
    OBF_IDENT_RE.lastIndex = 0;
    if (new Set(text.match(OBF_IDENT_RE) ?? []).size >= 5) found.push("is obfuscated");
    if (found.length) return [found, target];
  }
  return [[], null];
}

/** SC-AUTORUN findings for an editor's or AI agent's settings file (core.autorun_issues). */
export function autorunIssues(path, lines, read = null) {
  const [kind, tool] = configKind(path);
  const [found, error] = autorunEntries(kind, tool, lines.join("\n"));
  if (error !== null) {
    return [mkIssue(autorunRule("MAJOR",
      `These ${tool} settings could not be read as JSON (line ${error[0]}: ${error[1]}), ` +
      `but they name commands for ${tool} to run: read them by hand.`,
      AUTORUN_WHY, "Fix the file so it can be read, and check every command it names."), path, error[0], lines)];
  }
  const base = ownerDir(path);
  const out = [];
  for (const e of found) {
    const cmd = e.command;
    if (cmd === null) {
      out.push(mkIssue(autorunRule("INFO", `${e.trigger}.`, AUTORUN_WHY + " Listed for inventory.",
        "Check that you added it."), path, e.line, lines));
      continue;
    }
    const shown = cpLen(cmd) <= AUTORUN_SHOW ? cmd : cpPrefix(cmd, AUTORUN_SHOW) + "…";
    const [reasons, target] = autorunRisk(cmd, base, read);
    if (!reasons.length) {
      out.push(mkIssue(autorunRule("INFO", `${e.trigger}: ${pyRepr(shown)}.`, AUTORUN_WHY + " Listed for inventory.",
        "Check that you added it, and what it runs."), path, e.line, lines));
      continue;
    }
    const said = reasons.join("; and ");
    const msg = target === null ? `${e.trigger}: ${pyRepr(shown)} — a command that ${said}.`
      : `${e.trigger}: ${pyRepr(shown)}, which runs ${target}; that file ${said}.`;
    out.push(mkIssue(autorunRule("CRITICAL", msg, AUTORUN_WHY + " This one runs code that looks hostile.",
      "Do not open the folder in the editor or start the agent in it. Remove the entry and what it " +
      "runs, find the commit that added them, and rotate the credentials this machine holds if it " +
      "already ran."), path, e.line, lines));
  }
  return out;
}

// ---- workflows the worms planted (SC-WORKFLOW-*; core.workflow_issues) ----
const WORKFLOW_SECRETS_WHY =
  "`${{ toJSON(secrets) }}` is every secret of the repository in one value: a job that holds it can " +
  "leak them all, and a workflow that also sends it out is how the Shai-Hulud worms stole secrets " +
  "from the repositories they reached (a webhook.site upload, a build artifact).";
const WORKFLOW_BACKDOOR_WHY =
  "A `${{ … }}` expression is pasted into the script before it runs, so text from an issue, a " +
  "discussion or a pull request becomes shell commands; on a self-hosted runner they run on that " +
  "machine. The second Shai-Hulud wave registered its victims' machines as self-hosted runners and " +
  "planted exactly this workflow (discussion.yaml): opening a discussion ran commands on the victim's " +
  "machine.";

/** SC-WORKFLOW-SECRETS / SC-WORKFLOW-BACKDOOR for a GitHub Actions workflow (core.workflow_issues). */
export function workflowIssues(path, lines) {
  const out = [];
  for (const [kind, line, d] of workflowFindings(lines.join("\n"))) {
    if (kind === "secrets") {
      const sent = d.how !== null;
      out.push(mkIssue({
        id: "SC-WORKFLOW-SECRETS", name: "Workflow hands out every secret", type: "HOTSPOT",
        sev: sent ? "CRITICAL" : "MAJOR",
        msg: sent ? `The workflow hands every repository secret to ${d.where} and sends data out ` +
            `(${d.how}): the Shai-Hulud worms planted workflows like this.`
          : `The workflow hands every repository secret to ${d.where} (toJSON(secrets)): any ` +
            "step there can read them all.",
        why: WORKFLOW_SECRETS_WHY,
        fix: "Delete the workflow unless you wrote it, then rotate every secret of the repository. " +
          "A job should get only the secrets it uses, by name (${{ secrets.NAME }}).",
        ref: "CWE-200 · Supply chain" }, path, line, lines));
    } else {
      out.push(mkIssue({
        id: "SC-WORKFLOW-BACKDOOR", name: "Workflow runs event text on a self-hosted runner",
        type: "HOTSPOT", sev: "CRITICAL",
        msg: `The job "${d.job}" puts ${d.expr} into a command on a self-hosted runner, and ` +
          `${d.event} events start it: anyone who can ${d.act} runs commands on that machine.`,
        why: WORKFLOW_BACKDOOR_WHY,
        fix: "Delete the workflow unless you wrote it, and remove any runner you did not register. " +
          "Otherwise pass the text through an environment variable and quote it in the script.",
        ref: "CWE-94 · Supply chain" }, path, line, lines));
    }
  }
  return out;
}

/**
 * read(rel) for autorunIssues: the text of a scanned source or config file
 * ('/'-separated, root-relative, resolved as nodeCandidates does), or null
 * (core.tree_reader).
 */
export function treeReader(files, configs) {
  const texts = new Map();
  for (const f of [...files, ...configs]) {
    const key = f.path.replaceAll("\\", "/");
    if (!texts.has(key)) texts.set(key, f.content);
  }
  return (rel) => {
    for (const cand of nodeCandidates(rel)) if (texts.has(cand)) return normalizeNewlines(texts.get(cand));
    return null;
  };
}

/**
 * Credentials in a config or data file (twin of core.scan_config_file):
 * S-TOKEN on every line, S-SECRET outside comments, nothing else — it is not
 * code. Suppression markers work in the file's comments, as in code. An
 * editor's or AI agent's settings that run commands also get SC-AUTORUN, and
 * a GitHub Actions workflow the SC-WORKFLOW-* checks.
 */
export function scanConfigFile(path, rawContent, read = null) {
  const content = pinUnicode(normalizeSource(rawContent, "cfg"));
  const lines = content.split("\n");
  const lex = lexLines(lines, "cfg", content);
  registerScanContext(lines, SECRET_SKIP_RE, redactConfigValues);
  const deadline = Date.now() + timeBudgetMs;
  const issues = [];
  try {
    if (configKind(path) !== null) issues.push(...autorunIssues(path, lines, read));
    if (isWorkflow(path)) issues.push(...workflowIssues(path, lines));
    for (let i = 0; i < lines.length; i++) {
      if (Date.now() > deadline) throw new ScanBudgetExceeded();
      const line = lines[i];
      if (!line || isBlank(line)) continue;
      let col = configTokenCol(line, lines, i);
      if (col >= 0) issues.push(mkIssue(TOKEN_RULE, path, i + 1, lines, col));
      if (!lex.comment[i]) {
        col = secretCol(lex.code[i]);
        if (col >= 0) issues.push(mkIssue(CONFIG_SECRET_RULE, path, i + 1, lines, col));
      }
    }
  } catch (e) {
    if (!(e instanceof ScanBudgetExceeded)) throw e;
    issues.push(truncatedIssue(path, "scan time budget exceeded"));
  }
  const suppressed = makeSuppressor(lines, "cfg", { lex });
  return capIssues(path, issues.filter((i) => !suppressed(i)), lines);
}

function longLineIssue(path, i, lines) {
  return mkIssue({ id: "Q-LONGLINE", name: "Line too long", type: "SMELL", sev: "MINOR",
    msg: `Line exceeds ${LONG_LINE} characters.`,
    why: "Very long lines hurt readability and reviews.",
    fix: "Break the line up for readability.", ref: "Maintainability" }, path, i + 1, lines);
}

function scanLines(path, content, lines, lang, dep, ctx, issues) {
  const { cmask } = ctx;
  const mlines = ctx.mlines;
  const rules = RULES.filter((r) => r.langs.includes(lang)
    && (!dep || DEP_RULE_PREFIXES.some((p) => r.id.startsWith(p))));
  const secretLines = new Set();          // lines with S-TOKEN / S-SECRET (S-ENTROPY dedupe)
  let fileWords = null;                   // the file's ASCII words, read when a look-alike name needs them
  const words = () => (fileWords ??= new Set(content.match(ASCII_WORD_RE) ?? []));
  let runsCodeFlag = null;                 // whether the file runs code from a string (SC-HIDDEN-UNICODE severity)
  const fileRunsCode = () => (runsCodeFlag ??= HIDDEN_EXEC_RE.test(content));
  for (let i = 0; i < lines.length; i++) {
    ctx.checkTime();
    const line = lines[i];
    if (!line || isBlank(line)) {
      // no rule or heuristic matches whitespace alone; only the length rule applies
      if (!dep && cpLen(line) > LONG_LINE) issues.push(longLineIssue(path, i, lines));
      continue;
    }
    const mline = mlines[i];
    for (const r of rules) {
      if (cmask[i] && !COMMENT_LINE_RULES.has(r.id)) continue;
      // equality checks shouldn't match inside string literals
      const target = r.id === "B-EQEQ" ? mline.replace(STRING_LIT_RE, '""') : mline;
      let col;
      if (r.find) col = r.find(target);
      else { const m = r.re.exec(target); col = m ? m.index : -1; }
      if (col < 0 && r.id === "SC-EVAL-DECODE" && !cmask[i]) col = joinedEvalDecode(ctx, i, r.re) ?? -1;
      if (col < 0) continue;
      if (r.need && !r.need.test(mline)) continue;
      if (r.skip && r.skip.test(mline)) continue;
      if (r.id === "S-TOKEN" && !tokenHasMaterial(mline, mlines, i)) continue;
      if (r.id === "S-TOKEN" || r.id === "S-SECRET") secretLines.add(i);
      issues.push(mkIssue(r, path, i + 1, lines, col));
    }
    if (!dep && cpLen(line) > LONG_LINE) issues.push(longLineIssue(path, i, lines));
    // --- obfuscation heuristics (strong supply-chain indicators) ---
    const hidden = hexHiddenText(line);
    if (hidden !== null) {
      const dangerous = HIDDEN_TEXT_DANGER_RE.test(hidden);
      const preview = hidden.length <= 60 ? hidden : hidden.slice(0, 57) + "...";
      issues.push(mkIssue({ id: "SC-HEXSTR", name: "Hex-escaped readable text", type: "HOTSPOT",
        sev: dangerous ? "CRITICAL" : "MAJOR",
        msg: `Hex escapes hide readable text: ${pyRepr(preview)}.`,
        why: "Escaping ordinary printable characters serves no purpose except hiding them from review and search; this text "
          + (dangerous ? "names code execution, a download, or a URL." : "is readable once decoded."),
        fix: "Decode the string and review what it does.",
        ref: "CWE-506 · Supply chain" }, path, i + 1, lines, line.search(/\\x[0-9A-Fa-f]{2}/)));
    } else {
      const name = hexHiddenName(line);
      if (name) issues.push(mkIssue({ id: "SC-HEXSTR", name: "Hex-escaped readable text", type: "HOTSPOT",
        sev: "CRITICAL", msg: `Escape sequences hide a name: ${pyRepr(name[0])}.`,
        why: "Nothing needs to escape a letter of a name like this one: writing it as escape sequences only hides it from review and search, and this one names code execution, a download, or a URL.",
        fix: "Decode the string and review what it does.",
        ref: "CWE-506 · Supply chain" }, path, i + 1, lines, name[1]));
    }
    if ((lang === "js" || lang === "py") && !cmask[i]) {
      const code = ctx.mcode(i);
      if (!isAscii(code)) {
        const found = lookalikeName(ctx.namesCode(i), lang, words);
        if (found) issues.push(lookalikeIssue(found, path, i + 1, lines));
      }
      if (!dep && runsDownloadThroughShell(code))
        issues.push(mkIssue(PIPE_SHELL_RULE, path, i + 1, lines, EXEC_CALL_RE.exec(code).index));
    }
    if (!isAscii(line)) {
      const hrun = hiddenUnicodeRun(line);
      if (hrun) issues.push(hiddenUnicodeIssue(path, i + 1, lines, hrun[0], hrun[1], fileRunsCode()));
    }
    const cmCol = lang === "js" ? charcodeCol(line) : null;
    if (cmCol !== null)
      issues.push(mkIssue({ id: "SC-CHARCODE", name: "Char-code string building", type: "HOTSPOT", sev: "MAJOR",
        msg: "String assembled from character codes — obfuscation indicator.",
        why: "fromCharCode chains hide payloads from static review.",
        fix: "Decode and review what string is being built.",
        ref: "CWE-506 · Supply chain" }, path, i + 1, lines, cmCol));
    const bm = B64_BLOB_RE.exec(line);
    if (bm && !line.includes("sourceMappingURL"))
      issues.push(mkIssue({ id: "SC-B64", name: "Large base64 blob", type: "HOTSPOT", sev: "MAJOR",
        msg: "Base64 blob (200+ chars) embedded in code.",
        why: "Embedded encoded blobs can carry second-stage payloads.",
        fix: "Decode and verify the content; move legitimate assets to data files.",
        ref: "CWE-506 · Supply chain" }, path, i + 1, lines, bm.index));
    if (lang === "js" || lang === "py") {
      const off = offscreenCode(line, lang);
      if (off !== null && pyStrip(ctx.namesCode(i)) !== "") issues.push(offscreenIssue(path, i + 1, lines, off));
    }
    // --- entropy-based secret detection ---
    if (!cmask[i] && !secretLines.has(i) && !SECRET_SKIP_RE.test(line)) {
      const em = ENTROPY_VALUE_RE.exec(line);
      if (em && entropySecretish(em[1]))
        issues.push(mkIssue({ id: "S-ENTROPY", name: "High-entropy string", type: "HOTSPOT", sev: "MAJOR",
          msg: "High-entropy string literal — possible hardcoded secret.",
          why: "Random-looking constants are usually keys or tokens.",
          fix: "If it is a secret, rotate it and load it from the environment.",
          ref: "CWE-798 · OWASP A07" }, path, i + 1, lines, em.index + em[0].indexOf(em[1], 1)));
    }
  }
  // file-level: javascript-obfuscator identifier signature
  if (lang === "js" && content.includes("_0x")) {
    OBF_IDENT_RE.lastIndex = 0;
    const obf = content.match(OBF_IDENT_RE) || [];
    const uniq = new Set(obf);
    if (uniq.size >= 5) {
      const firstOff = content.indexOf(obf[0]);
      let firstLine = 1;
      for (let k = content.indexOf("\n"); k !== -1 && k < firstOff; k = content.indexOf("\n", k + 1)) firstLine++;
      issues.push(mkIssue({ id: "SC-OBF-IDENT", name: "Obfuscated identifier pattern", type: "HOTSPOT", sev: "CRITICAL",
        msg: `${uniq.size} '_0x…' identifiers — javascript-obfuscator signature.`,
        why: "This naming pattern is produced by obfuscation tools; in a dependency it is a classic indicator of a compromised or malicious package.",
        fix: "Diff against the package's published repository; consider removing the dependency.",
        ref: "CWE-506 · Supply chain" }, path, firstLine, lines, firstOff - content.lastIndexOf("\n", firstOff - 1) - 1));
    }
  }
  if (lang === "js" || lang === "py") {
    const at = selfPublishAt(content);
    if (at >= 0) {
      let lineNo = 1;
      for (let k = content.indexOf("\n"); k !== -1 && k < at; k = content.indexOf("\n", k + 1)) lineNo++;
      issues.push(mkIssue(SELF_PUBLISH_RULE, path, lineNo, lines, at - content.lastIndexOf("\n", at - 1) - 1));
    }
  }
  if (dep) {
    depDecodeFlow(path, ctx, issues, SC_EVAL_DECODE);
    return;
  }
  const mcontent = mlines === lines ? content : mlines.join("\n");
  let starts = null;
  for (const r of TEXT_RULES) {
    // *-NOWHERE SQL rules are fired by scanSqlNowhere() (linear pass)
    if (!r.langs.includes(lang) || !r.scan) continue;
    let n = 0, last = -1;
    for (const off of r.scan(mcontent)) {
      if (!(n++ & 255)) ctx.checkTime();     // the time backstop also holds inside one rule
      starts ??= lineStarts(mcontent);
      const lineNo = upperBound(starts, off);
      if (lineNo === last) continue;         // same (rule, line, msg): reported once (capIssues)
      last = lineNo;
      issues.push(mkIssue(r, path, lineNo, lines, off - starts[lineNo - 1]));
    }
    ctx.checkTime();
  }
  ctx.checkTime();
  if (lang === "sql") {
    try { scanSqlNowhere(path, content, issues, lines); } catch { /* analyzer must never break a scan */ }
  }
  ctx.checkTime();
  for (const t of taintScan(path, lines, lang, ctx)) issues.push(t);
  // G12: whole-argument SQL-sink analysis (Python, project mode)
  if (lang === "py") {
    try { sqlSinkScan(path, mlines, issues, lines); } catch (e) { if (e instanceof ScanBudgetExceeded) throw e; }
  }
  ctx.checkTime();
  for (const fn of extractFunctions(lines, lang)) {
    if (fn.len > FN_LEN_LIMIT) issues.push(mkIssue({ id: "Q-FN-LONG", name: "Function too long", type: "SMELL", sev: "MAJOR",
      msg: `Function "${fn.name}" is ${fn.len} lines long (limit ${FN_LEN_LIMIT}).`,
      why: "Long functions do too much and resist testing and reuse.",
      fix: "Extract cohesive blocks into helper functions.", ref: "Maintainability" }, path, fn.line, lines));
    if (fn.cx > FN_CX_LIMIT) issues.push(mkIssue({ id: "Q-FN-CX", name: "High cyclomatic complexity", type: "SMELL", sev: "MAJOR",
      msg: `Function "${fn.name}" has complexity ~${fn.cx} (limit ${FN_CX_LIMIT}).`,
      why: "Highly branched code is hard to reason about and to cover with tests.",
      fix: "Split branches into smaller functions; use early returns or lookup tables.", ref: "Maintainability" }, path, fn.line, lines));
  }
}

const CHARCODE_NUM_RE = pyRe(String.raw`\b\d{2,3}\b`, "g");
// SC-CHARCODE (twin of core._charcode_col): String.fromCharCode building text
// from character codes written in the code: ten or more 2-3 digit numbers
// inside the call's own parentheses (also through .apply / .call), or a name
// the call uses that the same line assigns an array of ten or more
// printable-ASCII codes. Counting numbers anywhere on the line made every
// fromCharCode on a long minified line fire (binary parsers, UTF-16 surrogate
// encoders), and so did any such array anywhere on the line.
const CHARCODE_ALL_RE = /String\.fromCharCode/g;
// NAME = [n, n, …] with ten or more numbers of two or three digits: what
// core._CHARCODE_TABLE_RE finds,
//   (?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*\[((?:\s*[0-9]{2,3}\s*,){9,}\s*[0-9]{2,3})\s*\]
// with the part before '[' matched and the numbers read by a loop: V8
// overflowed its stack on the repeated group over an array of a few million
// characters (review B3). -> [[name, numbers], …], as finditer finds them.
const CHARCODE_TABLE_HEAD_RE = pyRe(String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*\[`, "g");
export function charcodeTables(line) {
  const out = [];
  const n = line.length;
  CHARCODE_TABLE_HEAD_RE.lastIndex = 0;
  let m;
  while ((m = CHARCODE_TABLE_HEAD_RE.exec(line))) {
    const nums = [];
    let i = m.index + m[0].length, end = -1;
    for (;;) {
      while (i < n && isPySpace(line[i])) i++;
      const d = i;
      while (i < n && line.charCodeAt(i) >= 48 && line.charCodeAt(i) <= 57) i++;
      if (i - d < 2 || i - d > 3) break;
      nums.push(+line.slice(d, i));
      while (i < n && isPySpace(line[i])) i++;
      if (line[i] === ",") { i++; continue; }
      if (line[i] === "]" && nums.length >= 10) end = i + 1;
      break;
    }
    if (end >= 0) out.push([m[1], nums]);
    CHARCODE_TABLE_HEAD_RE.lastIndex = end >= 0 ? end : m.index + 1;
  }
  return out;
}
const CHARCODE_NAME_RE = pyRe(String.raw`(?<![\w$])(?:(?<=\.\.\.)|(?<!\.))[A-Za-z_$][\w$]*`, "g");  // a bare name; `...k` is a spread
const CHARCODE_CALL_TAIL_RE = pyRe(String.raw`\s*(?:\.\s*(?:apply|call)\s*)?\(`, "y");
const CHARCODE_ARGS_MAX = 4000;
const CHARCODE_SCAN_BUDGET = 200000;
/** Index of the ')' closing the '(' at k, or null before `stop` (twin of core._call_args_end). */
function callArgsEnd(line, k, stop) {
  let depth = 0, quote = null, j = k;
  while (j < stop) {
    const c = line[j];
    if (quote !== null) {
      if (c === "\\") { j += 2; continue; }
      if (c === quote) quote = null;
    } else if (c === "'" || c === '"' || c === "`") quote = c;
    else if (c === "(") depth++;
    else if (c === ")") { depth--; if (depth === 0) return j; }
    j++;
  }
  return null;
}
function lowerBound(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] < x) lo = mid + 1; else hi = mid; }
  return lo;
}
// core indexes lines by code point, this engine by UTF-16 unit; the bounded
// windows (CHARCODE_ARGS_MAX, DEP_SINK_ARGS_MAX, DEP_FLOW_WINDOW, the scan
// budget) are counted in code points here too, so both engines cut in the
// same place when a line holds astral characters.
const SURROGATE_PAIR_RE = /[\ud800-\udbff][\udc00-\udfff]/g;
/** UTF-16 offsets of the surrogate pairs in s (empty when there are none). */
function pairOffsets(s) {
  const out = [];
  if (/[\ud800-\udbff]/.test(s)) for (const p of s.matchAll(SURROGATE_PAIR_RE)) out.push(p.index);
  return out;
}
/** Code-point offset of the UTF-16 offset u. */
const cpAt = (pairs, u) => (pairs.length ? u - lowerBound(pairs, u) : u);
/** UTF-16 offset of the point n code points after offset k. */
function cpAdvance(pairs, k, n) {
  if (!pairs.length) return k + n;
  const before = lowerBound(pairs, k);
  for (let u = k + n; ;) {
    const v = k + n + lowerBound(pairs, u) - before;
    if (v === u) return u;
    u = v;
  }
}
function charcodeCol(line) {
  if (!CHARCODE_RE.test(line)) return null;
  let m;
  const nums = [];
  CHARCODE_NUM_RE.lastIndex = 0;
  while ((m = CHARCODE_NUM_RE.exec(line))) nums.push(m.index);
  if (nums.length < 10) return null;                    // a code table has ten too
  const tables = new Set();
  for (const [name, codes] of charcodeTables(line)) if (codes.every((v) => v >= 32 && v <= 126)) tables.add(name);
  const refs = [];
  if (tables.size) {
    CHARCODE_NAME_RE.lastIndex = 0;
    while ((m = CHARCODE_NAME_RE.exec(line))) if (tables.has(m[0])) refs.push(m.index);
  }
  const pairs = pairOffsets(line);
  let budget = CHARCODE_SCAN_BUDGET;
  CHARCODE_ALL_RE.lastIndex = 0;
  while ((m = CHARCODE_ALL_RE.exec(line))) {
    CHARCODE_CALL_TAIL_RE.lastIndex = m.index + m[0].length;
    const t = CHARCODE_CALL_TAIL_RE.exec(line);
    if (!t) continue;
    const k = t.index + t[0].length - 1;                 // the '('
    const stop = Math.min(line.length, cpAdvance(pairs, k, CHARCODE_ARGS_MAX));
    const end = budget > 0 ? callArgsEnd(line, k, stop) : null;
    const e = end === null ? stop : end;
    budget -= cpAt(pairs, e) - cpAt(pairs, k);
    if (lowerBound(nums, e) - lowerBound(nums, k) >= 10 || lowerBound(refs, e) > lowerBound(refs, k)) return m.index;
  }
  return null;
}
