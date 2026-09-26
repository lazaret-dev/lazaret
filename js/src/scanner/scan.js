// scanFile — twin of lazaret.scanner.core.scan_file / _scan_file,
// implementing the shared semantics (FIX-SPEC items 1, 2, 5, 6, 7, 12, 13, 14).
import { normalizeSource } from "./lines.js";
import { RULES, TEXT_RULES } from "./rules.js";
import { STRING_LIT_RE, TAINT_SOURCES, TAINT_SINKS, PARTIAL_SAN, neutralize, parseAssignment } from "./taint.js";
import { sqlSinkScan, scanSqlNowhere, parenCloseMap } from "./sql.js";
import {
  B64_BLOB_RE, OBF_IDENT_RE, SECRET_SKIP_RE, CHARCODE_RE, ENTROPY_VALUE_RE, entropySecretish,
  makeSuppressor, mkIssue,
} from "./engine.js";
import { lexLines } from "./lexer.js";
import { extractFunctions } from "./functions.js";
import { cpLen, pyRe, pyRepr, pyRstrip, isPySpace } from "../lib/pycompat.js";
import { findSecretToken, registerScanContext } from "../lib/redact.js";
import { truncatedIssue } from "../lib/fs.js";

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
  if (/\.(py)$/i.test(name)) return "py";
  if (/\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(name)) return "js";
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
const pyMatchText = (t) => (NON_ASCII_RE.test(t) ? t.normalize("NFKC") : t);

class FileCtx {
  constructor(lines, lang, content, deadline) {
    this.lines = lines;
    this.lang = lang;
    this.content = content;
    this.lex = lexLines(lines, lang, content);
    this.cmask = this.lex.comment;
    this.deadline = deadline;
    this._mlines = null;
    this._mcode = new Map();
    this._strStarts = null;
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
  jsText(i, dropComments) {
    const line = this.lines[i];
    const plain = dropComments ? this.lex.code[i] : line;
    if (!line.includes("\\u")) return plain.includes("\ufeff") ? plain.replaceAll("\ufeff", " ") : plain;
    if (this._strStarts === null) this._strStarts = this.lex.strings.map((s) => s[0]);
    const base = this.lex.starts[i];
    const cuts = dropComments ? (this.lex.spans.get(i) || []) : [];
    const edits = cuts.map(([a, b]) => [a, b, ""]);
    JS_UESC_RE.lastIndex = 0;
    let m;
    while ((m = JS_UESC_RE.exec(line))) {
      const at = m.index;
      if (cuts.some(([a, b]) => a <= at && at < b)) continue;
      const k = upperBound(this._strStarts, base + at) - 1;
      if (k >= 0 && this.lex.strings[k][1] > base + at) continue;   // inside a '…' or "…" literal
      const cp = parseInt(m[1] ?? m[2], 16);
      if (cp > 0x10ffff) continue;
      const ch = String.fromCodePoint(cp);
      if (ch === "$" || ID_CONTINUE_RE.test(ch)) edits.push([at, at + m[0].length, ch]);
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

// A "-----BEGIN ... PRIVATE KEY-----" header alone is not a key: libraries keep the
// header as a constant to recognize key files. Require base64 key material after it,
// on the same line or the next two. Twin of core._token_has_material.
const PEM_BODY_RE = /[A-Za-z0-9+/]{40,}={0,2}/;
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
 * variables) taint every bound name (spec 12); a sink whose arguments carry
 * a tainted variable (or a source) not cleansed for that sink is reported.
 */
export function taintScan(file, lines, lang, ctx = null) {
  const src = TAINT_SOURCES[lang];
  if (!src) return [];                   // SQL and others: pattern rules only
  if (!ctx || ctx.lines !== lines) {
    const content = lines.join("\n");
    ctx = new FileCtx(lines, lang, content, Infinity);
  }
  const issues = [];
  const tainted = new Map();             // var -> {line, clean:Set(suffix), order}
  const partialCats = Object.keys(PARTIAL_SAN[lang] || {});
  const identRe = IDENT_RUN_RE[lang];
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
  for (let i = 0; i < lines.length; i++) {
    if (ctx.cmask[i]) continue;
    const line = ctx.mcode(i);
    if (!line || isBlank(line)) continue;
    if (!(i & 63)) ctx.checkTime();
    const a = parseAssignment(line, lang);
    if (a) {
      const base = neutralize(a.rhs, lang).replace(STRING_LIT_RE, "");
      if (src.test(base) || carriers(base, null).length) {
        const clean = new Set();
        for (const suf of partialCats) {
          const neut = neutralize(a.rhs, lang, suf).replace(STRING_LIT_RE, "");
          if (!src.test(neut) && !carriers(neut, suf).length) clean.add(suf);
        }
        for (const name of a.names) if (!tainted.has(name)) tainted.set(name, { line: i + 1, clean, order: tainted.size });
      }
    }
    for (const [suffix, sinkRe, cat, sev, cwe, fix] of TAINT_SINKS[lang]) {
      const sm = sinkRe.exec(line);
      if (!sm) continue;
      const rest = neutralize(line.slice(sm.index + sm[0].length), lang, suffix);
      const restCode = rest.replace(STRING_LIT_RE, "");
      const found = carriers(restCode, suffix);
      if (!found.length && !src.test(restCode)) continue;
      const what = found.length ? `untrusted data via '${found[0]}' (tainted at line ${tainted.get(found[0]).line})` : "untrusted data";
      issues.push(mkIssue({ id: `T-${suffix}`, name: `Tainted flow → ${cat}`, type: "VULN", sev,
        msg: `Possible ${cat}: ${what} reaches this sink.`,
        why: "Data from user input or a decode function flows into a dangerous call without visible sanitization (lightweight intra-file taint tracking).",
        fix, ref: `${cwe} · Taint analysis` }, file, i + 1, lines, sm.index));
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
const SC_SINK_WORD_RE = pyRe(String.raw`\b(?:eval|exec|execSync|Function|runIn(?:This|New)?Context)\b`);
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
// (twin of core._dep_decode_flow).
const DECODE_CALL_RE = pyRe(String.raw`(?:\batob|\bb64decode|\.\s*fromhex|\bunhexlify|\bcodecs\s*\.\s*decode`
  + String.raw`|\bzlib\s*\.\s*decompress)\s*\(|\bBuffer\s*\.\s*from\s*\([^;\n]{0,300}?['\"` + "`" + String.raw`]base64['\"` + "`]");
const DECODE_SINK_RE = pyRe(String.raw`\b(?:eval|exec|execSync|execFile|execFileSync|spawn|spawnSync|Function`
  + String.raw`|runIn(?:This|New)?Context)\s*\(`, "g");
const DEP_ASSIGN_RE = pyRe(String.raw`(?<![\w$])([A-Za-z_$][\w$]*)\s*=(?![=>])([^;]*)`, "gd");
const DEP_SINK_ARGS_MAX = 1000;
const blankStrings = (code) => code.replace(STRING_LIT_RE, (s) => s[0] + " ".repeat(s.length - 2) + s[s.length - 1]);
function depDecodeFlow(path, ctx, issues, rule) {
  const identRe = IDENT_RUN_RE[ctx.lang] ?? IDENT_RUN_RE.js;
  const have = new Set(issues.filter((i) => i.rule === "SC-EVAL-DECODE").map((i) => i.line));
  const decoded = new Map();                 // name -> line its decoded value came from
  const namesIn = (text) => {
    const out = [];
    identRe.lastIndex = 0;
    let m;
    while ((m = identRe.exec(text))) if (decoded.has(m[0])) out.push(decoded.get(m[0]));
    return out;
  };
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.cmask[i]) continue;
    const code = ctx.mcode(i);
    if (!code || isBlank(code)) continue;
    if (!(i & 63)) ctx.checkTime();
    const hasDecode = DECODE_CALL_RE.test(code);
    if (!decoded.size && !hasDecode) continue;
    const blank = blankStrings(code);
    const events = [];
    DEP_ASSIGN_RE.lastIndex = 0;
    let m;
    while ((m = DEP_ASSIGN_RE.exec(blank))) events.push([m.index, 0, m]);
    DECODE_SINK_RE.lastIndex = 0;
    while ((m = DECODE_SINK_RE.exec(blank))) events.push([m.index, 1, m]);
    events.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
    let close = null;
    for (const [, kind, ev] of events) {
      if (kind === 0) {
        const [a, b] = ev.indices[2];
        if (DECODE_CALL_RE.test(code.slice(a, b))) { if (!decoded.has(ev[1])) decoded.set(ev[1], i + 1); continue; }
        const src = namesIn(blank.slice(a, b));
        if (src.length && !decoded.has(ev[1])) decoded.set(ev[1], Math.min(...src));
        continue;
      }
      if (have.has(i + 1)) continue;
      close ??= parenCloseMap(blank);
      const argStart = ev.index + ev[0].length;
      const end = Math.min(close.get(argStart - 1) ?? blank.length, argStart + DEP_SINK_ARGS_MAX);
      const src = namesIn(blank.slice(argStart, end));
      if (src.length) {
        have.add(i + 1);
        issues.push(mkIssue({ ...rule, msg: `Decoded payload (assigned at line ${Math.min(...src)}) reaches a code-execution sink.` },
          path, i + 1, ctx.lines, ev.index));
      }
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
      if (o) o[0]++; else omitted.set(i.rule, [1, i.line]);
    }
  }
  if (!dropped.size) return issues;
  const out = issues.filter((_, k) => !dropped.has(k));
  for (const [rid, [n, first]] of omitted) {
    out.push(mkIssue({ id: "Q-CAPPED", name: "Findings capped", type: "SMELL", sev: "INFO",
      msg: `${n} more ${rid} findings omitted`,
      why: "Findings of one rule that repeat hundreds of times in one file are capped so reports stay readable; security findings are never capped.",
      fix: `Fix or deliberately suppress the ${rid} pattern in this file, then re-scan to see the remaining occurrences.`,
      ref: "Maintainability" }, path, first, lines));
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
  const content = normalizeSource(file.content, lang);
  const lines = content.split("\n");
  const ctx = new FileCtx(lines, lang, content, Date.now() + timeBudgetMs);
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
    }
    const cm = lang === "js" ? CHARCODE_RE.exec(line) : null;
    if (cm && countMatches(line, CHARCODE_NUM_RE) >= 10)
      issues.push(mkIssue({ id: "SC-CHARCODE", name: "Char-code string building", type: "HOTSPOT", sev: "MAJOR",
        msg: "String assembled from character codes — obfuscation indicator.",
        why: "fromCharCode chains hide payloads from static review.",
        fix: "Decode and review what string is being built.",
        ref: "CWE-506 · Supply chain" }, path, i + 1, lines, cm.index));
    const bm = B64_BLOB_RE.exec(line);
    if (bm && !line.includes("sourceMappingURL"))
      issues.push(mkIssue({ id: "SC-B64", name: "Large base64 blob", type: "HOTSPOT", sev: "MAJOR",
        msg: "Base64 blob (200+ chars) embedded in code.",
        why: "Embedded encoded blobs can carry second-stage payloads.",
        fix: "Decode and verify the content; move legitimate assets to data files.",
        ref: "CWE-506 · Supply chain" }, path, i + 1, lines, bm.index));
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
  if (dep) {
    depDecodeFlow(path, ctx, issues, SC_EVAL_DECODE);
    return;
  }
  const mcontent = mlines === lines ? content : mlines.join("\n");
  let starts = null;
  for (const r of TEXT_RULES) {
    // *-NOWHERE SQL rules are fired by scanSqlNowhere() (linear pass)
    if (!r.langs.includes(lang) || !r.scan) continue;
    let last = -1;
    for (const off of r.scan(mcontent)) {
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
function countMatches(s, re) { re.lastIndex = 0; let n = 0; while (re.exec(s)) n++; return n; }
