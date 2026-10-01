// scanFile — twin of lazaret.scanner.core.scan_file / _scan_file,
// implementing the shared semantics (FIX-SPEC items 1, 2, 5, 6, 7, 12, 13, 14).
// Since 0.1.8 the pattern rules and the supply-chain and credential families
// are the native engine's (../lib/native.js: core.scan_rules in project mode,
// all of scan_file in dependency mode); this module adds what core does after
// them in project mode (the SQL statements without WHERE, taint, the SQL-sink
// pass, the function metrics), the suppression markers and the cap.
import { normalizeSource } from "./lines.js";
import {
  TAINT_SOURCES, TAINT_SINKS, PARTIAL_SAN, neutralize, parseAssignment, AUG_ASSIGN_RE, taintCode,
  TAINT_JOIN_MAX_LINES, TAINT_JOIN_MAX_CHARS, BRACKET_DELTA, bracketDepth, cpHead, firstArg, sinkArgs,
  GUARD_IF_RE, guardedNames, guardExits, VIEW_RETURN_RE, VIEW_RETURN_SKIP_RE, viewBody, viewReturns, scopeOpener,
  literalContinuations, routeParams, TEMPLATE_SINK_RE, TEMPLATE_IMPORT_RE, NON_HTML_TYPE_RE, NON_HTML_CHAIN_RE, extent, containerWrite,
  KEYED_WRITE_RE, keyedReads, SAME_SITE_RE, allowGuard,
} from "./taint.js";
import { sqlSinkScan, scanSqlNowhere } from "./sql.js";
import { OBF_IDENT_RE, SECRET_SKIP_RE, makeSuppressor, mkIssue } from "./engine.js";
import { lexLines, jsxReading } from "../lib/lexer.js";
import { extractFunctions } from "./functions.js";
import { cpLen, cpPrefix, pyRepr, pyLstrip, pyStrip, isPySpace } from "../lib/pycompat.js";
import { findSecretToken, registerScanContext, REDACT } from "../lib/redact.js";
import { truncatedIssue, normalizeNewlines, treeJoin } from "../lib/fs.js";
import { assigned13, pinUnicode } from "../lib/unicode13.js";
import { documentationToken, keyMaterial, secretCol, redactConfigValues } from "../lib/configsecrets.js";
import { configKind, ownerDir, entries as autorunEntries, localCommand } from "../lib/autorun.js";
import { isWorkflow, findings as workflowFindings } from "../lib/ghworkflow.js";
import { agentHijackInCommand, installScriptRisk, followHook, nodeCandidates, spawnedScripts, packValues,
  scanDependencyFile, scanRules, NativeExhausted } from "../lib/native.js";

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
/** The time each project file's scan may take (ms). */
export function scanTimeBudget() { return timeBudgetMs; }


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

/**
 * Scan one file: {name|path, content, lang, dep}. dep → dependency mode:
 * only supply-chain and secret rules, no suppression markers honored. The
 * native engine reads the file (all of it in dependency mode; in project
 * mode its pattern rules and families, then the passes below); a file that
 * spends the engine's work budget is SC-TRUNCATED.
 */
export function scanFile(file) {
  const path = file.name ?? file.path;
  const raw = String(file.content ?? "");
  const lang = file.lang ?? detectLang(String(path ?? ""), raw);
  const jsx = jsxReading(path);
  if (file.dep) {
    try {
      return scanDependencyFile(path, raw, lang, { jsx, redact: REDACT.on });
    } catch (e) {
      if (!(e instanceof NativeExhausted)) throw e;
      return [truncatedIssue(path, EXHAUSTED)];
    }
  }
  const content = pinUnicode(normalizeSource(raw, lang));   // Unicode 13.0 (core._unicode13)
  const lines = content.split("\n");
  const ctx = new FileCtx(lines, lang, content, Date.now() + timeBudgetMs, jsx);
  registerScanContext(lines, SECRET_SKIP_RE);
  const issues = [];
  try {
    for (const i of scanRules(path, raw, lang, { jsx, redact: REDACT.on })) issues.push(i);
    projectPasses(path, content, lines, lang, ctx, issues);
  } catch (e) {
    if (e instanceof NativeExhausted) issues.push(truncatedIssue(path, EXHAUSTED));
    else if (e instanceof ScanBudgetExceeded) issues.push(truncatedIssue(path, "scan time budget exceeded"));
    else throw e;
  }
  const suppressed = makeSuppressor(lines, lang, { lex: ctx.lex });
  return capIssues(path, issues.filter((i) => !suppressed(i)), lines);
}
const EXHAUSTED = "reading it spent the engine's work budget (a pattern that backtracks without end on this text)";

/** What core's _scan_file does after _scan_rules in project mode: SQL statements without WHERE, taint, the SQL-sink pass, function metrics. */
function projectPasses(path, content, lines, lang, ctx, issues) {
  ctx.checkTime();
  if (lang === "sql") {
    try { scanSqlNowhere(path, content, issues, lines); } catch { /* analyzer must never break a scan */ }
  }
  ctx.checkTime();
  for (const t of taintScan(path, lines, lang, ctx)) issues.push(t);
  // G12: whole-argument SQL-sink analysis (Python, project mode)
  if (lang === "py") {
    try { sqlSinkScan(path, ctx.mlines, issues, lines); } catch (e) { if (e instanceof ScanBudgetExceeded) throw e; }
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

// ---- config and data files (credentials only; core.scan_config_file) -------
let tokenRule = null;
/** core's S-TOKEN rule (its texts), from the native engine's rule pack. */
function TOKEN_RULE() {
  if (tokenRule === null) {
    const [rules] = packValues("RULES");
    const r = rules.find((x) => x.id === "S-TOKEN");
    tokenRule = { id: r.id, name: r.name, type: r.type, sev: r.sev, msg: r.msg, why: r.why, fix: r.fix, ref: r.ref };
  }
  return tokenRule;
}
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
    // (0.1.8) the scripts it starts (spawnedScripts): a loader that fetches a runtime and runs a file of the tree with it
    for (const [where, path] of spawnedScripts(normalizeNewlines(text))) {
      const srel = treeJoin(where === "dir" ? (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "") : base, path);
      const stext = srel !== null ? read(srel) : null;
      const more = stext ? autorunScriptRisk(stext) : [];
      if (more.length) return [[`starts ${srel}, which ${more.join("; and ")}`], target];
    }
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
      if (col >= 0) issues.push(mkIssue(TOKEN_RULE(), path, i + 1, lines, col));
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
