// SQL analyzers — twins of lazaret.scanner.core.sql_sink_analyzer (G12) and
// scan_sql_nowhere (F11), with the Python regex text verbatim.
import { mkIssue } from "./engine.js";
import { pyRe, pyStrip, pyLstrip, pyRstrip } from "../lib/pycompat.js";
import { TEXT_RULES } from "./rules.js";

/* ---------------- Flow-sensitive SQL-sink analysis (G12) ----------------
   The S-SQL-PY line rule only sees formatting applied to a literal INSIDE
   execute(); SQL assigned to a variable earlier in the file (concat /
   %-interpolation / .format / f-string) then passed to execute(q) escapes it.
   Mirrors Python exactly, INCLUDING not skipping comment lines (only the
   suppression filter applied to the final issue list removes those) and the
   dedup-by-line against the S-SQL-PY line-rule pass. Parameterized calls
   (2nd top-level arg starting with ( [ or {) are safe and never flagged. */
const SQL_CALL_RE = pyRe(String.raw`\.(execute|executemany)\s*\(`, "g");
const SQL_IDENT_RE = pyRe(String.raw`^[A-Za-z_]\w*$`);
// SQL_ASSIGN_RE = ^\s*([A-Za-z_]\w*)\s*(\+=|=)(?!=)\s*(.+)$ with the rhs
// rstrip()-ed by the caller (twin of core._sql_template_map).
const SQL_ASSIGN_RE = pyRe(String.raw`^\s*([A-Za-z_]\w*)\s*(\+=|=)(?!=)\s*(.+)$`);
const SQL_LIT_RE = pyRe(String.raw`^(?:[rbu]*)[\"'](.*)[\"']$`, "s");
const FORMAT_CALL_RE = pyRe(String.raw`\.format\s*\(`);
const PERCENT_RE = pyRe(String.raw`(?:[\"'][^\"']*[\"']|\b[A-Za-z_]\w*)\s*%\s*[^=%\s]`);
const CONCAT_L_RE = pyRe(String.raw`[\"'][^\"']*[\"']\s*\+`);
const CONCAT_R_RE = pyRe(String.raw`\+\s*[\"']`);

/** SQL_ASSIGN_RE.match(line) → [name, op, rhs.rstrip()] or null. */
function sqlAssign(line) {
  const m = SQL_ASSIGN_RE.exec(line);
  return m ? [m[1], m[2], pyRstrip(m[3])] : null;
}

function sqlSplitTopLevel(argstr) {      // split on top-level commas (nested brackets/quotes respected)
  const parts = [];
  let cur = "", depth = 0, quote = null;
  for (const ch of argstr) {
    if (quote) { cur += ch; if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; cur += ch; }
    else if (ch === "(" || ch === "[" || ch === "{") { depth++; cur += ch; }
    else if (ch === ")" || ch === "]" || ch === "}") { depth--; cur += ch; }
    else if (ch === "," && depth === 0) { parts.push(cur); cur = ""; }
    else cur += ch;
  }
  parts.push(cur);
  return parts;
}
function sqlParenSlice(line, openIdx) {  // content of the balanced (…) starting at openIdx, or null
  let depth = 0, quote = null;
  for (let j = openIdx; j < line.length; j++) {
    const ch = line[j];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "(") depth++;
    else if (ch === ")") { if (--depth === 0) return line.slice(openIdx + 1, j); }
  }
  return null;
}
function sqlBuildMethod(arg) {           // 'format' | 'percent' | 'concat' | null
  if (FORMAT_CALL_RE.test(arg) || /^(?:f"|f')/.test(pyLstrip(arg))) return "format";
  if (PERCENT_RE.test(arg)) return "percent";
  if (CONCAT_L_RE.test(arg) || CONCAT_R_RE.test(arg)) return "concat";
  return null;
}
function sqlTemplateMap(lines) {         // varname → how its value was built (flow-sensitive)
  const tmap = new Map();                // a Map: `constructor`/`toString` are just names
  for (const ln of lines) {
    const mm = sqlAssign(ln);
    if (!mm) continue;
    const [name, op, rhs] = mm;
    if (op === "+=") { if (!tmap.has(name)) tmap.set(name, "concat"); continue; }
    const build = sqlBuildMethod(rhs);
    if (build) { tmap.set(name, build); continue; }
    const lit = SQL_LIT_RE.exec(pyStrip(rhs));
    if (lit) tmap.set(name, lit[1].includes("%") ? "percent" : (lit[1].includes("{") ? "format" : "static"));
  }
  return tmap;
}
const HOW = { percent: "%-interpolation", format: ".format()/f-string", concat: "concatenation" };

// Per line, at most SQL_CALLS_PER_LINE execute() calls are analyzed and each
// argument string is cut to SQL_ARG_MAX characters (core.sql_sink_analyzer).
const SQL_CALLS_PER_LINE = 64;
const SQL_ARG_MAX = 10000;
/** {index of '(' → index of its ')'} for one line; quotes tracked from the line start. */
function parenCloseMap(line) {
  const close = new Map(), stack = [];
  let quote = null;
  for (let j = 0; j < line.length; j++) {
    const ch = line[j];
    if (ch !== "(" && ch !== ")" && ch !== '"' && ch !== "'") continue;
    if (quote) { if (ch === quote) quote = null; }
    else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "(") stack.push(j);
    else if (stack.length) close.set(stack.pop(), j);
  }
  return close;
}

/**
 * Append S-SQL-PY issues for execute()/executemany() calls on `lines`
 * (matching text) to `issues`; `snipLines` (default: lines) feed snippets.
 */
function sqlSinkScan(file, lines, issues, snipLines = lines) {
  const tmap = sqlTemplateMap(lines);
  const flagged = new Set(issues.filter((i) => i.rule === "S-SQL-PY").map((i) => i.line));
  lines.forEach((line, i) => {
    if (flagged.has(i + 1) || !line.includes(".execute")) return;
    SQL_CALL_RE.lastIndex = 0;
    let m, nCall = 0, close = null;
    while ((m = SQL_CALL_RE.exec(line))) {
      if (nCall++ >= SQL_CALLS_PER_LINE) break;
      close ??= parenCloseMap(line);
      const j = close.get(m.index + m[0].length - 1);
      if (j === undefined) continue;
      const argStr = line.slice(m.index + m[0].length, j).slice(0, SQL_ARG_MAX);
      const parts = sqlSplitTopLevel(argStr);
      const first = pyStrip(parts[0] ?? "");
      const second = parts.length > 1 ? pyStrip(parts[1]) : "";
      if (!first) continue;
      // SAFE: parameterized call — a tuple/list/dict of parameters after the top-level comma
      if (parts.length >= 2 && second && "([{".includes(second[0])) continue;
      let build = sqlBuildMethod(first);
      if (build === null && SQL_IDENT_RE.test(first)) {
        build = tmap.get(first);
        if (build === undefined || build === "static") continue;
      }
      if (build) issues.push(mkIssue({ id: "S-SQL-PY", name: "SQL built from strings", type: "VULN", sev: "BLOCKER",
        msg: `SQL query built with ${HOW[build] || "string-building"} into execute().`,
        why: "Interpolating values into SQL enables SQL injection — the classic path to full database compromise.",
        fix: 'Use parameterized queries: cursor.execute("SELECT … WHERE id = %s", (user_id,)).',
        ref: "CWE-89 · OWASP A03" }, file, i + 1, snipLines));
    }
  });
}

/* ---------------- Linear SQL *-NOWHERE scan (F11) ----------------
   Reproduces the original tempered-dot finditer semantics in one O(n)
   pass: a match starts at a DELETE/UPDATE head, consumes up to the next ';'
   and is aborted by a WHERE in between; heads before a reported match's ';'
   are consumed (non-overlapping); heads after a WHERE-aborted statement are
   still tried. */
const NOWHERE_RULES = TEXT_RULES.filter((r) => r.nowhere);
const WHERE_RE = pyRe(String.raw`\bWHERE\b`, "gi");
function lowerBound(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (a[mid] < x) lo = mid + 1; else hi = mid; }
  return lo;
}
function scanSqlNowhere(file, content, issues, lines, deadline = Infinity) {
  let semis = null, wheres = null, nl = null;
  for (const r of NOWHERE_RULES) {
    const re = new RegExp(r.re.source, r.re.flags.includes("g") ? r.re.flags : r.re.flags + "g");
    let skipTo = -1, m, count = 0;
    while ((m = re.exec(content))) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      if ((++count & 1023) === 0 && Date.now() > deadline) return false;
      const start = m.index, end = start + m[0].length;
      if (start < skipTo) continue;
      if (semis === null) {
        semis = []; nl = [];
        for (let i = 0; i < content.length; i++) {
          const c = content.charCodeAt(i);
          if (c === 59) semis.push(i); else if (c === 10) nl.push(i);
        }
        wheres = [];
        WHERE_RE.lastIndex = 0;
        let w;
        while ((w = WHERE_RE.exec(content))) wheres.push(w.index);
      }
      const k = lowerBound(semis, end);
      if (k === semis.length) continue;     // no ';' ahead: the old pattern could never match
      const semi = semis[k];
      const w = lowerBound(wheres, end);
      if (w < wheres.length && wheres[w] < semi) { skipTo = end; continue; }
      issues.push(mkIssue(r, file, lowerBound(nl, start) + 1, lines));
      skipTo = semi;
    }
  }
  return true;
}

export { sqlSplitTopLevel, sqlParenSlice, sqlBuildMethod, sqlTemplateMap, sqlSinkScan, scanSqlNowhere, parenCloseMap };
