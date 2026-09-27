// Cross-function and cross-file taint flows in JavaScript: the twin of the
// JavaScript half of lazaret/scanner/flow.py (_js_mask, _js_functions,
// _js_sink_args, _js_neutralize, _js_param_dangerous, _analyze_js,
// analyze). The two must report the same X-* findings — rule, file, line,
// severity, message, snippet — for the same JavaScript files; the parity
// tests hold them to it. The Python engine's other half (Python files,
// AST-based) has no port: the npm engine's gate says so.
//
// A bounded heuristic, not a parser (no JS parser is available without
// dependencies): a small linear lexer blanks the content of strings,
// comments, regex literals and template text, function headers are found
// with regexes and their bodies by brace matching, and each function gets a
// summary of the parameters that reach a sink. A call site passing a
// request-derived value into such a parameter is a finding. Patterns are
// the Python engine's source text, compiled with Python semantics (pyRe).
import { cmpCodePoints, cpLen, pyRe, pyStrip } from "../lib/pycompat.js";
import { REDACT, contextRedacted, contextSecrets, redactText, registerScanContext, SECRET_SKIP_RE }
  from "../lib/redact.js";
import { splitLines } from "./lines.js";

// category -> [severity, cwe, fix]; twin of flow.SINK_META
const SINK_META = {
  "SQL injection": ["BLOCKER", "CWE-89", "Use parameterized queries with placeholders."],
  "command injection": ["CRITICAL", "CWE-78", "Pass args as a list with shell=False / use execFile."],
  "code injection": ["CRITICAL", "CWE-95", "Never execute untrusted strings; use safe parsing."],
  "template injection": ["CRITICAL", "CWE-1336", "Pass data as template parameters, not template source."],
  "path traversal": ["MAJOR", "CWE-22", "Resolve and confine the path to an allowed base directory."],
  "server-side request forgery": ["MAJOR", "CWE-918", "Allowlist hosts/schemes; block internal addresses."],
  "open redirect": ["MAJOR", "CWE-601", "Allowlist redirect targets or use relative paths."],
  "cross-site scripting": ["MAJOR", "CWE-79", "Escape/sanitize before rendering; prefer textContent."],
};
const CAT_SUFFIX = {
  "SQL injection": "SQL", "command injection": "CMD", "code injection": "CODE",
  "template injection": "SSTI", "path traversal": "PATH",
  "server-side request forgery": "SSRF", "open redirect": "REDIR",
  "cross-site scripting": "XSS",
};

const capitalize = (s) => s.slice(0, 1).toUpperCase() + s.slice(1).toLowerCase();   // str.capitalize

/** An X-* finding (twin of flow._issue). */
function flowIssue(cat, callerFile, line, lines, sourceLoc, sinkLoc, chain) {
  const [sev, cwe, fix] = SINK_META[cat];
  const start = Math.max(0, line - 3);
  const cross = sourceLoc.split(":")[0] !== sinkLoc.split(":")[0];
  const scope = cross ? "cross-file" : "interprocedural";
  return {
    rule: `X-${CAT_SUFFIX[cat]}`, name: `${capitalize(scope)} tainted flow → ${cat}`,
    type: "VULN", sev,
    msg: `Possible ${cat}: untrusted data from ${sourceLoc} reaches a sink at ${sinkLoc} (${scope}).`,
    why: "Whole-program taint tracking followed user-controlled input from its " +
      "source through " + (chain || "a function call") + " into a dangerous " +
      "operation, without visible sanitization along the way.",
    fix, ref: `${cwe} · Interprocedural taint`,
    file: callerFile, line,
    snippet: lines.slice(start, Math.min(lines.length, line + 2)), snipStart: start + 1,
  };
}

/** An INFO coverage note (twin of flow._flow_note). */
function flowNote(rule, name, fname, line, msg, why, fix) {
  return { rule, name, type: "SMELL", sev: "INFO", msg, why, fix,
    ref: rule === "Q-FLOW-RECURSION" ? "CWE-400 (uncontrolled resource consumption)" : "Analysis coverage",
    file: fname, line, snippet: [], snipStart: 1 };
}

// ---- patterns (the Python engine's source text) --------------------------
// Python's named groups (?P<n>…) are written (?<n>…); its re.S dots, (?:.|\n).
const JS_FUNC_RE = pyRe(String.raw`(?:function\s+(?<n1>\w+)\s*\((?<p1>[^)]*)\)` +
  String.raw`|(?:const|let|var)\s+(?<n2>\w+)\s*=\s*(?:async\s*)?\((?<p2>[^)]*)\)\s*=>` +
  String.raw`|(?:const|let|var)\s+(?<n3>\w+)\s*=\s*(?:async\s*)?function\s*\((?<p3>[^)]*)\))`, "g");
const JS_SOURCE_RE = pyRe(String.raw`req\.(query|body|params|headers|cookies)|process\.argv|location\.(search|hash|href)`);
const JS_SINKS = [
  [pyRe(String.raw`\.(query|execute)\s*\(`, "g"), "SQL injection"],
  [pyRe(String.raw`\b(exec|execSync|spawn|spawnSync)\s*\(`, "g"), "command injection"],
  [pyRe(String.raw`(?<![\w.])eval\s*\(|new\s+Function\s*\(`, "g"), "code injection"],
  [pyRe(String.raw`\.innerHTML\s*=|document\.write\s*\(`, "g"), "cross-site scripting"],
  [pyRe(String.raw`\bfetch\s*\(|axios(\.\w+)?\s*\(`, "g"), "server-side request forgery"],
  [pyRe(String.raw`\.redirect\s*\(`, "g"), "open redirect"],
];

// ---- a small linear lexer (twin of flow._js_mask) -------------------------
const TOKEN_RE = pyRe(String.raw`(?<ws>\s+)` +
  String.raw`|(?<lc>//[^\n\u2028\u2029]*)` +
  String.raw`|(?<bc>/\*(?:.|\n)*?(?:\*/|\Z))` +
  String.raw`|(?<sq>'(?:[^'\\\n]|\\(?:.|\n))*'?)` +
  String.raw`|(?<dq>"(?:[^"\\\n]|\\(?:.|\n))*"?)` +
  String.raw`|(?<bt>` + "`)" +
  String.raw`|(?<id>[A-Za-z_$\u0080-\uffff][\w$\u0080-\uffff]*)` +
  String.raw`|(?<num>\d[\w.]*)` +
  String.raw`|(?<p>(?:.|\n))`, "y");
const TPL_TEXT_RE = pyRe(String.raw`(?:[^` + "`" + String.raw`\\$]|\\(?:.|\n)|\$(?!\{))*`, "y");
const REGEX_LIT_RE = pyRe(String.raw`/(?:[^/\\\[\n]|\\.|\[(?:[^\]\\\n]|\\.)*\])+/[A-Za-z]*`, "y");
const NOT_NL_RE = pyRe(String.raw`[^\n\u2028\u2029]`, "g");
const REGEX_AFTER = new Set("(,=:[!&|?{};+-*%<>~^");
const REGEX_KEYWORDS = new Set(["return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
  "void", "throw", "instanceof", "yield", "await"]);
const TOKEN_KINDS = ["ws", "lc", "bc", "sq", "dq", "bt", "id", "num", "p"];
const kindOf = (m) => TOKEN_KINDS.find((k) => m.groups[k] !== undefined);

/**
 * src with the CONTENT of '…', "…", `…` template text, comments and regex
 * literals replaced by spaces (one per code point, as Python counts them;
 * newlines and ${…} code kept), so every later pass only sees code. Linear.
 */
export function jsMask(src) {
  const out = [];
  let lastCopy = 0;
  const n = src.length;
  const blank = (a, b) => {
    if (b > a) {
      out.push(src.slice(lastCopy, a), src.slice(a, b).replace(NOT_NL_RE, " "));
      lastCopy = b;
    }
  };
  const templateText = (i) => {          // -> [next index, opened ${]
    TPL_TEXT_RE.lastIndex = i;
    const m = TPL_TEXT_RE.exec(src);
    const j = i + m[0].length;
    blank(i, j);
    if (j >= n) return [n, false];
    if (src[j] === "`") return [j + 1, false];
    return [j + 2, true];                // at "${"
  };
  const stack = [];                      // brace depth inside each open ${ … }
  let lastSig = "", lastWord = "";
  let i = 0;
  while (i < n) {
    TOKEN_RE.lastIndex = i;
    const m = TOKEN_RE.exec(src);
    const kind = kindOf(m);
    const j = i + m[0].length;
    if (kind === "ws") { i = j; continue; }
    if (kind === "lc" || kind === "bc") { blank(i, j); i = j; continue; }
    if (kind === "sq" || kind === "dq") {
      const closed = cpLen(m[0]) >= 2 && src[j - 1] === src[i];
      blank(i + 1, closed ? j - 1 : j);
      lastSig = '"'; lastWord = "";
      i = j;
      continue;
    }
    if (kind === "bt") {
      const [k, opened] = templateText(i + 1);
      if (opened) stack.push(0);
      lastSig = opened ? "{" : "`"; lastWord = "";
      i = k;
      continue;
    }
    if (kind === "id") { lastSig = "a"; lastWord = m[0]; i = j; continue; }
    if (kind === "num") { lastSig = "0"; lastWord = ""; i = j; continue; }
    const ch = m[0];
    if (ch === "/" && (lastSig === "" || (REGEX_AFTER.has(lastSig) && lastSig !== "}")
        || (lastSig === "a" && REGEX_KEYWORDS.has(lastWord)))) {
      REGEX_LIT_RE.lastIndex = i;
      const rm = REGEX_LIT_RE.exec(src);
      if (rm !== null) {
        const end = i + rm[0].length;
        const close = src.lastIndexOf("/", end - 1);
        blank(i + 1, close);
        lastSig = ")"; lastWord = "";     // a value: '/' after it divides
        i = end;
        continue;
      }
    }
    if (ch === "{" && stack.length) stack[stack.length - 1] += 1;
    else if (ch === "}" && stack.length) {
      if (stack[stack.length - 1] === 0) {
        stack.pop();
        const [k, opened] = templateText(i + 1);
        if (opened) stack.push(0);
        lastSig = opened ? "{" : "`"; lastWord = "";
        i = k;
        continue;
      }
      stack[stack.length - 1] -= 1;
    }
    lastSig = ch; lastWord = "";
    i = j;
  }
  out.push(src.slice(lastCopy));
  return out.join("");
}

/** Index of the first element of the sorted array a that is >= x (bisect_left). */
function bisectLeft(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (a[mid] < x) lo = mid + 1; else hi = mid;
  }
  return lo;
}

function newlineOffsets(code) {
  const nl = [];
  for (let k = code.indexOf("\n"); k !== -1; k = code.indexOf("\n", k + 1)) nl.push(k);
  return nl;
}

/**
 * [name, params, [body start, body end], start line] for every function
 * header (twin of flow._js_functions): headers and braces are read from the
 * masked code; one brace pass computes every body span.
 */
export function jsFunctions(content, code = null) {
  code ??= jsMask(content);
  const matches = [...code.matchAll(JS_FUNC_RE)];
  if (!matches.length) return [];
  const opens = [], matchClose = new Map(), stack = [];
  for (let k = 0; k < code.length; k++) {
    const c = code[k];
    if (c === "{") { opens.push(k); stack.push(k); }
    else if (c === "}" && stack.length) matchClose.set(stack.pop(), k);
  }
  const nl = newlineOffsets(code);
  const out = [];
  for (const m of matches) {
    const g = m.groups;
    const name = g.n1 || g.n2 || g.n3;
    const paramsS = g.p1 || g.p2 || g.p3 || "";
    const params = paramsS.split(",").filter((p) => pyStrip(p)).map((p) => pyStrip(pyStrip(p).split("=")[0]));
    const end = m.index + m[0].length;
    const k = bisectLeft(opens, end - 1);
    if (k === opens.length) continue;
    const brace = opens[k];
    const close = matchClose.has(brace) ? matchClose.get(brace) : code.length;   // EOF if never closed
    const startLine = bisectLeft(nl, m.index) + 1;
    out.push([name, params, [brace, close + 1], startLine]);
  }
  return out;
}

const JS_ARG_SCAN = 4000;   // max characters (code points, as Python counts) scanned for a sink's arguments

/**
 * Where a sink's argument text ends, scanning from k: the first unbalanced
 * closing bracket (or, for a statement sink, a ';' or newline outside
 * brackets), else JS_ARG_SCAN code points on. Counted in code points so an
 * astral character is one step, as in flow.py.
 */
function argEnd(code, k, statement) {
  let depth = 0, idx = k;
  for (let n = 0; idx < code.length && n < JS_ARG_SCAN; n++) {
    const ch = code[idx];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return idx;
      depth--;
    } else if (statement && (ch === ";" || ch === "\n") && depth === 0) return idx;
    const u = code.charCodeAt(idx);
    idx += u >= 0xd800 && u <= 0xdbff && (code.charCodeAt(idx + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
  }
  return idx;
}

/**
 * The text a sink match can consume (twin of flow._js_sink_args): the
 * balanced argument list of a call sink (`exec(` … `)`), else the rest of the
 * statement (`x.innerHTML = …;`). Computed on masked code.
 */
export function jsSinkArgs(code, start, end) {
  let k = end;
  if (!(end > start && code[end - 1] === "(")) {
    let k2 = end;
    while (k2 < code.length && (code[k2] === " " || code[k2] === "\t")) k2++;
    if (k2 < code.length && code[k2] === "(") k = k2 + 1;
    else return code.slice(end, argEnd(code, end, true));
  }
  return code.slice(k, argEnd(code, k, false));
}

// ---- sanitizers (twin of flow._JS_FULL_SAN_RE / _JS_PARTIAL_SAN) ----------
const FULL_SAN_RE = pyRe(String.raw`(?:parseInt|parseFloat|Number)\s*\([^()]*\)`, "g");
const PARTIAL_SAN = {
  "cross-site scripting": pyRe(String.raw`(?:DOMPurify\.sanitize|encodeURIComponent|escapeHtml|sanitizeHtml)\s*\([^()]*\)`, "g"),
  "SQL injection": pyRe(String.raw`(?:mysql2?|pool|connection|conn|db)\.escape\s*\([^()]*\)`, "g"),
  "path traversal": pyRe(String.raw`path\.basename\s*\([^()]*\)`, "g"),
  "command injection": pyRe(String.raw`(?:shellQuote|shell_quote|quote)\s*\([^()]*\)`, "g"),
};

/** Strip sanitizer calls so their content stops counting as tainted. */
export function jsNeutralize(text, cats) {
  text = text.replace(FULL_SAN_RE, " ");
  for (const c of cats) if (PARTIAL_SAN[c]) text = text.replace(PARTIAL_SAN[c], " ");
  return text;
}

// re.escape for u-mode: only syntax characters may be escaped there
const escapeRe = (s) => s.replace(/[\\^$.*+?()[\]{}|/]/g, "\\$&");
const paramReCache = new Map();
function paramRe(p, sql) {
  const key = (sql ? "s:" : "o:") + p;
  let re = paramReCache.get(key);
  if (re === undefined) {
    const pe = escapeRe(p);
    re = pyRe(sql ? String.raw`\+\s*${pe}\b|\b${pe}\s*\+|` + "`[^`]*" + String.raw`\$\{[^}]*\b${pe}\b`
      : String.raw`\b${pe}\b`);
    if (paramReCache.size > 4096) paramReCache.clear();
    paramReCache.set(key, re);
  }
  return re;
}

/** Does parameter p reach the sink in a dangerous way within seg? */
export function jsParamDangerous(seg, p, cat) {
  // SQL: safe when p only appears in a placeholder array (query(sql, [p]))
  return paramRe(p, cat === "SQL injection").test(seg);
}

/** JS source as the pattern engine numbers its lines: U+2028/U+2029 end a line. */
export function jsText(content) {
  return content.includes("\u2028") || content.includes("\u2029")
    ? content.replace(/[\u2028\u2029]/g, "\n") : content;
}

const JS_MAX_FILE = 2_000_000;   // skip interprocedural JS flow above 2 MB (code points)
const CALL_RE = pyRe(String.raw`\b(\w+)\s*\(([^;()]*)\)`, "g");
const ASSIGN_RE = pyRe(String.raw`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)` +
  String.raw`|(?:^|[;{]\s*)([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([^;\n]+)`, "g");
const WORD_RE = pyRe(String.raw`[A-Za-z_$][\w$]*`, "g");
const words = (s) => s.match(WORD_RE) || [];
const namesTainted = (tainted, s) => words(s).some((w) => tainted.has(w));

function analyzeJs(files, findings) {
  const summaries = new Map();   // name -> [params, Map param -> [category, sink line], file]
  const jsFiles = files.filter((f) => f.lang === "js");
  const texts = new Map(jsFiles.map((f) => [f, jsText(f.content)]));
  const codes = new Map();
  for (const f of jsFiles) {
    const content = texts.get(f);
    const size = cpLen(content);
    if (size > JS_MAX_FILE) {
      findings.push({
        rule: "X-FLOW-SKIPPED", name: "JS flow analysis skipped (size)",
        type: "HOTSPOT", sev: "INFO",
        msg: `${f.path} is ${size} bytes; interprocedural JS taint analysis is skipped above ${JS_MAX_FILE} bytes.`,
        why: "The heuristic JS engine scales poorly on minified or machine-generated files of this size; " +
          "a full analysis would risk a multi-minute scan.",
        fix: "Split or deminify the file, or exclude it from the scan explicitly if the code is generated.",
        ref: "Scalability",
        file: f.path, line: 1, snippet: [], snipStart: 1,
      });
      continue;
    }
    const code = jsMask(content);
    codes.set(f, code);
    const funcs = jsFunctions(content, code);
    if (!funcs.length) continue;
    const nl = newlineOffsets(code);
    const spans = funcs.map(([, , [s, e]], fi) => [s, e, fi]);
    const spanReach = funcs.map(() => new Map());   // fi -> Map param -> [category, line]
    for (const [sinkRe, cat] of JS_SINKS) {
      const byStart = [...spans].sort((a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2]);
      let active = [];
      let addIdx = 0;
      for (const m of code.matchAll(sinkRe)) {
        const pos = m.index, send = m.index + m[0].length;
        while (addIdx < byStart.length && byStart[addIdx][0] <= pos) active.push(byStart[addIdx++]);
        active = active.filter((sp) => sp[1] > pos);
        if (!active.length) continue;
        const seg = jsSinkArgs(code, pos, send);
        let line = null;
        for (const [, , fi] of active) {
          for (const p of funcs[fi][1]) {
            if (p && jsParamDangerous(seg, p, cat)) {
              // a later sink kind's category wins; within one category the first call is reported
              const prev = spanReach[fi].get(p);
              if (prev === undefined || prev[0] !== cat) {
                if (line === null) line = bisectLeft(nl, pos) + 1;
                spanReach[fi].set(p, [cat, line]);
              }
            }
          }
        }
      }
    }
    // in match order: a later function of the same name replaces an earlier one
    funcs.forEach(([name, params], fi) => {
      if (spanReach[fi].size) summaries.set(name, [params, spanReach[fi], f.path]);
    });
  }
  if (!summaries.size) return;
  for (const f of jsFiles) {
    const content = texts.get(f);
    if (cpLen(content) > JS_MAX_FILE) continue;   // reported above
    const lines = content.split("\n");
    const code = codes.get(f) ?? jsMask(content);
    const codeLines = code.split("\n");
    const tainted = new Set();
    for (const am of code.matchAll(ASSIGN_RE)) {
      const name = am[1] ?? am[3];
      const rhs = jsNeutralize(am[2] ?? am[4] ?? "", []);   // parseInt/Number(...) is clean
      if (JS_SOURCE_RE.test(rhs) || namesTainted(tainted, rhs)) tainted.add(name);
    }
    codeLines.forEach((ln, i) => {
      for (const cm of ln.matchAll(CALL_RE)) {
        const fname = cm[1], argstr = cm[2];
        const summary = summaries.get(fname);
        if (summary === undefined) continue;
        const [params, reach, sfile] = summary;
        const callArgs = argstr.split(",").map((a) => pyStrip(a));
        for (let idx = 0; idx < params.length; idx++) {
          const pname = params[idx];
          if (!reach.has(pname) || idx >= callArgs.length) continue;
          const [cat, sline] = reach.get(pname);
          const a = jsNeutralize(callArgs[idx], [cat]);   // sink-category sanitizers
          if (JS_SOURCE_RE.test(a) || namesTainted(tainted, a)) {
            findings.push(flowIssue(cat, f.path, i + 1, lines, `${f.path}:${i + 1}`,
              `${sfile}:${sline} (in ${fname}())`, `the call to ${fname}()`));
            break;
          }
        }
      }
    });
  }
}

/**
 * Cross-function / cross-file taint findings for the JavaScript files of a
 * scan (twin of flow.analyze for JavaScript). Never throws: an internal
 * error ends the pass with a Q-FLOW-INCOMPLETE note. Dependency files are
 * not analyzed.
 */
export function analyzeFlows(files) {
  const findings = [];
  let js = [];
  try {
    js = files.filter((f) => f && typeof f === "object" && f.lang === "js" && !f.dep && typeof f.path === "string");
  } catch { js = []; }
  try {
    analyzeJs(js, findings);
  } catch (e) {
    findings.push(flowNote("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (internal error)",
      js.length ? js[0].path : "?", 1,
      `The JavaScript cross-file taint pass stopped on an internal error (${e?.name ?? "Error"}); ` +
        "findings it had already produced are kept.",
      "An unexpected input made the interprocedural engine fail; the rest of the scan is unaffected.",
      "Please report the file that triggers this to the Lazaret maintainers."));
  }
  const sorted = findings.map((f, k) => [f, k])
    .sort((a, b) => cmpCodePoints(String(a[0].file), String(b[0].file)) || a[0].line - b[0].line || a[1] - b[1]);
  const seen = new Set(), unique = [];
  for (const [i] of sorted) {
    const key = JSON.stringify([i.rule, i.file, i.line, i.msg]);
    if (!seen.has(key)) { seen.add(key); unique.push(i); }
  }
  return unique;
}

/**
 * Give flow findings their file's redaction (twin of core.redact_file_issues
 * for the findings this module builds from raw lines): a snippet line that is
 * still its file line's raw text becomes the line as a file scan shows it
 * (PEM blocks, the file's entropy literals, credential patterns); msg gets
 * the file's literals. In place.
 */
export function redactFlowIssues(issues, files) {
  if (!REDACT.on) return issues;
  const byPath = new Map(files.map((f) => [f.path, f]));
  const groups = new Map();
  for (const i of issues) {
    if (!byPath.has(i.file)) continue;
    if (!groups.has(i.file)) groups.set(i.file, []);
    groups.get(i.file).push(i);
  }
  for (const [path, group] of groups) {
    const f = byPath.get(path);
    const lines = splitLines(f.content, f.lang);
    const ctx = registerScanContext(lines, SECRET_SKIP_RE);
    for (const i of group) {
      for (const key of ["msg", "cmd"]) {
        const v = i[key];
        if (typeof v === "string") {
          const nv = redactText(v, contextSecrets(ctx));
          if (nv !== v) i[key] = nv;
        }
      }
      const snip = i.snippet, start = i.snipStart;
      if (!Array.isArray(snip) || !Number.isInteger(start)) continue;
      let out = null;
      snip.forEach((line, k) => {
        const j = start - 1 + k;
        if (typeof line === "string" && j >= 0 && j < lines.length && line === lines[j]) {
          const shown = contextRedacted(ctx, j);
          if (shown !== line) { out ??= [...snip]; out[k] = shown; }
        }
      });
      if (out !== null) i.snippet = out;
    }
  }
  return issues;
}
