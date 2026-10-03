// Cross-function and cross-file taint flows in Python and JavaScript: the twin
// of lazaret/scanner/flow.py (_analyze_python, _analyze_js, analyze). The two
// must report the same X-* findings — rule, file, line, severity, message,
// snippet — for the same files; the parity tests hold them to it.
//
// The passes are the engine's (rust/crates/lazaret-engine/src/pyflow/ and
// jsflow/, the `py_flow` and `js_flow` calls, which the Python package runs
// too): parsed trees, function summaries to a fixpoint, a work budget per
// syntax tree node. This module builds the findings from their outputs and
// keeps the public entry points. (Until phase 3 of the Rust-first refactor
// the Python pass was flow.py's own, on Python's ast, and had no port here.)
import { cmpCodePoints } from "../lib/pycompat.js";
import { jsFlow, pyFlow } from "../lib/native.js";
import { REDACT, contextRedacted, contextSecrets, redactText, registerScanContext, SECRET_SKIP_RE }
  from "../lib/redact.js";
import { splitLines } from "./lines.js";

const LINES_RE = /\r\n|[\n\r\u2028\u2029]/;                // JavaScript's line terminators
// test hooks: { runLimit: [base, steps per node] } lowers the limit of one function's reading of
// JavaScript; py: the Python pass's lower limits (pyFlow's options: twin of flow.MAX_ITERS,
// FLOW_MAX_FILES, FLOW_MAX_BYTES and _PY_WORK_LIMIT)
export const FLOW_OPTIONS = { runLimit: null, py: { maxIters: 50, maxFiles: 20_000, maxBytes: 64_000_000, workLimit: null } };

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

/** X-FLOW-SKIPPED: a file over the pass's size limit, in code points (twin of flow._skipped_size). */
function skippedSize(path, n, limit) {
  return {
    rule: "X-FLOW-SKIPPED", name: "JS flow analysis skipped (size)", type: "HOTSPOT", sev: "INFO",
    msg: `${path} is ${n} characters; interprocedural JS taint analysis is skipped above ${limit} characters.`,
    why: "Reading a file this large (usually minified or machine-generated) would cost the " +
      "cross-file pass more time and memory than a scan should spend on one file.",
    fix: "Split or deminify the file, or exclude it from the scan explicitly if the code is generated.",
    ref: "Scalability", file: path, line: 1, snippet: [], snipStart: 1,
  };
}

/** The Python pass's findings for `files` (twin of flow._analyze_python). */
function analyzePy(files, findings) {
  if (!files.length) return;
  const lines = new Map();                               // a file's lines (by its index), for the snippets
  for (const out of pyFlow(files, FLOW_OPTIONS.py)) {
    if (out[0] === "issue") {
      const [, cat, path, line, source, sink, chain, k] = out;
      if (!lines.has(k)) lines.set(k, files[k].content.split("\n"));
      findings.push(flowIssue(cat, path, line, lines.get(k), source, sink, chain));
    } else {
      findings.push(flowNote(...out.slice(1)));
    }
  }
}

/** The JavaScript pass's findings for `files` (twin of flow._analyze_js). */
function analyzeJs(files, findings) {
  if (!files.length) return;
  const lines = new Map();                               // a file's lines (by its index), for the snippets
  for (const out of jsFlow(files, { runLimit: FLOW_OPTIONS.runLimit })) {
    if (out[0] === "skipped_size") {
      findings.push(skippedSize(out[1], out[2], out[3]));
    } else if (out[0] === "issue") {
      const [, cat, path, line, source, sink, chain, k] = out;
      if (!lines.has(k)) lines.set(k, files[k].content.split(LINES_RE));
      findings.push(flowIssue(cat, path, line, lines.get(k), source, sink, chain));
    } else {
      findings.push(flowNote(...out.slice(1)));
    }
  }
}

/** An INFO coverage note (twin of flow._flow_note). */
function flowNote(rule, name, fname, line, msg, why, fix) {
  return { rule, name, type: "SMELL", sev: "INFO", msg, why, fix,
    ref: rule === "Q-FLOW-RECURSION" ? "CWE-400 (uncontrolled resource consumption)" : "Analysis coverage",
    file: fname, line, snippet: [], snipStart: 1 };
}


/**
 * Cross-function / cross-file taint findings for the Python and JavaScript
 * files of a scan (twin of flow.analyze). Never throws: an internal error
 * ends a language's pass with a Q-FLOW-INCOMPLETE note. Dependency files
 * are not analyzed.
 */
export function analyzeFlows(files) {
  const findings = [];
  let own = [];
  try {
    own = files.filter((f) => f && typeof f === "object" && (f.lang === "py" || f.lang === "js") && !f.dep
      && typeof f.path === "string");
  } catch { own = []; }
  for (const [run, lang, name] of [[analyzePy, "py", "Python"], [analyzeJs, "js", "JavaScript"]]) {
    const mine = own.filter((f) => f.lang === lang);
    try {
      run(mine, findings);
    } catch (e) {
      findings.push(flowNote("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (internal error)",
        mine.length ? mine[0].path : "?", 1,
        `The ${name} cross-file taint pass stopped on an internal error (${e?.name ?? "Error"}); ` +
          "findings it had already produced are kept.",
        "An unexpected input made the interprocedural engine fail; the rest of the scan is unaffected.",
        "Please report the file that triggers this to the Lazaret maintainers."));
    }
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
