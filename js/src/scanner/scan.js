// scanFile — twin of lazaret.scanner.core.scan_file, implementing the
// shared semantics (FIX-SPEC items 1, 2, 5, 6, 7, 12, 13, 14). A source file's
// scan is the native engine's (../lib/native.js), in dependency mode and in
// project mode alike (Q-1, 0.1.9: the SQL statements without WHERE, taint,
// the SQL-sink pass, the function metrics, the suppression markers and the cap
// are the engine's too), and so is a config or data file's (BR-7: its
// credentials, an editor's or agent's settings, a CI file's checks).
import { mkIssue } from "./engine.js";
import { jsxReading } from "../lib/lexer.js";
import { REDACT } from "../lib/redact.js";
import { truncatedIssue, normalizeNewlines } from "../lib/fs.js";
import { call, nodeCandidates, scanDependencyFile, scanProjectFile, scanConfig, taintFindings, NativeExhausted }
  from "../lib/native.js";

export { isComment } from "./engine.js";

/* ---------------- Analyzers ---------------- */
export function detectLang(name, content) {
  if (/\.(py|pyw)$/i.test(name)) return "py";
  if (/\.(js|jsx|ts|tsx|mts|cts|mjs|cjs)$/i.test(name)) return "js";
  if (/\.sql$/i.test(name)) return "sql";
  if (/\.go$/i.test(name)) return "go";
  if (/\.rs$/i.test(name)) return "rs";
  // content heuristic: SQL keywords dominate and no JS/py structure
  if (/\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+(TABLE|PROCEDURE|USER)|GRANT|ALTER\s+TABLE)\b/i.test(content)
     && !/\b(function|=>|def |import )\b/.test(content)) return "sql";
  if (/^[^\S\n\r\u2028\u2029]*(def |import |from \w+ import|class \w.*:)/m.test(content) && !/[{};]\s*$/m.test(content)) return "py";
  return /\b(def |elif |None|self\.)/.test(content) && !/\b(const|let|=>|function)\b/.test(content) ? "py" : "js";
}

/**
 * Project mode's intra-file taint alone (twin of core.taint_scan; the engine's, taint.rs): the T-*
 * findings of a file's lines, before the suppression markers and the cap. scanFile runs the same pass.
 */
export function taintScan(file, lines, lang) {
  if (lang !== "py" && lang !== "js") return [];
  return taintFindings(file, lines.join("\n"), lang, { jsx: jsxReading(file), redact: REDACT.on });
}

/**
 * Scan one file: {name|path, content, lang, dep}. dep → dependency mode:
 * only supply-chain and secret rules, no suppression markers honored. The
 * native engine reads the file whole, in either mode; a file that spends the
 * engine's work budget is SC-TRUNCATED.
 */
export function scanFile(file) {
  const path = file.name ?? file.path;
  const raw = String(file.content ?? "");
  const lang = file.lang ?? detectLang(String(path ?? ""), raw);
  const opts = { jsx: jsxReading(path), redact: REDACT.on };
  try {
    return file.dep ? scanDependencyFile(path, raw, lang, opts) : scanProjectFile(path, raw, lang, opts);
  } catch (e) {
    if (!(e instanceof NativeExhausted)) throw e;
    return [truncatedIssue(path, EXHAUSTED)];
  }
}
export const EXHAUSTED = "reading it spent the engine's work budget (a pattern that backtracks without end on this text)";

// ---- settings that run commands (SC-AUTORUN; core's section comment) ----
/** How many times a settings file's issues are asked for at most (core._AUTORUN_ROUNDS). */
const AUTORUN_ROUNDS = 64;

/**
 * SC-AUTORUN findings for an editor's or AI agent's settings file (core.autorun_issues). The engine reads the file
 * and judges each command (BR-7 step 2: `autorun_issues`); it names the files of the tree it follows a command
 * into, and `read` reads them (null: the commands alone are judged).
 */
export function autorunIssues(path, lines, read = null) {
  const text = lines.join("\n");
  const files = {};
  for (let k = 0; k < AUTORUN_ROUNDS; k++) {
    const got = call("autorun_issues", { path, follow: read !== null, files }, text);
    if (got.issues) return got.issues.map(([line, rule]) => mkIssue(rule, path, line, lines));
    for (const rel of got.need) files[rel] = read(rel);
  }
  const got = call("autorun_issues", { path, follow: false }, text);
  return got.issues.map(([line, rule]) => mkIssue(rule, path, line, lines));
}

// ---- CI files (SC-WORKFLOW-*, SC-GITLAB-*; core.ci_issues) ----
/**
 * The issues of a CI file (core.ci_issues): a GitHub Actions workflow's SC-WORKFLOW-* or a GitLab CI file's
 * SC-GITLAB-*, nothing for another file. The engine reads the file (BR-7: `ci_issues`); the path is asked
 * first, so another file's text is not handed over.
 */
export function ciIssues(path, lines) {
  if (call("ci_kind", {}, path) === null) return [];
  return call("ci_issues", { path }, lines.join("\n")).map(([line, rule]) => mkIssue(rule, path, line, lines));
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
 * Credentials in a config or data file (core.scan_config_file): S-TOKEN on every line, S-SECRET outside comments,
 * nothing else — it is not code. Suppression markers work in the file's comments, as in code. An editor's or AI
 * agent's settings that run commands also get SC-AUTORUN, and a CI file its checks. The engine reads the file (BR-7
 * step 3: `scan_config`) and names the files of the tree a settings file's commands run; `read` reads them (null:
 * the commands alone are judged). A file that spends the engine's work budget is SC-TRUNCATED.
 */
export function scanConfigFile(path, rawContent, read = null) {
  const content = String(rawContent ?? "");
  const files = {};
  const args = { path, follow: read !== null, files, redact: REDACT.on, neumaier: false };
  try {
    for (let k = 0; k < AUTORUN_ROUNDS; k++) {
      const got = scanConfig(path, args, content);
      if (got.issues) return got.issues;
      for (const rel of got.need) files[rel] = read(rel);
    }
    return scanConfig(path, { ...args, follow: false }, content).issues;
  } catch (e) {
    if (!(e instanceof NativeExhausted)) throw e;
    return [truncatedIssue(path, EXHAUSTED)];
  }
}
