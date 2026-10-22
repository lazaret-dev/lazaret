// scanFile — twin of lazaret.scanner.core.scan_file, implementing the
// shared semantics (FIX-SPEC items 1, 2, 5, 6, 7, 12, 13, 14). A source file's
// scan is the native engine's (../lib/native.js), in dependency mode and in
// project mode alike (Q-1, 0.1.9: the SQL statements without WHERE, taint,
// the SQL-sink pass, the function metrics, the suppression markers and the cap
// are the engine's too), and so is a config or data file's (BR-7: its
// credentials, an editor's or agent's settings, a CI file's checks).
import { mkIssues } from "./engine.js";
import { jsxReading } from "../lib/lexer.js";
import { REDACT } from "../lib/redact.js";
import { truncatedIssue } from "../lib/issue.js";
import { normalizeNewlines } from "../lib/encoding.js";
import { call, nodeCandidates, scanDependencyFile, scanProjectFile, scanConfig, taintFindings, NativeExhausted, EXHAUSTED }
  from "../lib/native.js";

export { EXHAUSTED };

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
 * Scan one file: {name|path, content, lang, dep, helpers}. dep → dependency mode:
 * only supply-chain and secret rules, no suppression markers honored. `helpers`
 * (a project's Python file): what it imports from the others that the taint
 * pass follows calls into (taintHelpers; Q-4). The
 * native engine reads the file whole, in either mode; a file that spends the
 * engine's work budget is SC-TRUNCATED.
 */
export function scanFile(file) {
  const path = file.name ?? file.path;
  const raw = String(file.content ?? "");
  const lang = file.lang ?? detectLang(String(path ?? ""), raw);
  const opts = { jsx: jsxReading(path), redact: REDACT.on };
  try {
    return file.dep ? scanDependencyFile(path, raw, lang, opts)
      : scanProjectFile(path, raw, lang, { ...opts, helpers: file.helpers ?? null });
  } catch (e) {
    if (!(e instanceof NativeExhausted)) throw e;
    return [truncatedIssue(path, EXHAUSTED)];
  }
}

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
    if (got.issues) return mkIssues(path, lines, got.issues.map(([line, rule]) => [rule, line]));
    for (const rel of got.need) files[rel] = read(rel);
  }
  const got = call("autorun_issues", { path, follow: false }, text);
  return mkIssues(path, lines, got.issues.map(([line, rule]) => [rule, line]));
}

/** The kind of AI-agent skill or instruction file `path` names, or null (core.agentdoc_kind; RA-3). */
export const agentdocKind = (path) => call("agentdoc_kind", {}, path);

/**
 * SC-AGENT-SKILL findings for an agent skill or instruction file (core.agentdoc_issues; RA-3). The engine reads
 * the file (`agentdoc_issues`): the commands and code it tells the agent to run, a script of its folder they run
 * (followed via `read`), a password-protected archive, a paste host or public raw IP, hidden text, or an order to
 * send data out. `dep`: a dependency's file (CRITICAL / MAJOR), false the project's own (INFO); null, a file under a
 * dependency folder is a dependency's.
 */
export function agentdocIssues(path, lines, read = null, dep = null) {
  const text = lines.join("\n");
  const files = {};
  const args = { path, follow: read !== null, files };
  if (dep !== null) args.dep = !!dep;
  for (let k = 0; k < AUTORUN_ROUNDS; k++) {
    const got = call("agentdoc_issues", args, text);
    if (got.issues) return mkIssues(path, lines, got.issues.map(([line, rule]) => [rule, line]));
    for (const rel of got.need) files[rel] = read(rel);
  }
  const got = call("agentdoc_issues", { ...args, follow: false }, text);
  return mkIssues(path, lines, got.issues.map(([line, rule]) => [rule, line]));
}

// ---- CI files (SC-WORKFLOW-*, SC-GITLAB-*; core.ci_issues) ----
/**
 * The issues of a CI file (core.ci_issues): a GitHub Actions workflow's SC-WORKFLOW-* or a GitLab CI file's
 * SC-GITLAB-*, nothing for another file. The engine reads the file (BR-7: `ci_issues`); the path is asked
 * first, so another file's text is not handed over.
 */
export function ciIssues(path, lines) {
  if (call("ci_kind", {}, path) === null) return [];
  return mkIssues(path, lines, call("ci_issues", { path }, lines.join("\n")).map(([line, rule]) => [rule, line]));
}

/**
 * read(rel) for autorunIssues: the text of a scanned source or config file
 * ('/'-separated, root-relative, resolved as nodeCandidates does), or null
 * (core.tree_reader). `disk`: read(rel) of a file the walk did not keep (a
 * dependency's shell script its agent skill runs), tried for rel itself when no
 * scanned file answers.
 */
export function treeReader(files, configs, disk = null) {
  const texts = new Map();
  for (const f of [...files, ...configs]) {
    const key = f.path.replaceAll("\\", "/");
    if (!texts.has(key)) texts.set(key, f.content);
  }
  return (rel) => {
    for (const cand of nodeCandidates(rel)) if (texts.has(cand)) return normalizeNewlines(texts.get(cand));
    if (disk !== null) {
      const text = disk(rel);
      if (text !== null && text !== undefined) return normalizeNewlines(text);
    }
    return null;
  };
}

/**
 * Credentials in a config or data file (core.scan_config_file): S-TOKEN on every line, S-SECRET outside comments,
 * nothing else — it is not code. Suppression markers work in the file's comments, as in code. An editor's or AI
 * agent's settings that run commands also get SC-AUTORUN, a CI file its checks, and an AI agent's skill or instruction
 * file SC-AGENT-SKILL instead of the credential pass (`dep` as agentdocIssues'). The engine reads the file (BR-7
 * step 3: `scan_config`) and names the files of the tree a settings file's commands run; `read` reads them (null:
 * the commands alone are judged). A file that spends the engine's work budget is SC-TRUNCATED.
 */
export function scanConfigFile(path, rawContent, read = null, dep = null) {
  const content = String(rawContent ?? "");
  const files = {};
  const args = { path, follow: read !== null, files, redact: REDACT.on, neumaier: false };
  if (dep !== null) args.dep = !!dep;           // (an agent skill or instruction file's SC-AGENT-SKILL: RA-3)
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
