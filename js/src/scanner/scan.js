// scanFile — twin of lazaret.scanner.core.scan_file, implementing the
// shared semantics (FIX-SPEC items 1, 2, 5, 6, 7, 12, 13, 14). A source file's
// scan is the native engine's (../lib/native.js), in dependency mode and in
// project mode alike (Q-1, 0.1.9: the SQL statements without WHERE, taint,
// the SQL-sink pass, the function metrics, the suppression markers and the cap
// are the engine's too); this module scans config and data files (credentials,
// auto-run settings, workflows), whose checks are still the package's own.
import { normalizeSource } from "./lines.js";
import { OBF_IDENT_RE, SECRET_SKIP_RE, makeSuppressor, mkIssue } from "./engine.js";
import { lexLines, jsxReading } from "../lib/lexer.js";
import { cpLen, cpPrefix, pyRepr, isPySpace } from "../lib/pycompat.js";
import { findSecretToken, registerScanContext, REDACT } from "../lib/redact.js";
import { truncatedIssue, normalizeNewlines, treeJoin } from "../lib/fs.js";
import { pinUnicode } from "../lib/unicode13.js";
import { documentationToken, keyMaterial, secretCol, redactConfigValues, NETRC_NAMES, netrcAnonymous } from "../lib/configsecrets.js";
import { configKind, ownerDir, entries as autorunEntries, localCommand } from "../lib/autorun.js";
import { isWorkflow, findings as workflowFindings, hardening as workflowHardening,
  hardeningRule as workflowHardeningRule } from "../lib/ghworkflow.js";
import { isGitlabCi, hardening as gitlabHardening, hardeningRule as gitlabHardeningRule } from "../lib/gitlabci.js";
import { agentHijackInCommand, installScriptRisk, followHook, nodeCandidates, spawnedScripts, scriptLang, packValues,
  scanDependencyFile, scanProjectFile, taintFindings, NativeExhausted } from "../lib/native.js";

export { isComment } from "./engine.js";

export const LONG_LINE = 160;
/** Spec 7: per (file, rule) cap for every non-security rule (S-, T-, SC-, X-, SQL- are never capped). */
export const CAP_PER_RULE = 200;
export const FINDING_CAP = CAP_PER_RULE;
const NEVER_CAPPED_PREFIXES = ["S-", "T-", "SC-", "X-", "SQL-"];
/**
 * Spec 14: per-file backstop of a config or data file's scan (scanConfigFile). A source file's scan
 * is the engine's, bounded by its work budget instead (a file that spends it is SC-TRUNCATED).
 */
export const SCAN_TIME_BUDGET_MS = 30_000;
let timeBudgetMs = SCAN_TIME_BUDGET_MS;
export function setScanTimeBudget(ms) { timeBudgetMs = ms ?? SCAN_TIME_BUDGET_MS; }
/** The time each config file's scan may take (ms). */
export function scanTimeBudget() { return timeBudgetMs; }


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
  if (/^\s*(def |import |from \w+ import|class \w+.*:)/m.test(content) && !/[{};]\s*$/m.test(content)) return "py";
  return /\b(def |elif |None|self\.)/.test(content) && !/\b(const|let|=>|function)\b/.test(content) ? "py" : "js";
}

class ScanBudgetExceeded extends Error {}
const isBlank = (s) => { for (const ch of s) if (!isPySpace(ch)) return false; return true; };

/**
 * Project mode's intra-file taint alone (twin of core.taint_scan; the engine's, taint.rs): the T-*
 * findings of a file's lines, before the suppression markers and the cap. scanFile runs the same pass.
 */
export function taintScan(file, lines, lang) {
  if (lang !== "py" && lang !== "js") return [];
  return taintFindings(file, lines.join("\n"), lang, { jsx: jsxReading(file), redact: REDACT.on });
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
const autorunScriptRisk = (text, lang = null) =>
  installScriptRisk(text, true, false, lang).filter((r) => !r.startsWith(AGENT_SETTINGS_REASON));

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
    const found = autorunScriptRisk(text, scriptLang(rel));
    OBF_IDENT_RE.lastIndex = 0;
    if (new Set(text.match(OBF_IDENT_RE) ?? []).size >= 5) found.push("is obfuscated");
    if (found.length) return [found, target];
    // (0.1.8) the scripts it starts (spawnedScripts): a loader that fetches a runtime and runs a file of the tree with it
    for (const [where, path] of spawnedScripts(normalizeNewlines(text), scriptLang(rel))) {
      const srel = treeJoin(where === "dir" ? (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "") : base, path);
      const stext = srel !== null ? read(srel) : null;
      const more = stext ? autorunScriptRisk(stext, scriptLang(srel)) : [];
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
  const text = lines.join("\n");
  for (const [kind, line, d] of workflowFindings(text)) {
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
  for (const [kind, line, d] of workflowHardening(text)) out.push(mkIssue(workflowHardeningRule(kind, d), path, line, lines));
  return out;
}

/** A GitLab CI file's hardening checks (core.gitlab_issues). */
export function gitlabIssues(path, lines) {
  return gitlabHardening(lines.join("\n")).map(([kind, line, d]) => mkIssue(gitlabHardeningRule(kind, d), path, line, lines));
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
  const netrc = NETRC_NAMES.has(path.replace(/\\/g, "/").split("/").pop().toLowerCase());
  registerScanContext(lines, SECRET_SKIP_RE, (line) => redactConfigValues(line, netrc));
  const deadline = Date.now() + timeBudgetMs;
  const issues = [];
  try {
    if (configKind(path) !== null) issues.push(...autorunIssues(path, lines, read));
    if (isWorkflow(path)) issues.push(...workflowIssues(path, lines));
    else if (isGitlabCi(path)) issues.push(...gitlabIssues(path, lines));
    const anonymous = netrc ? netrcAnonymous(lex.code) : new Map();
    for (let i = 0; i < lines.length; i++) {
      if (Date.now() > deadline) throw new ScanBudgetExceeded();
      const line = lines[i];
      if (!line || isBlank(line)) continue;
      let col = configTokenCol(line, lines, i);
      if (col >= 0) issues.push(mkIssue(TOKEN_RULE(), path, i + 1, lines, col));
      if (!lex.comment[i]) {
        col = secretCol(lex.code[i], netrc, anonymous.get(i));
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
