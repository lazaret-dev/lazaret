// Supply-chain manifests (package.json lifecycle scripts and dependencies,
// binding.gyp actions and command expansions): the engine's since BR-7's step
// 3 (b) (rust/crates/lazaret-engine/src/manifest/, the scan_manifest,
// scan_gyp and manifest_data calls), as for the Python package (core's
// load_manifest, scan_manifest and scan_gyp). This module keeps the names the
// package calls. Secret redaction lives in ./redact.js and is re-exported
// here for the existing import paths.

import { mkIssue } from "./issue.js";
import { truncatedIssue } from "./issue.js";
import { pyRe, pyRepr, MAX_JSON_DEPTH, PY_ORDER } from "./pycompat.js";
import { call, hookIsSuspicious, installScriptSeverity, issuesOf, NativeExhausted, exhaustedWhy } from "./native.js";
import { REDACT, redactText } from "./redact.js";

export { SECRET_RULES, REDACT_PLACEHOLDER, redactContextLine, redactResult, setRedactSecrets } from "./redact.js";

// Scripts npm runs when a package is installed as a dependency. Publisher-side
// scripts (prepack, prepublishOnly, postpublish, ...) only ever run on the
// maintainer's machine while packaging a release, so they are not install hooks.
export const NPM_INSTALL_SCRIPTS = ["preinstall", "install", "postinstall"];
// In a checked-out project, `npm install` also runs the prepare family.
export const NPM_PREPARE_SCRIPTS = ["preprepare", "prepare", "postprepare"];
export const NPM_LOCAL_INSTALL_SCRIPTS = [...NPM_INSTALL_SCRIPTS, ...NPM_PREPARE_SCRIPTS];
export const NPM_LIFECYCLE_SCRIPTS = NPM_LOCAL_INSTALL_SCRIPTS;   // backwards-compatible name

/** A manifest at the top of the scanned tree / package (no directory part). */
export function isRootManifest(path) {
  const p = String(path).replace(/\\/g, "/").replace(/^\/+/, "");
  const dir = p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "";
  return dir === "" || dir === ".";
}

// G11: fetch/eval pattern list. Mere presence of a lifecycle script is MAJOR;
// matching this list is only a hint in that finding's message since 0.1.8
// (what escalates a hook is what its command does: hookCommandRisk). This and the patterns below are
// core's text compiled with Python semantics by pyRe (Unicode \w, \s and \b,
// Unicode case folding): as plain JS regexes, `baſe64` (U+017F folds to s)
// was CRITICAL in core but MAJOR here, and `require('./données')` in a gyp
// expansion was benign in core (\w matches é) but CRITICAL here.
export const INSTALL_HOOK_RE =
  pyRe(String.raw`curl|wget|iwr|Invoke-WebRequest|node\s+-e|bash\s+-c|sh\s+-c|powershell|base64|\beval\b`, "i");

export { hookIsSuspicious };

/**
 * The command of each SC-INSTALL-HOOK finding as the manifest writes it
 * (issue.cmd is redacted): what a --deps scan follows to the files the hook
 * runs (src/deps.js), as core follows issue["cmd"] before the report is
 * redacted. Not part of the finding, so never in a report.
 */
export const HOOK_COMMANDS = new WeakMap();

/**
 * SC-INSTALL-HOOK for an install hook's command: CRITICAL with the reasons it looks hostile (hookCommandRisk), else
 * MAJOR (or `sev`); `hint`: the command runs a download or evaluation tool (INSTALL_HOOK_RE), worth reading, not
 * evidence (0.1.8). Twin of core._sc_install_hook_issue.
 */
export function scInstallHookIssue(path, lineNo, lines, script, cmd, reasons, sev = null, hint = false) {
  const hostile = Boolean(reasons && reasons.length);
  // RA-12: a non-empty reason list is CRITICAL only when a reason is strong; a weaker one (cert-off) is MAJOR
  sev = sev || (hostile && installScriptSeverity(reasons)) || "MAJOR";
  let msg, why;
  if (hostile) {
    msg = `"${script}" script ${reasons.join("; and ")}.`;
    why = "Install hooks execute automatically on npm install — the most common supply-chain compromise vector — and this command does what malicious install hooks do.";
  } else {
    msg = hint ? `"${script}" script runs a download or evaluation command at install time: ${pyRepr(cmd)}.`
      : `"${script}" script runs code at install time: ${pyRepr(cmd)}.`;
    why = "Install hooks run automatically with user privileges on npm install, before anyone reviews the package. Many legitimate packages use one (to fetch a platform binary, for example), so on its own this is a capability to review, not evidence of malice.";
    if (sev === "INFO") {
      why = "A prepare-family script runs on `npm install` in this checkout; it is the project's own build step (husky, patch-package, a compile), listed for inventory. Hostile commands here stay CRITICAL.";
    }
  }
  const issue = mkIssue(
    { id: "SC-INSTALL-HOOK", name: "Install hook", type: "HOTSPOT",
      sev, msg, why,
      fix: `Review the ${script} script; use --ignore-scripts in CI if unneeded.`,
      ref: "CWE-506 · Supply chain" }, path, lineNo, lines);
  // lets a caller follow the hook to the script it runs; redacted here (spec 6:
  // any field copying source text) so library callers never see a credential
  issue.cmd = REDACT.on ? redactText(cmd) : cmd;
  HOOK_COMMANDS.set(issue, cmd);
  return issue;
}

// core.MANIFEST_DEPTH_MSG: the same limit (MAX_JSON_DEPTH = core.MAX_MANIFEST_DEPTH)
// and the same text in both packages (the engine's finding).
export const MANIFEST_DEPTH_MSG = `Manifest is too deeply nested to parse (more than ${MAX_JSON_DEPTH} levels).`;
/** SC-INSTALL-HOOK findings listed per gyp file (the rule pack's GYP_MAX_HOOK_FINDINGS); one more sums up the rest. */
export const GYP_MAX_HOOK_FINDINGS = 100;

/** The engine's issues of a manifest: each hook's command as it runs kept for --deps (HOOK_COMMANDS), its `cmd`
 * redacted (spec 6: any field copying source text). A manifest that spends the work budget is SC-TRUNCATED. */
function engineIssues(path, name, args, content) {
  let issues;
  try {
    issues = issuesOf(path, call(name, { path, redact: REDACT.on, ...args }, String(content)).issues);
  } catch (e) {
    if (!(e instanceof NativeExhausted)) throw e;
    return [truncatedIssue(path, exhaustedWhy(e))];
  }
  for (const issue of issues) {
    if (typeof issue.cmd !== "string") continue;
    HOOK_COMMANDS.set(issue, issue.cmd);
    if (REDACT.on) issue.cmd = redactText(issue.cmd);
  }
  return issues;
}

/**
 * A package.json, attacker-controlled, read the way npm reads it (the
 * engine's: core.load_manifest) → [data, issues]: data null when it cannot
 * be read, and then SC-MANIFEST-DEPTH, or SC-MANIFEST-UNPARSEABLE for a root
 * manifest. The data is what --deps reads (numbers as JSON numbers, null for
 * NaN and the infinities).
 */
export function loadManifest(path, content) {
  if (typeof content !== "string") return [null, []];
  const got = call("manifest_data", { path, redact: REDACT.on }, content);
  return [fromEngine(got.data), issuesOf(path, got.issues)];
}

/** The engine's data ({"d": [[key, value]…]} for each dict) as objects in Python's key order (PY_ORDER, pyEntries). */
function fromEngine(v) {
  if (Array.isArray(v)) return v.map(fromEngine);
  if (v === null || typeof v !== "object") return v;
  const obj = {}, order = [];
  Object.defineProperty(obj, PY_ORDER, { value: order });
  for (const [k, x] of v.d) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) order.push(k);
    Object.defineProperty(obj, k, { value: fromEngine(x), enumerable: true, writable: true, configurable: true });
  }
  return obj;
}

/**
 * package.json install hooks (G11 policy): MAJOR, CRITICAL when the command
 * looks hostile read as a program (hookCommandRisk, 0.1.8). `registry: true`
 * (or a manifest inside node_modules/...) counts only the scripts npm runs
 * for an installed dependency; a checked-out project also counts the
 * prepare family, which is INFO unless hostile or hinted (INSTALL_HOOK_RE).
 * Dependencies npm would fetch from an insecure source are SC-DEP-URL
 * (D-14). An unparseable root manifest is SC-MANIFEST-UNPARSEABLE. The
 * engine's (core.scan_manifest).
 */
export function scanManifest(path, content, { registry = null } = {}) {
  return engineIssues(path, "scan_manifest", { registry: registry === null ? null : !!registry, hooks: null }, content);
}

/** What makes a dependency's spec risky to fetch: ["a plain-http URL", "a raw IP address (HOST)"], the ones that
 * apply; [] for none (the engine's: core.dependency_url_risk). */
export function dependencyUrlRisk(spec) {
  return typeof spec === "string" ? call("manifest_check", { check: "dep_url_risk" }, spec) : [];
}

/**
 * binding.gyp custom build actions and command expansions (G11; the
 * engine's: core.scan_gyp): any action is MAJOR, one whose command looks
 * hostile read as a program is CRITICAL; a command expansion is CRITICAL when
 * hostile (its output is its value: kept), MAJOR when it only runs a
 * download or evaluation tool, INFO inventory when it runs a file of the
 * package (its `cmd`, the command as it runs, is what a --deps scan
 * follows), and otherwise not listed. gyp files are Python literals, so JSON
 * and Python-literal syntax are both accepted. At most GYP_MAX_HOOK_FINDINGS
 * are listed and one more sums up the rest; a document past the walk's
 * bounds is SC-TRUNCATED.
 */
export function scanGyp(path, content) {
  return engineIssues(path, "scan_gyp", {}, content);
}
