// Supply-chain manifest scanning (package.json lifecycle scripts, binding.gyp
// actions and command expansions) — JS twin of lazaret.scanner.core's
// load_manifest / scan_manifest / scan_gyp (shared semantics spec 3). Secret
// redaction lives in ./redact.js and is re-exported here for the existing
// import paths.

import { mkIssue } from "./issue.js";
import { DEP_MARKERS } from "./fs.js";
import { pyRepr, pyStr, pyStrip, MAX_JSON_DEPTH, jsonDepthExceeds } from "./pycompat.js";
import { pyJsonParse, jsonErrorWhere, pyLiteralParse } from "./pyjson.js";
import { REDACT, redactText } from "./redact.js";

export { SECRET_RULES, REDACT_PLACEHOLDER, redactContextLine, redactSecretSnippet, redactResult, setRedactSecrets } from "./redact.js";

// Scripts npm runs when a package is installed as a dependency. Publisher-side
// scripts (prepack, prepublishOnly, postpublish, ...) only ever run on the
// maintainer's machine while packaging a release, so they are not install hooks.
export const NPM_INSTALL_SCRIPTS = ["preinstall", "install", "postinstall"];
// In a checked-out project, `npm install` also runs the prepare family.
export const NPM_PREPARE_SCRIPTS = ["preprepare", "prepare", "postprepare"];
export const NPM_LOCAL_INSTALL_SCRIPTS = [...NPM_INSTALL_SCRIPTS, ...NPM_PREPARE_SCRIPTS];
export const NPM_LIFECYCLE_SCRIPTS = NPM_LOCAL_INSTALL_SCRIPTS;   // backwards-compatible name

// A manifest inside an installed-dependency directory belongs to a package that
// came from a registry: only the consumer-run scripts apply to it.
// Twin of lazaret.scanner.core.is_dependency_manifest (same DEP_MARKERS list).
export function isDependencyManifest(path) {
  return String(path).split(/[\\/]/).slice(0, -1).some((part) => DEP_MARKERS.has(part));
}
/** A manifest at the top of the scanned tree / package (no directory part). */
export function isRootManifest(path) {
  const p = String(path).replace(/\\/g, "/").replace(/^\/+/, "");
  const dir = p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "";
  return dir === "" || dir === ".";
}

// G11: fetch/eval pattern list. Mere presence of a lifecycle script is MAJOR;
// matching this list escalates to CRITICAL.
export const INSTALL_HOOK_RE =
  /curl|wget|iwr|Invoke-WebRequest|node\s+-e|bash\s+-c|sh\s+-c|powershell|base64|\beval\b/i;

const NODE_E_RE = /node\s+-e\s+(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|(\S+))/g;
const LOCAL_REQUIRE_RE = /require\(\s*\\?["'](\.{1,2}\/[^"'\\]+)\\?["']\s*\)/g;
const INLINE_DANGER_RE = /https?|fetch|child_process|exec|spawn|eval|Function|Buffer|atob|base64|net\.|dgram|process\.env/;

/**
 * Does an install-hook command fetch or evaluate code? `node -e` alone is not
 * evidence: core-js's `node -e "try{require('./postinstall')}catch(e){}"` only
 * loads a file shipped in the package (which is scanned like any other).
 * Twin of lazaret.scanner.core._hook_is_suspicious.
 */
export function hookIsSuspicious(cmd) {
  if (!INSTALL_HOOK_RE.test(cmd)) return false;
  let remainder = cmd;
  for (const m of cmd.matchAll(NODE_E_RE)) {
    const code = m[1] ?? m[2] ?? m[3] ?? "";
    const withoutRequires = code.replace(LOCAL_REQUIRE_RE, "");
    if (new RegExp(LOCAL_REQUIRE_RE.source).test(code) && !INLINE_DANGER_RE.test(withoutRequires))
      remainder = remainder.replace(m[0], " ");
  }
  return INSTALL_HOOK_RE.test(remainder);
}

function scInstallHookIssue(path, lineNo, lines, script, cmd, suspicious, sev = null) {
  sev = sev || (suspicious ? "CRITICAL" : "MAJOR");
  let msg, why;
  if (suspicious) {
    msg = `"${script}" script runs a network-fetch/eval command at install time.`;
    why = "Install hooks execute automatically on npm install — the most common supply-chain compromise vector — and this one fetches or executes remote code.";
  } else {
    msg = `"${script}" script runs code at install time: ${pyRepr(cmd)}.`;
    why = "Install hooks run automatically with user privileges on npm install, before anyone reviews the package. Many legitimate packages use one (to fetch a platform binary, for example), so on its own this is a capability to review, not evidence of malice.";
    if (sev === "INFO") {
      why = "A prepare-family script runs on `npm install` in this checkout; it is the project's own build step (husky, patch-package, a compile), listed for inventory. Suspicious commands here stay CRITICAL.";
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
  return issue;
}

// core.MANIFEST_DEPTH_MSG: the same limit (MAX_JSON_DEPTH = core.MAX_MANIFEST_DEPTH)
// and the same text in both engines.
export const MANIFEST_DEPTH_MSG = `Manifest is too deeply nested to parse (more than ${MAX_JSON_DEPTH} levels).`;

function manifestDepthIssue(path) {
  // 48033f94: pathologically deep-nested manifest — reported as CRITICAL,
  // never a crash, never a silent skip.
  return mkIssue(
    { id: "SC-MANIFEST-DEPTH", name: "Hostile manifest nesting depth",
      type: "HOTSPOT", sev: "CRITICAL",
      msg: MANIFEST_DEPTH_MSG,
      why: "A manifest nested this deep cannot be produced by any real build tool — it exists purely to crash or blind security scanners. Treating it as data would silently drop every other finding in the package.",
      fix: "Reject this package/file at your ingestion boundary; investigate the source.",
      ref: "CWE-506 · Supply chain" }, path, 1, []);
}

/** SC-MANIFEST-UNPARSEABLE (MAJOR): a ROOT package.json / binding.gyp the scanner cannot read. */
export function manifestUnparseableIssue(path, reason) {
  const p = String(path).replace(/\\/g, "/");
  const name = p.slice(p.lastIndexOf("/") + 1) || String(path);
  return mkIssue(
    { id: "SC-MANIFEST-UNPARSEABLE", name: "Unparseable manifest",
      type: "HOTSPOT", sev: "MAJOR",
      msg: `${name} could not be parsed (${reason}); its install hooks could not be checked.`,
      why: "Package managers are more forgiving than a strict parser in places (a byte-order mark, number formats), so a manifest the scanner cannot read may still run install scripts when the package is installed. An unreadable root manifest is reported instead of treated as empty.",
      fix: "Make the manifest valid JSON (binding.gyp: a Python/JSON literal) and review its scripts by hand.",
      ref: "CWE-506 · Supply chain" }, path, 1, []);
}

const pyTypeName = (v) => (v === null ? "NoneType" : Array.isArray(v) ? "list" : typeof v === "string" ? "str"
  : typeof v === "boolean" ? "bool" : typeof v === "number" ? (Number.isInteger(v) ? "int" : "float") : "dict");

/**
 * Parse manifest-shaped, attacker-controlled text the way the package
 * manager does (twin of core.load_manifest) → [data, issues]. A leading
 * UTF-8 BOM is stripped first (npm does). data is null when the text cannot
 * be parsed; issues then holds SC-MANIFEST-DEPTH for a document nested
 * deeper than MAX_JSON_DEPTH (brackets outside strings, checked before
 * parsing wherever a syntax error sits, as the Python engine does), or
 * SC-MANIFEST-UNPARSEABLE when the manifest is at the root. A top level
 * that is not an object counts as unparseable too. pythonLiteral: also
 * accept Python literal syntax (binding.gyp).
 */
export function loadManifest(path, content, { pythonLiteral = false } = {}) {
  const root = isRootManifest(path);
  if (typeof content !== "string") return [null, root ? [manifestUnparseableIssue(path, "not text")] : []];
  const text = content.startsWith("\ufeff") ? content.slice(1) : content;
  if (jsonDepthExceeds(text)) return [null, [manifestDepthIssue(path)]];
  let data = null, reason = null, litType = null;
  const r = pyJsonParse(text);
  if (r.depth) return [null, [manifestDepthIssue(path)]];
  if (r.ok) {
    data = r.value;
    // json.loads(parse_int=_json_int): an integer literal up to 1000 characters is a Python int
    if (typeof data === "number") {
      const lit = pyStrip(text);
      litType = /^-?(?:0|[1-9]\d*)$/.test(lit) && lit.length <= 1000 ? "int" : "float";
    }
  } else reason = `JSONDecodeError: ${jsonErrorWhere(text, r.pos)}`;
  if (data === null && pythonLiteral) {
    const lit = pyLiteralParse(pyStrip(text));
    if (lit.ok) { data = lit.value; reason = null; litType = lit.type; }
    else reason ||= lit.error;
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    if (data !== null) reason = `top level is a ${litType ?? pyTypeName(data)}, not an object`;
    return [null, root ? [manifestUnparseableIssue(path, reason || "unparseable")] : []];
  }
  return [data, []];
}

const own = (obj, key) => (Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined);

/**
 * package.json install hooks (G11 policy). `registry: true` (or a manifest
 * inside node_modules/...) counts only the scripts npm runs for an installed
 * dependency; a checked-out project also counts the prepare family, which
 * is INFO unless suspicious. An unparseable root manifest is
 * SC-MANIFEST-UNPARSEABLE.
 */
export function scanManifest(path, content, { registry = isDependencyManifest(path) } = {}) {
  const [data, issues] = loadManifest(path, content);
  if (data === null) return issues;
  const body = String(content).startsWith("\ufeff") ? String(content).slice(1) : String(content);
  const lines = body.split("\n");
  const scripts = own(data, "scripts");
  if (scripts && typeof scripts === "object" && !Array.isArray(scripts)) {
    for (const hook of (registry ? NPM_INSTALL_SCRIPTS : NPM_LOCAL_INSTALL_SCRIPTS)) {
      const cmd = own(scripts, hook);
      if (typeof cmd !== "string" || !pyStrip(cmd)) continue;
      const suspicious = hookIsSuspicious(cmd);
      const sev = !registry && NPM_PREPARE_SCRIPTS.includes(hook) && !suspicious ? "INFO" : null;
      const lineNo = lines.findIndex((l) => l.includes(`"${hook}"`)) + 1 || 1;
      issues.push(scInstallHookIssue(path, lineNo, lines, hook, cmd, suspicious, sev));
    }
  }
  return issues;
}

// gyp command expansions run a shell command while node-gyp configures the
// build: '<!(cmd)', '<!@(cmd)', '>!(cmd)', '>!@(cmd)'.
const GYP_EXPANSION_RE = /[<>]!@?\(/g;
// The ubiquitous benign form: print an include path of a dependency.
const GYP_NODE_REQUIRE_RE = /node\s+-[ep]\s+(?:"|')\s*require\(\s*\\?["'][\w@./-]+\\?["']\s*\)(?:\.[\w$]+)*\s*;?\s*(?:"|')/g;
const GYP_MAX_NODES = 100_000;

function gypExpansionCommand(text, start) {
  const i = text.indexOf("(", start) + 1;
  let depth = 1, j = i;
  while (j < text.length && depth) {
    if (text[j] === "(") depth++;
    else if (text[j] === ")") depth--;
    j++;
  }
  return depth === 0 ? text.slice(i, j - 1) : text.slice(i);
}

/** [command, kind] for every action and command expansion anywhere in a parsed gyp document. */
function gypCommands(data) {
  const out = [];
  const stack = [data];
  let seen = 0;
  while (stack.length && seen < GYP_MAX_NODES) {
    const node = stack.pop();
    seen++;
    if (Array.isArray(node)) { for (const x of node) stack.push(x); continue; }
    if (node && typeof node === "object") {
      for (const [key, value] of Object.entries(node)) {
        if (key === "action" && Array.isArray(value)) out.push([value.map(pyStr).join(" "), "action"]);
        stack.push(key);
        stack.push(value);
      }
      continue;
    }
    if (typeof node === "string" && /[<>]!@?\(/.test(node)) {
      GYP_EXPANSION_RE.lastIndex = 0;
      let m;
      while ((m = GYP_EXPANSION_RE.exec(node))) out.push([gypExpansionCommand(node, m.index), "expansion"]);
    }
  }
  return out.reverse();
}

/**
 * binding.gyp custom build actions (G11 policy, same as lifecycle scripts):
 * any action is MAJOR, one matching INSTALL_HOOK_RE is CRITICAL; command
 * expansions ('<!(cmd)') are findings only when suspicious. gyp files are
 * Python literals, so JSON and Python-literal syntax are both accepted.
 */
export function scanGyp(path, content) {
  const [data, issues] = loadManifest(path, content, { pythonLiteral: true });
  if (data === null) return issues;
  const body = String(content).startsWith("\ufeff") ? String(content).slice(1) : String(content);
  const lines = body.split("\n");
  for (const [cmd, kind] of gypCommands(data)) {
    let suspicious;
    if (kind === "action") suspicious = INSTALL_HOOK_RE.test(cmd);
    else {
      suspicious = INSTALL_HOOK_RE.test(cmd.replace(GYP_NODE_REQUIRE_RE, " "));
      if (!suspicious) continue;
    }
    const needles = kind === "expansion" ? [cmd] : cmd.split(" ");
    const lineNo = lines.findIndex((l) => needles.some((a) => a && l.includes(a))) + 1 || 1;
    issues.push(scInstallHookIssue(path, lineNo, lines,
      kind === "action" ? "binding.gyp action" : "binding.gyp command expansion", cmd, suspicious));
  }
  return issues;
}
