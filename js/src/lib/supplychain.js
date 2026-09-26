// Supply-chain manifest scanning (package.json lifecycle scripts, binding.gyp
// actions and command expansions) — JS twin of lazaret.scanner.core's
// load_manifest / scan_manifest / scan_gyp (shared semantics spec 3). Secret
// redaction lives in ./redact.js and is re-exported here for the existing
// import paths.

import { mkIssue } from "./issue.js";
import { DEP_MARKERS, truncatedIssue } from "./fs.js";
import { pyRe, pyRepr, pyLiteralStr, pyStrip, pyLstrip, cpLen, PyComplex, MAX_JSON_DEPTH, jsonDepthExceeds } from "./pycompat.js";
import { pyJsonParse, jsonErrorWhere, pyLiteralParse } from "./pyjson.js";
import { REDACT, redactText, registerScanContext, SecretLiterals } from "./redact.js";

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
// matching this list escalates to CRITICAL. This and the patterns below are
// core's text compiled with Python semantics by pyRe (Unicode \w, \s and \b,
// Unicode case folding): as plain JS regexes, `baſe64` (U+017F folds to s)
// was CRITICAL in core but MAJOR here, and `require('./données')` in a gyp
// expansion was benign in core (\w matches é) but CRITICAL here.
export const INSTALL_HOOK_RE =
  pyRe(String.raw`curl|wget|iwr|Invoke-WebRequest|node\s+-e|bash\s+-c|sh\s+-c|powershell|base64|\beval\b`, "i");

const NODE_E_SRC = String.raw`node\s+-e\s+(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|(\S+))`;
const NODE_E_RE = pyRe(NODE_E_SRC, "g");
const LOCAL_REQUIRE_SRC = String.raw`require\(\s*\\?["'](\.{1,2}/[^"'\\]+)\\?["']\s*\)`;
const LOCAL_REQUIRE_RE = pyRe(LOCAL_REQUIRE_SRC, "g");
const LOCAL_REQUIRE_ONE = pyRe(LOCAL_REQUIRE_SRC);
const INLINE_DANGER_RE = pyRe(String.raw`https?|fetch|child_process|exec|spawn|eval|Function|Buffer|atob|base64|net\.|dgram|process\.env`);

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
    if (LOCAL_REQUIRE_ONE.test(code) && !INLINE_DANGER_RE.test(withoutRequires))
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

// the parsers keep Python's number kinds: an int is a BigInt, a float a number
const pyTypeName = (v) => (v === null ? "NoneType" : Array.isArray(v) ? "list" : typeof v === "string" ? "str"
  : typeof v === "boolean" ? "bool" : typeof v === "bigint" ? "int" : typeof v === "number" ? "float"
  : v instanceof PyComplex ? "complex" : "dict");
const isDict = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof PyComplex);

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
  const [data, issues] = loadManifestWhere(path, content, { pythonLiteral });
  return [data, issues];
}

/**
 * loadManifest, plus → where: with `locate` (a key), for every object of the
 * result that holds that key, a Map object → offset (in the BOM-stripped
 * text) of the key token the parser kept, the last of equal keys (twin of
 * core._load_manifest).
 */
function loadManifestWhere(path, content, { pythonLiteral = false, locate = null } = {}) {
  const root = isRootManifest(path);
  if (typeof content !== "string") return [null, root ? [manifestUnparseableIssue(path, "not text")] : [], new Map()];
  const text = content.startsWith("\ufeff") ? content.slice(1) : content;
  if (jsonDepthExceeds(text)) return [null, [manifestDepthIssue(path)], new Map()];
  let data = null, reason = null, litType = null, where = new Map();
  const onKey = (base) => (locate === null ? null : (obj, key, at) => { if (key === locate) where.set(obj, base + at); });
  // json.loads(parse_int=_json_int): an integer literal up to 1000 characters is a Python int
  const r = pyJsonParse(text, { onKey: onKey(0), pyNumbers: true });
  if (r.depth) return [null, [manifestDepthIssue(path)], new Map()];
  if (r.ok) data = r.value;
  else reason = `JSONDecodeError: ${jsonErrorWhere(text, r.pos)}`;
  if (data === null && pythonLiteral) {
    where = new Map();                          // nothing from a failed JSON parse
    const lit = pyLiteralParse(pyStrip(text), onKey(text.length - pyLstrip(text).length));
    if (lit.ok) { data = lit.value; reason = null; litType = lit.type; }
    else reason ||= lit.error;
  }
  if (!isDict(data)) {
    if (data !== null) reason = `top level is a ${litType ?? pyTypeName(data)}, not an object`;
    return [null, root ? [manifestUnparseableIssue(path, reason || "unparseable")] : [], new Map()];
  }
  return [data, [], where];
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
const GYP_EXPANSION_SRC = String.raw`[<>]!@?\(`;
const GYP_EXPANSION_RE = pyRe(GYP_EXPANSION_SRC, "g");
const GYP_EXPANSION_ONE = pyRe(GYP_EXPANSION_SRC);
// The ubiquitous benign form: print an include path of a dependency.
const GYP_NODE_REQUIRE_RE = pyRe(String.raw`node\s+-[ep]\s+(?:"|')\s*require\(\s*\\?["'][\w@./-]+\\?["']\s*\)(?:\.[\w$]+)*\s*;?\s*(?:"|')`, "g");
// Bounds on one gyp document (twins of core's): past either limit the walk
// stops and the file gets SC-TRUNCATED. Characters are code points.
const GYP_MAX_NODES = 100_000;                  // values visited
const GYP_MAX_COMMAND_CHARS = 2_000_000;        // characters of action/expansion commands examined
/** SC-INSTALL-HOOK findings listed per gyp file; one more finding sums up the rest. */
export const GYP_MAX_HOOK_FINDINGS = 100;

/**
 * The command of every expansion in `text`, in order: up to its balanced
 * closing parenthesis, or to the end of the string. The closing parenthesis
 * of every "(" is found in one pass (a stack), not by a scan per expansion.
 */
function* gypExpansionCommands(text) {
  const close = new Map(), opened = [];
  for (let k = 0; k < text.length; k++) {
    const c = text.charCodeAt(k);
    if (c === 40) opened.push(k);
    else if (c === 41 && opened.length) close.set(opened.pop(), k);
  }
  for (const m of text.matchAll(GYP_EXPANSION_RE)) {
    const i = m.index + m[0].length - 1;                              // its "("
    const j = close.get(i);
    yield j === undefined ? text.slice(i + 1) : text.slice(i + 1, j);
  }
}

/**
 * [commands, truncated]: [command, kind, node] for every action (node: the
 * object holding "action") and command expansion anywhere in a parsed gyp
 * document, and why the walk stopped early (null if it did not).
 */
function gypCommands(data) {
  const out = [];
  const stack = [data];
  let seen = 0, chars = 0, truncated = null;
  while (stack.length) {
    if (seen >= GYP_MAX_NODES) { truncated = `more than ${GYP_MAX_NODES} values in the gyp document`; break; }
    const node = stack.pop();
    seen++;
    if (Array.isArray(node)) {
      for (const x of node) stack.push(x);
    } else if (isDict(node)) {
      for (const [key, value] of Object.entries(node)) {
        if (key === "action" && Array.isArray(value)) {
          const cmd = value.map(pyLiteralStr).join(" ");
          out.push([cmd, "action", node]);
          chars += cpLen(cmd);
        }
        stack.push(key);
        stack.push(value);
      }
    } else if (typeof node === "string" && GYP_EXPANSION_ONE.test(node)) {
      for (const cmd of gypExpansionCommands(node)) {
        out.push([cmd, "expansion", null]);
        chars += cpLen(cmd);
        if (chars > GYP_MAX_COMMAND_CHARS) break;
      }
    }
    if (chars > GYP_MAX_COMMAND_CHARS) { truncated = `more than ${GYP_MAX_COMMAND_CHARS} characters of gyp commands`; break; }
  }
  return [out.reverse(), truncated];
}

/**
 * binding.gyp custom build actions (G11 policy, same as lifecycle scripts):
 * any action is MAJOR, one matching INSTALL_HOOK_RE is CRITICAL; command
 * expansions ('<!(cmd)') are findings only when suspicious. gyp files are
 * Python literals, so JSON and Python-literal syntax are both accepted. An
 * action's finding is on the line of its own "action" key, an expansion's on
 * the first line holding its command; at most GYP_MAX_HOOK_FINDINGS are
 * listed and one more sums up the rest; a document past the walk's bounds
 * is SC-TRUNCATED. Linear in the size of the file (twin of core.scan_gyp).
 */
export function scanGyp(path, content) {
  const [data, issues, where] = loadManifestWhere(path, content, { pythonLiteral: true, locate: "action" });
  if (data === null) return issues;
  const body = String(content).startsWith("\ufeff") ? String(content).slice(1) : String(content);
  const lines = body.split("\n");
  const [commands, truncated] = gypCommands(data);
  const hooks = [];
  for (const [cmd, kind, node] of commands) {
    let suspicious;
    if (kind === "action") suspicious = INSTALL_HOOK_RE.test(cmd);
    else {
      suspicious = INSTALL_HOOK_RE.test(cmd.replace(GYP_NODE_REQUIRE_RE, " "));
      if (!suspicious) continue;
    }
    hooks.push([cmd, kind, node, suspicious]);
  }
  const newlines = [];
  if (hooks.length) for (let k = body.indexOf("\n"); k !== -1; k = body.indexOf("\n", k + 1)) newlines.push(k);
  const lineAt = (off) => {                                           // 1 + newlines before off
    let lo = 0, hi = newlines.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (newlines[mid] < off) lo = mid + 1; else hi = mid; }
    return lo + 1;
  };
  const firstLine = new Map();
  const lineOf = (cmd, kind, node) => {
    if (kind === "action") { const at = where.get(node); return at === undefined ? 1 : lineAt(at); }
    if (!cmd || cmd.includes("\n")) return 1;                        // no single line holds it
    if (!firstLine.has(cmd)) { const at = body.indexOf(cmd); firstLine.set(cmd, at < 0 ? 1 : lineAt(at)); }
    return firstLine.get(cmd);
  };
  // each line redacted once for all findings (mkIssue's context-free
  // redaction: PEM blocks and secret patterns, no entropy literals)
  registerScanContext(lines, null).secrets = new SecretLiterals([], null);
  for (const [cmd, kind, node, suspicious] of hooks.slice(0, GYP_MAX_HOOK_FINDINGS)) {
    issues.push(scInstallHookIssue(path, lineOf(cmd, kind, node), lines,
      kind === "action" ? "binding.gyp action" : "binding.gyp command expansion", cmd, suspicious));
  }
  const rest = hooks.slice(GYP_MAX_HOOK_FINDINGS);
  if (rest.length) {
    const bad = rest.filter((h) => h[3]).length;
    issues.push(mkIssue(
      { id: "SC-INSTALL-HOOK", name: "Install hook", type: "HOTSPOT",
        sev: bad ? "CRITICAL" : "MAJOR",
        msg: `${rest.length} more binding.gyp actions and command expansions run code at install time ` +
          `(${bad} of them fetch or evaluate code); only the first ${GYP_MAX_HOOK_FINDINGS} are listed.`,
        why: "Each action and command expansion in a binding.gyp runs a command during `node-gyp rebuild` " +
          "(npm install). A file with this many is listed in part so the report stays readable; this " +
          "finding carries the highest severity among the ones not listed.",
        fix: "Review every action and command expansion in the file; use --ignore-scripts in CI if unneeded.",
        ref: "CWE-506 · Supply chain" }, path, lineOf(rest[0][0], rest[0][1], rest[0][2]), lines));
  }
  if (truncated) issues.push(truncatedIssue(path, truncated));
  return issues;
}
