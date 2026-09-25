// Supply-chain manifest scanning (package.json lifecycle scripts, binding.gyp
// actions) and secret redaction — JS twin of lazaret.py's scan_manifest /
// scan_gyp / redaction helpers.

import { mkIssue } from "./issue.js";
import { DEP_MARKERS } from "./fs.js";

// Scripts npm runs when a package is installed as a dependency. Publisher-side
// scripts (prepack, prepublishOnly, postpublish, ...) only ever run on the
// maintainer's machine while packaging a release, so they are not install hooks.
export const NPM_INSTALL_SCRIPTS = ["preinstall", "install", "postinstall"];
// In a checked-out project (not an installed dependency), `npm install` also runs prepare.
export const NPM_LOCAL_INSTALL_SCRIPTS = [...NPM_INSTALL_SCRIPTS, "prepare"];
export const NPM_LIFECYCLE_SCRIPTS = NPM_LOCAL_INSTALL_SCRIPTS;   // backwards-compatible name

// A manifest inside an installed-dependency directory belongs to a package that
// came from a registry: only the consumer-run scripts apply to it.
// Twin of lazaret.scanner.core.is_dependency_manifest (same DEP_MARKERS list).
export function isDependencyManifest(path) {
  return String(path).split(/[\\/]/).slice(0, -1).some((part) => DEP_MARKERS.has(part));
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

function scInstallHookIssue(path, lineNo, lines, script, cmd, suspicious) {
  const sev = suspicious ? "CRITICAL" : "MAJOR";
  let msg, why;
  if (suspicious) {
    msg = `"${script}" script runs a network-fetch/eval command at install time.`;
    why = "Install hooks execute automatically on npm install — the most common supply-chain compromise vector — and this one fetches or executes remote code.";
  } else {
    msg = `"${script}" script runs code at install time: ${JSON.stringify(cmd)}.`;
    why = "Install hooks run automatically with user privileges on npm install, before anyone reviews the package. Many legitimate packages use one (to fetch a platform binary, for example), so on its own this is a capability to review, not evidence of malice.";
  }
  return mkIssue(
    { id: "SC-INSTALL-HOOK", name: "Install hook", type: "HOTSPOT",
      sev, msg, why,
      fix: `Review the ${script} script; use --ignore-scripts in CI if unneeded.`,
      ref: "CWE-506 · Supply chain" }, { name: path }, lineNo, lines);
}

function manifestDepthIssue(path) {
  // 48033f94: pathologically deep-nested manifest — reported as CRITICAL,
  // never a crash, never a silent skip.
  return mkIssue(
    { id: "SC-MANIFEST-DEPTH", name: "Hostile manifest nesting depth",
      type: "HOTSPOT", "sev": "CRITICAL",
      msg: "Manifest is too deeply nested to parse (recursion limit hit).",
      why: "A hostile repo benefits from both a crash and a silent skip; this finding keeps the signal visible either way.",
      fix: "Review the manifest manually.",
      ref: "CWE-506 · Supply chain" }, { name: path }, 1, [""]);
}

/**
 * json.loads-equivalent for manifest-shaped, attacker-controlled content:
 * returns [data, depthIssue]. data is null on any parse failure (normal JSON
 * errors → no issues); a depth error yields the SC-MANIFEST-DEPTH finding so
 * a hostile file can neither crash the scan nor hide behind "unparseable".
 */
function loadManifest(path, content) {
  try {
    return [JSON.parse(content), null];
  } catch (e) {
    if (e instanceof RangeError && /call stack|Maximum/i.test(String(e.message)))
      return [null, manifestDepthIssue(path)];
    return [null, null];
  }
}

/**
 * package.json install hooks (G11 policy). `registry: true` (or a manifest
 * inside node_modules/...) counts only the scripts npm runs for an installed
 * dependency; a checked-out project also counts `prepare`.
 */
export function scanManifest(path, content, { registry = isDependencyManifest(path) } = {}) {
  const [data, depthIssue] = loadManifest(path, content);
  if (depthIssue) return [depthIssue];
  if (!data || typeof data !== "object" || Array.isArray(data)) return [];
  const issues = [], lines = content.split("\n");
  const scripts = data.scripts;
  if (scripts && typeof scripts === "object" && !Array.isArray(scripts)) {
    for (const hook of (registry ? NPM_INSTALL_SCRIPTS : NPM_LOCAL_INSTALL_SCRIPTS)) {
      const cmd = scripts[hook];
      if (typeof cmd !== "string" || !cmd.trim()) continue;
      const suspicious = hookIsSuspicious(cmd);
      const lineNo = lines.findIndex((l) => l.includes(`"${hook}"`)) + 1 || 1;
      issues.push(scInstallHookIssue(path, lineNo, lines, hook, cmd, suspicious));
    }
  }
  return issues;
}

/** binding.gyp custom build actions (G11 policy, same as lifecycle scripts). */
export function scanGyp(path, content) {
  const [data, depthIssue] = loadManifest(path, content);
  if (depthIssue) return [depthIssue];
  if (!data || typeof data !== "object" || Array.isArray(data)) return [];
  const issues = [], lines = content.split("\n");
  const actions = [];
  const targets = Array.isArray(data.targets) ? data.targets : [];
  for (const target of targets) {
    if (!target || typeof target !== "object") continue;
    const acts = Array.isArray(target.actions) ? target.actions : [];
    for (const act of acts) {
      if (act && typeof act === "object" && Array.isArray(act.action))
        actions.push(act.action.map(String));
    }
  }
  for (const act of actions) {
    const cmd = act.join(" ");
    const suspicious = hookIsSuspicious(cmd);
    const lineNo = lines.findIndex((l) => act.some((a) => a && l.includes(a))) + 1 || 1;
    issues.push(scInstallHookIssue(path, lineNo, lines, "binding.gyp action", cmd, suspicious));
  }
  return issues;
}

// ---- Secret redaction (audit L1) -----------------------------------------
// The flagged line of a SECRET-rule finding is redacted at creation time, so
// every sink (terminal excerpt, JSON report) persists the placeholder, never
// the credential.

export const SECRET_RULES = new Set(["S-SECRET", "S-TOKEN", "SQL-CRED", "S-ENTROPY"]);
export const REDACT_PLACEHOLDER = "[redacted: secret rule {RULE}]";

const SECRET_LINE_PATTERNS = [
  /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*["'][^"']{4,}["']/gi,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bghp_[A-Za-z0-9]{36,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bsk_live_[A-Za-z0-9]{20,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, // JWT
];

export function redactContextLine(line) {
  let out = line;
  for (const pat of SECRET_LINE_PATTERNS) out = out.replace(pat, "[redacted]");
  return out;
}

/**
 * Redact a secret-bearing snippet copy (never mutates the caller's array).
 * Flagged line → REDACT_PLACEHOLDER + length (deterministic, so two scans of
 * the same line redact identically); context lines get credential matches
 * replaced with [redacted].
 */
export function redactSecretSnippet(ruleId, snippet, flaggedIdx, rawLine) {
  const out = [...snippet];
  for (let i = 0; i < out.length; i++) {
    if (i === flaggedIdx) {
      out[i] = REDACT_PLACEHOLDER.replace("{RULE}", ruleId) + ` (${rawLine.length} chars)`;
    } else if (typeof out[i] === "string") {
      out[i] = redactContextLine(out[i]);
    }
  }
  return out;
}

/** Sweep a whole result: belt-and-braces pass over every issue's snippet. */
export function redactResult(res) {
  for (const i of res.issues ?? []) {
    const snip = i.snippet;
    if (!Array.isArray(snip)) continue;
    const idx = i.line - (i.snipStart ?? i.line);
    const secret = SECRET_RULES.has(i.rule);
    if (secret && idx >= 0 && idx < snip.length && typeof snip[idx] === "string"
        && !snip[idx].startsWith("[redacted: secret rule ")) {
      const raw = snip[idx];
      i.snippet = redactSecretSnippet(i.rule, snip, idx, raw);
    } else if (!secret) {
      i.snippet = snip.map((l) => (typeof l === "string" ? redactContextLine(l) : l));
    }
  }
  return res;
}
