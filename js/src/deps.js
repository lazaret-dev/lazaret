// --deps: what a dependency runs — twin of lazaret.scanner.core's
// dependency_checks (see the section comment there).
//
// A --deps scan read a dependency's files with the supply-chain rules only,
// and the registry's two tests of what runs did not run on them: the
// install-script test (installScriptRisk) on the scripts a dependency's
// install hook runs, and the weaker import-time test (importTimeRisk) on
// its code. Now each install hook of a dependency's manifest is followed to
// the files it runs (followHook, then Node's resolution), only to regular
// files inside the scan root, through no link and nothing an exclusion
// prunes; the hook escalates to CRITICAL when one fails installScriptRisk. A
// file it runs that the walk did not read as source is read and scanned as a
// dependency's JavaScript (a shell script is only tested), and a hook the
// walk cannot follow to the end is SC-TRUNCATED. Every JavaScript or Python
// file of a dependency that no hook runs gets importTimeRisk: SC-IMPORT-RISK.

import { lstatSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { scanFile } from "./scanner/scan.js";
import { followHook, installScriptRisk, importTimeRisk, agentHijack, agentHijackInCommand, nodeCandidates, shebangLang,
  HOOK_MAX_CHARS, HOOK_MAX_COMMANDS, HOOK_MAX_TARGETS, HOOK_MAX_PATH } from "./lib/hooks.js";
import { HOOK_COMMANDS, loadManifest } from "./lib/supplychain.js";
import { readBounded, truncatedIssue, scanErrorIssue, strerror, normalizeNewlines, encodingIssues,
  MAX_FILE_BYTES } from "./lib/fs.js";
import { looksBinary, HEADER_SAMPLE } from "./lib/binary.js";
import { decodeSource } from "./lib/encoding.js";
import { mkIssue } from "./lib/issue.js";
import { REDACT, redactText, registerScanContext, SECRET_SKIP_RE } from "./lib/redact.js";
import { pyStrip, pyRepr } from "./lib/pycompat.js";

const DEP_IMPORT_RISK_WHY = "An installed package's code runs with the application's privileges when it is loaded " +
  "or its command runs. Collecting credentials or the whole environment next to a network call is the shape of an " +
  "import-time stealer; SDKs read the few variables they need. A weaker indicator than the same code in an install " +
  "script: the file may have a reason.";
const DRIVE_RE = /^[A-Za-z]:/;
const posix = (p) => (sep === "/" ? p : p.split(sep).join("/"));
const native = (p) => (sep === "/" ? p : p.split("/").join(sep));
/** n with thousands separators, as Python's f"{n:,}" writes it. */
const withCommas = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
const own = (obj, key) => (obj && Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined);

/** posixpath.normpath of a relative path. */
function normpath(path) {
  const comps = [];
  for (const c of path.split("/")) {
    if (c === "" || c === ".") continue;
    if (c !== ".." || !comps.length || comps[comps.length - 1] === "..") comps.push(c);
    else comps.pop();
  }
  return comps.join("/") || ".";
}

/** posixpath.dirname */
function dirname(path) {
  let head = path.slice(0, path.lastIndexOf("/") + 1);
  if (head && !/^\/+$/.test(head)) head = head.replace(/\/+$/, "");
  return head;
}

/** A path without its trailing "/" (Python's p.rstrip("/")). */
const stripSlashes = (p) => p.replace(/\/+$/, "");

/**
 * A hook's `target` joined with the directory `base` (relative to the scan
 * root), normalized; null when it is absolute or leaves the scan root.
 * Twin of core._tree_join.
 */
export function treeJoin(base, target) {
  target = target.replaceAll("\\", "/");
  if (target.startsWith("/") || DRIVE_RE.test(target)) return null;
  const joined = normpath(`${base || "."}/${target}`);
  if (joined === "." || joined === ".." || joined.startsWith("../")) return null;
  return joined;
}

/** Python's f"{x:.0%}": half-even on the exact binary value of x * 100. */
function percent(x) {
  const y = x * 100;
  const f = Math.floor(y);
  return `${y - f === 0.5 ? (f % 2 === 0 ? f : f + 1) : Math.round(y)}%`;
}

/** core._undecodable_share: U+FFFD and control characters in the first 65,536 code points. */
function undecodableShare(text) {
  let n = 0, bad = 0;
  for (const ch of text) {
    if (n === 65536) break;
    n++;
    const c = ch.codePointAt(0);
    if (c === 0xfffd || c <= 0x08 || (c >= 0x0e && c <= 0x1a) || (c >= 0x1c && c <= 0x1f) || c === 0x7f
        || (c >= 0xdc80 && c <= 0xdcff)) bad++;
  }
  return n ? bad / n : 0;
}

const mpegTs = (h) => h.length >= 377 && h[0] === 0x47 && h[188] === 0x47 && h[376] === 0x47;

/**
 * The text of a file read the way core.decode_member reads an archive member
 * run as JavaScript: [text, findings] (Q-ENCODING, and SC-TRUNCATED when it
 * does not decode to anything text-like).
 */
function decodeScript(path, data) {
  const dec = decodeSource(data, { py: false });
  const text = normalizeNewlines(dec.text);
  const out = encodingIssues(path, text, dec);
  const share = undecodableShare(text);
  if (share > 0.3 && !(path.toLowerCase().endsWith(".ts") && mpegTs(data.subarray(0, 512)))) {
    out.push(truncatedIssue(path, `content is not decodable as text (${percent(share)} invalid bytes or ` +
      "control characters), so no rule could read it"));
  }
  return [text, out];
}

/**
 * What a --deps scan knows of the tree, to follow a dependency's install
 * hook: the files it read and, for the others, the disk under the scan
 * root. Twin of core._DependencyTree.
 */
class DependencyTree {
  constructor(root, files, manifests, exclude, maxFileBytes) {
    this.root = resolve(root);
    this.sources = new Map(files.map((f) => [posix(f.path), f]));
    this.manifests = new Map(manifests.map((m) => [posix(m.path), m]));
    this.excludes = new Set([...(exclude || []), ".git"]);
    this.maxFileBytes = maxFileBytes;
    this.regular = new Map();
    this.read = new Map();
  }

  isFile(rel) {
    if (this.sources.has(rel) || this.manifests.has(rel)) return true;
    if (!this.regular.has(rel)) this.regular.set(rel, this.onDisk(rel));
    return this.regular.get(rel);
  }

  onDisk(rel) {
    const parts = rel.split("/");
    if (parts.slice(0, -1).some((p) => this.excludes.has(p) || p === "" || p === "." || p === "..")) return false;
    let path = this.root;
    try {
      for (let k = 0; k < parts.length; k++) {
        path = join(path, parts[k]);
        const st = lstatSync(path);
        if (st.isSymbolicLink()) return false;
        if (k < parts.length - 1) {
          if (!st.isDirectory()) return false;
        } else return st.isFile();
      }
    } catch { /* missing, unreadable, or a name the OS refuses */ }
    return false;
  }

  /** The file Node runs for `path`, or null (twin of core._DependencyTree.resolve). */
  resolve(path) {
    const candidates = nodeCandidates(path);
    const first = (list) => list.find((c) => this.isFile(c)) ?? null;
    const found = first(candidates.slice(0, 6));
    if (found) return found;
    const manifest = this.manifests.get(`${stripSlashes(path)}/package.json`);
    if (manifest !== undefined) {
      const [data] = loadManifest(manifest.path, manifest.content);
      const main = own(data, "main");
      if (typeof main === "string" && pyStrip(main)) {
        const target = treeJoin(stripSlashes(path), main);
        if (target !== null) {
          const hit = first(nodeCandidates(target));
          if (hit) return hit;
        }
      }
    }
    return first(candidates.slice(6));
  }
}

/**
 * The --deps checks of what dependencies run, after the files and manifests
 * were scanned: escalates the SC-INSTALL-HOOK findings of dependency
 * manifests in `issues` in place and returns { issues, files }: the findings
 * to add and the files read and scanned here. Twin of core.dependency_checks.
 */
export function dependencyChecks(root, files, manifests, issues, { exclude = [], maxFileBytes = MAX_FILE_BYTES } = {}) {
  const tree = new DependencyTree(root, files, manifests, exclude, maxFileBytes);
  const depManifests = new Set(manifests.filter((m) => m.dep).map((m) => m.path));
  const out = [], extra = [], run = new Set(), truncated = new Set();
  for (const issue of issues) {
    const cmd = HOOK_COMMANDS.get(issue);
    if (issue.rule !== "SC-INSTALL-HOOK" || !cmd || !depManifests.has(issue.file)) continue;
    try { followDependencyHook(tree, issue, cmd, out, extra, run, truncated); }
    catch (e) { out.push(scanErrorIssue(issue.file, e)); }       // one manifest must never kill the run
  }
  for (const f of files) {
    if (!f.dep || (f.lang !== "js" && f.lang !== "py") || run.has(posix(f.path))) continue;
    let found, agent;
    try { found = dependencyImportIssue(f.path, f.content); agent = dependencyAgentIssue(f.path, f.content); }
    catch (e) { found = scanErrorIssue(f.path, e); agent = null; }
    if (found) out.push(found);
    if (agent) out.push(agent);
  }
  return { issues: out, files: extra };
}

function followDependencyHook(tree, issue, cmd, out, extra, run, truncated) {
  const manifest = issue.file;
  const base = dirname(posix(manifest));
  const direct = agentHijackInCommand(cmd);              // the hook runs the agent itself
  if (direct) {
    const m = tree.manifests.get(posix(manifest));
    if (m) out.push(agentHijackIssue(manifest, issue.line, m.content.split("\n"), direct[0], direct[1]));
  }
  const [targets, complete] = followHook(cmd);
  if (!complete && !truncated.has(manifest)) {
    truncated.add(manifest);
    out.push(truncatedIssue(manifest, `its install hook is more than Lazaret follows (${withCommas(HOOK_MAX_COMMANDS)} ` +
      `commands, ${HOOK_MAX_TARGETS} scripts, ${withCommas(HOOK_MAX_CHARS)} characters, ` +
      `${withCommas(HOOK_MAX_PATH)}-character paths)`));
  }
  for (const target of targets) {
    const path = treeJoin(base, target);
    const rel = path === null ? null : tree.resolve(path);
    if (rel === null) continue;
    const text = scriptText(tree, rel, rel.endsWith(".sh") ? "sh" : "js", out, extra, run);
    const reasons = text ? installScriptRisk(text) : [];
    if (reasons.length && issue.sev !== "BLOCKER" && issue.sev !== "CRITICAL") {
      const msg = `Install hook runs ${target}, which ${reasons.join("; and ")}.`;
      issue.sev = "CRITICAL";
      issue.msg = REDACT.on ? redactText(msg) : msg;
    }
    const agent = text ? dependencyAgentIssue(native(rel), text) : null;
    if (agent) out.push(agent);
  }
}

function scriptText(tree, rel, asLang, out, extra, run) {
  run.add(rel);
  if (tree.sources.has(rel)) return tree.sources.get(rel).content;
  if (tree.manifests.has(rel)) return tree.manifests.get(rel).content;
  if (!tree.read.has(rel)) tree.read.set(rel, readScript(tree, rel, asLang, out, extra));
  return tree.read.get(rel);
}

/** A file an install hook runs that the walk did not read as source (twin of core._read_dependency_script). */
function readScript(tree, rel, asLang, out, extra) {
  const disp = native(rel);
  const cap = tree.maxFileBytes;
  let data;
  try {
    data = readBounded(join(tree.root, ...rel.split("/")), cap + 1);
  } catch (e) {
    out.push(truncatedIssue(disp, `it runs at install time but could not be read (${strerror(e)})`));
    return null;
  }
  if (data.length > cap) {
    out.push(truncatedIssue(disp, `it runs at install time but is larger than the ${withCommas(cap)}-byte file limit`));
    return null;
  }
  if (looksBinary(data.subarray(0, 2048))) {
    out.push(truncatedIssue(disp, "it runs at install time but is not text, so it could not be scanned"));
    return null;
  }
  const utf8 = new TextDecoder("utf-8", { ignoreBOM: true });
  if (asLang === "sh" || shebangLang(utf8.decode(data.subarray(0, HEADER_SAMPLE))) === "sh") {
    return normalizeNewlines(utf8.decode(data));
  }
  const [text, decodeFindings] = decodeScript(disp, data);
  for (const i of decodeFindings) out.push(i);
  for (const i of scanFile({ name: disp, path: disp, content: text, lang: "js", dep: true })) out.push(i);
  extra.push({ path: disp, content: text, lang: "js", dep: true });
  return text;
}

/** SC-IMPORT-RISK (MAJOR) for a dependency's file that fails the import-time test, else null. */
export function dependencyImportIssue(path, text) {
  const [reasons, line] = importTimeRisk(text);
  if (!reasons.length) return null;
  const lines = text.split("\n");
  registerScanContext(lines, SECRET_SKIP_RE);     // the file's own entropy literals (core: _Redactor(lines))
  return mkIssue({ id: "SC-IMPORT-RISK", name: "Risky import-time code", type: "HOTSPOT", sev: "MAJOR",
    msg: `Dependency code ${reasons.join("; and ")}.`, why: DEP_IMPORT_RISK_WHY,
    fix: "Read the file: what does it collect, and where does it send it?",
    ref: "CWE-506 · Supply chain" }, path, line, lines);
}

const AGENT_HIJACK_WHY = "A dependency that runs your AI coding agent hands the attacker your agent's access to " +
  "your machine and accounts, and a flag like --dangerously-skip-permissions or --yolo runs it with every " +
  "confirmation turned off: the s1ngularity / Nx attack spawned the agent from a postinstall hook to search the " +
  "disk for secrets, wallets and SSH keys and write them out (the first weaponized-AI-agent malware). No package " +
  "needs to launch your agent.";

/** SC-AGENT-HIJACK (CRITICAL) at line `lineNo` of `lines`. Twin of core._agent_hijack_issue. */
function agentHijackIssue(path, lineNo, lines, agent, flag, col = null) {
  registerScanContext(lines, SECRET_SKIP_RE);
  return mkIssue({ id: "SC-AGENT-HIJACK", name: "Dependency drives your AI agent", type: "HOTSPOT", sev: "CRITICAL",
    msg: `Dependency launches the ${pyRepr(agent)} AI agent with ${flag} — running your coding agent ` +
      "with its confirmations turned off.",
    why: AGENT_HIJACK_WHY,
    fix: "Do not install or run this package; read what it tells the agent to do. Report it to the registry.",
    ref: "CWE-506 · Supply chain" }, path, lineNo, lines, col);
}

/** SC-AGENT-HIJACK (CRITICAL) for a dependency's file that launches an AI agent, else null. Twin of core.dependency_agent_issue. */
export function dependencyAgentIssue(path, text) {
  const found = agentHijack(text);
  if (!found) return null;
  const [agent, flag, line] = found;
  return agentHijackIssue(path, line, text.split("\n"), agent, flag);
}
