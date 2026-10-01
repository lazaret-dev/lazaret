// --deps: what a dependency runs — twin of lazaret.scanner.core's
// dependency_checks (see the section comment there).
//
// A --deps scan read a dependency's files with the supply-chain rules only,
// and the registry's two tests of what runs did not run on them: the
// install-script test (installScriptRisk) on the scripts a dependency's
// install hook runs, and the weaker import-time test (importTimeRisk) on
// its code. Now each install hook of a dependency's manifest (package.json
// scripts, binding.gyp actions and the command expansions that run a file of
// the package) is followed to the files it runs (followHook, then Node's
// resolution), only to regular files inside the scan root, through no link
// and nothing an exclusion prunes; the hook escalates to CRITICAL when one
// fails installScriptRisk. A package root with a binding.gyp and no install
// script gets npm's implicit `node-gyp rebuild` hook (MAJOR). A
// file it runs that the walk did not read as source is read and scanned as a
// dependency's JavaScript (a shell script is only tested), and a hook the
// walk cannot follow to the end is SC-TRUNCATED. Every JavaScript or Python
// file of a dependency that no hook runs gets importTimeRisk: SC-IMPORT-RISK;
// and a file that runs what another file of its package received over the
// network, the cross-file follower's SC-IMPORT-RISK (the native engine's,
// through lib/native.js crossFileIssues).

import { lstatSync, readdirSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { scanFile } from "./scanner/scan.js";
import { followHook, persistenceReasons, installScriptRisk, importTimeRisk, importTimeSeverity, agentHijack,
  agentHijackInCommand, nodeCandidates, shebangLang, spawnedScripts, packValues, crossFileIssues, NativeError } from "./lib/native.js";
import { HOOK_COMMANDS, loadManifest, scInstallHookIssue } from "./lib/supplychain.js";
import { readBounded, truncatedIssue, scanErrorIssue, strerror, normalizeNewlines, encodingIssues, treeJoin,
  MAX_FILE_BYTES } from "./lib/fs.js";
import { looksBinary, HEADER_SAMPLE } from "./lib/binary.js";
import { decodeSource } from "./lib/encoding.js";
import { mkIssue } from "./lib/issue.js";
import { REDACT, redactText, registerScanContext, SECRET_SKIP_RE } from "./lib/redact.js";
import { mapTasks } from "./pool.js";
import { pyStrip, pyStripChars, pyRepr, cmpCodePoints, pyEntries, pyRe } from "./lib/pycompat.js";

const DEP_IMPORT_RISK_WHY = "An installed package's code runs with the application's privileges when it is loaded " +
  "or its command runs. Collecting credentials or the whole environment next to a network call is the shape of an " +
  "import-time stealer; SDKs read the few variables they need. A weaker indicator than the same code in an install " +
  "script: the file may have a reason.";
const posix = (p) => (sep === "/" ? p : p.split(sep).join("/"));
const native = (p) => (sep === "/" ? p : p.split("/").join(sep));
/** n with thousands separators, as Python's f"{n:,}" writes it. */
const withCommas = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
const own = (obj, key) => (obj && Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined);

/** posixpath.dirname */
function dirname(path) {
  let head = path.slice(0, path.lastIndexOf("/") + 1);
  if (head && !/^\/+$/.test(head)) head = head.replace(/\/+$/, "");
  return head;
}

/** A path without its trailing "/" (Python's p.rstrip("/")). */
const stripSlashes = (p) => p.replace(/\/+$/, "");

export { treeJoin };

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

/** The npm package root ("/"-separated) a dependency file lives in, innermost, else null. core._xf_js_package */
function jsPackageRoot(path) {
  const parts = path.split("/");
  for (let i = parts.length - 2; i >= 0; i--) {
    if (parts[i] === "node_modules") {
      if (parts[i + 1].startsWith("@") && i + 2 < parts.length) return parts.slice(0, i + 3).join("/");
      return parts.slice(0, i + 2).join("/");
    }
  }
  return null;
}

/**
 * The "/"-separated paths of the dependency JavaScript files that are a web app's static assets:
 * in a _next, static or public directory of their package, and reached from none of its npm
 * package's entry points. Twin of core._deps_web_assets.
 */
export function webAssets(tree, files) {
  const [webDirs] = packValues("_DEPS_WEB_DIRS");
  const found = new Map();                     // npm package root (null: not npm's) -> [paths]
  for (const f of files) {
    if (!f.dep || f.lang !== "js") continue;
    const path = posix(f.path);
    const root = jsPackageRoot(path);
    const rel = root !== null ? path.slice(root.length + 1) : path;
    if (rel.split("/").slice(0, -1).some((part) => webDirs.includes(part.toLowerCase()))) {
      if (!found.has(root)) found.set(root, []);
      found.get(root).push(path);
    }
  }
  const out = new Set();
  for (const [root, paths] of found) {
    const reached = root !== null ? npmReach(tree, root) : new Set();
    for (const p of paths) if (!reached.has(p)) out.add(p);
  }
  return out;
}

/** The paths an npm package.json's main, module, bin and exports name. core._deps_npm_entries */
export function npmEntries(data) {
  const [max] = packValues("_DEPS_REACH_MAX");
  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const out = [];
  for (const key of ["main", "module"]) {
    if (typeof own(data, key) === "string") out.push(own(data, key));
  }
  const b = own(data, "bin");
  if (typeof b === "string") out.push(b);
  else if (isObject(b)) for (const [, v] of pyEntries(b)) if (typeof v === "string") out.push(v);
  const stack = [own(data, "exports")];
  while (stack.length && out.length < max) {
    const e = stack.pop();
    if (typeof e === "string") {
      if (!e.includes("*")) out.push(e);
    } else if (Array.isArray(e)) {
      stack.push(...[...e].reverse());
    } else if (isObject(e)) {
      stack.push(...pyEntries(e).map(([, v]) => v).reverse());
    }
  }
  return out;
}

/**
 * The files of the npm package at `root` its entry points reach: what Node runs for the package
 * itself and for each entry point, then the local files they require or import and the scripts
 * they start with node (spawnedScripts), transitively. core._deps_npm_reach
 */
function npmReach(tree, root) {
  const [max, localDep] = packValues("_DEPS_REACH_MAX", "_DEPS_LOCAL_DEP_RE");
  const rx = pyRe(localDep.re, "gm");
  const manifest = tree.manifests.get(`${root}/package.json`);
  const data = manifest !== undefined ? loadManifest(manifest.path, manifest.content)[0] : null;
  const entries = data !== null && typeof data === "object" && !Array.isArray(data) ? npmEntries(data) : [];
  const queue = [tree.resolve(root), ...entries.map((e) => treeJoin(root, e)).filter((t) => t !== null).map((t) => tree.resolve(t))];
  const seen = new Set();
  while (queue.length && seen.size < max) {
    const rel = queue.pop();
    if (rel === null || rel === undefined || seen.has(rel) || !rel.startsWith(root + "/")) continue;
    seen.add(rel);
    const f = tree.sources.get(rel);
    if (f === undefined || f.lang !== "js") continue;
    const base = dirname(rel);
    const targets = [...String(f.content).matchAll(rx)].map((m) => [base, m[2]]);
    for (const [where, t] of spawnedScripts(String(f.content))) targets.push([where === "dir" ? base : root, t]);
    for (const [at, target] of targets) {
      const joined = treeJoin(at, target);
      if (joined !== null) queue.push(tree.resolve(joined));
    }
  }
  return seen;
}

/**
 * {"/"-separated path: group} for the dependency Python files under a site-packages or
 * dist-packages directory of the scan root whose top-level module or package a distribution's
 * .dist-info/RECORD lists with another: the cross-file follower reads them as one package (the
 * group is that directory and the first such .dist-info's name, by name). Twin of
 * core._xf_site_groups.
 */
export function siteGroups(root, files) {
  const [depMarkers, siteMarkers] = packValues("_XF_DEP_MARKERS", "_XF_SITE_MARKERS");
  const sites = new Map();                     // site dir -> Map(top-level name -> [paths])
  for (const f of files) {
    if (!f.dep || f.lang !== "py") continue;
    const path = posix(f.path);
    const parts = path.split("/");
    let idx = -1;
    for (const m of depMarkers) idx = Math.max(idx, parts.lastIndexOf(m));
    if (idx < 0 || idx >= parts.length - 1 || !siteMarkers.includes(parts[idx])) continue;
    const site = parts.slice(0, idx + 1).join("/");
    if (!sites.has(site)) sites.set(site, new Map());
    const tops = sites.get(site);
    if (!tops.has(parts[idx + 1])) tops.set(parts[idx + 1], []);
    tops.get(parts[idx + 1]).push(path);
  }
  const out = {};
  for (const [site, tops] of sites) {
    if (tops.size < 2) continue;
    const where = join(resolve(root), ...site.split("/"));
    let names;
    try {
      names = readdirSync(where).filter((n) => n.endsWith(".dist-info")).sort(cmpCodePoints);
    } catch { continue; }
    const label = new Map();                   // top-level name -> its group's .dist-info
    for (const name of names) {
      try {                                    // (a real directory: no link is followed)
        const st = lstatSync(join(where, name));
        if (!st.isDirectory() || st.isSymbolicLink()) continue;
      } catch { continue; }
      const listed = [...recordTops(join(where, name, "RECORD"))].filter((t) => tops.has(t)).sort(cmpCodePoints);
      if (listed.length < 2) continue;
      const joined = new Set([name, ...listed.filter((t) => label.has(t)).map((t) => label.get(t))]);
      const first = [...joined].sort(cmpCodePoints)[0];
      for (const t of [...[...label].filter(([, g]) => joined.has(g)).map(([t]) => t), ...listed]) label.set(t, first);
    }
    for (const [top, group] of label) for (const path of tops.get(top)) out[path] = `${site}/${group}`;
  }
  return out;
}

/** The top-level names a RECORD lists (its rows' first path parts); none when it cannot be read. core._xf_record_tops */
function recordTops(path) {
  const [limit] = packValues("_XF_RECORD_BYTES");
  let data;
  try { data = readBounded(path, limit + 1); } catch { return new Set(); }
  if (data.length > limit) return new Set();
  const out = new Set();
  for (const row of data.toString("utf8").split("\n")) {
    const entry = pyStripChars(pyStrip(row.split(",", 1)[0]), '"').replace(/\\/g, "/");
    const top = entry.split("/", 1)[0];
    if (top && top !== "." && top !== ".." && !top.includes(":")) out.add(top);
  }
  return out;
}

/**
 * The --deps checks of what dependencies run, after the files and manifests
 * were scanned: escalates the SC-INSTALL-HOOK findings of dependency
 * manifests in `issues` in place and returns { issues, files }: the findings
 * to add and the files read and scanned here. Twin of core.dependency_checks.
 */
export function dependencyChecks(root, files, manifests, issues, { exclude = [], maxFileBytes = MAX_FILE_BYTES, pool = null } = {}) {
  const tree = new DependencyTree(root, files, manifests, exclude, maxFileBytes);
  const depManifests = new Set(manifests.filter((m) => m.dep).map((m) => m.path));
  const out = [], extra = [], run = new Set(), truncated = new Set();
  for (const i of implicitGypHooks(tree, manifests)) out.push(i);
  for (const issue of issues) {
    const cmd = HOOK_COMMANDS.get(issue);
    if (issue.rule !== "SC-INSTALL-HOOK" || !cmd || !depManifests.has(issue.file)) continue;
    try { followDependencyHook(tree, issue, cmd, out, extra, run, truncated); }
    catch (e) { out.push(scanErrorIssue(issue.file, e)); }       // one manifest must never kill the run
  }
  // The import-time and agent checks of each dependency file no hook runs; with a worker pool
  // (pool.js) on its workers, and with them the cross-file follower (below), the answers taken
  // in order.
  // (the detection round) a web app's static assets no entry point reaches are left out (webAssets)
  const assets = webAssets(tree, files);
  const checks = files.filter((f) => f.dep && (f.lang === "js" || f.lang === "py") && !run.has(posix(f.path))
    && !assets.has(posix(f.path)))
    .map((f) => ["dep", [f.path, f.content, f.lang]]);
  const code = assets.size ? files.filter((f) => !assets.has(posix(f.path))) : files;
  const groups = siteGroups(tree.root, code);
  const follow = ["xf", {
    files: code.filter((f) => f.dep && (f.lang === "js" || f.lang === "py"))
      .map((f) => ({ path: f.path, lang: f.lang, dep: true, content: f.content })),
    redact: REDACT.on, siteGroups: groups,
  }];
  const answers = mapTasks(pool, pool ? [follow, ...checks] : checks, dependencyTask, dependencyTaskError);
  for (const [found, agent] of pool ? answers.slice(1) : answers) {
    if (found) out.push(found);
    if (agent) out.push(agent);
  }
  // Cross-file received code (both engines since 0.1.8; the native engine's follower, crossfile.rs):
  // a value received in one file of a package and run in another. Skips the files already flagged
  // CRITICAL single-file (on a worker the follower skipped none: a skipped file's findings are
  // left out after, which is the same, as the follower reads each file of a package on its own).
  const flagged = new Set(out.filter((i) => i.rule === "SC-IMPORT-RISK" && i.sev === "CRITICAL").map((i) => posix(i.file)));
  if (pool) {
    for (const i of answers[0]) if (!flagged.has(posix(i.file))) out.push(i);
  } else {
    try {
      for (const i of crossFileIssues(code, flagged, { redact: REDACT.on, siteGroups: groups })) out.push(i);
    } catch (e) {
      if (!(e instanceof NativeError)) throw e;        // (the engine stopped: no cross-file findings, as before)
    }
  }
  return { issues: out, files: extra };
}

/** A task of dependencyChecks, as a worker of pool.js runs it (pool-worker.js), run here. */
function dependencyTask([kind, args]) {
  if (kind === "dep") {
    const [path, content, lang] = args;
    return [dependencyImportIssue(path, content, lang), dependencyAgentIssue(path, content)];
  }
  return crossFileIssues(args.files, new Set(), { redact: args.redact, siteGroups: args.siteGroups });
}

/** What a task of dependencyChecks that threw stands for (`error`: an Error, or a worker's {name, message}). */
function dependencyTaskError([kind, args], error) {
  if (kind === "dep") return [scanErrorIssue(args[0], error), null];
  if (error instanceof NativeError || (error && /^Native(Error|Exhausted)$/.test(error.name))) return [];
  throw error instanceof Error ? error : new Error(`${error && error.name}: ${error && error.message}`);
}

/** Is `directory` ("/"-separated) an installed npm package's root? Twin of core._is_package_root. */
function isPackageRoot(directory) {
  const parts = directory.split("/");
  return parts.length >= 2 && (parts[parts.length - 2] === "node_modules" || (
    parts.length >= 3 && parts[parts.length - 3] === "node_modules" && parts[parts.length - 2].startsWith("@")));
}

/**
 * SC-INSTALL-HOOK (MAJOR) for each dependency npm builds with node-gyp: a
 * package whose root holds a binding.gyp and whose package.json names no
 * install or preinstall script (nor sets "gypfile": false) runs
 * `node-gyp rebuild` on install. Twin of core._implicit_gyp_hooks.
 */
function implicitGypHooks(tree, manifests) {
  const out = [];
  for (const m of manifests) {
    const rel = posix(m.path);
    if (!m.dep || rel.slice(rel.lastIndexOf("/") + 1) !== "package.json") continue;
    const base = dirname(rel);
    const gyp = base ? `${base}/binding.gyp` : "binding.gyp";
    if (!isPackageRoot(base) || !tree.manifests.has(gyp)) continue;
    const [data] = loadManifest(m.path, m.content);
    if (!data || typeof data !== "object" || Array.isArray(data) || own(data, "gypfile") === false) continue;
    const s = own(data, "scripts");
    const scripts = s && typeof s === "object" && !Array.isArray(s) ? s : {};
    if (["install", "preinstall"].some((h) => typeof own(scripts, h) === "string" && pyStrip(own(scripts, h)))) continue;
    out.push(scInstallHookIssue(tree.manifests.get(gyp).path, 1, [], "install (implicit)", "node-gyp rebuild", false));
  }
  return out;
}

function followDependencyHook(tree, issue, cmd, out, extra, run, truncated) {
  const manifest = issue.file;
  const base = dirname(posix(manifest));
  const direct = agentHijackInCommand(cmd);              // the hook runs the agent itself
  if (direct) {
    const m = tree.manifests.get(posix(manifest));
    if (m) out.push(agentHijackIssue(manifest, issue.line, m.content.split("\n"), direct[0], direct[1]));
  }
  const persist = persistenceReasons(cmd);              // the command itself plants something
  if (persist.length && issue.sev !== "BLOCKER" && issue.sev !== "CRITICAL") {
    const msg = `Install hook command ${persist.join("; and ")}.`;
    issue.sev = "CRITICAL";
    issue.msg = REDACT.on ? redactText(msg) : msg;
  }
  const [targets, complete] = followHook(cmd);
  if (!complete && !truncated.has(manifest)) {
    truncated.add(manifest);
    const [commands, scripts, chars, path] = packValues("HOOK_MAX_COMMANDS", "HOOK_MAX_TARGETS", "HOOK_MAX_CHARS",
      "HOOK_MAX_PATH");
    out.push(truncatedIssue(manifest, `its install hook is more than Lazaret follows (${withCommas(commands)} ` +
      `commands, ${scripts} scripts, ${withCommas(chars)} characters, ${withCommas(path)}-character paths)`));
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
    // the scripts it starts with node or python (0.1.8, spawnedScripts)
    for (const [started, stext] of startedScripts(tree, rel, text, base, out, extra, run)) {
      const more = stext ? installScriptRisk(stext) : [];
      if (more.length && issue.sev !== "BLOCKER" && issue.sev !== "CRITICAL") {
        const shown = base && started.startsWith(base + "/") ? started.slice(base.length + 1) : started;
        const msg = `Install hook runs ${target}, which starts ${shown}, which ${more.join("; and ")}.`;
        issue.sev = "CRITICAL";
        issue.msg = REDACT.on ? redactText(msg) : msg;
      }
    }
  }
}

/** [[rel, text]] for the scripts an install script starts with node or python, and those they start. core._started_dependency_scripts. */
function startedScripts(tree, rel, text, cwd, out, extra, run) {
  const [SPAWN_MAX_DEPTH, SPAWN_MAX_FILES] = packValues("_SPAWN_MAX_DEPTH", "_SPAWN_MAX_FILES");
  const found = [], seen = new Set([rel]), queue = [[rel, text, 0]];
  while (queue.length && seen.size <= SPAWN_MAX_FILES) {
    const [cur, curText, depth] = queue.shift();
    if (!curText || depth >= SPAWN_MAX_DEPTH) continue;
    for (const [where, path] of spawnedScripts(curText)) {
      const joined = treeJoin(where === "dir" ? dirname(cur) : cwd, path);
      const nxt = joined === null ? null : tree.resolve(joined);
      if (nxt === null || seen.has(nxt) || seen.size > SPAWN_MAX_FILES) continue;
      seen.add(nxt);
      const lang = nxt.endsWith(".py") ? "py" : nxt.endsWith(".sh") ? "sh" : "js";
      const ntext = scriptText(tree, nxt, lang, out, extra, run);
      found.push([nxt, ntext]);
      queue.push([nxt, ntext, depth + 1]);
    }
  }
  return found;
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

/** SC-IMPORT-RISK (MAJOR, or CRITICAL: importTimeSeverity) for a dependency's file (`lang` "js" or "py") that fails
 * the import-time test, else null. Twin of core.dependency_import_issue. */
export function dependencyImportIssue(path, text, lang = null) {
  const [reasons, line] = importTimeRisk(text, lang);
  if (!reasons.length) return null;
  const lines = text.split("\n");
  registerScanContext(lines, SECRET_SKIP_RE);     // the file's own entropy literals (core: _Redactor(lines))
  return mkIssue({ id: "SC-IMPORT-RISK", name: "Risky import-time code", type: "HOTSPOT", sev: importTimeSeverity(reasons),
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
