// --deps: what a dependency runs, and a project's own install hooks (core's sections of the same names say what
// the checks are).
//
// The decisions are the engine's (BR-7 step 3e: rust/crates/lazaret-engine/src/deps.rs; both packages made them
// until then, this module as the twin of core's): its deps_hooks call follows the install hooks of dependencies'
// manifests (after npm's implicit node-gyp hooks) or of the project's own package.json files, and deps_files says
// which dependency files are a web app's static assets, which the import-time and agent checks read and with what
// names, and how a site-packages directory groups into distributions. This module reads the tree for them
// (DependencyTree): a call asks for what it needs to know — whether a path is a file it may read, a manifest's
// text, what a file a hook runs does (read here, and scanned when it is a dependency's JavaScript the walk did not
// read: those findings are this module's), what a JavaScript file loads, a directory's entries, a file's head —
// and is asked again with the answers, until it answers. core's _DependencyTree reads the tree the same way. The
// import-time and agent checks of a file (dep_file_issues), the vendored Go modules' and crates' readers and the
// cross-file follower are calls of the engine's too, sent from here (on the worker pool when there is one).

import { lstatSync, readdirSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { scanFile } from "./scanner/scan.js";
import { call, shebangLang, crossFileIssues, NativeError, NativeExhausted, goPackage, rsCrate, cargoLayout,
  goVendoredModules, codePoints, packValues, issuesOf, dialectArgs } from "./lib/native.js";
import { HOOK_COMMANDS } from "./lib/supplychain.js";
import { readBounded, strerror, normpathRel } from "./lib/fs.js";
import { truncatedIssue, scanErrorIssue } from "./lib/issue.js";
import { normalizeNewlines, decodeMember } from "./lib/encoding.js";
import { MAX_FILE_BYTES, MAX_WALK_DEPTH, pathTooLong } from "./lib/collect.js";
import { looksBinary, HEADER_SAMPLE, pyExt } from "./lib/binary.js";
import { REDACT } from "./lib/redact.js";
import { mapTasks } from "./pool.js";
import { cmpCodePoints, cpLen } from "./lib/pycompat.js";
import { EXHAUSTED } from "./scanner/scan.js";

const posix = (p) => (sep === "/" ? p : p.split(sep).join("/"));
const native = (p) => (sep === "/" ? p : p.split("/").join(sep));
/** n with thousands separators, as Python's f"{n:,}" writes it. */
const withCommas = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");

/** posixpath.dirname */
function dirname(path) {
  let head = path.slice(0, path.lastIndexOf("/") + 1);
  if (head && !/^\/+$/.test(head)) head = head.replace(/\/+$/, "");
  return head;
}

/** SC-TRUNCATED for a file the engine could not answer about: EXHAUSTED when it spent its work budget (a worker's
 * error is {name, message}), "its scan failed" otherwise (core's engine.error_issue). */
const errorIssue = (path, e) => (e instanceof NativeExhausted || (e && e.name === "NativeExhausted")
  ? truncatedIssue(path, EXHAUSTED) : scanErrorIssue(path, e));

/**
 * The text of a file read the way core.decode_member reads an archive member
 * run as JavaScript: [text, findings] (Q-ENCODING, and SC-TRUNCATED when it
 * does not decode to anything text-like).
 */
const decodeScript = (path, data) => decodeMember(path, data, "js");

/** How many times a --deps call is asked at most: each answer that is not the call's names what it has yet to know
 * of the tree (the files a hook runs, then the scripts those start, …). core._DEPS_ROUNDS */
const ROUNDS = 4096;
/** What a file a hook runs does, when the engine could not say: its checks are taken to have spent their budget (the
 * hook's manifest is SC-TRUNCATED). core._DEPS_UNANSWERED */
const UNANSWERED = { exhausted: ["risk", "agent", "obfuscated", "spawned"] };

/** Is the folder `parts` (names below the root) too deep to reach? As the walk, the readers open no folder deeper
 * than MAX_WALK_DEPTH (core._Root: "it is nested deeper than 512 folders"). */
const tooDeep = (parts) => parts.length > MAX_WALK_DEPTH;
const TOO_DEEP = `it is nested deeper than ${MAX_WALK_DEPTH} folders`;

/**
 * What a --deps scan knows of the tree, to answer what the engine's --deps calls ask (deps.rs): the files it read
 * and, for the others, the disk under the scan root — regular files only, reached through no link and no directory
 * an exclusion prunes. `pruned`: the directories the walk pruned, when nothing in them is to be read either (a
 * project's own hooks: projectHookChecks); `project`: a file a hook runs is then read, not scanned. Twin of
 * core._DependencyTree. A folder or a file whose path the system refuses as too long (pathTooLong) is noted in
 * `tooLong` (its display path; the caller's list, given as an option): the scan says it was not read (SC-TRUNCATED)
 * and is incomplete (tooLongIssues).
 */
class DependencyTree {
  constructor(root, files, manifests, exclude, maxFileBytes, pruned = [], project = false) {
    this.root = resolve(root);
    this.sources = new Map(files.map((f) => [posix(f.path), f]));
    this.manifests = new Map(manifests.map((m) => [posix(m.path), m]));
    this.excludes = new Set([...(exclude || []), ".git"]);
    this.pruned = new Set(pruned.map(posix));
    this.maxFileBytes = maxFileBytes;
    this.project = project;
    this.regular = new Map();
    this.read = new Map();                        // rel -> [findings, the file as scanned or null, text]
    this.tooLong = [];
  }

  /** `rel` ("/"-separated) could not be reached: its path is too long for this system (when `e` says so). */
  noteLong(rel, e) {
    if (pathTooLong(e)) this.tooLong.push(native(rel));
  }

  isFile(rel) {
    if (this.sources.has(rel) || this.manifests.has(rel)) return true;
    if (!this.regular.has(rel)) this.regular.set(rel, this.onDisk(rel));
    return this.regular.get(rel);
  }

  onDisk(rel) {
    const parts = rel.split("/");
    if (parts.slice(0, -1).some((p) => this.excludes.has(p) || p === "" || p === "." || p === "..")) return false;
    if (this.inPruned(parts) || tooDeep(parts.slice(0, -1))) return false;
    let path = this.root, k = 0;
    try {
      for (; k < parts.length; k++) {
        path = join(path, parts[k]);
        const st = lstatSync(path);
        if (st.isSymbolicLink()) return false;
        if (k < parts.length - 1) {
          if (!st.isDirectory()) return false;
        } else return st.isFile();
      }
    } catch (e) {                                 // (missing, unreadable, or a name the OS refuses)
      this.noteLong(parts.slice(0, k + 1).join("/"), e);
    }
    return false;
  }

  /** Is one of the folders of `parts` (a path's, split at "/") a tree the walk pruned? core._DependencyTree._in_pruned */
  inPruned(parts) {
    return this.pruned.size > 0 && parts.slice(0, -1).some((_, k) => this.pruned.has(parts.slice(0, k + 1).join("/")));
  }

  /** The engine's answer to the --deps call `name` (deps_hooks, deps_files), what it asks of the tree answered here,
   * round after round. Throws NativeError when the engine could not answer. core._DependencyTree.ask */
  ask(name, args) {
    const known = { stat: Object.create(null), manifest: Object.create(null), script: [],
      targets: Object.create(null), list: Object.create(null), head: [], under: Object.create(null) };
    for (let k = 0; k < ROUNDS; k++) {
      const got = call(name, { ...args, known });
      if (!Object.prototype.hasOwnProperty.call(got, "need")) return got;
      this.answer(got.need, known);
    }
    throw new NativeError(`${name}: still asking after ${ROUNDS} rounds`);
  }

  answer(need, known) {
    for (const rel of need.stat) known.stat[rel] = this.isFile(rel);
    for (const rel of need.manifest) known.manifest[rel] = this.manifests.has(rel) ? this.manifests.get(rel).content : null;
    for (const [rel, release] of need.script) {
      const [disk, text] = this.scriptText(rel);
      let facts = null;
      if (text) {
        const args = { rel, project: this.project, redact: REDACT.on, neumaier: false };
        if (release) args.own = release;
        try {
          facts = call("deps_script", args, String(text));
        } catch (e) {
          if (!(e instanceof NativeError)) throw e;
          facts = UNANSWERED;
        }
      }
      known.script.push([rel, release, disk, facts]);
    }
    for (const rel of need.targets) {
      const f = this.sources.get(rel);
      let found = null;
      if (f !== undefined && f.lang === "js") {
        try {
          found = call("deps_targets", {}, String(f.content));
        } catch (e) {
          if (!(e instanceof NativeError)) throw e;
          found = { targets: [], exhausted: true };
        }
      }
      known.targets[rel] = found;
    }
    for (const folder of need.list) known.list[folder] = this.entries(folder);
    for (const folder of need.under) known.under[folder] = this.under(folder);
    for (const [path, cap] of need.head) {
      let got = null;
      try {
        if (tooDeep(path.split("/").slice(0, -1))) throw new Error(TOO_DEEP);      // (it can't be read: null)
        const data = readBounded(join(this.root, ...path.split("/")), cap + 1);
        got = [data.subarray(0, cap).toString("utf8"), data.length > cap];
      } catch (e) { this.noteLong(path, e); }       // (it can't be read: null)
      known.head.push([path, cap, got]);
    }
  }

  /** [[name, a real directory]] of a directory of the tree, or null when it can't be listed (no link is followed to
   * tell a directory). */
  entries(folder) {
    if (folder && tooDeep(folder.split("/"))) return null;
    const where = folder ? join(this.root, ...folder.split("/")) : this.root;
    let names;
    try { names = readdirSync(where).sort(cmpCodePoints); } catch (e) { this.noteLong(folder, e); return null; }
    return names.map((name) => {
      try {
        const st = lstatSync(join(where, name));
        return [name, st.isDirectory() && !st.isSymbolicLink()];
      } catch (e) {
        this.noteLong(folder ? `${folder}/${name}` : name, e);
        return [name, false];
      }
    });
  }

  /** Every path below the directory `folder` isFile answers true for: the walk's files, and the disk's regular files
   * below it, reached through no link and into nothing an exclusion or the walk pruned. core._DependencyTree._under */
  under(folder) {
    const prefix = folder + "/";
    const out = new Set([...this.sources.keys(), ...this.manifests.keys()].filter((rel) => rel.startsWith(prefix)));
    const parts = folder.split("/");
    if (parts.some((p) => this.excludes.has(p) || p === "" || p === "." || p === "..") || this.inPruned([...parts, ""])
        || tooDeep(parts.slice(0, -1))) {
      return [...out].sort(cmpCodePoints);
    }
    let path = this.root, k = 0;
    try {                                         // (the folder itself: a real directory, reached through no link)
      for (; k < parts.length; k++) {
        path = join(path, parts[k]);
        const st = lstatSync(path);
        if (!st.isDirectory() || st.isSymbolicLink()) return [...out].sort(cmpCodePoints);
      }
    } catch (e) {
      this.noteLong(parts.slice(0, k + 1).join("/"), e);
      return [...out].sort(cmpCodePoints);
    }
    const stack = [[path, folder, parts.length]];
    while (stack.length) {
      const [where, rel, depth] = stack.pop();
      if (depth > MAX_WALK_DEPTH) continue;
      let names;
      try { names = readdirSync(where); } catch (e) { this.noteLong(rel, e); continue; }
      for (const name of names) {
        const sub = `${rel}/${name}`;
        let st;
        try { st = lstatSync(join(where, name)); } catch (e) { this.noteLong(sub, e); continue; }
        if (st.isSymbolicLink()) continue;
        if (st.isDirectory()) {
          if (!this.excludes.has(name) && !this.pruned.has(sub)) stack.push([join(where, name), sub, depth + 1]);
        } else if (st.isFile()) out.add(sub);
      }
    }
    return [...out].sort(cmpCodePoints);
  }

  /** [read from the disk, text] of a file a hook runs: the walk's source or manifest, else read here once (null: it
   * can't be read as text; an SC-TRUNCATED finding then says why). */
  scriptText(rel) {
    if (this.sources.has(rel)) return [false, this.sources.get(rel).content];
    if (this.manifests.has(rel)) return [false, this.manifests.get(rel).content];
    if (!this.read.has(rel)) this.read.set(rel, this.readScript(rel));
    return [true, this.read.get(rel)[2]];
  }

  /** A file a hook runs that the walk did not read as source, read: [the findings of reading it, the file as scanned
   * or null, its text or null]. Scanned as a dependency's JavaScript unless it is a shell script, or a project's own
   * hook runs it (only read, for the tests of what the hook runs). Twin of core._DependencyTree._read_script. */
  readScript(rel) {
    const disp = native(rel);
    const cap = this.maxFileBytes;
    if (tooDeep(rel.split("/").slice(0, -1))) {
      return [[truncatedIssue(disp, `it runs at install time but could not be read (${TOO_DEEP})`)], null, null];
    }
    let data;
    try {
      data = readBounded(join(this.root, ...rel.split("/")), cap + 1);
    } catch (e) {
      this.noteLong(rel, e);
      const why = pathTooLong(e) ? "its path is longer than this system allows" : strerror(e);
      return [[truncatedIssue(disp, `it runs at install time but could not be read (${why})`)], null, null];
    }
    if (data.length > cap) {
      return [[truncatedIssue(disp, `it runs at install time but is larger than the ${withCommas(cap)}-byte file limit`)],
        null, null];
    }
    if (looksBinary(data.subarray(0, 2048))) {
      return [[truncatedIssue(disp, "it runs at install time but is not text, so it could not be scanned")], null, null];
    }
    const utf8 = new TextDecoder("utf-8", { ignoreBOM: true });
    if (rel.endsWith(".sh") || shebangLang(utf8.decode(data.subarray(0, HEADER_SAMPLE))) === "sh") {
      return [[], null, normalizeNewlines(utf8.decode(data))];
    }
    const [text, decodeFindings] = decodeScript(disp, data);
    if (this.project) return [[...decodeFindings], null, text];
    const scanned = { path: disp, content: text, lang: "js", dep: true };
    return [[...decodeFindings, ...scanFile({ name: disp, path: disp, content: text, lang: "js", dep: true })], scanned, text];
  }

  /** deps_hooks' answer applied: each of `hooks` (the SC-INSTALL-HOOK findings followed) gets its new severity and
   * message, `out` the findings in order (a file read here: the findings of reading it, and the file as scanned to
   * `extra`) -> the files the hooks run. core._DependencyTree.take */
  take(got, hooks, out, extra = null) {
    hooks.forEach((issue, k) => {
      const change = got.hooks[k];
      if (change) [issue.sev, issue.msg] = change;
    });
    for (const item of got.out) {
      if (item[0] === "read") {
        const [findings, scanned] = this.read.get(item[1]);
        for (const i of findings) out.push(i);
        if (scanned && extra) extra.push(scanned);
      } else {
        for (const i of issuesOf(native(item[1]), [item[2]])) out.push(i);
      }
    }
    return new Set(got.run);
  }
}

/** SC-INSTALL-HOOK findings as deps_hooks takes them: [manifest, line, severity, command]. core._hook_rows */
const hookRows = (hooks) => hooks.map((i) => [posix(i.file), i.line, i.sev, HOOK_COMMANDS.get(i)]);

/**
 * The --deps checks of what dependencies run, after the files and manifests
 * were scanned: escalates the SC-INSTALL-HOOK findings of dependency
 * manifests in `issues` in place and returns { issues, files }: the findings
 * to add and the files read and scanned here. Twin of core.dependency_checks.
 */
export function dependencyChecks(root, files, manifests, issues,
  { exclude = [], maxFileBytes = MAX_FILE_BYTES, pool = null, tooLong = [] } = {}) {
  const tree = new DependencyTree(root, files, manifests, exclude, maxFileBytes);
  tree.tooLong = tooLong;
  const depManifests = new Set(manifests.filter((m) => m.dep).map((m) => m.path));
  const hooks = issues.filter((i) => i.rule === "SC-INSTALL-HOOK" && HOOK_COMMANDS.get(i) && depManifests.has(i.file));
  const out = [], extra = [];
  let run = new Set();
  if (depManifests.size) {                                // (npm's implicit node-gyp hooks, then each hook)
    try {
      const got = tree.ask("deps_hooks", { project: false, hooks: hookRows(hooks), redact: REDACT.on, neumaier: false,
        manifests: manifests.map((m) => [posix(m.path), !!m.dep]) });
      run = tree.take(got, hooks, out, extra);
    } catch (e) {
      if (!(e instanceof NativeError)) throw e;           // (the run goes on: each hook's manifest says why)
      for (const file of new Set(hooks.map((i) => i.file))) out.push(errorIssue(file, e));
    }
  }
  // The import-time and agent checks of each dependency file no hook runs, given the names of the package it is in
  // (D-12b, D-9c); with a worker pool (pool.js) on its workers, and with them the cross-file follower (below), the
  // answers taken in order. (the detection round) a web app's static assets are left out.
  const dep = files.filter((f) => f.dep && (f.lang === "js" || f.lang === "py"));
  let plan = { assets: [], todo: [], groups: [] };
  try {
    if (dep.length) plan = planFiles(tree, dep, run);
  } catch (e) {
    if (!(e instanceof NativeError)) throw e;             // (every file is read then: none is taken for an asset)
    plan = { assets: [], groups: [], todo: dep.filter((f) => !run.has(posix(f.path))).map((f) => [posix(f.path), null]) };
  }
  const assets = new Set(plan.assets);
  const names = new Map(plan.todo);
  const checks = dep.filter((f) => names.has(posix(f.path)))
    .map((f) => ["dep", [f.path, f.content, f.lang, names.get(posix(f.path))]]);
  const code = assets.size ? files.filter((f) => !assets.has(posix(f.path))) : files;
  const groups = Object.fromEntries(plan.groups);
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
  // (0.1.9, Part C) the vendored Go modules' and crates' code, by the engine's readers (vendoredCode)
  for (const i of vendoredCode(tree, files)) out.push(i);
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

// ---- Go modules and crates: the readers' findings, and --deps's vendor trees (0.1.9, Part C) ----
// Twin of core's section of the same name: a Go project's vendor/ (vendor/modules.txt) and a Rust project's (cargo
// vendor: a .cargo-checksum.json in each crate's directory) are read as the registry reads a module zip and a .crate,
// the file rules on each .go and .rs file a build compiles (lib/fs.js collectFiles) and the engine's Go and Rust readers
// here, on each vendored module (the paths vendor/modules.txt lists) or crate.

const LAYOUT_ROOT_RE = /^(?:[A-Za-z]:)?\/+/;

/** A path a Cargo.toml names, relative to the crate's root (core._layout_path): drive roots and leading slashes off,
 * normalized; null for one with a `..` or none at all. */
function layoutPath(value) {
  if (typeof value !== "string" || cpLen(value) > 512) return null;
  let rest = value.split("\\").join("/");
  for (;;) {
    const stripped = rest.replace(LAYOUT_ROOT_RE, "");
    if (stripped === rest) break;
    rest = stripped;
  }
  if (rest.split("/").includes("..")) return null;
  const norm = rest ? normpathRel(rest) : "";
  return norm === "" || norm === "." ? null : norm;
}

/** [the build script, the library's root, whether it is a procedural macro] of a vendored crate whose Cargo.toml text
 * is `manifest` and whose .rs files are `members` (paths below its root): the engine's reading of the manifest
 * (cargoLayout), resolved as the registry resolves its own. Twin of core.cargo_layout. */
export function crateLayout(manifest, members) {
  const said = cargoLayout(manifest || "");
  const present = new Set(members || []);
  const build = said.build, lib = said.lib;
  const script = build === false ? null : typeof build === "string" ? layoutPath(build) : "build.rs";
  let root = typeof lib === "string" ? layoutPath(lib) : "src/lib.rs";
  root = root !== null && present.has(root) ? root : null;
  return [script !== null && present.has(script) ? script : null, root, root !== null && said.proc_macro === true];
}

/** [issues, what its use-time step read] of a reader's answer (goPackage, rsCrate, asked with `what` and the files'
 * names: the engine makes the findings, readers.rs) for the files `order` (their paths, in the order the reader was
 * given them). core.package_reader_issues */
export function packageReaderIssues(answer, order) {
  const issues = (answer.issues || []).map(([k, issue]) => issuesOf(k >= 0 && k < order.length ? order[k] : order[0],
    [issue])[0]);
  const read = answer.useRead || {};
  return [issues, Object.fromEntries(["files", "ofFiles", "chars", "ofChars"].map((key) => [key, Number(read[key] || 0)]))];
}

/**
 * read(rel) of a regular file of the tree the walk did not keep (a dependency's shell or PowerShell script its agent
 * skill runs, RA-3): read through no link and into nothing an exclusion prunes (DependencyTree), at most
 * `maxFileBytes`, as text; null for another (binary, too large, missing). Twin of core._disk_reader.
 */
export function diskReader(root, files, manifests, { exclude = [], maxFileBytes = MAX_FILE_BYTES, tooLong = [] } = {}) {
  let tree = null;                                                    // (made when first asked)
  return (rel) => {
    if (tree === null) {
      tree = new DependencyTree(root, files, manifests, exclude, maxFileBytes);
      tree.tooLong = tooLong;
    }
    if (!tree.isFile(rel)) return null;
    let data;
    try { data = readBounded(join(tree.root, ...rel.split("/")), maxFileBytes + 1); } catch (e) {
      tree.noteLong(rel, e);
      return null;
    }
    if (data.length > maxFileBytes || looksBinary(data.subarray(0, 2048))) return null;
    return new TextDecoder("utf-8", { ignoreBOM: true }).decode(data);
  };
}

/** The text of a regular file of the tree ("/"-separated rel), read through no link, at most `cap` bytes; null
 * otherwise (core._vendor_text). */
function vendorText(tree, rel, cap) {
  if (!tree.isFile(rel)) return null;
  let data;
  try { data = readBounded(join(tree.root, ...rel.split("/")), cap + 1); } catch (e) {
    tree.noteLong(rel, e);
    return null;
  }
  return data.length > cap ? null : new TextDecoder("utf-8", { ignoreBOM: true }).decode(data);
}

/** The module paths vendor/modules.txt says are vendored, longest first (core._vendored_modules). */
const vendoredModules = (text) => (text ? goVendoredModules(text) : []);

/** [[rel, text]] of the .c and .h files directly in `folder` (a vendored Go package's directory, "/"-separated):
 * what the Go reader reads with its cgo preambles. Regular files only, through no link (core._cgo_texts). */
function cgoTexts(tree, folder, exts) {
  if (folder && tooDeep(folder.split("/"))) return [];
  const where = folder ? join(tree.root, ...folder.split("/")) : tree.root;
  let names;
  try { names = readdirSync(where); } catch (e) { tree.noteLong(folder, e); return []; }
  const out = [];
  for (const name of names.filter((n) => exts.includes(pyExt(n).toLowerCase())).sort(cmpCodePoints)) {
    const rel = folder ? `${folder}/${name}` : name;
    if (!tree.isFile(rel)) continue;
    let data;
    try { data = readBounded(join(where, name), tree.maxFileBytes + 1); } catch (e) { tree.noteLong(rel, e); continue; }
    if (data.length <= tree.maxFileBytes && !looksBinary(data.subarray(0, HEADER_SAMPLE))) {
      out.push([rel, new TextDecoder("utf-8", { ignoreBOM: true }).decode(data)]);
    }
  }
  return out;
}

/** The readers on a --deps scan's vendored Go modules and crates (see the section comment): each module
 * vendor/modules.txt lists (a file of none is read with its package's directory), each crate of a cargo vendor tree.
 * A module or a crate over PACKAGE_CODE_CHARS is SC-TRUNCATED, and so is one the engine could not answer about.
 * Twin of core._vendored_code. */
export function vendoredCode(tree, files) {
  const [codeChars, useFileChars, useChars, textCap, cgoExts] = packValues("PACKAGE_CODE_CHARS", "USE_RISK_MAX_CHARS",
    "USE_RISK_CHARS", "_VENDOR_TEXT_CAP", "_CGO_EXTS");
  const units = new Map();                  // key -> {lang, top, unit, module, members}
  const listed = new Map();
  for (const f of files) {
    if (!f.vendor || (f.lang !== "go" && f.lang !== "rs")) continue;
    const path = posix(f.path), top = posix(f.vendor);
    const below = path.slice(top.length + 1);
    let unit, module = null;
    if (f.lang === "go") {
      if (!listed.has(top)) listed.set(top, vendoredModules(vendorText(tree, `${top}/modules.txt`, textCap)));
      module = listed.get(top).find((m) => below === m || below.startsWith(m + "/")) ?? null;
      unit = module !== null ? module : dirname(below);
    } else unit = below.split("/")[0];
    const key = JSON.stringify([f.lang, top, unit, module]);
    if (!units.has(key)) units.set(key, { lang: f.lang, top, unit, module, members: [] });
    units.get(key).members.push(f);
  }
  const cmpUnits = (a, b) => cmpCodePoints(a.lang, b.lang) || cmpCodePoints(a.top, b.top) || cmpCodePoints(a.unit, b.unit);
  const out = [];
  for (const { lang, top, unit, module, members } of [...units.values()].sort(cmpUnits)) {
    const base = unit ? `${top}/${unit}` : top;
    const sorted = [...members].sort((a, b) => cmpCodePoints(posix(a.path), posix(b.path)));
    const named = sorted.map((f) => [f.path, posix(f.path).slice(base.length + 1), f.content]);
    if (lang === "go") {
      const folders = [...new Set(sorted.map((f) => dirname(posix(f.path))))].sort(cmpCodePoints);
      for (const folder of folders) {
        for (const [rel, text] of cgoTexts(tree, folder, cgoExts)) named.push([native(rel), rel.slice(base.length + 1), text]);
      }
    }
    const order = named.map(([p]) => p);
    const size = named.reduce((n, [, , t]) => n + codePoints(t), 0);
    const what = lang === "go" ? "module" : "crate";
    if (size > codeChars) {
      out.push(truncatedIssue(order[0], `the vendored ${what}'s code (${withCommas(size)} characters) is more than the ` +
        `reader takes at once (${withCommas(codeChars)}), so it was not read`));
      continue;
    }
    let answer;
    try {
      const pairs = named.map(([, r, t]) => [r, t]);
      if (lang === "go") answer = goPackage(pairs, { module, useFileChars, useChars, what, names: order, redact: REDACT.on });
      else {
        const [script, lib, procMacro] = crateLayout(vendorText(tree, `${base}/Cargo.toml`, textCap), pairs.map(([r]) => r));
        answer = rsCrate(pairs, { build: script, procMacro, lib, useFileChars, useChars, what, names: order,
          redact: REDACT.on });
      }
    } catch (e) {                               // one module must never kill the run
      out.push(e instanceof NativeExhausted ? truncatedIssue(order[0], EXHAUSTED) : scanErrorIssue(order[0], e));
      continue;
    }
    for (const i of packageReaderIssues(answer, order)[0]) out.push(i);
  }
  return out;
}

/**
 * deps_files' answer for a --deps scan's dependency JavaScript and Python files `dep` (in the walk's order) after the
 * hooks ran the files `run`: { assets: the web app's static assets, todo: [[path, names]] the files the import-time and
 * agent checks read, with their package's names, groups: [[path, group]] the site-packages distributions } (paths
 * "/"-separated). `tree`: a DependencyTree, or the scan root (the tests'; `manifests` then the walk's). core._deps_plan
 */
export function planFiles(tree, dep, run = new Set(), manifests = []) {
  if (!(tree instanceof DependencyTree)) tree = new DependencyTree(tree, dep, manifests, [], MAX_FILE_BYTES);
  return tree.ask("deps_files", { files: dep.map((f) => [posix(f.path), f.lang]), run: [...run].sort(cmpCodePoints) });
}

/** A task of dependencyChecks, as a worker of pool.js runs it (pool-worker.js), run here. */
function dependencyTask([kind, args]) {
  if (kind === "dep") return depFileIssues(...args);
  return crossFileIssues(args.files, new Set(), { redact: args.redact, siteGroups: args.siteGroups });
}

/** What a task of dependencyChecks that threw stands for (`error`: an Error, or a worker's {name, message}). */
function dependencyTaskError([kind, args], error) {
  if (kind === "dep") return [errorIssue(args[0], error), null];
  if (error instanceof NativeError || (error && /^Native(Error|Exhausted)$/.test(error.name))) return [];
  throw error instanceof Error ? error : new Error(`${error && error.name}: ${error && error.message}`);
}

/**
 * The import-time and agent checks of a dependency's file no install hook runs (`lang` "js" or "py"; `names`: its
 * package's [declared, own], when known: D-12b): [SC-IMPORT-RISK, SC-AGENT-HIJACK], each or null, the engine's
 * (deps.rs dep_file_issues). Throws NativeError when the engine could not answer (NativeExhausted: it spent its work
 * budget). core's engine.dep_file_issues
 */
export function depFileIssues(path, content, lang = null, names = null) {
  const args = { redact: REDACT.on, neumaier: false };
  if (lang) args.lang = lang;
  if (lang === "js") Object.assign(args, dialectArgs(path));      // (TS-STRIP: a TypeScript file in its dialect)
  if (names && names[0] != null) args.declared = names[0];
  if (names && names[1]) args.own = names[1];
  const [found, agent] = call("dep_file_issues", args, String(content));
  return [found ? issuesOf(path, [found])[0] : null, agent ? issuesOf(path, [agent])[0] : null];
}

// ---- A project's own install hooks (SC-INSTALL-HOOK, 0.1.9) ----
// Twin of core's section of the same name: each install hook of every package.json that is not a dependency's is
// followed as a dependency's is, to the files it runs (followHook, then Node's resolution; into nothing the walk
// pruned: no dependency tree without --deps) and the scripts those start (spawnedScripts). The hook becomes CRITICAL
// when one of them fails installScriptRisk or is obfuscated (as SC-AUTORUN), the test's reasons first. A file the
// walk did not read as source is read for these tests only, not scanned; one that cannot be read as text, and a hook
// more than followHook reads, are SC-TRUNCATED. The follow is the engine's (deps_hooks), the reading of the tree
// this module's.

/**
 * The follow of a project's own install hooks, after the manifests were scanned: escalates the SC-INSTALL-HOOK
 * findings of the package.json files that are not a dependency's in `issues` in place and returns the findings to
 * add. `pruned`: the directories the walk pruned; `tooLong`: where the paths too long to read are noted (as for
 * dependencyChecks and diskReader: DependencyTree). Twin of core.project_hook_checks.
 */
export function projectHookChecks(root, files, manifests, issues,
  { exclude = [], pruned = [], maxFileBytes = MAX_FILE_BYTES, tooLong = [] } = {}) {
  const own = new Set(manifests.filter((m) => !m.dep && m.kind === "package.json").map((m) => m.path));
  const hooks = issues.filter((i) => i.rule === "SC-INSTALL-HOOK" && HOOK_COMMANDS.get(i) && own.has(i.file));
  const out = [];
  if (!hooks.length) return out;
  const tree = new DependencyTree(root, files, manifests, exclude, maxFileBytes, pruned, true);
  tree.tooLong = tooLong;
  try {
    tree.take(tree.ask("deps_hooks", { project: true, hooks: hookRows(hooks), redact: REDACT.on, neumaier: false }),
      hooks, out);
  } catch (e) {
    if (!(e instanceof NativeError)) throw e;             // one manifest must never kill the run
    for (const file of new Set(hooks.map((i) => i.file))) out.push(errorIssue(file, e));
  }
  return out;
}
