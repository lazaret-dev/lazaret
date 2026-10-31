// The scan of what a collection holds (core.scan_project's, after the walk): each file's scan, the config files, the
// manifests, the skipped trees and the cross-file flows. The CLI's project scan (project.js) runs it on what the walk
// collected, adding its checks of what is on disk (the project's install hooks, --deps' dependency checks), and so
// does the browser dashboard on what was uploaded (BR-7 step 5), so this module uses nothing of Node's.

import { scanErrorIssue } from "./lib/issue.js";
import { scanFile, scanConfigFile, treeReader } from "./scanner/scan.js";
import { scanManifest, scanGyp } from "./lib/supplychain.js";
import { analyzeFlows, redactFlowIssues } from "./scanner/flow.js";
import { taintHelpers, call, packValues } from "./lib/native.js";
import { modelOwnIssues } from "./lib/collect.js";

/** What scanFile reads of a collected file (`helpers`: projectHelpers' Map). */
export const scanTask = (f, helpers = null) => {
  const task = { name: f.path, path: f.path, content: f.content, lang: f.lang, dep: f.dep };
  const slice = helpers && !f.dep ? helpers.get(f.path) : undefined;
  if (slice !== undefined) task.helpers = slice;
  return task;
};

/**
 * (Q-4) What each of the collection's own Python files imports from the others that the taint pass follows calls
 * into (taintHelpers): a Map of path -> slice; an empty one when the engine could not answer (each file is then
 * read with its own helpers alone, and a process warning says so, as the Python package's scan warns).
 */
export function projectHelpers(files) {
  try {
    return taintHelpers(files.filter((f) => f.lang === "py" && !f.dep));
  } catch (e) {
    const why = `${(e && e.name) || "Error"}: ${String((e && e.message) || e).slice(0, 200)}`;
    globalThis.process?.emitWarning?.(`taint pass: the helpers other files define were not read (${why})`,
      { code: "LAZARET_TAINT_HELPERS" });
    return new Map();
  }
}

/** Each file's findings, one file after another (one file must never kill the run). */
export function scanEach(files, helpers = null) {
  return files.map((f) => {
    try { return scanFile(scanTask(f, helpers)); } catch (e) { return [scanErrorIssue(f.path, e)]; }
  });
}

/**
 * FP-B64-PROTOBUF (the review of Oct 27; core.b64_descriptor_pass): drop from `issues`, in place, the SC-B64 findings
 * of JavaScript files whose every run is a protobuf file's descriptor handed to its runtime's loader and used only as
 * generated code uses it, decided over the whole scan by the engine (b64_descriptors: protodesc/usage.rs). `files`,
 * `manifests`: the collection's; `holders`, `resolvers`: [[rel, read() -> its text or null]] of the files that may
 * hold script or say where modules are (collect_file's "holder" and "resolver"); `stopped`: the scan stopped before
 * its end; `pkg`: a package's scan; `unread`: the paths of what it did not read whole besides its SC-TRUNCATED,
 * Q-UNREADABLE and Q-SYMLINK findings' ("." for the scan). Fails closed: when the engine cannot answer every finding
 * stays, and the reason is returned (null otherwise).
 */
export function b64DescriptorPass(issues, files, manifests, holders, resolvers, { stopped = false, pkg = false, unread = [] } = {}) {
  const js = new Map();
  for (const f of files) if (f.lang === "js" && typeof f.content === "string" && !js.has(f.path)) js.set(f.path, f.content);
  const found = issues.filter((i) => i.rule === "SC-B64" && js.has(i.file ?? "") && Number.isInteger(i.line));
  // (a finding can be dropped only in a file that calls the loader's fileDesc: when none does, every one stays and
  // the scan's text need not be handed over)
  if (!found.some((i) => js.get(i.file).includes("fileDesc"))) return null;
  let got;
  try {
    const [kinds] = packValues("_B64_DESCRIPTOR_UNREAD");
    const missed = new Set(issues.filter((i) => kinds.includes(i.rule)).map((i) => i.file || "."));
    for (const x of unread) missed.add(x);
    got = call("b64_descriptors", {
      files: [...js],
      holders: holders.map(([rel, read]) => [rel, read()]),
      manifests: manifests.filter((m) => m.kind === "package.json").map((m) => [m.path, m.content]),
      configs: resolvers.map(([rel, read]) => [rel, read()]),
      findings: found.map((i) => [i.file, i.line]),
      unread: [...missed].sort(),
      stopped: !!stopped, package: !!pkg,
    }).findings;
    if (got.length !== found.length) throw new Error(`${got.length} answers for ${found.length} findings`);
  } catch (e) {                                                       // every finding stays
    return `SC-B64: protobuf descriptors were not checked (${(e && e.name) || "Error"}: ${String((e && e.message) || e).slice(0, 200)})`;
  }
  const drop = new Set(found.filter((_, k) => got[k][2] === null));
  let w = 0;
  for (const i of issues) if (!drop.has(i)) issues[w++] = i;
  issues.length = w;
  return null;
}

/**
 * The findings of a scan of `col` (a collection: lib/collect.js collectEntry's, the walk's or the dashboard's), in
 * the project scan's order: `extraIssues` (findings made before the scan that belong in its result), the
 * collection's, each file's (`scanAll(files, helpers)`: a list per file, `helpers` projectHelpers'; default
 * scanEach), the config files' (credentials only; a dependency's agent skill or instruction file, RA-3, also reads
 * the scripts it runs through `diskRead`, the CLI's read of what is on disk), the manifests', what `checks(issues)`
 * adds to them (the CLI's checks of what is on disk; it may add the files it read to col.files), the skipped trees,
 * then the cross-file flows in col.files, redacted as their files are.
 */
export function collectionIssues(col, { extraIssues = [], scanAll = scanEach, checks = null, diskRead = null } = {}) {
  const { files, manifests, configs, binaryIssues, skippedIssues } = col;
  const issues = [];
  const add = (list) => { for (const i of list) issues.push(i); };   // never push(...big)
  add(extraIssues);
  add(binaryIssues);
  add(modelOwnIssues(col.models ?? [], files));                     // (FP-MODEL-FILES: a model file's own imports)
  for (const found of scanAll(files, projectHelpers(files))) add(found);
  const read = treeReader(files, configs);                            // what an editor's or agent's settings run
  let depRead = null;                                                 // what a dependency's agent skill runs
  for (const cf of configs) {
    if (cf.dep && depRead === null) depRead = treeReader(files, configs, diskRead);
    try { add(scanConfigFile(cf.path, cf.content, cf.dep ? depRead : read, !!cf.dep)); } catch (e) { issues.push(scanErrorIssue(cf.path, e)); }
  }
  for (const mf of manifests) {
    // binding.gyp and every other .gyp / .gypi → scanGyp (G11); package.json
    // → scanManifest, with the registry hook set inside a dependency tree.
    try {
      add(mf.kind !== "package.json" ? scanGyp(mf.path, mf.content)
        : scanManifest(mf.path, mf.content, { registry: !!mf.dep }));
    } catch (e) { issues.push(scanErrorIssue(mf.path, e)); }
  }
  if (checks) checks(issues);
  // FP-B64-PROTOBUF: the SC-B64 findings that are protobuf descriptors generated code alone uses, over the whole
  // collection (its files, and what else could read them or remap their loader)
  const note = b64DescriptorPass(issues, files, manifests, col.holders ?? [], col.resolvers ?? []);
  if (note) globalThis.process?.emitWarning?.(note, { code: "LAZARET_B64_DESCRIPTORS" });
  add(skippedIssues ?? []);
  // Cross-file taint flows in the project's Python and JavaScript (the
  // Python engine's flow.analyze; dependency files are not analyzed). The
  // findings copy raw source lines: they get their file's redaction here.
  add(redactFlowIssues(analyzeFlows(files), files));
  return issues;
}
