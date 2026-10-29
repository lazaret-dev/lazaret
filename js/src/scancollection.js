// The scan of what a collection holds (core.scan_project's, after the walk): each file's scan, the config files, the
// manifests, the skipped trees and the cross-file flows. The CLI's project scan (project.js) runs it on what the walk
// collected, adding its checks of what is on disk (the project's install hooks, --deps' dependency checks), and so
// does the browser dashboard on what was uploaded (BR-7 step 5), so this module uses nothing of Node's.

import { scanErrorIssue } from "./lib/issue.js";
import { scanFile, scanConfigFile, treeReader } from "./scanner/scan.js";
import { scanManifest, scanGyp } from "./lib/supplychain.js";
import { analyzeFlows, redactFlowIssues } from "./scanner/flow.js";
import { taintHelpers } from "./lib/native.js";

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
  add(skippedIssues ?? []);
  // Cross-file taint flows in the project's Python and JavaScript (the
  // Python engine's flow.analyze; dependency files are not analyzed). The
  // findings copy raw source lines: they get their file's redaction here.
  add(redactFlowIssues(analyzeFlows(files), files));
  return issues;
}
