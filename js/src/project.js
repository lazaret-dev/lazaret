// The project scan (the Python package's core.scan_project), shared by `lazaret <dir>` (cli.js) and `lazaret hook`
// (hook.js): collect, each file's scan, the config files, the manifests, the dependency checks, the skipped trees, the
// cross-file flows, then the result built and redacted. Prints nothing.

import { collectFiles, ScanTargetError, scanErrorIssue, MAX_FILE_BYTES } from "./lib/fs.js";
import { fsNameToString } from "./lib/encoding.js";
import { scanFile, scanConfigFile, treeReader } from "./scanner/scan.js";
import { scanManifest, scanGyp } from "./lib/supplychain.js";
import { redactResult } from "./lib/redact.js";
import { buildResult } from "./report.js";
import { clipLine } from "./lib/issue.js";
import { dependencyChecks } from "./deps.js";
import { Pool, threadsFor, mapTasks } from "./pool.js";
import { analyzeFlows, redactFlowIssues } from "./scanner/flow.js";

/**
 * Collect what the project scan of `root` reads (collectFiles) -> the collection. Throws ScanTargetError (a usage
 * error) when root can't be listed or holds nothing to scan.
 */
export function collectProject(root, { deps = false, exclude = [], maxFileBytes = MAX_FILE_BYTES } = {}) {
  const col = collectFiles(root, { includeDeps: deps, exclude, maxFileBytes });
  if (!col.files.length && !col.manifests.length && !col.configs.length && !col.pth.length && !col.binaryIssues.length) {
    throw new ScanTargetError(`nothing to scan under ${fsNameToString(Buffer.from(root))}: no Python, JavaScript or SQL `
      + "sources, package manifests or other files to check");
  }
  return col;
}

/**
 * Scan what collectProject collected under `root` -> { res, files, configs }: the result (buildResult's, redacted,
 * with metrics.configFiles), every file read (the dependency files the checks read included) and the config files.
 * Each file's scan, and --deps' checks of each dependency file, run on worker threads for a scan with enough to read
 * (pool.js; env LAZARET_THREADS), the findings in the same order. `extraIssues`: findings made before the scan that
 * belong in its result (core.scan_project's extra_issues; the hook's files it could not copy).
 */
export function scanCollected(root, col, { exclude = [], env = process.env, extraIssues = [] } = {}) {
  const { files, manifests, configs, binaryIssues, skippedIssues } = col;
  const issues = [];
  const add = (list) => { for (const i of list) issues.push(i); };   // never push(...big)
  add(extraIssues);
  add(binaryIssues);
  const threads = threadsFor(env, files.reduce((n, f) => n + f.content.length, 0),
    files.reduce((n, f) => Math.max(n, f.content.length), 0));
  let pool = null;
  if (threads > 1) {
    try { pool = new Pool(threads); } catch { pool = null; }        // (no workers here: one thread does it all)
  }
  try {
    const scans = mapTasks(pool,
      files.map((f) => ["scan", { name: f.path, path: f.path, content: f.content, lang: f.lang, dep: f.dep }]),
      ([, file]) => scanFile(file),
      ([, file], e) => [scanErrorIssue(file.path, e)]);                  // one file must never kill the run
    for (const found of scans) add(found);
    const read = treeReader(files, configs);                            // what an editor's or agent's settings run
    for (const cf of configs) {                                         // config and data files: credentials only
      try { add(scanConfigFile(cf.path, cf.content, read)); } catch (e) { issues.push(scanErrorIssue(cf.path, e)); }
    }
    for (const mf of manifests) {
      // binding.gyp and every other .gyp / .gypi → scanGyp (G11); package.json
      // → scanManifest, with the registry hook set inside a dependency tree.
      try {
        add(mf.kind !== "package.json" ? scanGyp(mf.path, mf.content)
          : scanManifest(mf.path, mf.content, { registry: !!mf.dep }));
      } catch (e) { issues.push(scanErrorIssue(mf.path, e)); }
    }
    // --deps: what the dependencies run (install hooks, import-time code)
    const deps = dependencyChecks(root, files, manifests, issues, { exclude, maxFileBytes: col.maxFileBytes, pool });
    add(deps.issues);
    for (const f of deps.files) files.push(f);
  } finally {
    if (pool) pool.close();
  }
  add(skippedIssues);
  // Cross-file taint flows in the project's Python and JavaScript (the
  // Python engine's flow.analyze; dependency files are not analyzed). The
  // findings copy raw source lines: they get their file's redaction here.
  add(redactFlowIssues(analyzeFlows(files), files));
  const res = redactResult(buildResult(root, files, issues), clipLine);
  res.metrics.configFiles = configs.length;
  return { res, files, configs };
}
