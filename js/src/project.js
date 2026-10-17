// The project scan (the Python package's core.scan_project), shared by `lazaret <dir>` (cli.js) and `lazaret hook`
// (hook.js): collect, each file's scan, the config files, the manifests, what the project's own install hooks run, the
// dependency checks, the skipped trees, the cross-file flows, then the result built and redacted. Prints nothing.

import { collectFiles, ScanTargetError } from "./lib/fs.js";
import { scanErrorIssue } from "./lib/issue.js";
import { MAX_FILE_BYTES } from "./lib/collect.js";
import { fsNameToString } from "./lib/encoding.js";
import { scanFile } from "./scanner/scan.js";
import { collectionIssues, scanTask } from "./scancollection.js";
import { redactResult } from "./lib/redact.js";
import { buildResult } from "./report.js";
import { dependencyChecks, projectHookChecks, diskReader } from "./deps.js";
import { Pool, threadsFor, mapTasks } from "./pool.js";

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
  const { files, manifests, configs, skippedIssues } = col;
  const threads = threadsFor(env, files.reduce((n, f) => n + f.content.length, 0),
    files.reduce((n, f) => Math.max(n, f.content.length), 0));
  let pool = null;
  if (threads > 1) {
    try { pool = new Pool(threads); } catch { pool = null; }        // (no workers here: one thread does it all)
  }
  let issues;
  try {
    issues = collectionIssues(col, {
      extraIssues,
      // a dependency's agent skill (RA-3): the scripts it runs, from the disk when the walk did not keep them
      diskRead: diskReader(root, files, manifests, { exclude, maxFileBytes: col.maxFileBytes }),
      scanAll: (all) => mapTasks(pool, all.map((f) => ["scan", scanTask(f)]),
        ([, file]) => scanFile(file),
        ([, file], e) => [scanErrorIssue(file.path, e)]),                // one file must never kill the run
      checks: (sofar) => {
        // the project's own install hooks: what they run (projectHookChecks)
        for (const i of projectHookChecks(root, files, manifests, sofar,
          { exclude, pruned: skippedIssues.map((i) => i.file), maxFileBytes: col.maxFileBytes })) sofar.push(i);
        // --deps: what the dependencies run (install hooks, import-time code)
        const deps = dependencyChecks(root, files, manifests, sofar, { exclude, maxFileBytes: col.maxFileBytes, pool });
        for (const i of deps.issues) sofar.push(i);
        for (const f of deps.files) files.push(f);
      },
    });
  } finally {
    if (pool) pool.close();
  }
  const res = redactResult(buildResult(root, files, issues));
  res.metrics.configFiles = configs.length;
  return { res, files, configs };
}
