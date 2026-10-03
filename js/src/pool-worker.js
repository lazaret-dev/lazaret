// A worker of pool.js: the native engine's own instance (its compiled
// module handed over), the main thread's scan settings, and the tasks it
// answers — each exactly as the main thread would run it. A worker that
// could not start (its engine does not answer) sends each task back
// unanswered, and the main thread runs it.

import { isMainThread, workerData } from "node:worker_threads";

// (imported anywhere else, it does nothing)
if (!isMainThread && workerData && workerData.signal) await serve(workerData);

async function serve({ signal, port, module, config }) {
  let tasks = null;          // (null: this worker could not start; the main thread runs what it is sent)
  try {
    tasks = await setUp(module, config);
  } catch {
    tasks = null;
  }
  port.on("message", ({ id, kind, args }) => {
    let answer = { id, unable: true };
    if (tasks !== null) {
      try {
        answer = { id, ok: true, value: tasks[kind](args) };
      } catch (e) {
        answer = { id, ok: false, error: { name: (e && e.name) || "Error", message: String((e && e.message) || e) } };
      }
    }
    try {
      port.postMessage(answer);
    } catch {
      port.postMessage({ id, unable: true });        // (an answer that can't be sent: the main thread runs the task)
    }
    Atomics.add(signal, 0, 1);
    Atomics.notify(signal, 0);
  });
}

/** The tasks a worker answers, its engine ready (a call answered) and the main thread's settings set. */
async function setUp(module, config) {
  const native = await import("./lib/native.js");
  native.useModule(module);
  native.call("version");
  native.setWorkBudget(config.workBudget);
  const { setRedactSecrets } = await import("./lib/redact.js");
  setRedactSecrets(config.redact);
  const { scanFile, setScanTimeBudget } = await import("./scanner/scan.js");
  setScanTimeBudget(config.timeBudgetMs);
  const { dependencyImportIssue, dependencyAgentIssue } = await import("./deps.js");
  return {
    /** a source file's scan (cli.js) */
    scan: (file) => scanFile(file),
    /** a dependency file's import-time and agent checks (deps.js): [import issue, agent issue] */
    dep: ([path, content, lang]) => [dependencyImportIssue(path, content, lang), dependencyAgentIssue(path, content)],
    /** the cross-file follower over a scan's dependency files, no file skipped (deps.js) */
    xf: ({ files, redact, siteGroups }) => native.crossFileIssues(files, new Set(), { redact, siteGroups }),
  };
}
