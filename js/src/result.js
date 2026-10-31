// A scan's result, graded by the engine (result.rs): the CLI's report (report.js) and the browser dashboard's
// (BR-7 step 5), so this module uses nothing of Node's.

import { metricsFiles } from "./scanner/metrics.js";
import { call } from "./lib/native.js";

/** Local time, seconds precision, no zone — datetime.now().isoformat(timespec="seconds"). */
export function localIso(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/**
 * The cross-file gate condition's label: the Python engine's. (Until phase 3
 * of the Rust-first refactor this engine's flow pass covered JavaScript only,
 * and the label said when the project's Python files were not analyzed; the
 * engine's Python pass runs here too now: flow.js.)
 */
export const CROSS_FILE_LABEL = "No cross-file taint flows";

/**
 * What the engine's result reads of each finding (result.rs): [rule, type, severity, file, line, omitted,
 * omittedType] (a Q-CAPPED note's last two: the maintainability rating counts the smells it stands for).
 */
export function findingRows(issues) {
  return issues.map((i) => [i.rule, i.type, i.sev, String(i.file), i.line,
    Number.isInteger(i.omitted) ? i.omitted : null, typeof i.omittedType === "string" ? i.omittedType : null]);
}

/** `issues` put in the engine's order, where it is (a loop: a spread of a long list overflows the stack). */
function reorder(issues, order) {
  const sorted = order.map((k) => issues[k]);
  for (let k = 0; k < sorted.length; k++) issues[k] = sorted[k];
}

/**
 * `res` graded again from its issues, after something changed their severities or types (--verify-secrets: a live
 * credential is a BLOCKER vulnerability, verify.js): the order of its issues, the counts, the security and reliability
 * ratings, the gate's two conditions on severities and the gate (the engine's: result.rs). The other conditions are
 * left as they are.
 */
export function regrade(res) {
  const got = call("regrade", { issues: findingRows(res.issues), conditions: res.conditions.map((c) => [c.label, c.ok]) });
  reorder(res.issues, got.order);
  res.counts = got.counts;
  Object.assign(res.ratings, got.ratings);
  got.conditions.forEach((now, k) => { res.conditions[k].ok = now.ok; });
  res.pass = got.pass;
  return res;
}

/**
 * A scan graded (the engine's: result.rs, as core.build_result's): its issues in their order (put so where they
 * are), the gate and its conditions, the metrics, counts and ratings, the supply-chain indicators and cross-file
 * flows, the issues by file. The CLI's report (report.js buildResult) puts the version, the project's path and the
 * time first; the dashboard shows it as it is.
 */
export function gradeResult(files, issues) {
  const got = call("result", { issues: findingRows(issues), files: metricsFiles(files) });
  reorder(issues, got.order);
  return {
    pass: got.pass,
    conditions: got.conditions,
    metrics: got.metrics,
    counts: got.counts,
    ratings: got.ratings,
    supplyChain: got.supplyChain,
    crossFile: got.crossFile,
    perFile: got.perFile,
    issues,
  };
}
