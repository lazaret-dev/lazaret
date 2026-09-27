// lazaret — quarantine for your dependencies.
// Public exports for the npm package.

import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const version = pkg.version;
export const TAGLINE = "lazaret: quarantine for your dependencies";

// Product surface
export { scanFile, detectLang, taintScan, setScanTimeBudget } from "./scanner/scan.js";
export { analyzeFlows, redactFlowIssues } from "./scanner/flow.js";
export { RULES, TEXT_RULES, SEV_ORDER, TYPES } from "./scanner/rules.js";
export { computeMetrics, worstSevRating, maintainabilityRating } from "./scanner/metrics.js";
export {
  buildResult, jsonRenderer, htmlRenderer, printReport, sarifReport, sarifRenderer,
  jsonReportChunks, htmlReportChunks, sarifChunks, sanitizeTerm, sanitizeTermLine, safeExcerpt,
} from "./report.js";
export { scanManifest, scanGyp, redactResult, setRedactSecrets } from "./lib/supplychain.js";
export { followHook, hookScriptTargets, installScriptRisk, importTimeRisk, nodeCandidates } from "./lib/hooks.js";
export {
  collectFiles, reportPaths, writeReport, validateReportPaths, validateOutDir, isOurReport,
  ReportPathError, EXIT_OUTPUT,
} from "./lib/fs.js";
export { classifyBinary } from "./lib/binary.js";
export { pthIssues } from "./lib/pth.js";
export { applyBaseline, baselineSignature, fingerprint } from "./baseline.js";
export { run, parseArgs, EXIT_USAGE, EXIT_INTERNAL } from "./cli.js";
