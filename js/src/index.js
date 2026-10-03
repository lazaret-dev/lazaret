// lazaret — quarantine for your dependencies.
// Public exports for the npm package.

import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const version = pkg.version;
export const TAGLINE = "lazaret: quarantine for your dependencies";

// Product surface
export { scanFile, scanConfigFile, detectLang, taintScan, setScanTimeBudget } from "./scanner/scan.js";
export { isConfigFile } from "./lib/configsecrets.js";
export { analyzeFlows, redactFlowIssues } from "./scanner/flow.js";
export { SEV_ORDER, TYPES } from "./scanner/rules.js";
export { computeMetrics, worstSevRating, maintainabilityRating } from "./scanner/metrics.js";
export {
  buildResult, jsonRenderer, htmlRenderer, printReport, sarifReport, sarifRenderer,
  jsonReportChunks, htmlReportChunks, sarifChunks, sanitizeTerm, sanitizeTermLine, safeExcerpt,
} from "./report.js";
export { scanManifest, scanGyp, redactResult, setRedactSecrets } from "./lib/supplychain.js";
// The supply-chain tests, answered by the native engine (Rust, as WebAssembly: lib/native.js)
export {
  followHook, hookScriptTargets, installScriptRisk, importTimeRisk, importTimeSeverity, nodeCandidates,
  persistenceReasons, runsReceivedCode, runsSubstitutedDownload,
} from "./lib/native.js";
export {
  collectFiles, reportPaths, writeReport, validateReportPaths, validateOutDir, isOurReport,
  ReportPathError, EXIT_OUTPUT,
} from "./lib/fs.js";
export { classifyBinary } from "./lib/binary.js";
export { pthIssues } from "./lib/pth.js";
export { applyBaseline, baselineSignature, fingerprint } from "./baseline.js";
export { run, parseArgs, EXIT_USAGE, EXIT_INTERNAL } from "./cli.js";
