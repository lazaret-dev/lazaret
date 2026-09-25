// lazaret — quarantine for your dependencies.
// Public exports for the npm package.

import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const version = pkg.version;
export const TAGLINE = "lazaret: quarantine for your dependencies";

// Product surface
export { scanFile, detectLang } from "./scanner/scan.js";
export { RULES, TEXT_RULES, SEV_ORDER, TYPES } from "./scanner/rules.js";
export { computeMetrics, worstSevRating, maintainabilityRating } from "./scanner/metrics.js";
export { buildResult, jsonRenderer, printReport } from "./report.js";
export { scanManifest, scanGyp, redactResult } from "./lib/supplychain.js";
export { collectFiles, reportPaths, writeReport, ReportPathError, EXIT_OUTPUT } from "./lib/fs.js";
export { run } from "./cli.js";
