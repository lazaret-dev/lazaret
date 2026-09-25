// lazaret — quarantine for your dependencies.
// Public exports for the npm package.

import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const version = pkg.version;
export const TAGLINE = "lazaret: quarantine for your dependencies";

// Product surface
export { scanFile, detectLang, taintScan, setScanTimeBudget } from "./scanner/scan.js";
export { RULES, TEXT_RULES, SEV_ORDER, TYPES } from "./scanner/rules.js";
export { computeMetrics, worstSevRating, maintainabilityRating } from "./scanner/metrics.js";
export {
  buildResult, jsonRenderer, htmlRenderer, printReport, sarifReport, sarifRenderer,
  sanitizeTerm, safeExcerpt,
} from "./report.js";
export { scanManifest, scanGyp, redactResult, setRedactSecrets } from "./lib/supplychain.js";
export {
  collectFiles, reportPaths, writeReport, validateReportPaths, validateOutDir, isOurReport,
  ReportPathError, EXIT_OUTPUT,
} from "./lib/fs.js";
export { run, parseArgs, EXIT_USAGE, EXIT_INTERNAL } from "./cli.js";
