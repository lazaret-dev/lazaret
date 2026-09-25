// CLI entry: argument handling, returns an exit code (no process.exit —
// testable). Mirrors lazaret.py main()'s contract:

import { resolve } from "node:path";
import { statSync, readFileSync } from "node:fs";
import { collectFiles, reportPaths, writeReport, ReportPathError, EXIT_OUTPUT } from "./lib/fs.js";
import { scanFile } from "./scanner/scan.js";
import { scanManifest, scanGyp, redactResult } from "./lib/supplychain.js";
import { buildResult, jsonRenderer, printReport } from "./report.js";

// Local copies (NOT imported from index.js — that would be a cycle).
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const version = pkg.version;
const TAGLINE = "lazaret: quarantine for your dependencies";

const USAGE = `lazaret v${version} — ${TAGLINE}

Usage:
  lazaret check <directory> [options]

Options:
  --out-dir DIR        Directory for the default reports (default: the scan
                       root). Must already exist and be writable.
  --no-json            Do not write the JSON report.
  --no-html            Do not write the HTML report.
  --include-deps       Also scan dependency directories (node_modules, vendor…).
  --quiet              Suppress the per-issue terminal listing.
  --ci                 Exit 1 when the quality gate fails.
  --version            Print version.
  -h, --help           Show this help.`;

function sanitizeTerm(text) {
  // audit H1: strip ANSI/control bytes from anything that derives from
  // scanned content before it reaches the terminal.
  return String(text).replace(/[\u0000-\u001f\u007f]/g, (c) => (c === "\n" ? "\n" : ""));
}

/**
 * Run the CLI. Returns an exit code.
 * @param {string[]} argv arguments after the program name
 * @param {{ out?: (s: string)=>void, err?: (s: string)=>void }} io injectable
 */
export function run(argv, io = {}) {
  const out = io.out ?? ((s) => console.log(s));
  const err = io.err ?? ((s) => console.error(s));
  const args = argv ?? [];
  const want = (name) => args.includes(`--${name}`);

  if (want("help") || args.includes("-h")) { out(USAGE); return 0; }
  if (want("version")) { out(`lazaret v${version}`); return 0; }
  if (args.length === 0 || args[0] !== "check") {
    err(args.length ? `unknown command: ${sanitizeTerm(args[0])}`
                    : "no command given — lazaret: quarantine for your dependencies");
    err("Run 'lazaret --help' for usage.");
    return 1;
  }

  const positional = args.slice(1).filter((a) => !a.startsWith("--"));
  const dirArg = positional[0] ?? ".";
  const root = resolve(dirArg);

  let st;
  try {
    st = statSync(root);
  } catch {
    err(`error: ${sanitizeTerm(dirArg)} is not a directory`);
    return 2;
  }
  if (!st.isDirectory()) {
    err(`error: ${sanitizeTerm(dirArg)} is not a directory`);
    return 2;
  }

  // out-dir validation BEFORE the scan (fail fast, exit 3 — never pay the
  // scan cost only to lose the results at write time).
  let outDir = null;
  const oi = args.indexOf("--out-dir");
  if (oi !== -1) {
    outDir = args[oi + 1];
    if (!outDir) { err("error: --out-dir requires a value"); return 2; }
    try {
      const ost = statSync(resolve(outDir));
      if (!ost.isDirectory()) throw new Error("not a directory");
    } catch {
      err(`error: --out-dir ${sanitizeTerm(outDir)} is not an existing directory`);
      return EXIT_OUTPUT;
    }
  }

  // ---- scan -------------------------------------------------------------
  const { files, manifests, binaryIssues } = collectFiles(root, {
    includeDeps: want("include-deps"),
  });
  const issues = [...binaryIssues];
  for (const f of files) issues.push(...scanFile({ name: f.path, content: f.content, lang: f.lang, dep: f.dep }));
  for (const mf of manifests) {
    // binding.gyp manifests are handled by scanGyp (G11); package.json by
    // scanManifest.
    issues.push(...(mf.kind === "binding.gyp" ? scanGyp(mf.path, mf.content) : scanManifest(mf.path, mf.content)));
  }
  const res = redactResult(buildResult(root, files, issues));
  printReport(res, { out, quiet: want("quiet") });

  // ---- reports (atomic, no-clobber, marker-checked) ----------------------
  try {
    const paths = reportPaths(root, {
      outDir: outDir ? resolve(outDir) : null,
      json: !want("no-json"),
      html: !want("no-html"),
    });
    if (paths.json) {
      writeReport(paths.json, jsonRenderer(res), {
        marker: { key: "generatedBy", value: "lazaret-cli-1" },
      });
      out(`  JSON report: ${sanitizeTerm(paths.json)}`);
    }
    // HTML report: the JSON report wrapped in a minimal page carrying the
    // provenance marker (same pair as the JSON's first key).
    if (paths.html) {
      const html = `<!doctype html>\n<html><head><meta charset="utf-8">\n<meta name="generatedBy" content="lazaret-cli-1">\n<title>lazaret report</title></head>\n<body><pre>${jsonRenderer(res)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;")}</pre></body></html>\n`;
      writeReport(paths.html, html, {
        marker: { key: "generatedBy", value: "lazaret-cli-1" },
      });
      out(`  HTML report: ${sanitizeTerm(paths.html)}`);
    }
  } catch (e) {
    if (e instanceof ReportPathError) {
      err(`error: ${sanitizeTerm(e.message)}`);
      return EXIT_OUTPUT;
    }
    throw e;
  }

  // 48033f94 / --ci parity: a CRITICAL SC- finding must be reflected in the
  // exit code (scan completes, reports written — then signal).
  if (want("ci") && !res.pass) return 1;
  if (res.issues.some((i) => i.sev === "CRITICAL" && i.rule.startsWith("SC-"))) return 1;
  return 0;
}
