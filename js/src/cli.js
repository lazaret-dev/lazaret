// CLI entry: argument handling, returns an exit code (no process.exit —
// testable). Mirrors the Python CLI's contract (lazaret.scanner.core.main):
//   0 ok (or gate failed without --ci) · 1 gate failed with --ci, or a
//   SC-MANIFEST-DEPTH finding · 2 usage error (or the native engine is
//   missing: a checkout without `npm run build`) · 3 report output error ·
//   5 internal error (never a raw stack trace, never mistaken for "gate failed").

import { resolve } from "node:path";
import { statSync, readFileSync } from "node:fs";
import {
  collectFiles, reportPaths, writeReport, validateReportPaths, validateOutDir,
  ReportPathError, EXIT_OUTPUT, ScanTargetError, scanErrorIssue, MAX_FILE_BYTES,
} from "./lib/fs.js";
import { fsNameToString } from "./lib/encoding.js";
import { pyRepr } from "./lib/pycompat.js";
import { scanFile, scanConfigFile, treeReader } from "./scanner/scan.js";
import { scanManifest, scanGyp } from "./lib/supplychain.js";
import { redactResult, setRedactSecrets } from "./lib/redact.js";
import {
  buildResult, jsonReportChunks, htmlReportChunks, printReport, sarifReport, sarifChunks,
  sanitizeTerm, sanitizeTermLine, setExcerptWidth,
} from "./report.js";
import { clipLine } from "./lib/issue.js";
import { applyBaseline, BASELINE_KEY_ENV } from "./baseline.js";
import { dependencyChecks } from "./deps.js";
import { loadError } from "./lib/native.js";
import { Pool, threadsFor, mapTasks } from "./pool.js";
import { analyzeFlows, redactFlowIssues } from "./scanner/flow.js";

// Local copies (NOT imported from index.js — that would be a cycle).
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const version = pkg.version;
const TAGLINE = "lazaret: quarantine for your dependencies";

export const EXIT_USAGE = 2;
export const EXIT_INTERNAL = 5;

const USAGE = `lazaret v${version} — ${TAGLINE}

Usage:
  lazaret check <directory> [options]
  lazaret <directory> [options]

Options:
  --out-dir DIR         Directory for the default reports (default: the scan
                        root). Must already exist and be writable.
  --json PATH           JSON report path (default: <out-dir>/lazaret-report.json;
                        relative paths resolve under --out-dir / the scan root)
  --html PATH           HTML report path (default: <out-dir>/lazaret-report.html)
  --sarif PATH          Also write a SARIF 2.1.0 report (GitHub code scanning)
  --no-json             Do not write the JSON report.
  --no-html             Do not write the HTML report.
  --force-overwrite     Replace an existing report file even if Lazaret did not
                        write it (directories, symlinks and special files are
                        always refused).
  --deps, --include-deps
                        Also scan dependency directories (node_modules, venv,
                        vendor…) with the supply-chain/secret rules.
  --exclude NAME        Extra directory name to skip (repeatable).
  --baseline PATH       Previous JSON report; findings not in it are marked new.
                        A baseline inside the scanned tree is trusted only when
                        ${BASELINE_KEY_ENV} is set and its signature verifies.
  --no-redact-secrets   Keep credential lines in reports (default: redacted).
  --excerpt-width N     Characters of the flagged line shown per finding (100).
  --max-source-bytes N  Largest source file or manifest read (16,000,000, env
                        LAZARET_MAX_SOURCE_BYTES); a larger one is not scanned
                        and gets SC-TRUNCATED, which fails the gate.
  -q, --quiet           Only print the summary (no per-issue lines).
  --ci                  Exit 1 when the quality gate fails.
  --version             Print version.
  -h, --help            Show this help.

A scan with much to read uses worker threads, one per core (at most 8);
env LAZARET_THREADS sets how many (1: none). The report is the same.

Exit codes: 0 ok (or gate failed without --ci) · 1 gate failed with --ci, or a
hostile-depth manifest · 2 usage error · 3 report output error · 5 internal error.`;

// ---- argument parsing (argparse-compatible: --k=v, --, abbreviations) ------
const OPTIONS = [
  { flag: "--out-dir", dest: "outDir", value: true },
  { flag: "--json", dest: "json", value: true },
  { flag: "--html", dest: "html", value: true },
  { flag: "--sarif", dest: "sarif", value: true },
  { flag: "--baseline", dest: "baseline", value: true },
  { flag: "--exclude", dest: "exclude", value: true, append: true },
  { flag: "--excerpt-width", dest: "excerptWidth", value: true, int: true },
  { flag: "--max-source-bytes", dest: "maxSourceBytes", value: true, int: true, positive: true },
  { flag: "--no-json", dest: "noJson" },
  { flag: "--no-html", dest: "noHtml" },
  { flag: "--force-overwrite", dest: "force" },
  { flag: "--deps", dest: "deps" },
  { flag: "--include-deps", dest: "deps" },
  { flag: "--no-redact-secrets", dest: "noRedact" },
  { flag: "--quiet", short: "-q", dest: "quiet" },
  { flag: "--ci", dest: "ci" },
  { flag: "--version", dest: "version" },
  { flag: "--help", short: "-h", dest: "help" },
];
// Python-engine options this engine does not implement: refused by name.
const PYTHON_ONLY = ["--taint-config", "--strict-taint-config", "--trust-repo-config"];

class UsageError extends Error {}

// Python's int() of a str (argparse's type=int, core._positive_int and
// core._env_int read the integer options with it): whitespace around it
// (ASCII, and Unicode's), a sign, decimal digits of any script with single
// underscores between them, at most 4300 digits (sys.get_int_max_str_digits()).
const PY_INT_WS = "[\\t\\n\\v\\f\\r \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]*";
const PY_INT_RE = new RegExp(`^${PY_INT_WS}([-+]?)(\\p{Nd}+(?:_\\p{Nd}+)*)${PY_INT_WS}$`, "u");
const DIGIT_RE = /^\p{Nd}$/u;
function digitValue(ch) {
  const cp = ch.codePointAt(0);
  if (cp < 0x80) return cp - 0x30;
  let zero = cp;                    // each script's digits 0-9 are consecutive code points
  while (DIGIT_RE.test(String.fromCodePoint(zero - 1))) zero--;
  return (cp - zero) % 10;
}

/** int(text) as Python computes it (a number), or null where it raises ValueError. */
export function pyInt(text) {
  const m = PY_INT_RE.exec(String(text));
  if (!m) return null;
  const digits = Array.from(m[2].replaceAll("_", ""), digitValue);
  if (digits.length > 4300) return null;
  const n = Number(digits.join(""));
  return m[1] === "-" ? 0 - n : n;
}

/** A positive integer environment value, read as core._env_int reads it, else null. */
function envPositiveInt(v) {
  if (v === undefined || v === null) return null;
  const n = pyInt(v);
  return n > 0 ? n : null;
}

function findLong(name) {
  const exact = OPTIONS.find((o) => o.flag === name);
  if (exact) return exact;
  const hits = OPTIONS.filter((o) => o.flag.startsWith(name));
  const flags = [...new Set(hits.map((o) => o.flag))];
  if (flags.length > 1) throw new UsageError(`ambiguous option: ${name} could match ${flags.join(", ")}`);
  if (flags.length === 1) return hits[0];
  if (PYTHON_ONLY.some((f) => f === name || (name.length > 2 && f.startsWith(name))))
    throw new UsageError(`${name} is only supported by the Python engine (pip install lazaret)`);
  throw new UsageError(`unrecognized arguments: ${name}`);
}

export function parseArgs(argv) {
  const opts = { exclude: [] };
  const positional = [];
  let onlyPositional = false;
  const takeValue = (o, inline, i) => {
    if (inline !== undefined) return [inline, i];
    const v = argv[i + 1];
    if (v === undefined || (v.startsWith("-") && v !== "-" && !/^-\d/.test(v)))
      throw new UsageError(`argument ${o.flag}: expected one argument`);
    return [v, i + 1];
  };
  const set = (o, v) => {
    if (o.int) {
      const raw = String(v), n = pyInt(raw);
      if (o.positive && !(n > 0))                                 // as core._positive_int words it
        throw new UsageError(`argument ${o.flag}: expected a positive number of bytes, got ${pyRepr(raw)}`);
      if (n === null) throw new UsageError(`argument ${o.flag}: invalid int value: ${pyRepr(raw)}`);
      v = n;
    }
    if (o.append) opts[o.dest].push(v);
    else opts[o.dest] = o.value ? v : true;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = String(argv[i]);
    if (onlyPositional) { positional.push(a); continue; }
    if (a === "--") { onlyPositional = true; continue; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = eq === -1 ? a : a.slice(0, eq);
      const inline = eq === -1 ? undefined : a.slice(eq + 1);
      const o = findLong(name);
      if (o.value) { let v; [v, i] = takeValue(o, inline, i); set(o, v); }
      else {
        if (inline !== undefined) throw new UsageError(`argument ${o.flag}: ignored explicit argument '${inline}'`);
        set(o, true);
      }
      continue;
    }
    if (a.length > 1 && a.startsWith("-") && !/^-\d/.test(a)) {
      for (let k = 1; k < a.length; k++) {
        const o = OPTIONS.find((x) => x.short === `-${a[k]}`);
        if (!o) throw new UsageError(`unrecognized arguments: ${a}`);
        if (o.value) { const rest = a.slice(k + 1); let v; [v, i] = takeValue(o, rest || undefined, i); set(o, v); break; }
        set(o, true);
      }
      continue;
    }
    positional.push(a);
  }
  return { opts, positional };
}

/**
 * Run the CLI. Returns an exit code.
 * @param {string[]} argv arguments after the program name
 * @param {{ out?: (s: string)=>void, err?: (s: string)=>void, env?: object }} io injectable
 */
export function run(argv, io = {}) {
  const err = io.err ?? ((s) => console.error(s));
  const env = io.env ?? process.env;
  try {
    return runChecked(argv ?? [], io);
  } catch (e) {
    // Any internal error is `error: internal: …` with exit 5 — never a raw
    // stack trace, never confusable with a failed gate (exit 1).
    const debug = env.LAZARET_DEBUG === "1";
    try {
      if (debug && e && e.stack) err(sanitizeTerm(e.stack));
      let detail = sanitizeTerm(e && e.message !== undefined ? e.message : String(e)).replace(/[\n\u2028\u2029]/g, " ");
      if (detail.length > 500) detail = detail.slice(0, 497) + "...";
      err(`error: internal: ${(e && e.name) || "Error"}` + (detail ? `: ${detail}` : ""));
      if (!debug) err("  (this is a Lazaret bug, not a scan result; set LAZARET_DEBUG=1 for a traceback)");
    } catch { /* never throw from the error path */ }
    return EXIT_INTERNAL;
  } finally {
    setRedactSecrets(true);
  }
}

const GUARD_TOOLS = ["npm", "pnpm", "pip", "pip3", "uv"];

/** `lazaret guard <tool> …`, the Python package's install guard: a package
 * manager after `guard`, or only options (or nothing) when no path named
 * guard is here to scan (lazaret._cli.is_guard). */
function isGuardCommand(argv) {
  if (argv[0] !== "guard") return false;
  const rest = argv.slice(1);
  if (rest.some((a) => GUARD_TOOLS.includes(a))) return true;
  if (!rest.every((a) => a.startsWith("-"))) return false;
  try { statSync("guard"); return false; } catch { return true; }
}

function runChecked(argv, io) {
  const out = io.out ?? ((s) => console.log(s));
  const err = io.err ?? ((s) => console.error(s));
  const env = io.env ?? process.env;
  const usage = (msg) => {
    err(`error: ${sanitizeTermLine(msg)}`);
    err("Run 'lazaret --help' for usage.");
    return EXIT_USAGE;
  };

  if (isGuardCommand(argv)) {
    err("error: lazaret guard comes with the Python package: pip install lazaret (or pipx install lazaret), "
      + "then run: lazaret guard npm install …");
    return EXIT_USAGE;
  }
  let parsed;
  try {
    if (argv.includes("-h") || argv.includes("--help")) { out(USAGE); return 0; }
    parsed = parseArgs(argv);
  } catch (e) {
    if (e instanceof UsageError) return usage(e.message);
    throw e;
  }
  const { opts } = parsed;
  if (opts.help) { out(USAGE); return 0; }
  if (opts.version) { out(`lazaret v${version}`); return 0; }
  const positional = [...parsed.positional];
  if (positional[0] === "check") positional.shift();
  if (positional.length === 0) {
    return usage(parsed.positional.length ? "the following arguments are required: directory"
      : "no directory given — lazaret: quarantine for your dependencies");
  }
  if (positional.length > 1) return usage(`unrecognized arguments: ${positional.slice(1).join(" ")}`);
  const dirArg = positional[0];
  const root = resolve(dirArg);
  let st = null;
  try { st = statSync(root); } catch { /* missing */ }
  if (!st) {
    err(`error: ${sanitizeTermLine(dirArg)} does not exist (expected a directory to scan)`);
    return EXIT_USAGE;
  }
  if (!st.isDirectory()) {
    err(`error: ${sanitizeTermLine(dirArg)} is not a directory (lazaret scans a project directory)`);
    return EXIT_USAGE;
  }
  // The native engine (native/lazaret.wasm) answers every file's rules: a
  // checkout that has not built it scans nothing (as the Python package's
  // --engine rust without its library, exit 2), rather than report every file
  // SC-TRUNCATED.
  const missing = loadError();
  if (missing) {
    err(`error: ${sanitizeTermLine(missing)}`);
    return EXIT_USAGE;
  }
  if (opts.excerptWidth !== undefined) setExcerptWidth(opts.excerptWidth);
  setRedactSecrets(!opts.noRedact);

  // Report destinations: resolved under the scan root (or --out-dir) and
  // validated BEFORE scanning (fail fast, exit 3 — never pay the scan cost
  // only to lose the results at write time).
  let paths;
  try {
    if (opts.outDir) validateOutDir(opts.outDir);
    paths = reportPaths(root, {
      outDir: opts.outDir || null,
      json: opts.noJson ? false : (opts.json || true),
      html: opts.noHtml ? false : (opts.html || true),
      sarif: opts.sarif || null,
    });
    validateReportPaths(paths, !!opts.force);
  } catch (e) {
    if (e instanceof ReportPathError) { err(`error: ${sanitizeTermLine(e.message)}`); return EXIT_OUTPUT; }
    throw e;
  }

  // ---- scan -------------------------------------------------------------
  let col;
  try {
    col = collectFiles(root, { includeDeps: !!opts.deps, exclude: opts.exclude,
      maxFileBytes: opts.maxSourceBytes ?? envPositiveInt(env.LAZARET_MAX_SOURCE_BYTES) ?? MAX_FILE_BYTES });
  } catch (e) {
    if (e instanceof ScanTargetError) { err(`error: ${sanitizeTermLine(e.message)}`); return EXIT_USAGE; }
    throw e;
  }
  const { files, manifests, configs, binaryIssues, skippedIssues } = col;
  if (!files.length && !manifests.length && !configs.length && !col.pth.length && !binaryIssues.length) {
    err(`error: ${sanitizeTermLine(`nothing to scan under ${fsNameToString(Buffer.from(root))}: no Python, JavaScript or SQL sources, package manifests or other files to check`)}`);
    return EXIT_USAGE;
  }
  const issues = [];
  const add = (list) => { for (const i of list) issues.push(i); };   // never push(...big)
  add(binaryIssues);
  // Each file's scan, and --deps' checks of each dependency file: on worker threads for a scan
  // with enough to read (pool.js; LAZARET_THREADS), the findings in the same order.
  const threads = threadsFor(env, files.reduce((n, f) => n + f.content.length, 0),
    files.reduce((n, f) => Math.max(n, f.content.length), 0));
  let pool = null;
  if (threads > 1) {
    try { pool = new Pool(threads); } catch { pool = null; }        // (no workers here: one thread does it all)
  }
  try {
    return scanAndReport(pool);
  } finally {
    if (pool) pool.close();
  }

  function scanAndReport(pool) {
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
    const deps = dependencyChecks(root, files, manifests, issues, { exclude: opts.exclude, maxFileBytes: col.maxFileBytes, pool });
    add(deps.issues);
    for (const f of deps.files) files.push(f);
    add(skippedIssues);
    // Cross-file taint flows in the project's JavaScript (the Python engine's
    // flow.analyze, JavaScript half; dependency files are not analyzed). The
    // findings copy raw source lines: they get their file's redaction here.
    add(redactFlowIssues(analyzeFlows(files), files));
    const res = redactResult(buildResult(root, files, issues), clipLine);
    res.metrics.configFiles = configs.length;
    if (opts.baseline) {
      applyBaseline(res, opts.baseline, { root, env, warn: (m) => err(sanitizeTermLine(m)) });
    }
    printReport(res, { out, quiet: !!opts.quiet });

    // ---- reports (atomic, no-clobber, marker-checked) ----------------------
    // Written in pieces: a report can be too big for one string (report.js).
    const strict = !!opts.force;
    try {
      if (paths.sarif) {
        writeReport(paths.sarif, () => sarifChunks(sarifReport(res, root)), { kind: "sarif", strict });
        out(`  SARIF report: ${sanitizeTermLine(paths.sarif)}`);
      }
      if (paths.json) {
        writeReport(paths.json, () => jsonReportChunks(res, { key: env[BASELINE_KEY_ENV] }), { kind: "json", strict });
        out(`  JSON report: ${sanitizeTermLine(paths.json)}`);
      }
      if (paths.html) {
        writeReport(paths.html, () => htmlReportChunks(res), { kind: "html", strict });
        out(`  HTML report: ${sanitizeTermLine(paths.html)}`);
      }
    } catch (e) {
      // Any write failure (a race with the pre-scan checks, ENOSPC, EISDIR, …)
      // is a report output error, not an internal one.
      if (e instanceof ReportPathError) err(`error: ${sanitizeTermLine(e.message)}`);
      else err(`error: could not write a report: ${sanitizeTermLine(e && e.message ? e.message : e)}`);
      return EXIT_OUTPUT;
    }

    if (opts.ci && !res.pass) return 1;
    // 48033f94: a hostile-depth manifest is the one finding that forces a
    // non-zero exit without --ci (spec 10).
    if (res.issues.some((i) => i.rule === "SC-MANIFEST-DEPTH")) return 1;
    return 0;
  }
}
