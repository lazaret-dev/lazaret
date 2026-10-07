// The native engine (rust/, docs/RUST_ENGINE.md): Lazaret's Rust engine,
// built as WebAssembly (`npm run build`: native/lazaret.wasm) and run by
// Node's own WebAssembly, so the package stays free of dependencies. It
// answers the supply-chain tests (install scripts, import-time code, install
// hooks, received code …), scan_file's pattern rules and families and the
// cross-file follower, as in the Python package, whose wheels carry the
// same engine as a library: since the Rust-first refactor the only engine,
// held to its recorded outputs (python/tests/architecture/test_snapshot_*.py),
// and this build to the library (test_wasm_parity*.py).
//
// One call: a request [u32 LE name length][name][u32 LE args length][args,
// JSON][text], the text as UTF-8 with lone surrogates passed through (WTF-8:
// the engine reads a JavaScript string as Python reads the same str), copied
// into the module's memory (lazaret_alloc; lazaret_call takes it back); the
// answer [u32 LE status][u32 LE length][JSON] (lazaret_free). Offsets in
// answers are code points, as in Python. Status 1 (an error) and 2 (the
// call's work budget spent on a hostile input) throw NativeError and
// NativeExhausted. A trap (the module aborts on a panic) throws NativeError
// too, and the next call starts a fresh instance; so does a call after one
// that left the memory larger than MEMORY_KEEP.

import { readFileSync } from "node:fs";
import { sep } from "node:path";
import { fileURLToPath } from "node:url";

const WASM = new URL("../../native/lazaret.wasm", import.meta.url);
const MEMORY_KEEP = 512 * 1024 * 1024;   // bytes of module memory kept between calls

export class NativeError extends Error {
  constructor(message) { super(message); this.name = "NativeError"; }
}
/** The call's work budget was spent (a hostile input): it has no answer. */
export class NativeExhausted extends NativeError {
  constructor(message) { super(message); this.name = "NativeExhausted"; }
}

let compiled = null;       // the WebAssembly.Module (compiled once per process)
let engine = null;         // the instance's exports
let workBudget = null;     // steps of the regex matcher a call may take (null: the engine's default)

/** The work each call may do, in steps of the engine's regex matcher (null: its default, about 4e9). */
export function setWorkBudget(steps = null) {
  workBudget = steps;
}

/** The compiled module; throws NativeError when native/lazaret.wasm is missing. */
export function wasmModule() {
  if (compiled) return compiled;
  let bytes;
  try {
    bytes = readFileSync(WASM);
  } catch (e) {
    throw new NativeError(`the native engine is missing (${fileURLToPath(WASM)}: ${e.code ?? e.message}); `
      + "build it with `npm run build` (Rust and its wasm32-unknown-unknown target)");
  }
  compiled = new WebAssembly.Module(bytes);
  return compiled;
}

/**
 * Use `module` (a WebAssembly.Module of native/lazaret.wasm, compiled in
 * another thread: pool.js hands its own to each worker) rather than
 * compile the file again.
 */
export function useModule(module) {
  if (!compiled && module instanceof WebAssembly.Module) compiled = module;
}

/** The work budget each call is given (null: the engine's default). */
export function workBudgetSteps() {
  return workBudget;
}

function instance() {
  if (!engine) engine = new WebAssembly.Instance(wasmModule(), {}).exports;
  return engine;
}

/** Why the native engine can't be loaded (a message), or null when it can. */
export function loadError() {
  try {
    instance();
    return null;
  } catch (e) {
    return e instanceof NativeError ? e.message : `the native engine could not be loaded (${e.message})`;
  }
}

/** Is the native engine there to load? */
export function available() {
  return loadError() === null;
}

const utf8 = new TextEncoder();
const ascii = new TextDecoder("utf-8");

/** UTF-8 bytes of `s`, a lone surrogate written as its three bytes (WTF-8). */
function wtf8(s) {
  if (s.isWellFormed()) return utf8.encode(s);
  const out = new Uint8Array(s.length * 3);
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      }
    }
    if (c < 0x80) out[n++] = c;
    else if (c < 0x800) { out[n++] = 0xc0 | (c >> 6); out[n++] = 0x80 | (c & 63); }
    else if (c < 0x10000) { out[n++] = 0xe0 | (c >> 12); out[n++] = 0x80 | ((c >> 6) & 63); out[n++] = 0x80 | (c & 63); }
    else {
      out[n++] = 0xf0 | (c >> 18); out[n++] = 0x80 | ((c >> 12) & 63);
      out[n++] = 0x80 | ((c >> 6) & 63); out[n++] = 0x80 | (c & 63);
    }
  }
  return out.subarray(0, n);
}

function concatBytes(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** The code points of `s` as the engine reads it: a surrogate pair is one, a lone surrogate one. */
export function codePoints(s) {
  let n = s.length;
  for (const _ of s.matchAll(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g)) n--;
  return n;
}

/**
 * Run one call of the engine: `name`, its arguments (an object) and, for the
 * calls that read one, the text (or texts, sent one after another, each
 * encoded on its own). Returns the answer (JSON-decoded).
 */
export function call(name, args = {}, text = "") {
  const e = instance();
  if (workBudget !== null && name !== "batch") args = { ...args, budget: workBudget };
  const nameBytes = utf8.encode(name);
  const argBytes = utf8.encode(JSON.stringify(args));   // lone surrogates come out as \u escapes
  const textBytes = Array.isArray(text) ? concatBytes(text.map((t) => wtf8(String(t)))) : wtf8(String(text));
  const len = 8 + nameBytes.length + argBytes.length + textBytes.length;
  let status, answer;
  try {
    const req = e.lazaret_alloc(len);
    let view = new DataView(e.memory.buffer);
    let bytes = new Uint8Array(e.memory.buffer);
    view.setUint32(req, nameBytes.length, true);
    bytes.set(nameBytes, req + 4);
    view.setUint32(req + 4 + nameBytes.length, argBytes.length, true);
    bytes.set(argBytes, req + 8 + nameBytes.length);
    bytes.set(textBytes, req + 8 + nameBytes.length + argBytes.length);
    const out = e.lazaret_call(req, len);                  // frees the request
    view = new DataView(e.memory.buffer);
    status = view.getUint32(out, true);
    const n = view.getUint32(out + 4, true);
    answer = ascii.decode(new Uint8Array(e.memory.buffer, out + 8, n));
    e.lazaret_free(out, 8 + n);
  } catch (err) {
    engine = null;                                         // a trap: the next call gets a fresh instance
    throw new NativeError(`the native engine stopped in ${name} (${err.message})`);
  }
  if (e.memory.buffer.byteLength > MEMORY_KEEP) engine = null;
  const value = JSON.parse(answer);
  if (status === 0) return value;
  if (status === 2) throw new NativeExhausted(`${name}: the call's work budget was spent`);
  throw new NativeError(`${name}: ${value && value.error}`);
}

// ---- core's values, as the engine's rule pack holds them ----

/** A pack value in plain form: numbers, strings, arrays (lists and sorted sets), objects, {re, flags} patterns. */
function plain(v) {
  if (v === null || typeof v !== "object") return v;
  if ("value" in v) return v.value;
  if ("re" in v) return { re: v.re, flags: v.flags };
  if ("set" in v) return v.set.slice();
  if ("list" in v) return v.list.map(plain);
  if ("map" in v) return Object.fromEntries(Object.entries(v.map).map(([k, x]) => [k, plain(x)]));
  if ("items" in v) return v.items.map(([k, x]) => [k, plain(x)]);
  return v;
}

const values = new Map();
/** core's module-level values by name (plain form), read once. */
export function packValues(...names) {
  const missing = names.filter((n) => !values.has(n));
  if (missing.length) {
    const got = call("pack.values", { names: missing });
    for (const n of missing) {
      if (got[n] === null || got[n] === undefined) throw new NativeError(`the rule pack has no value ${n}`);
      values.set(n, plain(got[n]));
    }
  }
  return names.map((n) => values.get(n));
}

// ---- the supply-chain tests (core's functions of the same names) ----

/** Reasons an install-time script looks hostile ([] if none). `shell`: read a shell script as a program
 * too; `command`: the text is a hook's command; `lang`: the script's language when known ("js", "py": its
 * strings are read as its runtime reads them). core.install_script_risk */
export const installScriptRisk = (text, shell = true, command = false, lang = null) =>
  call("install_script_risk", lang ? { shell, command, lang } : { shell, command }, text);
/** The language a script runs in, for the tests that read its strings: "py" for a .py file, null for a
 * shell script (.sh), "js" for the rest (what node runs). core's engine.script_lang */
export const scriptLang = (path) => (path.endsWith(".py") ? "py" : path.endsWith(".sh") ? null : "js");
/** [reasons, line] of the weaker import-time test ([] and null if none); `lang` "py", "js" or null. */
export const importTimeRisk = (text, lang = null) => call("import_time_risk", lang ? { lang } : {}, text);
/** "CRITICAL" when one of importTimeRisk's reasons is a strong one, else "MAJOR". */
export const importTimeSeverity = (reasons) => call("import_time_severity", { reasons });
/** [targets, complete]: the files an install hook's command runs, and whether it was read to the end
 * ([[], true] for what is not a string, as core answers). */
export const followHook = (cmd) => (typeof cmd === "string" ? call("follow_hook", {}, cmd) : [[], true]);
/** The files an install hook runs (followHook's targets). */
export const hookScriptTargets = (cmd) => followHook(cmd)[0];
/** shlex.split(cmd) as a hook command is split (posix, punctuation chars), or null where shlex raises. */
export const shlexSplit = (cmd) => call("shlex_split", {}, cmd);
/** The tokens followHook reads of a hook command (core._hook_tokens). */
export const hookTokens = (cmd) => call("hook_tokens", {}, cmd);
/** The code of each `node -e` in a command (core._NODE_E_RE's matches). */
export const nodeECodes = (cmd) => call("node_e_codes", {}, cmd);
/** The paths Node tries for `require(path)`, in its order. */
export const nodeCandidates = (path) => call("node_candidates", {}, path);
/** "js", "py" or "sh" from a file's #! line, else null. */
export const shebangLang = (text) => call("shebang_lang", {}, text);
/** [[base, path]]: the package scripts `text` (in `lang`, when known) starts with node or python ("dir": its
 * directory, "cwd"). */
export const spawnedScripts = (text, lang = null) => call("spawned_scripts", lang ? { lang } : {}, text);
/** What a text plants to run again (a login item, a cron job, a shell profile …). */
export const persistenceReasons = (text) => call("persistence_reasons", {}, text);
/** Why a .pth file's import line is hostile (SC-PTH-EXEC CRITICAL), or []. core.pth_issues */
export const pthLineRisk = (line) => call("pth_line_risk", {}, line);
/** [agent, flag, line] when dependency code hands an AI agent's CLI a flag that turns off its confirmations
 * to an exec call, else null. */
export const agentHijack = (text) => call("agent_hijack", {}, text);
/** [agent, flag] when an install hook's command launches the agent itself, else null. */
export const agentHijackInCommand = (cmd) => call("agent_hijack_in_command", {}, cmd);
/** Reasons an install hook's command looks hostile, read as a program; `outputKept`: what it prints is used. */
export const hookCommandRisk = (cmd, outputKept = false) =>
  (typeof cmd === "string" ? call("hook_command_risk", outputKept ? { output_kept: true } : {}, cmd) : []);
/** Does a hook's command run a download or evaluation tool (a hint, not evidence)? */
export const hookIsSuspicious = (cmd) => call("hook_is_suspicious", {}, cmd);
/** `text` ("py" or "js") with its prose blanked, as the import-time test reads it. */
export const importCode = (text, lang) => call("import_code", { lang }, text);
/** [line, category] where code runs, deserializes or imports what it received over the network, else null. */
export const receivedCodeKind = (text, extraAlways = [], extraRunners = []) =>
  call("received_code_kind", { extra_always: extraAlways, extra_runners: extraRunners }, text);
/** The line where code runs what it received over the network, else null. */
export const runsReceivedCode = (text) => call("runs_received_code", {}, text);
/** Does the code read its own file (its comments and strings may be what it runs)? */
export const readsOwnSource = (text) => call("reads_own_source", {}, text);
/** Does this row hand a download to a shell or an interpreter through a substitution? */
export const runsSubstitutedDownload = (text) => call("runs_substituted_download", {}, text);
/** The text with the strings it decodes as it runs decoded (the reading install and import-time tests add);
 * `lang` "js" or "py": its literals read as the runtime reads them. */
export const decodedView = (text, lang = null) => call("decoded_view", lang ? { lang } : {}, text);

// The detectors those tests read, one by one (offsets in code points; -1 or null: none found)
export const powershellRisk = (text) => call("powershell_risk", {}, text);
export const stagerAt = (text) => call("stager_at", {}, text);
export const reverseShellAt = (text) => call("reverse_shell_at", {}, text);
export const runsOwnSourceAt = (text) => call("runs_own_source_at", {}, text);
export const serviceReasons = (text) => call("service_reasons", {}, text);
export const secretEndpointAt = (text) => call("secret_endpoint_at", {}, text);
export const credentialSweepAt = (text) => call("credential_sweep_at", {}, text);
export const minerAt = (text) => call("miner_at", {}, text);
export const rawIpConnect = (text) => call("raw_ip_connect", {}, text);
export const dnsBeaconAt = (text, host = true) => call("dns_beacon_at", { host }, text);
export const deadDropAt = (text) => call("dead_drop_at", {}, text);

// ---- the cross-file follower ----

/**
 * The cross-file follower (core._cross_file_received_issues): SC-IMPORT-RISK for each dependency
 * file that runs a value another file of its package received over the network, or hands one to
 * another file's function that runs it, as core finds them and in core's order. `skipPaths`
 * ("/"-separated): the files already flagged single-file. `siteGroups`: deps.js siteGroups' answer
 * (core's site_groups), the packages a distribution's top-level modules make. The engine reads each
 * package with its own work budget; one that spends it is skipped, as core skips a package that raises.
 */
export function crossFileIssues(files, skipPaths = new Set(), { who = "Dependency code", onePackage = false, redact = true,
  siteGroups = null } = {}) {
  const todo = files.filter((f) => f.dep && (f.lang === "py" || f.lang === "js"));
  if (todo.length < 2) return [];
  const texts = todo.map((f) => String(f.content));
  const args = {
    files: todo.map((f, k) => [f.path, f.lang, codePoints(texts[k])]), skip: [...skipPaths], who,
    one_package: onePackage, sep, redact, neumaier: false,
  };
  if (siteGroups && Object.keys(siteGroups).length) {
    args.groups = todo.map((f) => siteGroups[sep === "/" ? f.path : f.path.split(sep).join("/")] ?? null);
  }
  const out = [];
  for (const pkg of call("cross_file", args, texts)) {
    if (!pkg.issues) continue;                          // (failed: skipped)
    for (const [k, a] of pkg.issues) out.push(...issuesOf(todo[k].path, [a]));
  }
  return out;
}

// ---- Go modules and crates (0.1.9): the readers, and what a vendored manifest says ----

/** The Go reader (G-1; the Python package's engine.go_package) on a module's files, [[path below the module's root,
 * text]] of its .go files and its cgo packages' .c and .h files; `module`: its path. */
export function goPackage(files, { module = null, useFileChars = null, useChars = null } = {}) {
  const args = { files: files.map(([path, text]) => [path, codePoints(text)]) };
  if (module) args.module = module;
  if (useFileChars !== null) args.use_file_chars = useFileChars;
  if (useChars !== null) args.use_chars = useChars;
  return call("go_package", args, files.map(([, text]) => text));
}

/** The Rust reader (R-1; engine.rs_crate) on a crate's .rs files, [[path below the crate's root, text]]: `build` its
 * build script's path, `procMacro` whether its library is a procedural macro, `lib` its library's root. */
export function rsCrate(files, { build = null, procMacro = false, lib = null, useFileChars = null, useChars = null } = {}) {
  const args = { proc_macro: Boolean(procMacro), files: files.map(([path, text]) => [path, codePoints(text)]) };
  if (build) args.build = build;
  if (lib) args.lib = lib;
  if (useFileChars !== null) args.use_file_chars = useFileChars;
  if (useChars !== null) args.use_chars = useChars;
  return call("rs_crate", args, files.map(([, text]) => text));
}

/** What a crate's Cargo.toml says of its build script and library ({build: a path, false or null, lib, proc_macro});
 * engine.cargo_layout. */
export const cargoLayout = (text) => call("cargo_layout", {}, text);
/** The module paths a vendor/modules.txt says are vendored, longest first (engine.go_vendored_modules). */
export const goVendoredModules = (text) => call("go_vendored_modules", {}, text);

// ---- the cross-file JavaScript taint pass ----

/**
 * The cross-file JavaScript taint pass (rust/crates/lazaret-engine/src/jsflow/; the Python
 * package's engine.js_flow) over `files` ({path, content}: a project's own JavaScript and
 * TypeScript; a content that is not a string is noted as not text). `runLimit` ([base, steps per
 * node]) lowers the limit of one function's reading. The pass's outputs, in order:
 * ["skipped_size", path, n, limit], ["issue", category, path, line, source, sink, chain, the index
 * of the path's file in `files`], ["note", rule, name, path, line, msg, why, fix].
 */
export function jsFlow(files, { runLimit = null } = {}) {
  const texts = files.map((f) => (typeof f.content === "string" ? f.content : null));
  const args = { files: files.map((f, k) => [f.path, texts[k] === null ? null : codePoints(texts[k])]) };
  if (runLimit) args.run_limit = runLimit;
  return call("js_flow", args, texts.filter((t) => t !== null));
}

// ---- the cross-file Python taint pass ----

/**
 * The cross-file Python taint pass (rust/crates/lazaret-engine/src/pyflow/; the Python package's
 * engine.py_flow) over `files` ({path, content}: a project's own Python; a content that is not a
 * string is noted as not text), on its built-in model. Each limit lowers the pass's own, never
 * raises it: `maxIters` (readings of one function in the fixpoint), `maxFiles` and `maxBytes` (the
 * files and code points read), `workLimit` and `runLimit` ([base, steps per node]: the fixpoint's
 * budget, one reading's). The pass's outputs, in order: ["issue", category, path, line, source,
 * sink, chain, the index of the path's file in `files`], ["note", rule, name, path, line, msg, why,
 * fix].
 */
export function pyFlow(files, { maxIters = null, maxFiles = null, maxBytes = null, workLimit = null, runLimit = null } = {}) {
  const texts = files.map((f) => (typeof f.content === "string" ? f.content : null));
  const args = { files: files.map((f, k) => [f.path, texts[k] === null ? null : codePoints(texts[k])]) };
  if (maxIters !== null) args.max_iters = maxIters;
  if (maxFiles !== null) args.max_files = maxFiles;
  if (maxBytes !== null) args.max_bytes = maxBytes;
  if (workLimit) args.work_limit = workLimit;
  if (runLimit) args.run_limit = runLimit;
  return call("py_flow", args, texts.filter((t) => t !== null));
}

// ---- scan_file ----

const ISSUE_KEYS = ["rule", "name", "type", "sev", "msg", "why", "fix", "ref"];

/** The engine's findings as this package's issues (lib/issue.js mkIssue's keys, in its order). */
function issuesOf(path, answer) {
  return answer.map((a) => {
    const issue = {};
    ISSUE_KEYS.forEach((k, i) => { issue[k] = a[i]; });
    issue.file = path;
    issue.line = a[8];
    issue.snippet = a[9];
    issue.snipStart = a[10];
    if (a.length > 11) { issue.omitted = a[11]; issue.omittedType = a[12]; }
    return issue;
  });
}

/**
 * scan_file in dependency mode (core.scan_file(dep=True)): the supply-chain and credential rules,
 * deduplicated and capped, as core lists them. `content` is the file's text as read (the engine
 * splits it into lines and pins it to Unicode 13.0 as core does).
 */
export function scanDependencyFile(path, content, lang, { jsx = true, redact = true } = {}) {
  return issuesOf(path, call("scan_file", { lang, dep: true, jsx, redact, neumaier: false }, content));
}

/**
 * scan_file in project mode (core.scan_file(dep=False); Q-1, 0.1.9): every pattern rule of the
 * language, the supply-chain and credential families, the file-level and whole-text rules, then the
 * SQL statements without WHERE, the intra-file taint, the SQL built from strings into execute(), the
 * function metrics, the suppression markers and the cap, as core lists them.
 */
export function scanProjectFile(path, content, lang, { jsx = true, redact = true } = {}) {
  return issuesOf(path, call("scan_file", { lang, dep: false, jsx, redact, neumaier: false }, content));
}

/** Project mode's intra-file taint alone (core.taint_scan): its T-* findings, before the markers and the cap. */
export function taintFindings(path, content, lang, { jsx = true, redact = true } = {}) {
  return issuesOf(path, call("taint_scan", { lang, jsx, redact, neumaier: false }, content));
}
