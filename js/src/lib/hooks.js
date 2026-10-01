// SPDX-License-Identifier: Apache-2.0 AND Python-2.0.1
// Following an install hook to the files it runs, and the install-script and
// import-time tests — JS twin of lazaret.scanner.core's hook_script_targets,
// install_script_risk, import_time_risk and node_candidates. Results are
// core's for every input: the patterns are core's text, verbatim, compiled
// with Python `re` semantics by pyRe; the shell tokenizer is Python's shlex.
//
// Hook commands and script texts can be up to 16,000,000 characters, and
// V8's backtracking regex engine overflows its stack ("Maximum call stack
// size exceeded") on a repeated alternation matching millions of them (the
// review B3 notes in pycompat.js). So shlex is a loop, and so is core's
// `node -e` pattern; the loop's matches are the pattern's (NODE_E_RE stays
// here as the reference, and test/review-hooks.test.js compares the two).
// Where core takes quadratic time (every `cd` normalizes the whole path
// again; wrappers are popped off the front of a list), this module does
// not, with the same results.

import { pyRe, pyStrip, pyLstrip, pyRstrip, pyStripChars, isPySpace, cpLen } from "./pycompat.js";
import { PIPE_SCAN_SRC, EXEC_CALL_SRC, EXEC_CALL_RE, DL_SUBST_SRC, DL_SUBST_NEEDLE_SRC, pipesDownloadToShell,
  runsDownloadThroughShell, runsSubstitutedDownload } from "./shellpipe.js";
import { receivedCodeKind, downloadsAndRunsFile, downloadsAndRuns, decodesAndRuns, SCRIPT_INTERP_SRC, SCRIPT_LOAD_SRC,
  DECODE_CALL_SRC, RECEIVED_TWINS, DL_NEEDLES, DL_RUN_NEEDLES, DL_DESERIAL_NEEDLES,
  DL_IMPORT_NEEDLES, DL_SINK_NEEDLES, DL_ALIAS_NEEDLES, DL_ALIAS_MAX, DL_FILE_WRITE_NEEDLES, DL_PATHRUN_NEEDLES,
  DL_PY_NET_MODULES, DL_NOT_NAMES, DL_PREFIX_CHARS, DL_DEFINING, DL_CALLEE_CHARS, DL_LIMITS, cpBack, cpForward } from "./received.js";
import { commentSpans } from "./lexer.js";

// ---- Python details the patterns depend on --------------------------------

/**
 * Python's `$` (without re.M) also matches before a "\n" that ends the
 * string; JavaScript's only at the very end. For a pattern whose `$` ends
 * every alternative that uses it, and whose other parts never match "\n",
 * testing the text without that one "\n" gives Python's answer: a token
 * "python\n" (a quoted newline) is Python's interpreter to core.
 */
const pyEnd = (s) => (s.endsWith("\n") ? s.slice(0, -1) : s);

/**
 * Python's s.replace(a, b) for one character a. (split/join: V8's
 * replaceAll took 1.3 s over 9 million backslashes, this 0.2 s.)
 */
const replaceChar = (s, a, b) => (s.includes(a) ? s.split(a).join(b) : s);

/** Python's str.lstrip("/"). */
function lstripSlashes(s) {
  let i = 0;
  while (i < s.length && s[i] === "/") i++;
  return i ? s.slice(i) : s;
}

/** The index after a run of Python whitespace (\s) starting at s[i]. */
function skipPySpace(s, i) {
  while (i < s.length && isPySpace(s[i])) i++;
  return i;
}

/**
 * posixpath.normpath's loop for a relative path: apply the components of
 * `path` to `comps`, the components kept so far ("" and "." dropped, ".."
 * removing the one before it unless there is none, or it is ".." too).
 * normpath(p) is comps.join("/") || "." after applying p to [], and since
 * normpath(p) has the components p leaves, normpath(a + "/" + b) is b
 * applied to a's components (CPython 3.11+ run a C version of normpath that
 * gives the same results; the parity test runs 3.10 to 3.14).
 */
function applyPath(comps, path) {
  for (const comp of path.split("/")) {
    if (comp === "" || comp === ".") continue;
    if (comp !== ".." || !comps.length || comps[comps.length - 1] === "..") comps.push(comp);
    else comps.pop();
  }
  return comps;
}

// ---- Tokenizing a hook command: Python's shlex ------------------------------
// shlexSplit is a translation into JavaScript of the token state machine of
// CPython's Lib/shlex.py (shlex.read_token), distributed under CPython's
// license, the PSF License Version 2 (../../LICENSE-PYTHON; what changed:
// ../../NOTICE):
//   Copyright (c) 2001 Python Software Foundation; All Rights Reserved
// core._hook_tokens reads a command with shlex.shlex(cmd, posix=True,
// punctuation_chars=True), whitespace_split = True and no commenters.
// shlex.read_token is the same state machine in CPython 3.10 through 3.14;
// shlexSplit is that machine as one loop, with its states:
//   " "  between tokens        "a"  in a word        "c"  in a run of punctuation
//   "'" or '"'  inside quotes    "\\"  after a backslash (then back to escapedstate)
// shlex's one-character push-back is "not consumed": the character is read
// again in the next state. Its whitespace is " \t\r\n" only (not Python's
// \s), and with whitespace_split every other character that is not
// punctuation, a quote or a backslash belongs to the word: its wordchars
// never decide anything. Runs of ordinary characters are copied as slices,
// so a token of millions of characters is not built one character at a time.
const SHLEX_SPACE = 1, SHLEX_PUNCT = 2, SHLEX_QUOTE = 4, SHLEX_ESCAPE = 8;
const SHLEX_CLASS = new Uint8Array(128);
for (const c of " \t\r\n") SHLEX_CLASS[c.charCodeAt(0)] = SHLEX_SPACE;
for (const c of "();<>|&") SHLEX_CLASS[c.charCodeAt(0)] = SHLEX_PUNCT;     // punctuation_chars=True
for (const c of "'\"") SHLEX_CLASS[c.charCodeAt(0)] = SHLEX_QUOTE;
SHLEX_CLASS[92] = SHLEX_ESCAPE;                                                // "\\"
const shlexClass = (s, i) => { const k = s.charCodeAt(i); return k < 128 ? SHLEX_CLASS[k] : 0; };

/**
 * The tokens shlex gives for `cmd` (see above), or null where it raises
 * ValueError: a quote left open ("No closing quotation") or a backslash at
 * the end ("No escaped character").
 */
export function shlexSplit(cmd) {
  const tokens = [];
  const n = cmd.length;
  let state = " ", escapedstate = "a", parts = [], i = 0;
  // A token ends only where shlex's read_token returns one: its text so far,
  // possibly "" when it was quoted ('' or ""). An unquoted "" is shlex's
  // end-of-input, which only happens between tokens.
  const emit = () => { tokens.push(parts.length === 1 ? parts[0] : parts.join("")); parts = []; };
  for (;;) {
    if (state === " ") {
      if (i >= n) return tokens;
      const c = cmd[i++], cls = shlexClass(cmd, i - 1);
      if (cls === SHLEX_SPACE) continue;
      if (cls === SHLEX_ESCAPE) { escapedstate = "a"; state = "\\"; }
      else if (cls === SHLEX_PUNCT) { parts.push(c); state = "c"; }
      else if (cls === SHLEX_QUOTE) state = c;
      else { parts.push(c); state = "a"; }
    } else if (state === "a") {
      if (i >= n) { emit(); return tokens; }
      const cls = shlexClass(cmd, i);
      if (cls === SHLEX_SPACE) { i++; emit(); state = " "; }
      else if (cls === SHLEX_QUOTE) state = cmd[i++];
      else if (cls === SHLEX_ESCAPE) { i++; escapedstate = "a"; state = "\\"; }
      else if (cls === SHLEX_PUNCT) { emit(); state = " "; }            // pushed back
      else {
        let j = i + 1;
        while (j < n && !shlexClass(cmd, j)) j++;
        parts.push(cmd.slice(i, j));
        i = j;
      }
    } else if (state === "c") {
      if (i >= n) { emit(); return tokens; }
      const cls = shlexClass(cmd, i);
      if (cls === SHLEX_PUNCT) {
        let j = i + 1;
        while (j < n && shlexClass(cmd, j) === SHLEX_PUNCT) j++;
        parts.push(cmd.slice(i, j));
        i = j;
      } else {
        if (cls === SHLEX_SPACE) i++;                                  // anything else is pushed back
        emit();
        state = " ";
      }
    } else if (state === "\\") {
      if (i >= n) return null;                                         // "No escaped character"
      const c = cmd[i++];
      // inside double quotes a backslash escapes only a backslash or the quote
      if (escapedstate === '"' && c !== "\\" && c !== '"') parts.push("\\");
      parts.push(c);
      state = escapedstate;
    } else if (state === "'") {                                        // no escapes in single quotes
      const j = cmd.indexOf("'", i);
      if (j < 0) return null;                                          // "No closing quotation"
      parts.push(cmd.slice(i, j));
      i = j + 1;
      state = "a";
    } else {                                                           // state '"'
      let j = i;
      while (j < n && cmd[j] !== '"' && cmd[j] !== "\\") j++;
      if (j >= n) return null;                                         // "No closing quotation"
      parts.push(cmd.slice(i, j));
      i = j + 1;
      if (cmd[j] === '"') state = "a";
      else { escapedstate = '"'; state = "\\"; }
    }
  }
}

// core's fallback where shlex raises, re.findall(r"&&|\|\||[;|&()]|[^\s;|&()]+", cmd),
// read with a loop (\s is Python's whitespace here, not shlex's)
const FALLBACK_OPERATORS = new Set(";|&()");
function fallbackTokens(cmd) {
  const tokens = [];
  const n = cmd.length;
  for (let i = 0; i < n;) {
    const c = cmd[i];
    if ((c === "&" || c === "|") && cmd[i + 1] === c) { tokens.push(c + c); i += 2; }
    else if (FALLBACK_OPERATORS.has(c)) { tokens.push(c); i++; }
    else if (isPySpace(c)) i++;
    else {
      let j = i + 1;
      while (j < n && !FALLBACK_OPERATORS.has(cmd[j]) && !isPySpace(cmd[j])) j++;
      tokens.push(cmd.slice(i, j));
      i = j;
    }
  }
  return tokens;
}

/**
 * Shell-like tokenization of an npm script: quotes respected, operators
 * (&& || ; | & parentheses) as their own tokens. Never throws.
 * Twin of lazaret.scanner.core._hook_tokens.
 */
export function hookTokens(cmd) {
  return shlexSplit(cmd) ?? fallbackTokens(cmd);            // unbalanced quotes: best effort
}

// ---- Following a hook command to the files it runs -------------------------
// core's constants, by the same names (the parity test compares them)
const HOOK_SEPARATORS = new Set(["&&", "||", ";", "|", "&", "(", ")", ";;", "|&"]);
const HOOK_REDIRECTS = new Set([">", ">>", "<", "<<", ">&", "<&", "&>", ">|"]);
const HOOK_WRAPPERS = new Set(["env", "cross-env", "exec", "command", "nohup", "time", "nice", "sudo",
  "cross-env-shell", "dotenv"]);
const NODE_NAMES = new Set(["node", "nodejs", "node.exe"]);
// core._JS_RUNTIMES: other JavaScript runtimes, each with the subcommands that run a file
const JS_RUNTIMES = new Map([["bun", new Set(["run"])], ["bun.exe", new Set(["run"])], ["deno", new Set(["run"])],
  ["deno.exe", new Set(["run"])], ["tsx", new Set()], ["ts-node", new Set()], ["ts-node-esm", new Set()],
  ["esno", new Set()], ["babel-node", new Set()], ["vite-node", new Set()]]);
const RUNTIME_SCRIPT_SRC = String.raw`\.(?:[cm]?[jt]s|[jt]sx)$`;
const RUNTIME_SCRIPT_RE = pyRe(RUNTIME_SCRIPT_SRC, "i");
const SHELL_NAMES = new Set(["sh", "bash", "dash", "zsh", "ksh", "ash", "sh.exe", "bash.exe"]);
const NODE_CODE_FLAGS = new Set(["-e", "--eval", "-p", "--print"]);
const NODE_PRELOAD_FLAGS = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader"]);
const NODE_VALUE_FLAGS = new Set([...NODE_PRELOAD_FLAGS, "-C", "--conditions", "--input-type", "--env-file",
  "--title", "--inspect-port", "--redirect-warnings", "--report-dir", "--diagnostic-dir", "--cpu-prof-dir",
  "--heap-prof-dir", "--watch-path"]);
const OPERATOR_CHARS = new Set(";&|()");
const PYTHON_NAME_SRC = String.raw`^(?:python(?:\d+(?:\.\d+)?)?|py)(?:\.exe)?$`;
const PYTHON_NAME_RE = pyRe(PYTHON_NAME_SRC, "i");
const SCRIPT_EXT_SRC = String.raw`\.(?:c|m)?js$|\.sh$|\.py$`;
const SCRIPT_EXT_RE = pyRe(SCRIPT_EXT_SRC, "i");
const ENV_ASSIGN_SRC = String.raw`^[A-Za-z_][A-Za-z0-9_]*=`;
const ENV_ASSIGN_RE = pyRe(ENV_ASSIGN_SRC);
// flush's re.fullmatch(r"\d?[<>]{1,2}&?\d?", tok) (whole token: ^…$ with no
// m flag is \A…\Z) and re.search(r"&\d$", tok)
const REDIRECT_RE = pyRe(String.raw`^(?:\d?[<>]{1,2}&?\d?)$`);
const DUP_FD_RE = pyRe(String.raw`&\d$`);
// core._NODE_E_RE and _LOCAL_REQUIRE_RE: `node -e <code>` and a package-relative require() in it
const NODE_E_SRC = String.raw`node\s+-e\s+(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|(\S+))`;
/** core._NODE_E_RE, the reference for nodeECodes (which does its work) */
export const NODE_E_RE = pyRe(NODE_E_SRC, "g");
const LOCAL_REQUIRE_SRC = String.raw`require\(\s*\\?["'](\.{1,2}/[^"'\\]+)\\?["']\s*\)`;
const LOCAL_REQUIRE_RE = pyRe(LOCAL_REQUIRE_SRC, "g");

/** twin of core._local_module: a path Node loads from the package, not a package name */
function localModule(value) {
  return Boolean(value) && (value.startsWith("./") || value.startsWith("../") || value.startsWith("/")
    || SCRIPT_EXT_RE.test(pyEnd(value)));
}

/**
 * twin of core._node_script: [script, preloads, code] for `node [flags] script
 * [args]`; code is the inline code of -e / --eval / -p / --print (else null)
 */
function nodeScriptAt(args) {
  const preloads = [];
  let i = 0;
  while (i < args.length) {
    const a = args[i];
    if (a === "--") return [i + 1 < args.length ? i + 1 : null, preloads, null];
    if (a.startsWith("-") && a !== "-") {
      const eq = a.indexOf("=");                                      // a.partition("=")
      const name = eq < 0 ? a : a.slice(0, eq);
      if (NODE_CODE_FLAGS.has(name)) return [null, preloads, eq >= 0 ? a.slice(eq + 1) : i + 1 < args.length ? args[i + 1] : ""];
      if (NODE_VALUE_FLAGS.has(name)) {
        const value = eq >= 0 ? a.slice(eq + 1) : i + 1 < args.length ? args[i + 1] : "";
        if (NODE_PRELOAD_FLAGS.has(name) && localModule(value)) preloads.push(value);
        i += eq >= 0 ? 1 : 2;
        continue;
      }
      i++;
      continue;
    }
    return [i, preloads, null];
  }
  return [null, preloads, null];
}

/** twin of core._node_script: [script, preloads, code] (see nodeScriptAt) */
function nodeScript(args) {
  const [at, preloads, code] = nodeScriptAt(args);
  return [at === null ? null : args[at], preloads, code];
}

/**
 * twin of core._runtime_script: [script, preloads, code] for a JavaScript runtime other than node — node's
 * reading of its words, a subcommand in `runs` skipped, the script kept only when it names a file
 */
function runtimeScript(args, runs) {
  let [at, preloads, code] = nodeScriptAt(args);
  if (at !== null && runs.has(args[at])) {
    const [moreAt, more, moreCode] = nodeScriptAt(args.slice(at + 1));
    preloads = [...preloads, ...more];
    code = moreCode;
    at = moreAt === null ? null : at + 1 + moreAt;
  }
  let script = at === null ? null : args[at];
  if (script !== null && !(script.startsWith("./") || script.startsWith("../") || script.startsWith("/")
      || RUNTIME_SCRIPT_RE.test(pyEnd(script)))) script = null;
  return [script, preloads, code];
}

/** twin of core._interpreter_script: [script, inlineCode] for `sh|python [flags] script` / `-c code` */
function interpreterScript(args) {
  let i = 0;
  while (i < args.length) {
    const a = args[i];
    if (a === "-c") return [null, i + 1 < args.length ? args[i + 1] : ""];
    if (a === "-m" && i + 1 < args.length) {                          // python -m pkg.mod
      return [replaceChar(args[i + 1], ".", "/") + ".py", null];
    }
    if ((a === "-o" || a === "-O" || a === "-W" || a === "-X") && i + 1 < args.length) { i += 2; continue; }
    if (a.startsWith("-") && a !== "-") { i++; continue; }
    return [a, null];
  }
  return [null, null];
}

/** Is tok made only of ; & | ( ) (core: set(tok) <= set(";&|()"))? */
function onlyOperators(tok) {
  for (let i = 0; i < tok.length; i++) if (!OPERATOR_CHARS.has(tok[i])) return false;
  return true;
}

// Following a hook is bounded (twin of core's HOOK_MAX_* and their comment):
// a hook longer than HOOK_MAX_CHARS code points is not followed, at most
// HOOK_MAX_COMMANDS commands (those in `sh -c` / `env -S` code too) and
// HOOK_MAX_TARGETS scripts are, and a script path longer than HOOK_MAX_PATH
// is dropped; followHook says when a limit stopped it.
export const HOOK_MAX_CHARS = 100_000;
export const HOOK_MAX_COMMANDS = 1000;
export const HOOK_MAX_TARGETS = 100;
export const HOOK_MAX_PATH = 4096;
const FD_NUMBER_RE = /^[0-9]+$/;                                       // core: _FD_NUMBER_RE.fullmatch
// A wrapper's options that take a value (the next word, `--name=value`, or
// the rest of a short option: `-Cdir`), those among them that change the
// directory the command runs in, and those whose value is a command line.
const WRAPPER_VALUE_OPTIONS = new Map([
  ["env", new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"])],
  ["sudo", new Set(["-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from",
    "-D", "--chdir", "-r", "--role", "-t", "--type", "-T", "--command-timeout", "-U", "--other-user"])],
  ["nice", new Set(["-n", "--adjustment"])],
  ["exec", new Set(["-a"])],
  ["time", new Set(["-f", "--format", "-o", "--output"])],
  ["dotenv", new Set(["-e", "-v", "-p"])],
]);
const WRAPPER_CHDIR_OPTIONS = new Map([["env", new Set(["-C", "--chdir"])], ["sudo", new Set(["-D", "--chdir"])]]);
const WRAPPER_COMMAND_OPTIONS = new Map([["env", new Set(["-S", "--split-string"])]]);
const NONE = new Set();

/** More than n code points (Python's len(s) > n)? */
function cpLongerThan(s, n) {
  if (s.length <= n) return false;
  let cps = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xdc00 && c <= 0xdfff && i > 0 && (s.charCodeAt(i - 1) & 0xfc00) === 0xd800) continue;   // a pair's low half
    if (++cps > n) return true;
  }
  return false;
}

/**
 * twin of core._hook_cd: the directory [set, components] after `cd dest`
 * from `where` (set is false while no `cd` has named one), or null for a
 * destination the walk cannot follow (~, -, $VAR). An absolute path counts
 * from the package root: core keeps it as written (lstrip("/"), not
 * normalized), so "set" is whether that text is neither "" nor ".".
 */
function hookCd(where, dest) {
  if (!dest || dest === "~" || dest === "-" || dest.startsWith("$") || dest.startsWith("~")) return null;
  dest = replaceChar(dest, "\\", "/");
  if (dest.startsWith("/")) {
    const raw = lstripSlashes(dest);
    return [raw !== "" && raw !== ".", applyPath([], raw)];
  }
  const comps = applyPath(where[1].slice(), dest);
  return [comps.length > 0, comps];
}

/**
 * Targets of one tokenized command line; tracks `cd` across segments.
 * Twin of lazaret.scanner.core._hook_segment_targets. core kept the
 * directory as a string and normalized cwd + path again at every `cd` and
 * for every target; both now keep normpath's components (the same for a
 * path and for its normpath: see applyPath), so a `cd` applies only its
 * own, and a target is joined once per directory.
 */
function hookSegmentTargets(tokens, depth, walk) {
  const targets = [];
  let state = [false, []];
  let joined = new Map();

  const join = (path, where = null) => {                // core: normpath(join(cwd, path)) once a cd set cwd
    path = replaceChar(path, "\\", "/");
    const [isSet, comps] = where ?? state;
    if (!isSet || path.startsWith("/")) return path;
    if (where) return applyPath(comps.slice(), path).join("/") || ".";
    let out = joined.get(path);
    if (out === undefined) joined.set(path, out = applyPath(comps.slice(), path).join("/") || ".");
    return out;
  };

  const flush = (seg) => {
    const words = [];
    let skip = false;
    for (const tok of seg) {
      if (skip) { skip = false; continue; }
      if (HOOK_REDIRECTS.has(tok) || REDIRECT_RE.test(tok)) {       // a redirect and its target
        skip = !DUP_FD_RE.test(pyEnd(tok));                            // (2>&1 has none)
        if (words.length && FD_NUMBER_RE.test(words[words.length - 1])) words.pop();   // 2>/dev/null: the 2 is the redirect's
        continue;
      }
      words.push(tok);
    }
    if (!words.length) return;
    if (walk.commands >= HOOK_MAX_COMMANDS) { walk.complete = false; return; }
    walk.commands++;
    // env assignments and wrappers (with their options) in front; an index,
    // not core's old pop(0), keeps a line of a million wrappers linear
    let i = 0, where = null;
    while (i < words.length) {
      const word = words[i];
      if (ENV_ASSIGN_RE.test(word)) { i++; continue; }
      const name = word.toLowerCase();
      if (!HOOK_WRAPPERS.has(name)) break;
      i++;
      const values = WRAPPER_VALUE_OPTIONS.get(name) ?? NONE;
      while (i < words.length && words[i].startsWith("-") && (words[i] !== "-" || name === "env")) {
        const opt = words[i++];
        if (opt === "--") break;
        let key, value;
        if (opt.startsWith("--")) {
          const eq = opt.indexOf("=");
          key = eq < 0 ? opt : opt.slice(0, eq);
          if (!values.has(key)) continue;
          if (eq >= 0) value = opt.slice(eq + 1);
          else value = i < words.length ? words[i++] : (i++, "");
        } else if (values.has(opt.slice(0, 2))) {
          key = opt.slice(0, 2);
          value = opt.slice(2);
          if (!value) value = i < words.length ? words[i++] : (i++, "");
        } else continue;
        if ((WRAPPER_CHDIR_OPTIONS.get(name) ?? NONE).has(key)) {
          where = hookCd(where ?? state, value) ?? where;
        } else if ((WRAPPER_COMMAND_OPTIONS.get(name) ?? NONE).has(key)) {
          if (depth < 2) for (const t of hookTargets(value, depth + 1, walk)) targets.push(join(t, where));   // env -S "node x.js"
          return;
        }
      }
    }
    if (i >= words.length) return;
    const head = replaceChar(words[i], "\\", "/");
    const base = head.slice(head.lastIndexOf("/") + 1).toLowerCase();
    if (base === "cd" || base === "pushd") {
      let dest = "";
      for (let k = i + 1; k < words.length; k++) if (!words[k].startsWith("-")) { dest = words[k]; break; }
      const moved = hookCd(state, dest);
      if (moved !== null) { state = moved; joined = new Map(); }
      return;
    }
    let script = null, extra = [], code = null;
    if (NODE_NAMES.has(base)) {
      [script, extra, code] = nodeScript(words.slice(i + 1));
    } else if (JS_RUNTIMES.has(base)) {
      [script, extra, code] = runtimeScript(words.slice(i + 1), JS_RUNTIMES.get(base));
    } else if (SHELL_NAMES.has(base) || PYTHON_NAME_RE.test(pyEnd(base))) {
      let inline;
      [script, inline] = interpreterScript(words.slice(i + 1));
      if (inline && depth < 2 && SHELL_NAMES.has(base)) {
        for (const t of hookTargets(inline, depth + 1, walk)) targets.push(join(t, where));
      }
    } else if (head.startsWith("./") || head.startsWith("../") || (head.includes("/") && !head.startsWith("/"))
        || SCRIPT_EXT_RE.test(pyEnd(head))) {
      script = head;                                                    // executed directly (shebang)
    }
    if (script) targets.push(join(script, where));
    for (const t of extra) if (t) targets.push(join(t, where));
    if (code) for (const m of code.matchAll(LOCAL_REQUIRE_RE)) targets.push(join(m[1], where));   // node -e "require('./x')"
  };

  let seg = [];
  for (const tok of tokens) {
    if (HOOK_SEPARATORS.has(tok) || (tok && onlyOperators(tok))) {
      flush(seg);
      seg = [];
    } else {
      seg.push(tok);
    }
  }
  flush(seg);
  return targets;
}

/** twin of core._hook_targets */
function hookTargets(cmd, depth = 0, walk = { commands: 0, complete: true }) {
  const targets = [];
  const variants = [cmd];
  if (cmd.includes("\\")) variants.push(replaceChar(cmd, "\\", "/"));   // cmd.exe: backslash is a path separator
  for (const variant of variants) {
    for (const t of hookSegmentTargets(hookTokens(variant), depth, walk)) targets.push(t);   // (no spread: millions)
  }
  return targets;
}

/**
 * The code of each match of core's _NODE_E_RE in `cmd`, in finditer's
 * order: the text inside "…" or '…', or the word after `node -e`. A loop
 * with the pattern's matches (test/review-hooks.test.js compares them):
 * its `(?:\\.|[^"\\])*` overflowed V8's stack on a quoted string of
 * millions of characters.
 */
export function nodeECodes(cmd) {
  return nodeEMatches(cmd).map((m) => m[2]);
}

/** [start, end, code] of each match of core's _NODE_E_RE in `cmd` (finditer's order); see nodeECodes. */
export function nodeEMatches(cmd) {
  const found = [];
  for (let from = 0, p; (p = cmd.indexOf("node", from)) !== -1;) {
    const m = nodeEAt(cmd, p);
    if (m === null) from = p + 1;
    else { found.push([p, m[0], m[1]]); from = m[0]; }
  }
  return found;
}

/**
 * [end, code] of _NODE_E_RE's match at s[p] (s[p..] starts with "node"),
 * or null. Every run of \s is taken whole (the next part needs a
 * non-space), and a quoted string that fails to close falls back to (\S+)
 * from its quote, as the pattern's backtracking does.
 */
function nodeEAt(s, p) {
  const flag = skipPySpace(s, p + 4);
  if (flag === p + 4 || s[flag] !== "-" || s[flag + 1] !== "e") return null;
  const q = skipPySpace(s, flag + 2);
  if (q === flag + 2 || q === s.length) return null;
  const quote = s[q];
  if (quote === '"' || quote === "'") {
    for (let k = q + 1; k < s.length;) {
      const c = s[k];
      if (c === quote) return [k + 1, s.slice(q + 1, k)];
      if (c !== "\\") k++;
      else if (k + 1 < s.length && s[k + 1] !== "\n") k += 2;          // \\. (`.` is not "\n")
      else break;
    }
  }
  let e = q + 1;
  while (e < s.length && !isPySpace(s[e])) e++;
  return [e, s.slice(q, e)];
}

/**
 * [targets, complete] for an install hook command: the package-relative
 * files it runs, in order and without duplicates — `node install.js`,
 * `node ./scripts/x.mjs`, `node install` (no extension: resolve like Node),
 * `node --no-warnings x.js`, `node -r ./preload.js x.js`,
 * `cd scripts && node x.js`, `sh ./install.sh`, `./install.sh`,
 * `python setup_helper.py`, `node scripts\\x.js`,
 * `node -e "require('./postinstall')"`, `env -C sub node x.js`,
 * `sudo -u me node x.js`, `2>/dev/null node x.js` — and false for complete
 * when a limit stopped the walk (see HOOK_MAX_CHARS).
 * Twin of lazaret.scanner.core.follow_hook.
 */
export function followHook(cmd) {
  if (typeof cmd !== "string" || !pyStrip(cmd)) return [[], true];
  if (cpLongerThan(cmd, HOOK_MAX_CHARS)) return [[], false];
  const walk = { commands: 0, complete: true };
  const targets = hookTargets(cmd, 0, walk);
  for (const code of nodeECodes(cmd)) {                                 // `node -e` anywhere (`npx node -e …`), as written
    for (const m of code.matchAll(LOCAL_REQUIRE_RE)) targets.push(m[1]);
  }
  const seen = new Set();
  let out = [];
  for (const t of targets) {
    if (t && !seen.has(t) && t !== "-" && t !== ".") {
      if (cpLongerThan(t, HOOK_MAX_PATH)) { walk.complete = false; continue; }
      seen.add(t);
      out.push(t);
    }
  }
  if (out.length > HOOK_MAX_TARGETS) { out = out.slice(0, HOOK_MAX_TARGETS); walk.complete = false; }
  return [out, walk.complete];
}

/** The files an install hook runs (followHook's targets). Twin of core.hook_script_targets. */
export function hookScriptTargets(cmd) {
  return followHook(cmd)[0];
}

// ---- an install hook's command read as a program (0.1.8; core's comment above _SH_MAX_DEPTH) ----
export const SH_MAX_DEPTH = 3;
const SH_HTTP = new Set(["curl", "wget", "wget2"]);
const SH_RAW = new Set(["nc", "ncat", "netcat", "socat", "telnet"]);
const SH_LOOKUP = new Set(["nslookup", "dig", "host", "ping", "ping6"]);
const SH_SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh", "ash"]);
const SH_EVAL = new Set(["eval"]);
const SH_CMD = new Set(["cmd"]);
const SH_IDENTITY = new Set(["whoami", "id", "hostname", "logname", "users", "groups", "who", "w"]);
const SH_ENVIRONMENT = new Set(["printenv", "set", "export", "declare"]);
const SH_FILE_READERS = new Set(["cat", "head", "tail", "base64", "xxd", "od", "strings", "gzip", "bzip2", "xz", "tar",
  "zip", "type", "more", "less", "tac", "nl", "cut"]);
const SH_LISTINGS = new Set(["ls", "dir", "find", "tree", "du", "pwd", "ps", "ifconfig", "ipconfig", "ip", "netstat",
  "ss", "arp", "route", "systeminfo", "uptime", "df", "mount", "lsblk", "lscpu", "last"]);
const SH_FILTERS = new Set(["base64", "gzip", "bzip2", "xz", "xxd", "od", "tr", "sed", "awk", "cut", "sort", "uniq",
  "head", "tail", "grep", "jq", "openssl", "rev", "fold", "tee", "cat", "tac", "nl", "strings"]);
const SH_SCRIPTED_FILTERS = new Set(["sed", "awk", "grep", "jq"]);
const SH_ECHO = new Set(["echo", "printf"]);
const SH_XARGS_SHORT_VALUE = new Set("IndLPsa");
const SH_XARGS_LONG_VALUE = new Set(["--max-args", "--max-lines", "--delimiter", "--max-procs", "--max-chars",
  "--arg-file", "--eof", "--process-slot-var"]);
const SH_NOOPS = new Set(["true", ":", "false", "exit", "echo", "printf", "return"]);
const SH_KEYWORDS = new Set(["if", "then", "else", "elif", "while", "until", "do", "!", "{"]);
const SH_STATUS_KEYWORDS = new Set(["if", "elif", "while", "until", "!"]);
const SH_CURL_SHORT_VALUE = new Set("AbcCdDeEFHKmoPQrtTuUwxXyYz");
const SH_CURL_LONG_VALUE = new Set([
  "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--json", "--form", "--form-string",
  "--header", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--output", "--output-dir", "--upload-file",
  "--url", "--url-query", "--request", "--user", "--proxy", "--proxy-user", "--proxy-header", "--write-out",
  "--max-time", "--connect-timeout", "--retry", "--retry-delay", "--retry-max-time", "--config", "--cacert",
  "--capath", "--cert", "--cert-type", "--key", "--key-type", "--dump-header", "--range", "--continue-at",
  "--resolve", "--connect-to", "--interface", "--limit-rate", "--max-filesize", "--max-redirs", "--oauth2-bearer",
  "--proto", "--proto-redir", "--time-cond", "--trace", "--trace-ascii", "--stderr", "--unix-socket",
  "--dns-servers", "--doh-url", "--variable", "--ciphers", "--local-port", "--speed-limit", "--speed-time",
  "--mail-from", "--mail-rcpt", "--quote", "--telnet-option", "--socks4", "--socks4a", "--socks5",
  "--socks5-hostname", "--noproxy", "--pinnedpubkey", "--netrc-file", "--etag-save", "--etag-compare",
  "--alt-svc", "--hsts", "--aws-sigv4"]);
const SH_CURL_DATA = new Set(["-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode",
  "--json", "-F", "--form", "--form-string", "--url-query"]);
const SH_CURL_META = new Set(["-H", "--header", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-u",
  "--user", "--oauth2-bearer", "--proxy-header"]);
const SH_CURL_UPLOAD = new Set(["-T", "--upload-file"]);
const SH_CURL_OUTPUT = new Set(["-o", "--output"]);
const SH_CURL_REMOTE_NAME = new Set(["-O", "--remote-name", "--remote-name-all"]);
const SH_WGET_SHORT_VALUE = new Set("OoaPUtTweiBlADXIQ");
const SH_WGET_LONG_VALUE = new Set([
  "--output-document", "--output-file", "--append-output", "--directory-prefix", "--user-agent", "--header",
  "--post-data", "--post-file", "--body-data", "--body-file", "--method", "--tries", "--timeout", "--wait",
  "--user", "--password", "--http-user", "--http-password", "--referer", "--input-file", "--load-cookies",
  "--save-cookies", "--execute", "--limit-rate", "--ca-certificate", "--certificate", "--private-key",
  "--bind-address", "--dns-timeout", "--connect-timeout", "--read-timeout", "--level", "--accept", "--reject",
  "--domains", "--quota", "--restrict-file-names", "--progress", "--backups", "--config", "--default-page",
  "--local-encoding", "--remote-encoding", "--base", "--waitretry", "--exclude-directories",
  "--include-directories", "--ca-directory", "--certificate-type", "--private-key-type", "--secure-protocol",
  "--proxy-user", "--proxy-password", "--ftp-user", "--ftp-password"]);
const SH_WGET_DATA = new Set(["--post-data", "--body-data"]);
const SH_WGET_META = new Set(["--header", "-U", "--user-agent", "--referer", "--user", "--http-user", "--password",
  "--http-password"]);
const SH_WGET_UPLOAD = new Set(["--post-file", "--body-file"]);
const SH_WGET_OUTPUT = new Set(["-O", "--output-document"]);
const SH_NULL = new Set(["/dev/null", "nul", "$null"]);
const SH_ENV_REF_SRC = String.raw`\$env:([A-Za-z_][A-Za-z0-9_]*)|\$\{?([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%`;
const SH_IDENTITY_VAR_SRC = String.raw`(?:USER|USERNAME|LOGNAME|HOSTNAME|COMPUTERNAME|USERDOMAIN)\Z`;
const SH_PATH_VAR_SRC = String.raw`(?:HOME|USERPROFILE|PWD|INIT_CWD)\Z`;
const SH_SECRET_VAR_SRC = String.raw`TOKEN|SECRET|PASSW|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL|AUTH`;
const SH_URL_SRC = String.raw`[A-Za-z][A-Za-z0-9+.-]*://[^\s/?#]|[^\s/'"]*\.[A-Za-z]{2,}(?::[0-9]+)?(?:[/?#]|\Z)`
  + String.raw`|[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?::[0-9]+)?(?:[/?#]|\Z)`;
const SH_HOST_SRC = String.raw`(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^\s/?#@]*@)?(\[[^\]\s]*\]|[^\s/?#:]*)`;
const SH_FLAG_A_OR_N_SRC = String.raw`-[A-Za-z]*[an][A-Za-z]*\Z`;
const SH_ENV_REF_G = pyRe(SH_ENV_REF_SRC, "gi");
const SH_IDENTITY_VAR_Y = pyRe(SH_IDENTITY_VAR_SRC, "iy");
const SH_PATH_VAR_Y = pyRe(SH_PATH_VAR_SRC, "iy");
const SH_SECRET_VAR_RE = pyRe(SH_SECRET_VAR_SRC, "i");
const SH_URL_Y = pyRe(SH_URL_SRC, "y");
const SH_HOST_Y = pyRe(SH_HOST_SRC, "y");
const SH_FLAG_A_OR_N_Y = pyRe(SH_FLAG_A_OR_N_SRC, "y");
/** re.match of a sticky pattern: at the start of s only. */
const atStart = (rx, s) => { rx.lastIndex = 0; return rx.exec(s); };
const SH_BEACON_REASON = "tells a server it was installed (a request whose answer it throws away)";
const SH_DATA_REASONS = {
  identity: "sends the machine's user or host name over the network",
  "lookup-identity": "sends the machine's user or host name in a DNS lookup of a name it builds",
  environment: "sends environment variables over the network",
  file: "uploads a local file over the network",
  report: "sends what local commands report about the machine over the network",
  credentials: "sends what the cloud's instance metadata service gives it (the machine's credentials) over the network",
  address: "sends the machine's public IP address over the network",
};
// commands that assign a shell variable given as their argument (`export T=$(…)`; core._SH_DECLARE)
const SH_DECLARE = new Set(["export", "declare", "local", "readonly", "typeset"]);
const SH_VAR_NAME_SRC = String.raw`[A-Za-z_][A-Za-z0-9_]*\Z`;
const SH_VAR_NAME_Y = pyRe(SH_VAR_NAME_SRC, "y");
const SH_REDIRECT_OPS = ["<<<", "<<-", ">>", ">&", ">|", "<<", "<&", "<>", ">", "<"];

/** core._sh_subst_end */
function shSubstEnd(text, i) {
  let depth = 0, quote = null;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (quote !== null) {
      if (ch === "\\" && quote === '"') { i += 2; continue; }
      if (ch === quote) quote = null;
    } else if (ch === "\\") { i += 2; continue; }
    else if (ch === "'" || ch === '"') quote = ch;
    else if (ch === "(") depth++;
    else if (ch === ")") {
      if (depth === 0) return i;
      depth--;
    }
    i++;
  }
  return n;
}

/** core._sh_tick_end */
function shTickEnd(text, i) {
  const n = text.length;
  while (i < n) {
    if (text[i] === "\\") { i += 2; continue; }
    if (text[i] === "`") return i;
    i++;
  }
  return n;
}

/** core._sh_parse: the simple commands of a shell text, in order (exported for the parity tests). */
export function shParse(text) {
  const out = [];
  let words = [], subs = [], redirs = [];
  const state = { cur: null, curSubs: [], redir: null, pipeIn: false };
  const endWord = () => {
    if (state.cur === null) return;
    if (state.redir !== null) { redirs.push([state.redir, state.cur]); state.redir = null; }
    else { words.push(state.cur); subs.push(state.curSubs); }
    state.cur = null;
    state.curSubs = [];
  };
  const endCommand = (after) => {
    endWord();
    state.redir = null;
    if (words.length || redirs.length) {
      out.push({ words, subs, redirs, pipeIn: state.pipeIn, pipeOut: after === "|", after });
      state.pipeIn = after === "|";
    } else state.pipeIn = false;
    words = []; subs = []; redirs = [];
  };
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === " " || ch === "\t" || ch === "\r") { endWord(); i++; }
    else if (ch === "\n" || ch === ";" || ch === "(" || ch === ")") { endCommand(""); i++; }
    else if (ch === "&") {
      if (text.startsWith("&&", i)) { endCommand("&&"); i += 2; }
      else if (text.startsWith("&>", i)) {
        endWord();
        state.redir = text.startsWith("&>>", i) ? "&>>" : "&>";
        i += state.redir.length;
      } else { endCommand(""); i++; }
    } else if (ch === "|") {
      if (text.startsWith("||", i)) { endCommand("||"); i += 2; }
      else { endCommand("|"); i += text.startsWith("|&", i) ? 2 : 1; }
    } else if (ch === "<" || ch === ">") {
      if (state.cur !== null && /^[0-9]+$/.test(state.cur) && !state.curSubs.length) {
        state.cur = null;                                          // 2>/dev/null: the fd number is the redirect's
        state.curSubs = [];
      } else endWord();
      const op = SH_REDIRECT_OPS.find((o) => text.startsWith(o, i));
      state.redir = op;
      i += op.length;
    } else {
      if (state.cur === null) state.cur = "";
      i = shWordPart(text, i, state);
    }
  }
  endCommand("");
  return out;
}

/** core._sh_word_part */
function shWordPart(text, i, state) {
  const n = text.length, ch = text[i];
  if (ch === "\\") {
    if (i + 1 < n && text[i + 1] !== "\n") state.cur += shQuiet(text[i + 1]);
    return i + 2;
  }
  if (ch === "'") {
    let j = text.indexOf("'", i + 1);
    if (j < 0) j = n;
    state.cur += text.slice(i + 1, j).replaceAll("$", "\x00").replaceAll("`", "\x01");
    return j + 1;
  }
  if (ch === '"') {
    i++;
    while (i < n && text[i] !== '"') {
      const c2 = text[i];
      if (c2 === "\\" && i + 1 < n && '$`"\\\n'.includes(text[i + 1])) {
        const nxt = text[i + 1];
        state.cur += nxt === "\n" ? "" : shQuiet(nxt);
        i += 2;
      } else if ((c2 === "$" && text.startsWith("$(", i)) || c2 === "`") i = shSubstitution(text, i, state);
      else { state.cur += c2; i++; }
    }
    return i + 1;
  }
  if ((ch === "$" && text.startsWith("$(", i)) || ch === "`") return shSubstitution(text, i, state);
  state.cur += ch;
  return i + 1;
}

/** core._sh_quiet: a character where it expands nothing ($ is \x00, a backtick \x01). */
const shQuiet = (ch) => (ch === "$" ? "\x00" : ch === "`" ? "\x01" : ch);
/** core._sh_literal: a word as the text it is (what a program that reads it again gets). */
const shLiteral = (word) => word.replaceAll("\x00", "$").replaceAll("\x01", "`");

/** core._sh_substitution */
function shSubstitution(text, i, state) {
  let j;
  if (text[i] === "`") {
    j = shTickEnd(text, i + 1);
    state.curSubs.push(text.slice(i + 1, j));
  } else {
    j = shSubstEnd(text, i + 2);
    state.curSubs.push(text.slice(i + 2, j));
  }
  state.cur += text.slice(i, j + 1);
  return j + 1;
}

/** core._sh_name */
function shName(word) {
  const slashed = replaceChar(word, "\\", "/");
  const name = slashed.slice(slashed.lastIndexOf("/") + 1).toLowerCase();
  return name.endsWith(".exe") && name.length > 4 ? name.slice(0, -4) : name;
}

/** core._sh_xargs_command */
function shXargsCommand(args) {
  let k = 0;
  while (k < args.length) {
    const a = args[k];
    if (a === "--") return k + 1 < args.length ? k + 1 : null;
    if (!a.startsWith("-") || a === "-") return k;
    if (a.startsWith("--")) { k += SH_XARGS_LONG_VALUE.has(a) ? 2 : 1; continue; }
    k += SH_XARGS_SHORT_VALUE.has(a.slice(1, 2)) && a.length === 2 ? 2 : 1;
  }
  return null;
}

/** core._sh_program: [index of the program word or null, its name, a keyword in front uses its exit status]. */
function shProgram(cmd) {
  const words = cmd.words;
  let i = 0, status = false, last = null;
  while (i < words.length) {
    const word = words[i];
    if (ENV_ASSIGN_RE.test(word)) { i++; continue; }
    if (SH_KEYWORDS.has(word)) { status = status || SH_STATUS_KEYWORDS.has(word); i++; continue; }
    const name = shName(word);
    if (!HOOK_WRAPPERS.has(name)) return [i, name, status];
    last = [i, name];
    i++;
    const values = WRAPPER_VALUE_OPTIONS.get(name) ?? NONE;
    while (i < words.length && words[i].startsWith("-") && (words[i] !== "-" || name === "env")) {
      const opt = words[i++];
      if (opt === "--") break;
      if (opt.startsWith("--")) {
        const eq = opt.indexOf("=");
        if (values.has(eq < 0 ? opt : opt.slice(0, eq)) && eq < 0) i++;
      } else if (values.has(opt.slice(0, 2)) && opt.length === 2) i++;
    }
  }
  if (last !== null) return [last[0], last[1], status];
  return [null, "", status];
}

/** core._sh_options: [[[option, value or null, index]], [[positional, index]]]. */
function shOptions(args, shortValue, longValue) {
  const opts = [], pos = [];
  let k = 0;
  while (k < args.length) {
    const a = args[k];
    if (a === "--") {
      for (let j = k + 1; j < args.length; j++) pos.push([args[j], j]);
      break;
    }
    if (a.startsWith("--") && a.length > 2) {
      const eq = a.indexOf("=");
      const name = eq < 0 ? a : a.slice(0, eq);
      if (longValue.has(name) && eq < 0) {
        opts.push([name, k + 1 < args.length ? args[k + 1] : "", k + 1]);
        k += 2;
        continue;
      }
      opts.push([name, eq >= 0 ? a.slice(eq + 1) : null, k]);
    } else if (a.startsWith("-") && a.length > 1) {
      for (let j = 1; j < a.length; j++) {
        const letter = a[j];
        if (shortValue.has(letter)) {
          if (j + 1 < a.length) opts.push(["-" + letter, a.slice(j + 1), k]);
          else { opts.push(["-" + letter, k + 1 < args.length ? args[k + 1] : "", k + 1]); k++; }
          break;
        }
        opts.push(["-" + letter, null, k]);
      }
    } else pos.push([a, k]);
    k++;
  }
  return [opts, pos];
}

/** core._sh_code: the command line a program hands a shell to read again, as its text, else null. */
function shCode(name, args) {
  let code;
  if (SH_SHELLS.has(name)) code = shCCode(args);
  else if (SH_EVAL.has(name)) code = args.join(" ");
  else if (SH_CMD.has(name) && args.length && (args[0].toLowerCase() === "/c" || args[0].toLowerCase() === "/k")) code = args.slice(1).join(" ");
  else return null;
  return code === null ? null : shLiteral(code);
}

/** core._sh_c_code */
function shCCode(args) {
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (a.startsWith("-") && !a.startsWith("--") && a.slice(1).includes("c")) return k + 1 < args.length ? args[k + 1] : "";
    if (!a.startsWith("-")) return null;
  }
  return null;
}

/** core._sh_word_data: [[kind, what]] the local data a word of a request sends (`shvars`: the shell variables
 * the text assigned local data). */
function shWordData(word, subs, depth, download, shvars = null) {
  const out = [];
  for (const sub of subs) {
    for (const [kind, what] of shOutputData(sub, depth + 1)) if (!download || kind === "identity") out.push([kind, what]);
  }
  for (const m of word.matchAll(SH_ENV_REF_G)) {
    const name = m[1] || m[2] || m[3];
    if (shvars && shvars.has(name)) {
      for (const [kind, what] of shvars.get(name)) if (!download || kind === "identity") out.push([kind, what]);
    } else if (atStart(SH_IDENTITY_VAR_Y, name)) out.push(["identity", "$" + name]);
    else if (download) continue;
    else if (atStart(SH_PATH_VAR_Y, name)) out.push(["report", "$" + name]);
    else if (SH_SECRET_VAR_RE.test(name)) out.push(["environment", "$" + name]);
  }
  return out;
}

/** core._sh_output_data: what each pipeline of a shell text prints. */
function shOutputData(text, depth, shvars = null) {
  if (depth > SH_MAX_DEPTH) return [];
  const cmds = shParse(text);
  const out = [];
  for (let k = 0; k < cmds.length; k++) if (!cmds[k].pipeOut) out.push(...shPipedData(cmds, k + 1, depth, shvars));
  return out;
}

/** core._sh_piped_data */
function shPipedData(cmds, at, depth, shvars = null) {
  for (let k = at - 1; k >= 0; k--) {
    const cmd = cmds[k];
    if (k < at - 1 && !cmd.pipeOut) return [];
    const found = shCommandData(cmd, depth, shvars);
    if (found !== null) return found;
    if (!cmd.pipeIn) return [];
  }
  return [];
}

/** core._sh_command_data: [[kind, what]], or null for a filter of what is piped into it. */
function shCommandData(cmd, depth, shvars = null) {
  const [p, name] = shProgram(cmd);
  if (p === null) return [];
  const args = cmd.words.slice(p + 1);
  const positional = args.filter((a) => a && a[0] !== "-");
  if (name === "uname") {
    return args.some((a) => a === "--all" || a === "--nodename" || atStart(SH_FLAG_A_OR_N_Y, a)) ? [["identity", "uname"]] : [];
  }
  if (SH_IDENTITY.has(name)) return [["identity", name]];
  if (name === "env" || name === "printenv" || (SH_ENVIRONMENT.has(name) && !positional.length)) return [["environment", LD_WHOLE_ENV]];
  for (const [op, target] of cmd.redirs) if (op === "<" || op === "<>") return [["file", target]];
  if (SH_FILE_READERS.has(name) || SH_FILTERS.has(name)) {
    const files = SH_SCRIPTED_FILTERS.has(name) ? positional.slice(1) : name === "tr" || name === "openssl" ? [] : positional;
    if (files.length) return [["file", files[files.length - 1]]];
    return SH_FILTERS.has(name) ? null : [];
  }
  if (SH_LISTINGS.has(name)) return [["report", name]];
  if (SH_ECHO.has(name)) {
    const out = [];
    for (let k = p + 1; k < cmd.words.length; k++) out.push(...shWordData(cmd.words[k], cmd.subs[k], depth, false, shvars));
    return out;
  }
  if (SH_HTTP.has(name)) {                                            // what the cloud gives the machine; its public IP address
    if (args.some((a) => LD_METADATA_RE.test(a))) return [["credentials", "the instance's metadata"]];
    if (args.some((a) => LD_PUBLIC_IP_RE.test(a))) return [["address", "the machine's public IP address"]];
  }
  return [];
}

/** core._sh_assignments: records in `shvars` the local data the shell variables a command assigns hold. */
function shAssignments(cmd, depth, shvars) {
  const words = cmd.words;
  let k = 0;
  while (k < words.length && ENV_ASSIGN_RE.test(words[k])) k++;
  const at = [...Array(k).keys()];
  if (k < words.length && SH_DECLARE.has(shName(words[k]))) {
    for (let j = k + 1; j < words.length; j++) if (ENV_ASSIGN_RE.test(words[j])) at.push(j);
  }
  for (const j of at) {
    const eq = words[j].indexOf("=");
    const name = words[j].slice(0, eq), value = words[j].slice(eq + 1);
    const data = [];
    for (const sub of cmd.subs[j]) data.push(...shOutputData(sub, depth + 1, shvars));
    data.push(...shWordData(value, [], depth, false, shvars));
    if (data.length) shvars.set(name, data);
    else shvars.delete(name);
  }
}

/** core._sh_remote */
function shRemote(address) {
  let host = pyStripChars(atStart(SH_HOST_Y, address)[1], "[]").toLowerCase();
  while (host.endsWith(".")) host = host.slice(0, -1);
  if (host === "" || host === "localhost" || host === "0.0.0.0" || host === "::1" || host.startsWith("127.")) return false;
  return !DNS_LOCAL_TLDS.has(host.slice(host.lastIndexOf(".") + 1));
}

/** core._sh_request: [sent, uploads, stdin, disposition, addresses] of a curl or wget command. */
function shRequest(name, args) {
  const curl = name === "curl";
  const [opts, pos] = shOptions(args, curl ? SH_CURL_SHORT_VALUE : SH_WGET_SHORT_VALUE, curl ? SH_CURL_LONG_VALUE : SH_WGET_LONG_VALUE);
  const sent = [], uploads = [];
  let stdin = false, disposition = curl ? "stdout" : "file", writesOut = false;
  const addresses = pos.filter(([a]) => atStart(SH_URL_Y, a));
  for (const [opt, value, k] of opts) {
    if (value === null) {
      if (curl && SH_CURL_REMOTE_NAME.has(opt)) disposition = "file";
      else if (!curl && opt === "--spider") disposition = "discard";
      continue;
    }
    if (curl && opt === "--url") {
      if (atStart(SH_URL_Y, value)) addresses.push([value, k]);
    } else if (curl && SH_CURL_DATA.has(opt)) {
      const body = (opt === "-F" || opt === "--form") && value.includes("=") ? value.slice(value.indexOf("=") + 1) : value;
      const at = body.indexOf("@");                                    // --data-urlencode name@file
      const named = opt === "--data-urlencode" && at >= 0 && !body.slice(0, at).includes("=");
      if (named || ((body.startsWith("@") || body.startsWith("<")) && opt !== "--form-string" && opt !== "--data-raw"
          && opt !== "--url-query")) {
        const path = (named ? body.slice(at + 1) : body.slice(1)).split(";")[0];
        if (path === "-" || path === "") stdin = true;
        else uploads.push(path);
      } else sent.push([k, "data"]);
    } else if (!curl && SH_WGET_DATA.has(opt)) sent.push([k, "data"]);
    else if ((curl && SH_CURL_META.has(opt)) || (!curl && SH_WGET_META.has(opt))) sent.push([k, "meta"]);
    else if ((curl && SH_CURL_UPLOAD.has(opt)) || (!curl && SH_WGET_UPLOAD.has(opt))) {
      if (value === "-" || value === ".") stdin = true;
      else uploads.push(value);
    } else if ((curl && SH_CURL_OUTPUT.has(opt)) || (!curl && SH_WGET_OUTPUT.has(opt))) {
      disposition = SH_NULL.has(value.toLowerCase()) ? "discard" : value === "-" ? "stdout" : "file";
    } else if (curl && (opt === "-w" || opt === "--write-out")) writesOut = true;
  }
  if (disposition === "discard" && writesOut) disposition = "stdout";   // what -w writes (the status code …) is the output
  return [sent, uploads, stdin, disposition, addresses];
}

/** core._sh_kept */
function shKept(cmd, inSubst) {
  for (const [op, target] of cmd.redirs) {
    if (op === ">" || op === ">>" || op === ">|" || op === "&>" || op === "&>>") return !SH_NULL.has(target.toLowerCase());
  }
  return cmd.pipeOut || inSubst;
}

/** core._sh_status_used */
function shStatusUsed(cmds, k, status) {
  if (status) return true;
  const cmd = cmds[k];
  if ((cmd.after !== "&&" && cmd.after !== "||") || k + 1 >= cmds.length) return false;
  return !SH_NOOPS.has(shProgram(cmds[k + 1])[1]);
}

const pushNew = (list, items) => { for (const r of items) if (!list.includes(r)) list.push(r); };

/** core._sh_reasons: the reasons a shell text's network commands give. */
function shReasons(text, depth, inSubst, walk) {
  const reasons = [];
  if (depth > SH_MAX_DEPTH || !text) return reasons;
  const cmds = shParse(text);
  const shvars = new Map();                                           // the shell variables the text assigns local data
  for (let k = 0; k < cmds.length; k++) {
    const cmd = cmds[k];
    if (walk.commands >= HOOK_MAX_COMMANDS) { walk.complete = false; break; }
    walk.commands++;
    for (const wordSubs of cmd.subs) for (const sub of wordSubs) pushNew(reasons, shReasons(sub, depth + 1, true, walk));
    shAssignments(cmd, depth, shvars);
    const [p, name0, status] = shProgram(cmd);
    if (p === null) continue;
    let name = name0;
    let args = cmd.words.slice(p + 1), argSubs = cmd.subs.slice(p + 1);
    if (name === "read") {                                            // `… | while read V`: V holds what is piped in
      const data = cmd.pipeIn ? shPipedData(cmds, k, depth, shvars) : [];
      for (const a of args) {
        if (atStart(SH_VAR_NAME_Y, a)) {
          if (data.length) shvars.set(a, data);
          else shvars.delete(a);
        }
      }
      continue;
    }
    const code = shCode(name, args);
    if (code !== null) {
      pushNew(reasons, shReasons(code, depth + 1, inSubst || shKept(cmd, inSubst), walk));
      continue;
    }
    let piped = [];                                                   // what xargs hands the command as arguments
    if (name === "xargs") {
      const inner = shXargsCommand(args);
      if (inner === null) continue;
      if (cmd.pipeIn) piped = shPipedData(cmds, k, depth, shvars);
      name = shName(cmd.words[p + 1 + inner]);
      args = args.slice(inner + 1);
      argSubs = argSubs.slice(inner + 1);
    }
    const data = [];
    let beacon = false;
    if (SH_HTTP.has(name)) {
      const [sent, uploads, stdin, disposition, addresses] = shRequest(name, args);
      if (!addresses.length) continue;
      const kept = disposition === "file" || (disposition === "stdout" && shKept(cmd, inSubst));
      for (const [idx, what] of sent) {                   // (an option given no value sends nothing)
        if (idx < args.length) data.push(...shWordData(args[idx], argSubs[idx], depth, kept && what === "meta", shvars));
      }
      for (const [address, idx] of addresses) data.push(...shWordData(address, argSubs[idx], depth, kept, shvars));
      for (const path of uploads) data.push(["file", path]);
      if (stdin && cmd.pipeIn && !piped.length) data.push(...shPipedData(cmds, k, depth, shvars));
      for (const [kind, what] of piped) if (!kept || kind === "identity") data.push([kind, what]);
      beacon = !kept && !shStatusUsed(cmds, k, status) && addresses.some(([address]) => shRemote(address));
    } else if (SH_RAW.has(name)) {
      if (cmd.pipeIn) data.push(...(piped.length ? piped : shPipedData(cmds, k, depth, shvars)));
      for (const [op, target] of cmd.redirs) if (op === "<" || op === "<>") data.push(["file", target]);
      const hosts = [];
      for (let j = 0; j < args.length; j++) if (args[j] && args[j][0] !== "-" && atStart(SH_URL_Y, args[j])) hosts.push([args[j], argSubs[j]]);
      for (const [word, subs] of hosts) data.push(...shWordData(word, subs, depth, false, shvars));
      beacon = !shStatusUsed(cmds, k, status) && !shKept(cmd, inSubst) && hosts.some(([a]) => shRemote(a));
    } else if (SH_LOOKUP.has(name)) {
      for (const [kind, what] of piped) data.push([kind === "identity" ? "lookup-identity" : kind, what]);
      const names = [];
      for (let j = 0; j < args.length; j++) if (args[j] && args[j][0] !== "-" && atStart(SH_URL_Y, args[j])) names.push([args[j], argSubs[j]]);
      for (const [word, subs] of names) {
        for (const [kind, what] of shWordData(word, subs, depth, false, shvars)) data.push([kind === "identity" ? "lookup-identity" : kind, what]);
      }
      beacon = !shStatusUsed(cmds, k, status) && !shKept(cmd, inSubst) && names.some(([a]) => shRemote(a));
    } else continue;
    for (const [kind, what] of data) {
      let reason = SH_DATA_REASONS[kind];
      if (kind === "file" || kind === "report" || kind === "environment") reason += " (" + cpPrefix(shLiteral(what), 40) + ")";
      if (!reasons.includes(reason)) reasons.push(reason);
    }
    if (beacon && !data.length && !reasons.includes(SH_BEACON_REASON)) reasons.push(SH_BEACON_REASON);
  }
  return reasons;
}

/** core._hook_inline_code: the code a shell text hands node or python inline (exported for the parity tests). */
export function hookInlineCode(text, walk = { commands: 0, complete: true }, depth = 0) {
  const out = [];
  if (depth > SH_MAX_DEPTH) return out;
  for (const cmd of shParse(text)) {
    if (walk.commands >= HOOK_MAX_COMMANDS) { walk.complete = false; break; }
    walk.commands++;
    const [p, name] = shProgram(cmd);
    if (p === null) continue;
    const args = cmd.words.slice(p + 1);
    if (NODE_NAMES.has(name) || JS_RUNTIMES.has(name)) {
      const code = nodeScript(args)[2];
      if (code) out.push(shLiteral(code));
    } else if (PYTHON_NAME_RE.test(pyEnd(name))) {
      const code = interpreterScript(args)[1];
      if (code) out.push(shLiteral(code));
    } else {
      const code = shCode(name, args);
      if (code) out.push(...hookInlineCode(code, walk, depth + 1));
    }
  }
  return out;
}

/**
 * Reasons an install hook's command looks hostile ([] if none), read as a program: the install-script test's
 * reasons for the command and for the code it hands an interpreter inline, then what its network commands do.
 * `outputKept`: what the command prints is used (a binding.gyp command expansion's value).
 * Twin of core.hook_command_risk.
 */
export function hookCommandRisk(cmd, outputKept = false) {
  if (typeof cmd !== "string" || !pyStrip(cmd) || cpLongerThan(cmd, HOOK_MAX_CHARS)) return [];
  const reasons = installScriptRisk(cmd, false, true);
  const walk = { commands: 0, complete: true };
  for (const code of hookInlineCode(cmd, walk)) pushNew(reasons, installScriptRisk(code, false));
  pushNew(reasons, shReasons(cmd, 0, outputKept, walk));
  labelSends(cmd, reasons);
  return reasons;
}

// ---- Install-script and import-time inspection ------------------------------
// (core's comments explain what each pattern is for; the text is core's.)
const NETWORK_SRC =
  String.raw`\b(?:https?\.(?:get|request)|fetch\s*\(|axios|XMLHttpRequest|net\.connect|dns\.resolve|` +
  String.raw`require\(\s*["'](?:node:)?(?:https?|net|dgram|tls)["']\s*\)|` +
  String.raw`from\s+["'](?:node:)?(?:https?|net|dgram|tls)["'])` +
  // Python
  String.raw`|\burllib\.request\b|\burlopen\s*\(|\burlretrieve\s*\(|\bhttp\.client\b|` +
  String.raw`\bHTTPS?Connection\s*\(|\bsocket\.(?:socket|create_connection)\s*\(|` +
  String.raw`\brequests\.(?:get|post|put|patch|request|Session)\b|\bimport\s+(?:requests|httpx|aiohttp|urllib3)\b|` +
  String.raw`\bfrom\s+(?:requests|httpx|aiohttp|urllib3|urllib\.request|http\.client)\s+import\b|` +
  String.raw`\bhttpx\.\w+\s*\(|\baiohttp\.ClientSession\b|\bsmtplib\b|\bftplib\b` +
  // shell: a download tool pointed at a URL (at most 24 options, each read
  // one way only: linear time), netcat to a host and port, bash's /dev/tcp
  String.raw`|\b(?:curl|wget)\s+(?:-{1,2}\w[\w-]*(?:=\S*|\s+(?!-{1,2}\w)(?!["']?https?:)\S+)?\s+){0,24}` +
  String.raw`["']?https?://` +
  String.raw`|\b(?:nc|ncat|netcat)\s+(?:-\w+\s+){0,8}[\w.-]+\s+\d{2,5}\b|/dev/tcp/`;
// (re.M changes nothing here: the pattern has no ^ or $)
const NETWORK_RE = pyRe(NETWORK_SRC, "m");
// RequestBin by its host names only (0.1.8; core's comment above _EXFIL_SERVICES)
const EXFIL_SERVICES_SRC =
  String.raw`pastebin\.com|\bngrok|webhook\.site|` +
  String.raw`discord(?:app)?\.com/api/webhooks|api\.telegram\.org|oastify\.com|burpcollaborator|` +
  String.raw`\binteract\.sh|\boast\.(?:pro|live|site|online|fun|me)\b|requestbin\.(?:com|net|io)\b|\brequestb\.in\b|` +
  String.raw`pipedream\.net|transfer\.sh|\.onion\b`;
const EXFIL_SERVICE_RE = pyRe(EXFIL_SERVICES_SRC, "i");              // the named ones, no raw IPs
/** The first n code points of s (Python's s[:n]). */
export function cpPrefix(s, n) {
  let i = 0;
  for (let k = 0; k < n && i < s.length; k++) {
    const c = s.charCodeAt(i);
    i += c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
  }
  return s.slice(0, i);
}

// the reason each received-code category adds (twin of core._DL_CATEGORY_REASON)
export const DL_CATEGORY_REASON = {
  run: "runs code it receives over the network",
  deserialize: "deserializes data it receives over the network",
  import: "loads a module named by data it receives over the network",
};

// ---- PowerShell, stagers, reverse shells, host information --------------------
// Twins of core's powershell_risk, string_stager, reverse_shell and
// sends_host_info (see core's section comment): the install-script blind
// spots of the audit's PyPI benchmark. Patterns are core's, Python semantics.
const PS_SRC = String.raw`\b(?:powershell|pwsh)(?:\.exe)?\b`;
const PS_RE = pyRe(PS_SRC, "i");
const PS_ALL_RE = pyRe(PS_SRC, "gi");
const PS_ENCODED_SRC = String.raw`\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,400}?[\s\"',\[(][-/\u2013\u2014]`
  + String.raw`(?:encodedcommand|encodedcomman|encodedcomma|encodedcomm|encodedcom|encodedco|encodedc|encoded|encode`
  + String.raw`|encod|enco|enc|en|ec|e)[\s\"',]+([A-Za-z0-9+/]{16}[A-Za-z0-9+/]*={0,2})`;
const PS_ENCODED_RE = pyRe(PS_ENCODED_SRC, "gi");
const PS_ENCODED_MAX = 65536;
const PS_CRADLE_SRC = String.raw`\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|curl|wget)\b[^\n|;]{0,400}\|\s*(?:iex|Invoke-Expression)\b`
  + String.raw`|\b(?:iex|Invoke-Expression)\b[\s(]{0,8}(?:New-Object\s+(?:System\.)?Net\.WebClient\s*\)\s*\.\s*DownloadString`
  + String.raw`|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b`
  + String.raw`|\.DownloadString\s*\([^\n)]{0,400}\)\s*\|\s*(?:iex|Invoke-Expression)\b`;
const PS_CRADLE_RE = pyRe(PS_CRADLE_SRC, "i");
const PS_DOWNLOAD_FILE_SRC = String.raw`\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl(?:\.exe)?|wget|Start-BitsTransfer)\b[^\n]{0,400}?`
  + String.raw`\s-(?:OutFile|Destination|o)\b|\.DownloadFile\s*\(`;
const PS_DOWNLOAD_FILE_RE = pyRe(PS_DOWNLOAD_FILE_SRC, "i");
const PS_START_SRC = String.raw`\b(?:Start-Process|saps|Invoke-Item|Invoke-Expression|iex)\b`;
const PS_START_RE = pyRe(PS_START_SRC, "i");

function powershellScriptRisk(ps) {
  if (PS_CRADLE_RE.test(ps) || (PS_DOWNLOAD_FILE_RE.test(ps) && PS_START_RE.test(ps))) return "downloads and runs code";
  return null;
}
/** The UTF-16LE text of an -EncodedCommand argument (core._decode_powershell). */
function decodePowershell(b64) {
  b64 = b64.slice(0, PS_ENCODED_MAX);
  b64 = b64.endsWith("=") ? b64.slice(0, b64.length - (b64.length % 4)) : b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  if (b64.replace(/=+$/, "").length % 4 === 1) return "";      // what base64.b64decode(validate=True) refuses
  const data = Buffer.from(b64, "base64");
  return data.subarray(0, data.length & ~1).toString("utf16le");
}
/** Reasons PowerShell in `text` looks hostile (core.powershell_risk). */
export function powershellRisk(text) {
  if (!PS_RE.test(text)) return [];
  const reasons = [];
  PS_ENCODED_RE.lastIndex = 0;
  const m = PS_ENCODED_RE.exec(text);
  if (m) {
    const does = powershellScriptRisk(decodePowershell(m[1]));
    reasons.push("runs an encoded PowerShell command" + (does ? ` that ${does}` : ""));
  } else {
    const does = powershellScriptRisk(text);
    if (does) reasons.push(`runs PowerShell that ${does}`);
  }
  return reasons;
}

const STAGER_MIN = 24;
const STAGER_MAX_LITERALS = 2000;
const STAGER_RUN_NEEDLES = ["exec", "eval", "Function", "system", "popen", "spawn", "-c"];
const STAGER_NET_NEEDLES = ["urlopen", "requests", "urllib", "http", "fetch", "curl", "wget", "socket"];
/** [offset, contents] of the string literals of `text` (core._string_literals). */
function stringLiterals(text) {
  const out = [];
  const n = text.length;
  let i = 0;
  while (i < n && out.length < STAGER_MAX_LITERALS) {
    const ch = text[i];
    if (ch !== '"' && ch !== "'" && ch !== "`") { i++; continue; }
    if (ch !== "`" && text.startsWith(ch.repeat(3), i)) {
      const j = text.indexOf(ch.repeat(3), i + 3);
      const end = j < 0 ? n : j;
      out.push([i, text.slice(i + 3, end)]);
      i = end + 3;
      continue;
    }
    let j = i + 1;
    while (j < n && text[j] !== ch && (ch === "`" || text[j] !== "\n")) j += text[j] === "\\" ? 2 : 1;
    out.push([i, text.slice(i + 1, Math.min(j, n))]);
    i = j + 1;
  }
  return out;
}
/** The offset of a string literal holding a script that downloads and runs code, else -1 (core.stager_at). */
export function stagerAt(text) {
  if (!STAGER_NET_NEEDLES.some((nd) => text.includes(nd))) return -1;
  for (const [at, lit] of stringLiterals(text)) {
    if (cpLen(lit) >= STAGER_MIN && STAGER_RUN_NEEDLES.some((nd) => lit.includes(nd))
        && STAGER_NET_NEEDLES.some((nd) => lit.includes(nd))) {
      const found = receivedCodeKind(lit.replaceAll(";", "\n"));
      if (found !== null && found[1] === "run") return at;
    }
  }
  return -1;
}

const REVSHELL_DUP2_SRC = String.raw`\bdup2\s*\(\s*[\w.]+\.fileno\s*\(\s*\)\s*,\s*[012]\s*\)`;
const REVSHELL_SHELL_SRC = String.raw`["'](?:/bin/(?:ba|z|da|k)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?)["']|\bpty\.spawn\s*\(`;
const REVSHELL_LINE_SRC = String.raw`\b(?:ba|z|k)?sh\s+-i\b[^\n]{0,80}?[<>]&?\s*/dev/(?:tcp|udp)/`
  + String.raw`|/dev/(?:tcp|udp)/[\w.\-]+/\d+[^\n]{0,40}?0\s*>\s*&\s*1`
  + String.raw`|\b(?:nc|ncat|netcat)\b[^\n]{0,120}?\s-[ec]\s+[\"']?(?:/bin/)?(?:ba|z)?sh\b`;
const REVSHELL_JS_SPAWN_SRC = String.raw`\bspawn\s*\(\s*["'](?:/bin/(?:ba|z)?sh|cmd(?:\.exe)?)["']`;
const REVSHELL_JS_PIPE_SRC = String.raw`\.pipe\s*\(\s*[\w$.]+\.stdin\s*\)`;
const REVSHELL_JS_NET_SRC = String.raw`\bnet\s*\.\s*(?:Socket|connect|createConnection)\b|\bnew\s+Socket\s*\(`;
const REVSHELL_DUP2_RE = pyRe(REVSHELL_DUP2_SRC);
const REVSHELL_SHELL_RE = pyRe(REVSHELL_SHELL_SRC);
const REVSHELL_LINE_RE = pyRe(REVSHELL_LINE_SRC);
const REVSHELL_JS_SPAWN_RE = pyRe(REVSHELL_JS_SPAWN_SRC);
const REVSHELL_JS_PIPE_RE = pyRe(REVSHELL_JS_PIPE_SRC);
const REVSHELL_JS_NET_RE = pyRe(REVSHELL_JS_NET_SRC);
const REVSHELL_NGROK_TCP_SRC = String.raw`\b\d+\.tcp(?:\.[a-z]{2,3})?\.ngrok\.io\b`;
const REVSHELL_ARG_SHELL_SRC = String.raw`["'](?:nc|ncat|netcat|(?:/bin/)?(?:ba|z|da)?sh|cmd(?:\.exe)?|powershell(?:\.exe)?)["']`;
const REVSHELL_ARGS_SRC = String.raw`["'](?:nc|ncat|netcat)["'][^\n]{0,160}?["']-[ec]["']\s*,\s*["'](?:/bin/)?(?:ba|z|da)?sh["']`;
const REVSHELL_NGROK_TCP_RE = pyRe(REVSHELL_NGROK_TCP_SRC, "i");
const REVSHELL_ARG_SHELL_RE = pyRe(REVSHELL_ARG_SHELL_SRC);
const REVSHELL_ARGS_RE = pyRe(REVSHELL_ARGS_SRC);
const REVSHELL_ARGS_NEEDLES = ["'nc'", '"nc"', "'ncat'", '"ncat"', "'netcat'", '"netcat"'];
const REVSHELL_NGROK_NEEDLES = [".ngrok.io"];   // core: needles, which code scanners don't read as a URL check
/** The offset where `text` opens a reverse shell, else -1 (core.reverse_shell_at). */
export function reverseShellAt(text) {
  let m = REVSHELL_LINE_RE.exec(text);
  if (m) return m.index;
  if (text.includes("dup2")) {
    m = REVSHELL_DUP2_RE.exec(text);
    if (m && REVSHELL_SHELL_RE.test(text)) return m.index;
  }
  if (text.includes("pty") && text.includes("socket") && text.includes("connect") && text.includes("pty.spawn")) {
    return text.indexOf("pty.spawn");
  }
  if (text.includes("spawn")) {
    m = REVSHELL_JS_SPAWN_RE.exec(text);
    if (m && REVSHELL_JS_PIPE_RE.test(text) && REVSHELL_JS_NET_RE.test(text)) return m.index;
  }
  // an argument list, or a shell or netcat run with an ngrok TCP address (0.1.8)
  if (REVSHELL_ARGS_NEEDLES.some((nd) => text.includes(nd))) {
    m = REVSHELL_ARGS_RE.exec(text);
    if (m) return m.index;
  }
  if (REVSHELL_NGROK_NEEDLES.some((nd) => text.includes(nd))) {
    m = REVSHELL_NGROK_TCP_RE.exec(text);
    if (m && REVSHELL_ARG_SHELL_RE.test(text) && EXEC_CALL_RE.test(text)) return m.index;
  }
  return -1;
}

const HOST_INFO_SRC = String.raw`\b(?:socket\.gethostname|socket\.getfqdn|platform\.node|getpass\.getuser|os\.getlogin|pwd\.getpwuid`
  + String.raw`|os\.hostname|os\.userInfo)\s*\(`
  + String.raw`|\b(?:getoutput|check_output|getstatusoutput|execSync|popen)\s*\(\s*\[?\s*["'](?:whoami|hostname|id`
  + String.raw`|uname\s+(?:-[A-Za-z]*[an]|--(?:all|nodename))|ifconfig|ipconfig|systeminfo)\b`
  + String.raw`|(?:\$\(|` + "`" + String.raw`)\s*(?:whoami|hostname|id|uname\s+(?:-[A-Za-z]*[an]|--(?:all|nodename))|ifconfig|ip\s+a|pwd|ls`
  + String.raw`|cat\s+/etc/passwd|ps)\b`
  + String.raw`|\bos\.(?:hostname|userInfo)\s*[,)]`
  // (0.1.8) uname with -a or -n only; through the module itself or a name taken from it (core's comment)
  + String.raw`|\brequire\(\s*["'](?:node:)?os["']\s*\)\s*\.\s*(?:hostname|userInfo)\b`
  + String.raw`|\b(?:const|let|var|import)\s*\{[^{}\n]{0,200}\b(?:hostname|userInfo)\b[^{}\n]{0,200}\}\s*`
  + String.raw`(?:=\s*require\(\s*|from\s*)["'](?:node:)?os["']`
  + String.raw`|\bfrom\s+(?:socket|getpass)\s+import\s+[^\n]{0,200}\b(?:gethostname|getfqdn|getuser)\b`;
const HOST_INFO_RE = pyRe(HOST_INFO_SRC);

// Exfiltration shapes (0.1.8; core's comment above _CRED_DIR_RE): a request
// to a webhook whose secret is written in the code, a sweep of several
// credential folders, the host name sent to a base64-hidden address or in a
// DNS name the code builds, a miner, and (install time only) a raw socket to
// a hard-coded IP address.
const PUBLIC_IP_URL_SRC = String.raw`\b(?:https?|wss?|tcp)://(?!(?:10|127|0)\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!169\.254\.)`
  + String.raw`(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])`;
const CRED_DIR_SRC = String.raw`["'` + "`" + String.raw`](?:~[/\\]|\$HOME[/\\]|%USERPROFILE%[/\\])?\.(ssh|aws|azure|gnupg|docker|kube|ethereum|electrum|bitcoin`
  + String.raw`|solana|npmrc|pypirc|netrc|git-credentials|config[/\\]gcloud|password-store|vault-token|terraform\.d)`
  + String.raw`(?:[/\\][^"'` + "`" + String.raw`\n]{0,60})?["'` + "`" + "]";
const B64_URL_LITERAL_SRC = String.raw`["'` + "`" + String.raw`]aHR0c[A-Za-z0-9+/]{2,}={0,2}["'` + "`" + "]";
// The DNS beacon's name: core's comment above _DNS_CALL_RE.
const DNS_CALL_SRC = String.raw`(?:\b(?:getaddrinfo|gethostbyname(?:_ex)?)|\bdns\.(?:promises\.)?(?:resolve\w*|lookup)`
  + String.raw`|\bresolver\.(?:resolve|query))\s*\(`;
const DNS_TEMPLATE_SRC = String.raw`\A(?:f"([^"\n]{0,300})"|f'([^'\n]{0,300})'|` + "`" + String.raw`([^` + "`"
  + String.raw`\n]{0,300})` + "`)";
const DNS_BUILT_NAME_SRC = String.raw`\{[^}\n]+\}[^\n]*\.([A-Za-z]{2,})\Z`;
const DNS_SUM_SRC = String.raw`\+\s*(?:"[^"\n]*\.([A-Za-z]{2,})"|'[^'\n]*\.([A-Za-z]{2,})'|` + "`" + String.raw`[^` + "`"
  + String.raw`$\n]*\.([A-Za-z]{2,})` + "`" + String.raw`)\s*\Z`;
const DNS_FORMAT_SRC = String.raw`\A(?:"[^"\n]*(?:%(?:\([^)\n]*\))?[-#0 +]?\d*[sdirx]|\{[^}\n]*\})[^"\n]*\.([A-Za-z]{2,})"|`
  + String.raw`'[^'\n]*(?:%(?:\([^)\n]*\))?[-#0 +]?\d*[sdirx]|\{[^}\n]*\})[^'\n]*\.([A-Za-z]{2,})')`
  + String.raw`\s*(?:%|\.\s*format\s*\()`;
const DNS_LITERAL_SRC = String.raw`"[^"\n]*"|'[^'\n]*'|` + "`" + String.raw`[^` + "`" + String.raw`$\n]*` + "`";
const DNS_VALUE_SRC = String.raw`[A-Za-z_$(]`;
const DNS_NAME_SRC = String.raw`\A[A-Za-z_$][\w$]*\Z`;
const DNS_ASSIGN_HEAD = String.raw`(?<![^\n;{])[ \t]*(?:(?:const|let|var)[ \t]+)?`;     // core._DNS_ASSIGN_HEAD
const DNS_ASSIGN_TAIL = String.raw`[ \t]*=(?![=>])[ \t]*([^\n;]*)`;                      // core._DNS_ASSIGN_TAIL
const DNS_LOCAL_TLDS = new Set(["local", "localhost", "localdomain", "internal", "intranet", "lan", "home", "corp",
  "private", "test", "example", "invalid", "arpa"]);
const DNS_SHELL_ID_SRC = String.raw`\$\(\s*(?:whoami|hostname|id\s+-un|uname\s+-n)\s*\)|` + "`" + String.raw`\s*(?:whoami|hostname|id\s+-un|uname\s+-n)\s*` + "`"
  + String.raw`|\$\{?(?:USER|USERNAME|HOSTNAME|LOGNAME)\b\}?|%(?:USERNAME|COMPUTERNAME|USERDOMAIN)%`
  + String.raw`|\$env:(?:USERNAME|COMPUTERNAME|USERDOMAIN)\b`;
const DNS_SHELL_CMD_SRC = String.raw`(?<![\w.$-])(?:nslookup|dig|host|ping6?|curl|wget|Resolve-DnsName)\s`;
const DNS_CMD_SUM_SRC = String.raw`(["'` + "`" + String.raw`])(?:nslookup|dig|host|ping6?|curl|wget|Resolve-DnsName)\s[^"'` + "`"
  + String.raw`\n]{0,100}\1\s*\+([^\n;]{1,300})`;
const DNS_CMD_TEMPLATE_SRC = String.raw`["'` + "`" + String.raw`](?:nslookup|dig|host|ping6?|curl|wget|Resolve-DnsName)\s[^"'` + "`"
  + String.raw`\n]{0,200}?\{[^}\n]+\}[^\s"'` + "`" + String.raw`/:\n]*\.([A-Za-z]{2,})(?![\w.-])`;
const DNS_SHELL_CUT_SRC = String.raw`[\n|;&]`;
const DNS_SHELL_LEFT_SRC = String.raw`[^\s"'` + "`" + String.raw`(]*\Z`;
const DNS_SHELL_RIGHT_SRC = String.raw`[^\s"'` + "`" + String.raw`)]*`;
const DNS_SHELL_HOST_SRC = String.raw`\A(?:https?://)?[^\s/:"'` + "`" + String.raw`|;&<>()]*\x00[^\s/:"'` + "`"
  + String.raw`|;&<>()]*\.([A-Za-z]{2,})(?![\w.-])`;
const IP_LITERAL_SRC = String.raw`["'](?!(?:127|0|255)\.)((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))["']`;
const RAW_CONNECT_SRC = String.raw`\b(?:socket\.create_connection|net\.connect|net\.createConnection|connect(?:_ex)?)\s*\(|\bnew\s+net\.Socket\b`;
const MONERO_ADDR_SRC = String.raw`(?<![A-Za-z0-9])[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?(?![A-Za-z0-9])`;
const MINER_ARG_SRC = String.raw`["'](?:-o|--url)["']|\bstratum\+(?:tcp|ssl|tls)://|--donate-level\b|\b(?:xmrig|XMRig|XMRIG)\b`;
const MINER_ARG_NEEDLES = ["'-o'", '"-o"', "'--url'", '"--url"', "stratum+", "--donate-level", "xmrig", "XMRig", "XMRIG"];
const PUBLIC_IP_URL_RE = pyRe(PUBLIC_IP_URL_SRC);
const CRED_DIR_RE = pyRe(CRED_DIR_SRC, "g");
const B64_URL_LITERAL_RE = pyRe(B64_URL_LITERAL_SRC);
const DNS_CALL_RE = pyRe(DNS_CALL_SRC, "g");
const DNS_TEMPLATE_RE = pyRe(DNS_TEMPLATE_SRC);
const DNS_BUILT_NAME_RE = pyRe(DNS_BUILT_NAME_SRC);
const DNS_SUM_RE = pyRe(DNS_SUM_SRC);
const DNS_FORMAT_RE = pyRe(DNS_FORMAT_SRC);
const DNS_LITERAL_ALL_RE = pyRe(DNS_LITERAL_SRC, "g");
const DNS_VALUE_RE = pyRe(DNS_VALUE_SRC);
const DNS_NAME_RE = pyRe(DNS_NAME_SRC);
const DNS_SHELL_ID_ALL_RE = pyRe(DNS_SHELL_ID_SRC, "gi");
const DNS_SHELL_ID_SUB_RE = pyRe(DNS_SHELL_ID_SRC, "gi");                  // (replace(): a regex of its own)
const DNS_SHELL_CMD_RE = pyRe(DNS_SHELL_CMD_SRC);
const DNS_CMD_SUM_ALL_RE = pyRe(DNS_CMD_SUM_SRC, "g");
const DNS_CMD_TEMPLATE_ALL_RE = pyRe(DNS_CMD_TEMPLATE_SRC, "g");
const DNS_SHELL_CUT_RE = pyRe(DNS_SHELL_CUT_SRC);
const DNS_SHELL_CUT_ALL_RE = pyRe(DNS_SHELL_CUT_SRC, "g");
const DNS_SHELL_LEFT_RE = pyRe(DNS_SHELL_LEFT_SRC);
const DNS_SHELL_RIGHT_RE = pyRe("^(?:" + DNS_SHELL_RIGHT_SRC + ")");       // Python's match(): at the start
const DNS_SHELL_HOST_RE = pyRe(DNS_SHELL_HOST_SRC);
const DNS_LOOKUP_MAX = 50, DNS_ARG_SPAN = 400, DNS_ASSIGN_SPAN = 5000, DNS_SHELL_SPAN = 300;
const IP_LITERAL_RE = pyRe(IP_LITERAL_SRC, "g");
const RAW_CONNECT_RE = pyRe(RAW_CONNECT_SRC);
const MONERO_ADDR_RE = pyRe(MONERO_ADDR_SRC);
const MINER_ARG_RE = pyRe(MINER_ARG_SRC);
const CRED_SWEEP_NEEDLES = [".ssh", ".aws", ".azure", ".gnupg", ".docker", ".kube", ".ethereum", ".electrum", ".bitcoin",
  ".solana", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".config", ".password-store", ".vault-token", ".terraform.d"];
const CRED_SWEEP_SPAN = 400;
const CRED_SWEEP_MIN = 3;
const CRED_SWEEP_MAX = 200;
const RAW_CONNECT_SPAN = 600;
const IP_LITERAL_MAX = 100;
const PUBLIC_RESOLVERS = new Set(["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
  "208.67.222.222", "208.67.220.220"]);

// A webhook whose secret is written in the code (0.1.8; core's comment above _SE_URL_RE): a request given an
// http(s) URL whose path carries a credential, for any service.
const SE_URL_SRC = String.raw`https?://([^\s"'` + "`" + String.raw`<>/?#]{1,300})([^\s"'` + "`" + String.raw`<>?#]{0,600})`;
const SE_SEGMENT_SRC = String.raw`[A-Za-z0-9_:-]{20,200}`;
const SE_HOLE_SRC = String.raw`\$\{\s*([A-Za-z_$][\w$]*)\s*\}|\{\s*([A-Za-z_]\w*)\s*\}`;
const SE_REQUEST_SRC = String.raw`\b(?:fetch|urlopen|Request|sendBeacon|axios|got|ky|needle|superagent)\s*\(`
  + String.raw`|\.\s*(?:get|post|put|patch|request|send|open)\s*\(`;
const SE_NEEDLES = ["fetch", "urlopen", "Request", "sendBeacon", "axios", "got", "ky", "needle", "superagent", ".get",
  ".post", ".put", ".patch", ".request", ".send", ".open", "curl", "wget"];
const SE_MIN_DISTINCT = 10, SE_MAX = 200;
const SE_URL_G = pyRe(SE_URL_SRC, "g");
const SE_SEGMENT_WHOLE = pyRe("^(?:" + SE_SEGMENT_SRC + ")$");
const SE_HOLE_G = pyRe(SE_HOLE_SRC, "g");
const SE_REQUEST_G = pyRe(SE_REQUEST_SRC, "g");

/** core._se_secret: is a path segment a credential? */
function seSecret(segment) {
  return SE_SEGMENT_WHOLE.test(segment) && new Set(segment).size >= SE_MIN_DISTINCT
    && /[A-Z]/.test(segment) && /[a-z]/.test(segment) && /[0-9]/.test(segment);
}

/** core._se_url_secret: does a URL (an SE_URL match) carry a credential in its path? */
function seUrlSecret(url, values) {
  for (let segment of url[2].split("/")) {
    if (segment.includes("{")) segment = segment.replace(SE_HOLE_G, (h, a, b) => values.get(a ?? b) ?? "{");
    if (seSecret(segment)) return true;
  }
  return false;
}

/** [offset, reason] of the first request to a webhook whose secret is written in text, else null (core.secret_endpoint_at). */
export function secretEndpointAt(text) {
  if (!text.includes("http") || !SE_NEEDLES.some((nd) => text.includes(nd))) return null;
  const values = new Map();                            // name -> the plain literal it is given
  const assigns = [];                                  // [name, start, end] of what is assigned
  DD_ASSIGN_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DD_ASSIGN_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    const lit = matchIn(LD_PLAIN_LITERAL_Y, pyStrip(m[2]), 0);
    if (lit !== null && !values.has(m[1])) values.set(m[1], lit[2]);
    assigns.push([m[1], m.indices[2][0], ldStatementEnd(text, m.indices[2][0])]);
  }
  const endpoints = [];                                // [start, host] of the literals that hold one
  for (const [a, b] of literalSpans(text)) {
    if (endpoints.length >= SE_MAX) break;
    const h = text.indexOf("http", a);
    if (h < 0 || h + 4 > b) continue;
    const part = text.slice(a, b);
    SE_URL_G.lastIndex = 0;
    for (let url; (url = SE_URL_G.exec(part)) !== null;) {
      if (seUrlSecret(url, values)) {
        const at = url[1].lastIndexOf("@");
        endpoints.push([a, cpPrefix(at >= 0 ? url[1].slice(at + 1) : url[1], 60)]);
        break;
      }
    }
  }
  if (!endpoints.length) return null;
  const starts = endpoints.map(([a]) => a);
  const inLiteral = ldLiteralTest(text);
  const held = new Map();                              // name -> the host of the endpoint it holds
  const holds = (lo, hi) => {
    const k = firstAtOrAfter(starts, lo);
    if (k < starts.length && starts[k] < hi) return endpoints[k][1];
    if (held.size) for (const [at, name] of identTokens(text, lo, hi)) if (held.has(name) && !inLiteral(at)) return held.get(name);
    return null;
  };
  const params = new Map();                            // the script's own functions -> their parameters
  LD_FUNC_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_FUNC_G.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    const name = m[1] || m[3] || m[5] || m[9];
    const plist = [m[2], m[4], m[6], m[7], m[8], m[10]].find((g) => g !== undefined) ?? "";
    const names = [];
    for (const part of plist.split(",")) {
      const p = matchIn(LD_PARAM_Y, part, 0);
      if (p !== null && p[1] !== "self" && p[1] !== "cls") names.push(p[1]);
    }
    if (names.length && !params.has(name) && params.size < SE_MAX) params.set(name, names);
  }
  const callRe = params.size
    ? pyRe(DV_NAME_HEAD + "(" + [...params.keys()].sort().map(reEscape).join("|") + String.raw`)\s*\(`, "g") : null;
  for (let pass = 0; pass < DD_PASSES; pass++) {
    let grown = false;
    for (const [name, lo, hi] of assigns) {
      if (held.has(name)) continue;
      const host = holds(lo, hi);
      if (host !== null) { held.set(name, host); grown = true; }
    }
    if (callRe !== null) {
      callRe.lastIndex = 0;
      for (let c, k = 0; (c = callRe.exec(text)) !== null; k++) {
        if (k >= SE_MAX) break;
        if (inLiteral(c.index)) continue;
        const start = c.index + c[0].length;
        const args = callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN)));
        for (const [param, lo, hi] of ldBound(text, start, args, params.get(c[1]))) {
          if (held.has(param)) continue;
          const host = holds(lo, hi);
          if (host !== null) { held.set(param, host); grown = true; }
        }
        callRe.lastIndex = start;
      }
    }
    if (!grown) break;
  }
  const found = [];
  for (const [re, where] of [[SE_REQUEST_G, null], [LD_EXEC_SEND_G, LD_NET_PROGRAM_RE]]) {
    re.lastIndex = 0;
    for (let r, k = 0; (r = re.exec(text)) !== null; k++) {
      if (k >= SE_MAX) break;
      if (inLiteral(r.index)) continue;
      const start = r.index + r[0].length;
      const args = callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN)));
      re.lastIndex = start;
      if (where !== null && !where.test(args)) continue;
      const host = holds(start, start + args.length);
      if (host !== null) { found.push([r.index, host]); break; }
    }
  }
  if (!found.length) return null;
  const [at, host] = tupleMin(found);
  return [at, `sends data to a webhook whose secret is written in the code (${host})`];
}

/** [offset, names] where text names CRED_SWEEP_MIN or more distinct credential folders within CRED_SWEEP_SPAN code points, else null (core.credential_sweep_at). */
export function credentialSweepAt(text) {
  if (CRED_SWEEP_NEEDLES.filter((nd) => text.includes(nd)).length < CRED_SWEEP_MIN) return null;
  const found = [];                                   // [unit offset, code-point offset, name]
  CRED_DIR_RE.lastIndex = 0;
  let cp = 0;
  let prev = 0;
  let k = 0;
  for (let m; (m = CRED_DIR_RE.exec(text)) !== null; k++) {
    if (k >= CRED_SWEEP_MAX) break;
    cp += cpLen(text.slice(prev, m.index));
    prev = m.index;
    found.push([m.index, cp, m[1].replaceAll("\\", "/")]);
    if (m[0].length === 0) CRED_DIR_RE.lastIndex++;
  }
  for (let i = 0; i < found.length; i++) {
    const names = [];
    for (let j = i; j < found.length; j++) {
      if (found[j][1] - found[i][1] > CRED_SWEEP_SPAN) break;
      if (!names.includes(found[j][2])) names.push(found[j][2]);
    }
    if (names.length >= CRED_SWEEP_MIN) return [found[i][0], names];
  }
  return null;
}

/** A call's first argument: what follows its '(' (as callArgs gives it) up to a comma outside brackets and
 * string literals, stripped (core._call_first_arg). */
function firstArg(args) {
  let depth = 0, i = 0;
  const n = args.length;
  while (i < n) {
    const ch = args[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      const j = args.indexOf(ch, i + 1);
      if (j < 0) break;
      i = j + 1;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 0) return pyStrip(args.slice(0, i));
    i++;
  }
  return pyStrip(args);
}
const dnsDomainOk = (tld) => tld !== undefined && tld !== null && !DNS_LOCAL_TLDS.has(tld.toLowerCase());
const dnsValue = (part) => { DNS_LITERAL_ALL_RE.lastIndex = 0; return DNS_VALUE_RE.test(part.replace(DNS_LITERAL_ALL_RE, "")); };

/** Does the expression build a name from values and a literal domain? (core._dns_built) */
function dnsBuilt(expr) {
  let m = DNS_TEMPLATE_RE.exec(expr);
  if (m !== null) {
    const built = DNS_BUILT_NAME_RE.exec(m[1] ?? m[2] ?? m[3]);
    return built !== null && dnsDomainOk(built[1]);
  }
  m = DNS_SUM_RE.exec(expr);
  if (m !== null) return dnsDomainOk(m[1] ?? m[2] ?? m[3]) && dnsValue(expr.slice(0, m.index));
  m = DNS_FORMAT_RE.exec(expr);
  return m !== null && dnsDomainOk(m[1] ?? m[2]);
}

/** The offset of a lookup call of a built name, else -1 (core._dns_call_at). */
function dnsCallAt(text) {
  DNS_CALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DNS_CALL_RE.exec(text)) !== null; k++) {
    if (k >= DNS_LOOKUP_MAX) break;
    const start = m.index + m[0].length;
    const arg = firstArg(callArgs(text.slice(start, cpForward(text, start, DNS_ARG_SPAN))));
    if (dnsBuilt(arg)) return m.index;
    if (DNS_NAME_RE.test(arg)) {
      const assign = pyRe(DNS_ASSIGN_HEAD + reEscape(arg) + DNS_ASSIGN_TAIL, "g");
      const part = text.slice(0, m.index);
      assign.lastIndex = cpBack(text, m.index, DNS_ASSIGN_SPAN);
      let last = null;
      for (let a; (a = assign.exec(part)) !== null;) last = a;
      if (last !== null && dnsBuilt(pyStrip(last[1]))) return m.index;
    }
  }
  return -1;
}

/** The offset of a lookup command code writes with a built name, else -1 (core._dns_command_at). */
function dnsCommandAt(text) {
  const found = [];
  DNS_CMD_SUM_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DNS_CMD_SUM_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DNS_LOOKUP_MAX) break;
    const rest = firstArg(callArgs(m[2]));
    const tail = DNS_SUM_RE.exec("+" + rest);
    if (tail !== null && dnsDomainOk(tail[1] ?? tail[2] ?? tail[3]) && dnsValue(rest.slice(0, Math.max(0, tail.index - 1)))) {
      found.push(m.index);
      break;
    }
  }
  DNS_CMD_TEMPLATE_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DNS_CMD_TEMPLATE_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DNS_LOOKUP_MAX) break;
    if (dnsDomainOk(m[1])) { found.push(m.index); break; }
  }
  return found.length ? Math.min(...found) : -1;
}

/** The offset of a shell command that looks up a name holding the machine's user or host name, else -1 (core._dns_shell_at). */
function dnsShellAt(text) {
  DNS_SHELL_ID_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DNS_SHELL_ID_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DNS_LOOKUP_MAX) break;
    let head = text.slice(cpBack(text, m.index, DNS_SHELL_SPAN), m.index);
    let cutAt = -1;
    DNS_SHELL_CUT_ALL_RE.lastIndex = 0;
    for (let c; (c = DNS_SHELL_CUT_ALL_RE.exec(head)) !== null;) cutAt = c.index + c[0].length;
    if (cutAt >= 0) head = head.slice(cutAt);
    const cmd = DNS_SHELL_CMD_RE.exec(head);
    if (cmd === null) continue;
    const end = m.index + m[0].length;
    let tail = text.slice(end, cpForward(text, end, DNS_SHELL_SPAN));
    const cut = DNS_SHELL_CUT_RE.exec(tail);
    if (cut !== null) tail = tail.slice(0, cut.index);
    tail = tail.replace(DNS_SHELL_ID_SUB_RE, "\x00");
    const token = DNS_SHELL_LEFT_RE.exec(head)[0] + "\x00" + DNS_SHELL_RIGHT_RE.exec(tail)[0];
    const found = DNS_SHELL_HOST_RE.exec(token);
    if (found !== null && dnsDomainOk(found[1])) return m.index - head.length + cmd.index;
  }
  return -1;
}

/** The offset of a DNS lookup of a name text builds from values and a literal domain, else -1; host: does the
 * text read the machine's user or host name? Without, only a shell command's name that holds it counts
 * (core.dns_beacon_at). */
export function dnsBeaconAt(text, host = true) {
  const found = (host ? [dnsCallAt(text), dnsCommandAt(text)] : []).filter((at) => at >= 0);
  const at = dnsShellAt(text);
  if (at >= 0) found.push(at);
  return found.length ? Math.min(...found) : -1;
}

/** The offset of the Monero wallet address text runs a miner with, else -1 (core.miner_at). */
export function minerAt(text) {
  if (!MINER_ARG_NEEDLES.some((nd) => text.includes(nd)) || !MINER_ARG_RE.test(text)) return -1;
  const m = MONERO_ADDR_RE.exec(text);
  if (m && EXEC_CALL_RE.test(text)) return m.index;
  return -1;
}

/** [offset, reason] of the exfiltration shapes, and of a miner, that text shows; host: HOST_INFO_RE.exec(text) (core._exfil_signs). */
function exfilSigns(text, host) {
  const signs = [];
  const at = minerAt(text);
  if (at >= 0) signs.push([at, "runs a cryptocurrency miner (a Monero wallet address)"]);
  const endpoint = secretEndpointAt(text);
  if (endpoint !== null) signs.push(endpoint);
  let net = null;                                     // NETWORK_RE's answer, searched once when needed
  const network = () => (net === null ? (net = NETWORK_RE.test(text)) : net);
  const sweep = credentialSweepAt(text);
  if (sweep !== null && network()) {
    signs.push([sweep[0], "collects files from several credential folders and sends data over the network "
      + `(${sweep[1].slice(0, 4).map((n) => "." + n).join(", ")})`]);
  }
  if (host && B64_URL_LITERAL_RE.test(text) && network()) {
    signs.push([host.index, "sends the machine's user or host name to an address it hides in base64"]);
  }
  const dns = dnsBeaconAt(text, host !== null);
  if (dns >= 0) signs.push([dns, "sends the machine's user or host name in a DNS lookup of a name it builds"]);
  if (host) {
    const drop = deadDropAt(text);
    if (drop !== null) signs.push([drop[0], `sends the machine's user or host name to an address it fetches at run time (from ${drop[1]})`]);
  }
  return signs;
}

/** The first hard-coded IP address text opens a raw socket to (install time only), else null (core.raw_ip_connect). */
export function rawIpConnect(text) {
  if (!text.includes("connect") && !text.includes("Socket")) return null;
  IP_LITERAL_RE.lastIndex = 0;
  let k = 0;
  for (let m; (m = IP_LITERAL_RE.exec(text)) !== null; k++) {
    if (k >= IP_LITERAL_MAX) break;
    if (PUBLIC_RESOLVERS.has(m[1])) continue;
    const end = m.index + m[0].length;
    const after = text.slice(end);
    if (RAW_CONNECT_RE.test(cpPrefix(after, RAW_CONNECT_SPAN))) return m[1];
  }
  return null;
}

// Code read back from the file itself (core's comment above _SELF_READ_RE):
// running what a read of its own source, or of a data file shipped next to
// it, gives; followed through the names it is assigned to.
const SELF_READ_SRC = String.raw`\bopen\s*\(\s*(?:os\.path\.(?:abspath|realpath)\s*\(\s*)?__file__\b`
  + String.raw`|\bPath\s*\(\s*__file__\s*\)\s*\.\s*(?:read_text|read_bytes|open)\s*\(`
  + String.raw`|\blinecache\.getlines?\s*\(\s*__file__\b|(?<![\w.])__loader__\s*\.\s*get_source\s*\(|(?<![\w.])__doc__\b`
  + String.raw`|\breadFile(?:Sync)?\s*\(\s*(?:__filename\b|(?:new\s+URL\s*\(\s*)?import\.meta\.url`
  + String.raw`|fileURLToPath\s*\(\s*import\.meta\.url)|\barguments\s*\.\s*callee\b|\}\s*\)?\s*\.\s*toString\s*\(\s*\)`;
const DATA_EXT = String.raw`(?:txt|dat|bin|png|jpe?g|gif|ico|bmp|svg|wav|mp3|mp4|woff2?|ttf|json|md|cfg|ini|log|db|pyc|so|dll`
  + String.raw`|dylib|exe)`;
// a data file's name inside quotes: a data extension, or a licence or readme with or without one (0.1.8)
const NAME_CHAR = String.raw`[^\"'` + "`" + String.raw`{}$\n]`;
const DATA_FILE = String.raw`(?:` + NAME_CHAR + String.raw`{1,100}\.` + DATA_EXT + String.raw`|(?:` + NAME_CHAR + String.raw`{0,100}[/\\])?`
  + String.raw`(?:LICEN[CS]E|COPYING|NOTICE|README|AUTHORS|CHANGELOG|CHANGES|HISTORY|PATENTS)(?:[-.]\w{1,10})?)`;
const SIBLING_DATA_SRC = String.raw`\b(?:open|read_text|read_bytes|readFileSync|readFile)\s*\([^\n]{0,200}?(?:__file__|__dirname|import\.meta\.url)`
  + String.raw`[^\n]{0,200}?[\"']` + DATA_FILE + String.raw`[\"']`
  + String.raw`|(?:__file__|__dirname)[^\n]{0,200}?[\"']` + DATA_FILE + String.raw`[\"'][^\n]{0,60}?`
  + String.raw`\.\s*(?:read_text|read_bytes)\s*\(`;
// a data file's path assigned to a name, a read of a path by its name, a read
// call's head, its node-style callback, and `.then(x => …)` or Python's `as f`
// after it (0.1.8; core's comment above _SELF_READ_RE)
const SIBLING_PATH_SRC = String.raw`(?:__file__|__dirname|import\.meta\.url)[^\n]{0,200}?(?:[\"'` + "`" + String.raw`]|\}[/\\])`
  + DATA_FILE + String.raw`[\"'` + "`]";
const PATH_READ_SRC = String.raw`\b(?:open|read_text|read_bytes|readFileSync|readFile)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]`
  + String.raw`|(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:read_text|read_bytes)\s*\(`;
const READ_HEAD_SRC = String.raw`\b(?:open|read_text|read_bytes|readFileSync|readFile)\s*\(`;
const READ_CALLBACK_SRC = String.raw`\(\s*[A-Za-z_$][\w$]*\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*(?:=>|\{)`;
const READ_THEN_SRC =
  String.raw`\s*(?:\.\s*then\s*\(\s*(?:async\s+)?(?:function\b\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)|as\s+([A-Za-z_]\w*))`;
const SELF_SHELL_RUNNERS = ["execSync", "system", "popen", "Popen", "check_output", "getoutput", "subprocess"];
const SELF_RUN_SRC = String.raw`(?<![\w.$])(?:exec|eval|compile)\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*run\w*\s*\(`
  + String.raw`|\b(?:execSync|system|popen|Popen|check_output|getoutput)\s*\(|\bsubprocess\s*\.\s*\w+\s*\(`;
const SELF_READ_ASSIGN_SRC = String.raw`(?<![^\n])[ \t]*(?:(?:const|let|var)[ \t]+)?([A-Za-z_$][\w$]*)[ \t]*(?::[^=\n]*)?=(?![=>])([^\n]*)`;
const IDENT_TOKEN_SRC = String.raw`(?<![\w$.])[A-Za-z_$][\w$]*`;
const SELF_READ_RE = pyRe(SELF_READ_SRC);
const SELF_READ_ALL_RE = pyRe(SELF_READ_SRC, "g");
const SIBLING_DATA_RE = pyRe(SIBLING_DATA_SRC);
const SIBLING_DATA_ALL_RE = pyRe(SIBLING_DATA_SRC, "g");
const SELF_RUN_ALL_RE = pyRe(SELF_RUN_SRC, "g");
const SIBLING_PATH_RE = pyRe(SIBLING_PATH_SRC);
const SIBLING_PATH_ALL_RE = pyRe(SIBLING_PATH_SRC, "g");
const PATH_READ_ALL_RE = pyRe(PATH_READ_SRC, "g");
const READ_HEAD_ALL_RE = pyRe(READ_HEAD_SRC, "g");
const READ_CALLBACK_RE = pyRe(READ_CALLBACK_SRC);
const READ_THEN_AT_START_RE = pyRe("^(?:" + READ_THEN_SRC + ")");      // Python's match(): at the start
const SELF_READ_ASSIGN_ALL_RE = pyRe(SELF_READ_ASSIGN_SRC, "gd");      // d: the groups' offsets
const IDENT_TOKEN_ALL_RE = pyRe(IDENT_TOKEN_SRC, "g");
const SELF_READ_PASSES = 3, SELF_READ_MAX_CALLS = 200, SELF_READ_ARG_SPAN = 2000, SELF_READ_MAX_ASSIGNS = 5000;
const SELF_READ_THEN_SPAN = 200;
const LITERAL_SPANS_MAX = 20000;

/** Does `text` read its own source? (core.reads_own_source) */
export function readsOwnSource(text) {
  return SELF_READ_RE.test(text);
}
/** `text` (what follows a call's '(') up to the bracket that closes the call (core._call_args). */
function callArgs(text) {
  let depth = 0, i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      const j = text.indexOf(ch, i + 1);
      if (j < 0) return text;
      i = j + 1;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return text.slice(0, i);
      depth--;
    }
    i++;
  }
  return text;
}
/** [start, end] of the string literals of `text` (core._literal_spans). */
function literalSpans(text) {
  const out = [];
  const n = text.length;
  let i = 0;
  while (i < n && out.length < LITERAL_SPANS_MAX) {
    const ch = text[i];
    if (ch !== '"' && ch !== "'" && ch !== "`") { i++; continue; }
    if (ch !== "`" && text.startsWith(ch.repeat(3), i)) {
      const j = text.indexOf(ch.repeat(3), i + 3);
      const end = j < 0 ? n : j + 3;
      out.push([i, end]);
      i = end;
      continue;
    }
    let j = i + 1;
    while (j < n && text[j] !== ch && (ch === "`" || text[j] !== "\n")) j += text[j] === "\\" ? 2 : 1;
    const end = Math.min(j + 1, n);
    out.push([i, end]);
    i = end;
  }
  return out;
}
/** The offset of a runner that runs code read from the text's own source or a data file next to it, else -1 (core.runs_own_source_at). */
export function runsOwnSourceAt(text) {
  if (!SELF_READ_RE.test(text) && !SIBLING_DATA_RE.test(text) && !SIBLING_PATH_RE.test(text)) return -1;
  const spans = literalSpans(text);
  const literalAt = (pos) => {
    let lo = 0, hi = spans.length;               // the last span starting at or before pos
    while (lo < hi) { const mid = (lo + hi) >> 1; if (spans[mid][0] <= pos) lo = mid + 1; else hi = mid; }
    return lo > 0 && pos < spans[lo - 1][1] ? spans[lo - 1] : null;
  };
  const inLiteral = (pos) => literalAt(pos) !== null;
  const reads = (lo, hi) => {
    const part = text.slice(lo, hi);
    for (const rx of [SELF_READ_ALL_RE, SIBLING_DATA_ALL_RE]) {
      rx.lastIndex = 0;
      for (let m; (m = rx.exec(part)) !== null;) {
        if (!inLiteral(lo + m.index)) return true;
        if (m[0] === "") rx.lastIndex++;
      }
    }
    return false;
  };
  const paths = new Set();                         // names of data files' paths
  const pathReads = (lo, hi) => {
    if (!paths.size) return false;
    const part = text.slice(lo, hi);
    PATH_READ_ALL_RE.lastIndex = 0;
    for (let m; (m = PATH_READ_ALL_RE.exec(part)) !== null;) {
      if (paths.has(m[1] !== undefined ? m[1] : m[2]) && !inLiteral(lo + m.index)) return true;
    }
    return false;
  };
  const uses = (lo, hi, names) => {
    if (!names.size) return false;
    const part = text.slice(lo, hi);
    IDENT_TOKEN_ALL_RE.lastIndex = 0;
    for (let m; (m = IDENT_TOKEN_ALL_RE.exec(part)) !== null;) if (names.has(m[0]) && !inLiteral(lo + m.index)) return true;
    return false;
  };
  const assigns = [];
  SELF_READ_ASSIGN_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = SELF_READ_ASSIGN_ALL_RE.exec(text)) !== null; k++) {
    if (k >= SELF_READ_MAX_ASSIGNS) break;
    if (!inLiteral(m.indices[1][0])) assigns.push([m[1], m.indices[2][0], m.indices[2][1]]);
  }
  for (const [name, lo, hi] of assigns) {           // a template's `${__dirname}` counts
    const part = text.slice(lo, hi);
    SIBLING_PATH_ALL_RE.lastIndex = 0;
    for (let m; (m = SIBLING_PATH_ALL_RE.exec(part)) !== null;) {
      const lit = literalAt(lo + m.index);
      if (lit === null || text[lit[0]] === "`") { paths.add(name); break; }
    }
  }
  if (!reads(0, text.length) && !pathReads(0, text.length)) return -1;
  const names = new Set();                         // values of a read written out: any runner
  const codeNames = new Set();                     // values of a path read by name: code runners only
  READ_HEAD_ALL_RE.lastIndex = 0;
  for (let h, k = 0; (h = READ_HEAD_ALL_RE.exec(text)) !== null; k++) {
    if (k >= SELF_READ_MAX_CALLS) break;
    if (inLiteral(h.index)) continue;
    const start = h.index + h[0].length;
    const args = callArgs(text.slice(start, cpForward(text, start, SELF_READ_ARG_SPAN)));
    const close = start + args.length;             // the closing bracket, when there is one
    const past = cpForward(text, close, 1);
    const into = reads(h.index, past) ? names : pathReads(h.index, past) ? codeNames : null;
    if (into === null) continue;
    const cb = READ_CALLBACK_RE.exec(args);
    if (cb !== null && !inLiteral(start + cb.index)) into.add(cb[1]);
    if (close < text.length && text[close] === ")") {
      const then = READ_THEN_AT_START_RE.exec(text.slice(close + 1, cpForward(text, close + 1, SELF_READ_THEN_SPAN)));
      if (then !== null) into.add(then[1] !== undefined ? then[1] : then[2]);
    }
  }
  for (let pass = 0; pass < SELF_READ_PASSES; pass++) {
    let grown = false;
    for (const [name, lo, hi] of assigns) {
      if (names.has(name)) continue;
      if (reads(lo, hi) || uses(lo, hi, names)) { names.add(name); grown = true; }
      else if (!codeNames.has(name) && (pathReads(lo, hi) || uses(lo, hi, codeNames))) { codeNames.add(name); grown = true; }
    }
    if (!grown) break;
  }
  SELF_RUN_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = SELF_RUN_ALL_RE.exec(text)) !== null; k++) {
    if (k >= SELF_READ_MAX_CALLS) break;
    if (inLiteral(m.index)) continue;
    const start = m.index + m[0].length;
    const hi = start + callArgs(text.slice(start, cpForward(text, start, SELF_READ_ARG_SPAN))).length;
    if (reads(start, hi) || uses(start, hi, names)) return m.index;
    if (!SELF_SHELL_RUNNERS.some((r) => m[0].startsWith(r)) && (pathReads(start, hi) || uses(start, hi, codeNames))) {
      return m.index;
    }
  }
  return -1;
}

// ---- dead drops (0.1.8; core's comment above _DD_FETCH_RE) ----
const DD_FETCH_SRC = String.raw`\b(?:urlopen|requests\s*\.\s*get|httpx\s*\.\s*get|fetch|axios\s*\.\s*get|https?\s*\.\s*get|got)\s*\(`;
const DD_SEND_SRC = String.raw`\b(?:Request|urlopen|fetch|https?\s*\.\s*request`
  + String.raw`|(?:requests|httpx|axios|got|superagent|needle|session|client)\s*\.\s*(post|put|patch)|(sendBeacon))\s*\(`;
const DD_DATA_SRC = String.raw`\b(?:data|body)\s*[=:]|\bjson\s*=|["'](?:POST|PUT|PATCH)["']`;
const DD_URL_SRC = String.raw`\A[rbfRBF]{0,2}["'` + "`" + String.raw`]https?://([^/"'` + "`" + String.raw`\s?#]+)`;
const DD_URL_IN_SRC = String.raw`["'` + "`" + String.raw`]https?://([^/"'` + "`" + String.raw`\s?#]+)`;
const DD_ASSIGN_SRC = String.raw`(?:(?<![^\n])|[;{]|=>)[ \t]*(?:(?:const|let|var)[ \t]+)?([A-Za-z_$][\w$]*)[ \t]*\+?=(?![=>])([^;\n]*)`;
const DD_DESTRUCT_SRC = String.raw`\b(?:const|let|var)\s*\{([^}\n]{1,200})\}\s*=([^;\n]*)`;
const DD_DESTRUCT_NAME_SRC = String.raw`(?:[A-Za-z_$][\w$]*\s*:\s*)?([A-Za-z_$][\w$]*)\s*(?:=[^,]*)?\Z`;
const DD_FOR_SRC = String.raw`\bfor\s+([A-Za-z_]\w*)\s+in\s+([^\n:]{1,200})`
  + String.raw`|\bfor\s*\(\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s+(?:of|in)\s+([^\n)]{1,200})`;
const DD_CALLBACK_SRC = String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*){0,8}\s*\.\s*(?:on|once|forEach|map|then|each)\s*\(`
  + String.raw`\s*(?:["'][^"'\n]{0,40}["']\s*,\s*)?(?:async\s+)?(?:function\b\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)`;
const DD_ARG_CALLBACK_SRC = String.raw`,\s*(?:async\s+)?(?:function\b\s*[\w$]*\s*\(\s*([A-Za-z_$][\w$]*)|\(\s*([A-Za-z_$][\w$]*)[^)\n]*\)\s*=>`
  + String.raw`|([A-Za-z_$][\w$]*)\s*=>)`;
const DD_THEN_HEAD_SRC = String.raw`\s*\.\s*then\s*\(`;
const DD_PARAM_SRC = String.raw`\s*(?:async\s+)?(?:function\b\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)`;
const DD_AS_SRC = String.raw`\s*as\s+([A-Za-z_]\w*)`;
const DD_RETURN_SRC = String.raw`\breturn\s+([^\n;]{1,200})`;
const DD_FUNC_SRC = String.raw`\bdef\s+([A-Za-z_]\w*)\s*\(|\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(`
  + String.raw`|(?<![\w$.])([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\b|\([^)\n]{0,200}\)\s*=>|[A-Za-z_$][\w$]*\s*=>)`;
const DD_FETCH_RE = pyRe(DD_FETCH_SRC), DD_FETCH_ALL_RE = pyRe(DD_FETCH_SRC, "g");
const DD_SEND_RE = pyRe(DD_SEND_SRC), DD_SEND_ALL_RE = pyRe(DD_SEND_SRC, "g");
const DD_DATA_RE = pyRe(DD_DATA_SRC, "i");
const DD_URL_RE = pyRe(DD_URL_SRC), DD_URL_IN_RE = pyRe(DD_URL_IN_SRC);
const DD_ASSIGN_ALL_RE = pyRe(DD_ASSIGN_SRC, "gd"), DD_DESTRUCT_ALL_RE = pyRe(DD_DESTRUCT_SRC, "gd");
const DD_DESTRUCT_NAME_RE = pyRe(DD_DESTRUCT_NAME_SRC);
const DD_FOR_ALL_RE = pyRe(DD_FOR_SRC, "gd"), DD_CALLBACK_ALL_RE = pyRe(DD_CALLBACK_SRC, "g");
const DD_ARG_CALLBACK_RE = pyRe(DD_ARG_CALLBACK_SRC);
const DD_THEN_HEAD_AT_RE = pyRe(DD_THEN_HEAD_SRC, "y"), DD_AS_AT_RE = pyRe(DD_AS_SRC, "y");
const DD_PARAM_AT_START_RE = pyRe("^(?:" + DD_PARAM_SRC + ")");       // Python's match(): at the start
const DD_RETURN_ALL_RE = pyRe(DD_RETURN_SRC, "gd"), DD_FUNC_ALL_RE = pyRe(DD_FUNC_SRC, "g");
const DD_PASSES = 4, DD_MAX_CALLS = 100, DD_ARG_SPAN = 2000, DD_MAX_ASSIGNS = 5000, DD_THEN_MAX = 4;

/** [offset, host] of a send whose address the text fetched at run time from a literal URL on host, else null
 * (core.dead_drop_at; the caller checks that the text reads the machine's user or host name). */
export function deadDropAt(text) {
  if (!text.includes("http") || !DD_FETCH_RE.test(text) || !DD_SEND_RE.test(text)) return null;
  const spans = literalSpans(text);
  const inLiteral = (pos) => {
    let lo = 0, hi = spans.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (spans[mid][0] <= pos) lo = mid + 1; else hi = mid; }
    return lo > 0 && pos < spans[lo - 1][1];
  };
  const uses = (lo, hi, names) => {
    if (!names.size) return false;
    const part = text.slice(lo, hi);
    IDENT_TOKEN_ALL_RE.lastIndex = 0;
    for (let m; (m = IDENT_TOKEN_ALL_RE.exec(part)) !== null;) if (names.has(m[0]) && !inLiteral(lo + m.index)) return true;
    return false;
  };
  const assigns = [];                               // [name, start, end] of what is assigned
  const urlNames = new Map();                       // name -> the host of the URL literal assigned to it
  DD_ASSIGN_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DD_ASSIGN_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    if (inLiteral(m.indices[1][0])) continue;
    assigns.push([m[1], m.indices[2][0], m.indices[2][1]]);
    const url = DD_URL_IN_RE.exec(m[2]);
    if (url !== null && !urlNames.has(m[1])) urlNames.set(m[1], url[1]);
  }
  DD_DESTRUCT_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DD_DESTRUCT_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    if (inLiteral(m.index)) continue;
    for (const part of m[1].split(",")) {
      const name = DD_DESTRUCT_NAME_RE.exec(pyStrip(part));
      if (name !== null) assigns.push([name[1], m.indices[2][0], m.indices[2][1]]);
    }
  }
  const followed = new Set();
  let origin = null;
  DD_FETCH_ALL_RE.lastIndex = 0;
  for (let f, k = 0; (f = DD_FETCH_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_CALLS) break;
    if (inLiteral(f.index)) continue;
    const start = f.index + f[0].length;
    const args = callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN)));
    const first = firstArg(args);
    const url = DD_URL_RE.exec(first);
    const host = url !== null ? url[1] : (urlNames.has(first) ? urlNames.get(first) : null);
    if (host === null) continue;
    const before = followed.size;
    for (const [name, lo, hi] of assigns) if (lo <= f.index && f.index < hi) followed.add(name);
    const cb = DD_ARG_CALLBACK_RE.exec(args);
    if (cb !== null && !inLiteral(start + cb.index)) followed.add(cb[1] ?? cb[2] ?? cb[3]);
    let pos = start + args.length + 1;              // after the call's closing bracket
    DD_AS_AT_RE.lastIndex = pos;
    const as = DD_AS_AT_RE.exec(text);
    if (as !== null) followed.add(as[1]);
    for (let t = 0; t < DD_THEN_MAX; t++) {
      DD_THEN_HEAD_AT_RE.lastIndex = pos;
      const h = DD_THEN_HEAD_AT_RE.exec(text);
      if (h === null) break;
      const hEnd = h.index + h[0].length;
      const thenArgs = callArgs(text.slice(hEnd, cpForward(text, hEnd, DD_ARG_SPAN)));
      const param = DD_PARAM_AT_START_RE.exec(thenArgs);
      if (param !== null) followed.add(param[1]);
      pos = hEnd + thenArgs.length + 1;
    }
    if (origin === null && followed.size > before) origin = host;
  }
  if (!followed.size) return null;
  const funcs = [];                                 // [start, name] of the functions defined
  DD_FUNC_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DD_FUNC_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    funcs.push([m.index, m[1] ?? m[2] ?? m[3]]);
  }
  const loops = [];
  DD_FOR_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DD_FOR_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    if (inLiteral(m.index)) continue;
    loops.push(m[2] !== undefined ? [m[1], m.indices[2][0], m.indices[2][1]] : [m[3], m.indices[4][0], m.indices[4][1]]);
  }
  for (let pass = 0; pass < DD_PASSES; pass++) {
    let grown = false;
    for (const [name, lo, hi] of [...assigns, ...loops]) {
      if (!followed.has(name) && uses(lo, hi, followed)) { followed.add(name); grown = true; }
    }
    DD_CALLBACK_ALL_RE.lastIndex = 0;
    for (let m, k = 0; (m = DD_CALLBACK_ALL_RE.exec(text)) !== null; k++) {
      if (k >= DD_MAX_CALLS) break;
      if (followed.has(m[1]) && !followed.has(m[2]) && !inLiteral(m.index)) { followed.add(m[2]); grown = true; }
    }
    DD_RETURN_ALL_RE.lastIndex = 0;
    for (let m, k = 0; (m = DD_RETURN_ALL_RE.exec(text)) !== null; k++) {
      if (k >= DD_MAX_CALLS) break;
      if (inLiteral(m.index) || !uses(m.indices[1][0], m.indices[1][1], followed)) continue;
      let lo = 0, hi = funcs.length;                // the last function defined at or before the return
      while (lo < hi) { const mid = (lo + hi) >> 1; if (funcs[mid][0] <= m.index) lo = mid + 1; else hi = mid; }
      if (lo > 0 && !followed.has(funcs[lo - 1][1])) { followed.add(funcs[lo - 1][1]); grown = true; }
    }
    if (!grown) break;
  }
  DD_SEND_ALL_RE.lastIndex = 0;
  for (let s, k = 0; (s = DD_SEND_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_CALLS) break;
    if (inLiteral(s.index)) continue;
    const start = s.index + s[0].length;
    const args = callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN)));
    const first = firstArg(args);
    const lead = args.length - pyLstrip(args).length;
    if (!uses(start + lead, start + lead + first.length, followed)) continue;
    if (s[1] !== undefined || s[2] !== undefined || DD_DATA_RE.test(args)) return [s.index, origin];
  }
  return null;
}

// ---- local data sent (0.1.8; core's comment above _LD_ENV_RE) ----
// What an install script sends is read as a flow: data read from the machine
// (the environment's secrets and the user or host name, the whole
// environment, files outside the package, what local commands report, the
// machine's names and addresses, the cloud's instance metadata, the public IP
// address a lookup service answers), followed through the names given it, into
// the data (or, for what is not a variable of the environment, the address) of
// a request. Twin of core.local_data_sent_at.
const LD_ENV_SRC = String.raw`\bprocess\s*\.\s*env\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*["'` + "`" + String.raw`]([^"'` + "`" + String.raw`\n]{1,100})["'` + "`" + String.raw`]\s*\])`
  + String.raw`|\bos\s*\.\s*environ\s*(?:\[\s*[rbuRBU]?["']([^"'\n]{1,100})["']\s*\]`
  + String.raw`|\.\s*get\s*\(\s*[rbuRBU]?["']([^"'\n]{1,100})["'])`
  + String.raw`|\bos\s*\.\s*getenv\s*\(\s*[rbuRBU]?["']([^"'\n]{1,100})["']`;
const LD_ENV_ALL_SRC = String.raw`\bprocess\s*\.\s*env\b(?!\s*(?:\.|\[|\?\.))`
  + String.raw`|\bos\s*\.\s*environ\b(?!\s*(?:\[|\.\s*(?:get|setdefault|pop|update)\s*\())|\bos\s*\.\s*environb\b`;
const LD_WHOLE_ENV = "the whole environment";
// the whole environment narrowed to what a condition selects is the package's own settings, unless the condition
// excludes or picks secrets (core's comment above _LD_ENV_SELECT_RE)
const LD_ENV_SELECT_SRC = String.raw`(?:\s*\))?\s*\.\s*filter\s*\(|(?:\s*\.\s*(?:items|keys|values)\s*\(\s*\))?[ \t]+if\b`;
const LD_EXCLUDES_SRC = String.raw`!|\bnot\b`;
// a value tested, not used (core's comment above _LD_TEST_AFTER_RE)
const LD_TEST_AFTER_SRC = String.raw`\s*(?:[=!]==?|=(?![=>])|&&|\?(?![.?])|\b(?:and|is|in|else|instanceof)\b)`;
const LD_TEST_BEFORE = ["typeof", "not"];
const LD_MEMBER_READ_SRC = String.raw`\s*(?:\??\.\s*[A-Za-z_$][\w$]*(?![\w$])(?!\s*\()|\[)`;
const LD_ENV_QUIET_SRC = String.raw`(?:npm_(?:package|lifecycle|config)_(?![\w]*(?:auth|token|passw|secret))\w*|npm_node_execpath|npm_execpath`
  + String.raw`|INIT_CWD|NODE_ENV|CI)\Z`;
const LD_IDENTITY_SRC = String.raw`(?:\bos\s*\.\s*|\brequire\(\s*["'](?:node:)?os["']\s*\)\s*\.\s*)(hostname|userInfo|homedir|networkInterfaces)\b`
  + String.raw`(\s*\()?|\b(?:socket\s*\.\s*(?:gethostname|getfqdn)|platform\s*\.\s*node|getpass\s*\.\s*getuser`
  + String.raw`|os\s*\.\s*getlogin|os\s*\.\s*uname|platform\s*\.\s*uname)\b(\s*\()?`;
const LD_IMPORT_JS_SRC = String.raw`\b(?:(?:const|let|var)\s*\{([^{}\n]{1,300})\}\s*=\s*require\(\s*|import\s*\{([^{}\n]{1,300})\}\s*from\s*)`
  + String.raw`["'](?:node:)?os["']`;
const LD_IMPORT_PY_SRC = String.raw`\bfrom\s+(os|socket|getpass|platform)\s+import\s+\(?([^\n)]{1,300})`;
const LD_IMPORT_NAME_SRC = String.raw`\s*([A-Za-z_$][\w$]*)(?:\s*(?::|\bas\b)\s*([A-Za-z_$][\w$]*))?\s*\Z`;
const LD_MODULE_NAMES = {
  os: { hostname: "identity", userInfo: "identity", homedir: "report", networkInterfaces: "report",
    getlogin: "identity", uname: "identity" },
  socket: { gethostname: "identity", getfqdn: "identity" },
  getpass: { getuser: "identity" },
  platform: { node: "identity", uname: "identity" },
};
const LD_PUBLIC_IP_SRC = String.raw`\bapi(?:64)?\.ipify\.org\b|\bip-api\.com\b|\bipinfo\.io\b|\bifconfig\.me\b|\bicanhazip\.com\b`
  + String.raw`|\bcheckip\.amazonaws\.com\b|\bipapi\.co\b|\bident\.me\b|\bapi\.myip\.com\b|\bwtfismyip\.com\b`;
const LD_CALL_SRC = String.raw`(?<![\w$.])(?:(?:[A-Za-z_$][\w$]*|require\s*\(\s*["'` + "`" + String.raw`][^"'` + "`"
  + String.raw`\n]{1,60}["'` + "`" + String.raw`]\s*\))\s*\.\s*)*([A-Za-z_$][\w$]*)\s*\(\s*`;
const LD_READERS = new Set(["readFileSync", "readFile", "readdirSync", "readdir", "createReadStream", "opendirSync",
  "opendir", "read_text", "read_bytes", "listdir", "scandir", "walk", "glob", "iglob", "open", "Path", "readlines"]);
const LD_READS_SRC = String.raw`\b(?:` + [...LD_READERS].sort().join("|") + String.raw`)\s*\(`;
const LD_NOT_READS = new Set(["require", "import", "join", "resolve", "normalize", "dirname", "basename", "relative",
  "mkdirSync", "mkdir", "makedirs", "writeFileSync", "writeFile", "appendFileSync",
  "existsSync", "exists", "chdir", "spawn", "spawnSync", "execFile", "execFileSync", "fork",
  "exec", "execSync", "unlinkSync", "unlink", "rmSync", "rmdirSync", "remove", "rmtree",
  "chmodSync", "chmod", "symlinkSync", "copyFileSync", "copyfile", "copy", "move", "rename",
  "renameSync", "isfile", "isdir", "isabs", "abspath", "realpath", "expanduser", "log",
  "print", "error", "warn", "info", "debug", "system", "popen", "run", "call", "check_call",
  "check_output", "Popen", "startsWith", "endsWith", "includes", "test", "match", "replace",
  "split", "indexOf", "push", "append", "extend", "set", "add"]);
const LD_ABSOLUTE_SRC = String.raw`[fFrRbBuU]{0,2}["'` + "`" + String.raw`](?:/[\w.~-]|~[/\\]|[A-Za-z]:[\\/]|\$HOME\b|\$\{HOME\}|%USERPROFILE%)`;
const LD_FS_ROOT_SRC = String.raw`["'` + "`" + String.raw`](?:/(?:etc|proc|home|root|Users|var|opt|flag|tmp|usr|srv|mnt|run|sys|dev|boot|data`
  + String.raw`|app|workspace|secrets?)\b|~[/\\]|[A-Za-z]:[\\/]|\$HOME\b|\$\{HOME\}|%USERPROFILE%)`;
const LD_FS_ROOT_ANY_SRC = String.raw`[fFrRbBuU]{0,2}` + LD_FS_ROOT_SRC;           // core's _LD_FS_ROOT_RE
const LD_HOME_SRC = String.raw`\bhomedir\s*\(|\bexpanduser\s*\(|\bPath\s*\.\s*home\s*\(|\bgetcwd\s*\(|\bprocess\s*\.\s*cwd\s*\(`
  + String.raw`|\bPath\s*\.\s*cwd\s*\(|\bprocess\s*\.\s*env\s*(?:\.\s*|\[\s*["'` + "`" + String.raw`])(?:HOME|USERPROFILE|INIT_CWD|APPDATA|LOCALAPPDATA)\b`
  + String.raw`|\b(?:environ\s*(?:\[\s*|\.\s*get\s*\(\s*)|getenv\s*\(\s*)["'](?:HOME|USERPROFILE|APPDATA|LOCALAPPDATA)["']`;
const LD_OWN_FOLDER_SRC = String.raw`__dirname|__filename|import\s*\.\s*meta|__file__`;
const LD_CRED_FILE_SRC = String.raw`[fFrRbBuU]{0,2}["'` + "`" + String.raw`](?:[^"'` + "`" + String.raw`\n]{0,200}[/\\])?\.(?:env(?:\.[\w.-]{1,30})?|npmrc|pypirc|netrc|git-credentials)["'` + "`" + String.raw`]`;
const LD_PLAIN_LITERAL_SRC = String.raw`[fFrRbBuU]{0,2}(["'` + "`" + String.raw`])([^"'` + "`" + String.raw`\n]*)\1\Z`;
const LD_PATH_EXPR_SRC = String.raw`\s*(?:(?:path|os\s*\.\s*path|posixpath|ntpath)\s*\.\s*(?:join|resolve|normalize)\s*\(|Path\s*\(`
  + String.raw`|[fFrRbBuU]{0,2}["'` + "`" + String.raw`]|[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*){0,4}`
  + String.raw`\s*(?:\(\s*(?:["'][^"'\n]{0,200}["'])?\s*\))?\s*(?:[+/]|\Z))`;
const LD_EXEC_SRC = String.raw`\b(?:execSync|execFileSync|spawnSync|exec|execFile|check_output|getoutput|getstatusoutput|popen|run)\s*(\()\s*`
  + String.raw`(?:\[\s*)?[rbuRBU]?["'` + "`" + String.raw`]([^"'` + "`" + String.raw`\n]{1,300})["'` + "`" + String.raw`]((?:\s*,\s*[rbuRBU]?["'` + "`" + String.raw`][^"'` + "`" + String.raw`\n]{0,100}["'` + "`" + String.raw`]){0,8})`;
const LD_ARGV_ITEM_SRC = String.raw`["'` + "`" + String.raw`]([^"'` + "`" + String.raw`\n]{0,100})["'` + "`" + String.raw`]`;
const LD_METADATA_SRC = String.raw`169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|\bfd00:ec2::254|/computeMetadata/v1`
  + String.raw`|Metadata-Flavor|/latest/meta-data|/metadata/instance|/metadata/identity/oauth2`;
const LD_FUNC_SRC = String.raw`\bdef\s+([A-Za-z_]\w*)\s*\(([^)\n]{0,300})\)|\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(([^)\n]{0,300})\)`
  + String.raw`|(?<![\w$])([A-Za-z_$][\w$]*)\s*[=:]\s*(?:async\s+)?(?:function\b\s*\*?\s*[\w$]*\s*\(([^)\n]{0,300})\)`
  + String.raw`|\(([^)\n]{0,300})\)\s*=>|([A-Za-z_$][\w$]*)\s*=>)`
  + String.raw`|(?<![\w$.])(?!(?:if|for|while|switch|catch|function|with|return)\b)(?:async\s+|static\s+|get\s+|set\s+)*`
  + String.raw`([A-Za-z_$][\w$]*)\s*\(([^)\n]{0,300})\)\s*\{`;
const LD_PARAM_SRC = String.raw`\s*(?:\.\.\.|\*{1,2})?\s*([A-Za-z_$][\w$]*)`;
const LD_MEMBER_ASSIGN_SRC = String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)((?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]\n]{1,200}\]){1,8})[ \t]*\+?=(?![=>])`;
const LD_MEMBER_SRC = String.raw`\.\s*([A-Za-z_$][\w$]*)|\[\s*["'` + "`" + String.raw`]([^"'` + "`" + String.raw`\n]{1,60})["'` + "`" + String.raw`]\s*\]`;
const LD_FUNC_VALUE_SRC = String.raw`\s*(?:async\s+)?(?:function\b|\([^)\n]{0,300}\)\s*=>|[A-Za-z_$][\w$]*\s*=>)|\s*(?:lambda\b|class\b)`;
const LD_ARROW_BODY_SRC = String.raw`\s*(?:async\s+)?(?:\([^)\n]{0,300}\)|[A-Za-z_$][\w$]*)\s*=>\s*(?!\{)|\s*lambda\b[^:\n]{0,300}:`;
const LD_CALLED_SRC = String.raw`\s*\(`;
const LD_SEAL_SRC = String.raw`\b(?:readFileSync|readFile|readdirSync|readdir|createReadStream|opendirSync|opendir|listdir|scandir|walk|glob`
  + String.raw`|iglob|open|existsSync|exists|statSync|lstatSync|isfile|isdir)\s*\(`;
const LD_COLLECT_SRC = String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*){0,4}\s*\.\s*`
  + String.raw`(?:push|append|extend|add|update|unshift|insert|setdefault)\s*\(`;
const LD_CONNECTION_SRC = String.raw`\b(?:https?|http2|net|tls|dgram)\s*\.\s*(?:get|createSocket)\s*\(`
  + String.raw`|\brequire\s*\(\s*["'](?:node:)?(?:https?|http2|net|tls|dgram)["']\s*\)\s*\.\s*`
  + String.raw`(?:request|get|connect|createConnection|createSocket)\s*\(`
  + String.raw`|(?<![\w$])[A-Za-z_$][\w$]*\s*\.\s*(?:request|connect|createConnection)\s*\(`
  + String.raw`|\bnew\s+(?:net\s*\.\s*)?(?:Socket|XMLHttpRequest|WebSocket)\s*\(`
  + String.raw`|\bsocket\s*\.\s*(?:socket|create_connection)\s*\(|\bHTTPS?Connection\s*\(`;
const LD_WRITE_TAIL = String.raw`\s*\.\s*(?:write|end|send|sendall|sendto|request)\s*\(`;
const LD_BODY_SRC = String.raw`\s*\{`;
const LD_HOST_BUILT_SRC = String.raw`[fFrRbBuU]{0,2}(["'` + "`" + String.raw`])(?:https?|wss?)://[^"'` + "`" + String.raw`/\s?#]{0,200}?`
  + String.raw`(?:\1\s*\+\s*([^\n+;,)]{1,200})|\$\{([^}\n]{1,200})\}|\{([^}\n]{1,200})\})`;
const LD_SEND_SRC = String.raw`\b(?:axios|got|needle|superagent|ky|requests|httpx|session|client|aiohttp)\s*\.\s*(?:post|put|patch)\s*\(`
  + String.raw`|\bsendBeacon\s*\(|\bRequest\s*\(|\burlopen\s*\(|(?<![\w$.])fetch\s*\(`
  + String.raw`|\b(?:globalThis|window|self|global)\s*\.\s*fetch\s*\(`;
const LD_OPTIONS_SEND_SRC = String.raw`\baxios\s*\(`;
const LD_REQUEST_SEND_SRC = String.raw`\b(?:requests|httpx|session|client)\s*\.\s*request\s*\(`;
const LD_EXEC_SEND_SRC = String.raw`\b(?:execSync|exec|spawnSync|spawn|execFileSync|execFile|system|popen|check_output|check_call|call|run`
  + String.raw`|Popen|getoutput)\s*\(`;
const LD_NET_PROGRAM_SRC = String.raw`(?:["'` + "`" + String.raw`]|[;&|]\s*|\$\(\s*)(?:[\w./-]*/)?(?:curl|wget|nc|ncat|netcat|nslookup|dig`
  + String.raw`|ping|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b`;
const LD_ADDRESS_SEND_SRC = String.raw`\b(?:https?\s*\.\s*(?:get|request)|axios\s*\.\s*get|got|requests\s*\.\s*get|httpx\s*\.\s*get)\s*\(`
  + String.raw`|\brequire\s*\(\s*["'](?:node:)?https?["']\s*\)\s*\.\s*(?:get|request)\s*\(`;
const LD_LOOKUP_SEND_SRC = String.raw`\b(?:dns\s*\.\s*(?:lookup|resolve\w*)|gethostbyname|getaddrinfo)\s*\(`;
const LD_KWARG_SRC = String.raw`\s*([A-Za-z_]\w*)\s*=(?!=)`;
const LD_KEY_SRC = String.raw`\s*(?:["']([^"'\n]{1,60})["']|([A-Za-z_$][\w$]*))\s*:(?!:)`;
const LD_NEEDLES = ["env", "hostname", "userInfo", "homedir", "networkInterfaces", "getuser", "getlogin", "uname", "exec",
  "ipify", "ip-api", "ipinfo", "ifconfig.me", "icanhazip", "checkip", "ipapi", "ident.me", "myip",
  "wtfismyip", "gethostname", "getfqdn", ".env", "npmrc", "pypirc", "netrc", "git-credentials",
  "check_output", "getoutput", "popen", "run", "read", "open", "listdir", "scandir", "walk", "glob",
  "169.254", "metadata", "Metadata", "100.100.100.200", "fd00:ec2"];
const LD_SEND_NEEDLES = ["request", "fetch", "post", "put", "patch", "send", "write", "end(", "urlopen", "Request", "get",
  "dns", "gethostbyname", "getaddrinfo", "connect", "Socket", "socket", "curl", "wget", "nc ",
  "nslookup", "dig", "ping"];
const LD_METADATA_NEEDLES = ["169.254", "metadata", "Metadata", "100.100.100.200", "fd00:ec2"];
const LD_MAX = 200, LD_MAX_CALLS = 10000, LD_STATEMENT_SPAN = 2000;
const LD_REASONS = {
  address: "sends the machine's public IP address over the network",
  environment: "sends environment variables over the network",
  file: "reads files outside the package and sends them over the network",
  identity: "sends the machine's user or host name over the network",
  report: "sends what local commands report about the machine over the network",
  credentials: "sends what the cloud's instance metadata service gives it (the machine's credentials) over the network",
};
const LD_NOT_IN_ADDRESS = new Set(["environment", "credentials", "address"]);
const LD_OPTION_KEYS = new Set([
  "headers", "agent", "httpsAgent", "httpAgent", "proxy", "proxies", "auth", "signal", "timeout", "method",
  "dispatcher", "cert", "key", "ca", "rejectUnauthorized", "verify", "credentials", "mode", "cache", "redirect",
  "allow_redirects", "follow_redirects", "stream", "keepalive", "integrity", "referrerPolicy", "responseType",
  "maxRedirects", "validateStatus", "url", "baseURL", "base_url", "hostname", "host", "port", "path", "protocol",
  "family", "localAddress", "lookup", "retry", "hooks", "https", "http2", "decompress", "followRedirect",
  "throwHttpErrors", "encoding", "trust_env", "timeout_ms"]);
const LD_PROCESS_KEYS = new Set([
  "env", "cwd", "shell", "stdin", "stdout", "stderr", "capture_output", "text", "check", "close_fds",
  "creationflags", "startupinfo", "universal_newlines", "bufsize", "executable", "preexec_fn", "pass_fds",
  "start_new_session", "user", "group", "umask"]);
const LD_REPORT_NAMES = new Set(["homedir", "networkInterfaces"]);

const LD_ENV_ALL_G = pyRe(LD_ENV_SRC, "gd"), LD_ENV_WHOLE_G = pyRe(LD_ENV_ALL_SRC, "g");
const LD_MEMBER_READ_Y = pyRe(LD_MEMBER_READ_SRC, "y");
const LD_ENV_SELECT_Y = pyRe(LD_ENV_SELECT_SRC, "y"), LD_EXCLUDES_RE = pyRe(LD_EXCLUDES_SRC);
const LD_TEST_AFTER_Y = pyRe(LD_TEST_AFTER_SRC, "y"), LD_BODY_Y = pyRe(LD_BODY_SRC, "y");
const LD_ENV_QUIET_Y = pyRe(LD_ENV_QUIET_SRC, "iy");
const LD_IDENTITY_G = pyRe(LD_IDENTITY_SRC, "g");
const LD_IMPORT_JS_G = pyRe(LD_IMPORT_JS_SRC, "g"), LD_IMPORT_PY_G = pyRe(LD_IMPORT_PY_SRC, "g");
const LD_IMPORT_NAME_Y = pyRe(LD_IMPORT_NAME_SRC, "y");
const LD_PUBLIC_IP_RE = pyRe(LD_PUBLIC_IP_SRC);
const LD_CALL_G = pyRe(LD_CALL_SRC, "gd");
const LD_READS_RE = pyRe(LD_READS_SRC);
const LD_ABSOLUTE_Y = pyRe(LD_ABSOLUTE_SRC, "y");
const LD_FS_ROOT_Y = pyRe(LD_FS_ROOT_ANY_SRC, "y");
const LD_ABSOLUTE_IN_RE = pyRe(LD_FS_ROOT_SRC);
const LD_HOME_RE = pyRe(LD_HOME_SRC);
const LD_OWN_FOLDER_RE = pyRe(LD_OWN_FOLDER_SRC);
const LD_CRED_FILE_Y = pyRe(LD_CRED_FILE_SRC, "y");
const LD_PLAIN_LITERAL_Y = pyRe(LD_PLAIN_LITERAL_SRC, "y");
const LD_PATH_EXPR_Y = pyRe(LD_PATH_EXPR_SRC, "y");
const LD_EXEC_G = pyRe(LD_EXEC_SRC, "gd");
const LD_ARGV_ITEM_G = pyRe(LD_ARGV_ITEM_SRC, "g");
const LD_METADATA_RE = pyRe(LD_METADATA_SRC);
const LD_FUNC_G = pyRe(LD_FUNC_SRC, "g");
const LD_PARAM_Y = pyRe(LD_PARAM_SRC, "y");
const LD_MEMBER_ASSIGN_G = pyRe(LD_MEMBER_ASSIGN_SRC, "gd");
const LD_MEMBER_G = pyRe(LD_MEMBER_SRC, "g");
const LD_FUNC_VALUE_Y = pyRe(LD_FUNC_VALUE_SRC, "y");
const LD_ARROW_BODY_Y = pyRe(LD_ARROW_BODY_SRC, "y");
const LD_CALLED_Y = pyRe(LD_CALLED_SRC, "y");
const LD_SEAL_G = pyRe(LD_SEAL_SRC, "g");
const LD_COLLECT_G = pyRe(LD_COLLECT_SRC, "gd");
const LD_CONNECTION_RE = pyRe(LD_CONNECTION_SRC), LD_CONNECTION_G = pyRe(LD_CONNECTION_SRC, "g");
const LD_WRITE_TAIL_Y = pyRe(LD_WRITE_TAIL, "y");
const LD_HOST_BUILT_G = pyRe(LD_HOST_BUILT_SRC, "gd");
const LD_SEND_G = pyRe(LD_SEND_SRC, "g"), LD_OPTIONS_SEND_G = pyRe(LD_OPTIONS_SEND_SRC, "g");
const LD_REQUEST_SEND_G = pyRe(LD_REQUEST_SEND_SRC, "g"), LD_EXEC_SEND_G = pyRe(LD_EXEC_SEND_SRC, "g");
const LD_NET_PROGRAM_RE = pyRe(LD_NET_PROGRAM_SRC);
const LD_ADDRESS_SEND_G = pyRe(LD_ADDRESS_SEND_SRC, "g"), LD_LOOKUP_SEND_G = pyRe(LD_LOOKUP_SEND_SRC, "g");
const LD_KWARG_Y = pyRe(LD_KWARG_SRC, "y");
const LD_KEY_Y = pyRe(LD_KEY_SRC, "y");
const QUOTE_CHAR_SRC = String.raw`["'` + "`" + "]";
const QUOTE_CHAR_RE = pyRe(QUOTE_CHAR_SRC);
const DD_ARG_CALLBACK_G = pyRe(DD_ARG_CALLBACK_SRC, "g");
const DD_RETURN_G = pyRe(DD_RETURN_SRC, "gd");
const DD_CALLBACK_G = pyRe(DD_CALLBACK_SRC, "g");
const IDENT_TOKEN_Y = pyRe(IDENT_TOKEN_SRC, "y");
const IDENT_BEFORE_RE = pyRe(String.raw`[\w$.]`);

/** Python's pattern.match(text, lo, hi) for a pattern that looks nowhere before lo: a sticky regex on text[lo:hi]. */
function matchIn(re, text, lo, hi = text.length) {
  re.lastIndex = 0;
  return re.exec(lo === 0 && hi === text.length ? text : text.slice(lo, hi));
}
/** Python's pattern.match(text, pos): a sticky regex at pos. */
function matchAt(re, text, pos) {
  if (pos > text.length) return null;
  re.lastIndex = pos;
  return re.exec(text);
}
/** Python's pattern.search(text, lo, hi) (a pattern that looks nowhere before lo): a search of text[lo:hi]. */
function searchIn(re, text, lo, hi) {
  return re.test(text.slice(lo, hi));
}
/** The code point before UTF-16 index i ("" at 0). */
function cpBefore(text, i) {
  if (i <= 0) return "";
  const c = text.charCodeAt(i - 1);
  return c >= 0xdc00 && c <= 0xdfff && i >= 2 && (text.charCodeAt(i - 2) & 0xfc00) === 0xd800 ? text.slice(i - 2, i) : text[i - 1];
}
const IDENT_TOKEN_LD_G = pyRe(IDENT_TOKEN_SRC, "g");                       // (its own: never used nested)
/** [start, name] of core's _IDENT_TOKEN_RE.finditer(text, lo, hi): its look-behind sees text before lo. */
function* identTokens(text, lo, hi) {
  const part = text.slice(lo, hi);
  const before = lo > 0 && IDENT_BEFORE_RE.test(cpBefore(text, lo));
  const re = IDENT_TOKEN_LD_G;
  re.lastIndex = 0;
  for (let m; (m = re.exec(part)) !== null;) {
    if (m.index === 0 && before) continue;
    const at = re.lastIndex;
    yield [lo + m.index, m[0]];
    re.lastIndex = at;
  }
}
/** The index of the last item of sorted `starts` at or before pos (bisect_right - 1). */
function lastAtOrBefore(starts, pos) {
  let lo = 0, hi = starts.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (starts[mid] <= pos) lo = mid + 1; else hi = mid; }
  return lo - 1;
}
/** The index of the first item of sorted `starts` at or after pos (bisect_left). */
function firstAtOrAfter(starts, pos) {
  let lo = 0, hi = starts.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (starts[mid] < pos) lo = mid + 1; else hi = mid; }
  return lo;
}
/** Compares two tuples (arrays) as Python does: item by item. */
function tupleCmp(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] === b[i]) continue;
    return a[i] < b[i] ? -1 : 1;
  }
  return a.length - b.length;
}
const tupleMin = (items) => items.reduce((m, t) => (tupleCmp(t, m) < 0 ? t : m));

/** core._ld_statement_end: the end of the statement whose value starts at i. */
function ldStatementEnd(text, i) {
  let depth = 0;
  const n = cpForward(text, i, LD_STATEMENT_SPAN);
  while (i < n) {
    const ch = text[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      if (ch !== "`" && text.startsWith(ch.repeat(3), i)) {
        const j = text.indexOf(ch.repeat(3), i + 3);
        if (j < 0 || j + 3 > n) return n;
        i = j + 3;
        continue;
      }
      let j = i + 1;
      while (j < n && text[j] !== ch) j += text[j] === "\\" ? 2 : 1;
      if (j >= n) return n;
      i = j + 1;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return i;
      depth--;
    } else if (depth === 0 && (ch === ";" || ch === "\n")) return i;
    i++;
  }
  return n;
}

/** core._ld_literal_test: inLiteral(pos) — a template literal's or an f-string's text is code. */
function ldLiteralTest(text) {
  const spans = literalSpans(text).filter(([a]) => text[a] !== "`" && !(a > 0 && "fF".includes(text[a - 1]))
    && !(a > 1 && "fF".includes(text[a - 2]) && "rRbB".includes(text[a - 1])));
  const starts = spans.map(([a]) => a);
  return (pos) => {
    const k = lastAtOrBefore(starts, pos);
    return k >= 0 && pos < spans[k][1];
  };
}

/** core._ld_split_args: [start, end] of a call's arguments in `args`. */
function ldSplitArgs(args) {
  const out = [];
  let depth = 0, start = 0, i = 0;
  const n = args.length;
  while (i < n) {
    const ch = args[i];
    if (ch === '"' || ch === "'" || ch === "`") {
      const j = args.indexOf(ch, i + 1);
      if (j < 0) break;
      i = j + 1;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 0) { out.push([start, i]); start = i + 1; }
    i++;
  }
  out.push([start, n]);
  return out;
}

/** core._ld_object_spans: [start, end, address] for the values of the object literal whose '{' is at lo. */
function ldObjectSpans(text, lo, hi) {
  const close = lo + 1 + callArgs(text.slice(lo + 1, hi)).length;
  const out = [];
  for (const [a, b] of ldSplitArgs(text.slice(lo + 1, close))) {
    const part = text.slice(lo + 1 + a, lo + 1 + b);
    const key = matchIn(LD_KEY_Y, part, 0);
    if (key !== null) {
      if (matchIn(LD_FUNC_VALUE_Y, part, key[0].length) !== null) continue;   // a function (a callback): code, not data
      out.push([lo + 1 + a + key[0].length, lo + 1 + b, LD_OPTION_KEYS.has(key[1] ?? key[2])]);
    } else out.push([lo + 1 + a, lo + 1 + b, LD_OPTION_KEYS.has(pyStrip(part))]);
  }
  return out;
}

/** core._ld_process_options: [start, end] of the values of a process's options in a call's arguments text[lo:hi]. */
function ldProcessOptions(text, lo, hi) {
  const out = [];
  for (let [a, b] of ldSplitArgs(text.slice(lo, hi))) {
    a += lo;
    b += lo;
    const kw = matchIn(LD_KWARG_Y, text, a, b);
    if (kw !== null) {
      if (LD_PROCESS_KEYS.has(kw[1])) out.push([a + kw[0].length, b]);
      continue;
    }
    const stripped = pyLstrip(text.slice(a, b));
    if (stripped.startsWith("{")) {
      const start = b - stripped.length;
      const close = start + 1 + callArgs(text.slice(start + 1, b)).length;
      for (const [c, d] of ldSplitArgs(text.slice(start + 1, close))) {
        const key = matchIn(LD_KEY_Y, text, start + 1 + c, start + 1 + d);
        if (key !== null && LD_PROCESS_KEYS.has(key[1] ?? key[2])) out.push([start + 1 + c + key[0].length, start + 1 + d]);
      }
    }
  }
  return out;
}

/** core._ld_value_spans: an object literal's values, else the value whole. */
function ldValueSpans(text, lo, hi) {
  const stripped = pyLstrip(text.slice(lo, hi));
  if (stripped.startsWith("{")) return ldObjectSpans(text, hi - stripped.length, hi);
  return [[lo, hi, false]];
}

/** core._ld_arg_spans: [start, end, address] for a call's arguments text[lo:hi]. */
function ldArgSpans(text, lo, hi, addresses = 0, process = false) {
  const out = [];
  const parts = ldSplitArgs(text.slice(lo, hi));
  for (let k = 0; k < parts.length; k++) {
    const a = lo + parts[k][0], b = lo + parts[k][1];
    if (matchIn(LD_FUNC_VALUE_Y, text, a, b) !== null) continue;          // a callback: code run later, not data sent
    if (k < addresses) { out.push([a, b, true]); continue; }
    const kw = matchIn(LD_KWARG_Y, text, a, b);
    if (kw !== null) out.push([a + kw[0].length, b, LD_OPTION_KEYS.has(kw[1]) || (process && LD_PROCESS_KEYS.has(kw[1]))]);
    else if (process && pyLstrip(text.slice(a, b)).startsWith("{")) out.push([a, b, true]);
    else out.push(...ldValueSpans(text, a, b));
  }
  return out;
}

/** core._ld_bound: [parameter, start, end] the arguments `args` (a call's, at `at`) give parameters `names`. */
function ldBound(text, at, args, names) {
  const out = [];
  const parts = ldSplitArgs(args);
  for (let k = 0; k < parts.length; k++) {
    const a = at + parts[k][0], b = at + parts[k][1];
    const kw = matchIn(LD_KWARG_Y, text, a, b);
    if (kw !== null && names.includes(kw[1])) out.push([kw[1], a + kw[0].length, b]);
    else if (k < names.length) out.push([names[k], a, b]);
  }
  return out;
}

/** core._ld_names_in: the first name of `names` used in text[lo:hi] (not in a literal), else null. */
/** core._ld_word_before: the index where the run of spaces before text[i] starts (i itself when there is none). */
function ldWordBefore(text, i) {
  while (i > 0 && " \t\n".includes(text[i - 1])) i--;
  return i;
}
const LD_IDENT_CHAR_RE = /[A-Za-z0-9_$]/;
/** Does a word of words end at j in text, not inside a longer name? */
function ldWordEndsAt(text, j, words) {
  for (const word of words) {
    const k = j - word.length;
    if (k >= 0 && text.startsWith(word, k) && (k === 0 || !LD_IDENT_CHAR_RE.test(text[k - 1]))) return true;
  }
  return false;
}
/** core._ld_tested: is the value text[start:end] tested rather than used? */
function ldTested(text, start, end) {
  if (matchAt(LD_TEST_AFTER_Y, text, end) !== null) return true;
  const j = ldWordBefore(text, start);
  return (j > 0 && text[j - 1] === "!") || ldWordEndsAt(text, j, LD_TEST_BEFORE);
}
/** core._ld_defined: is the call text[start:end] (to its ')') a function's definition? */
function ldDefined(text, start, end) {
  if (text.startsWith(")", end) && matchAt(LD_BODY_Y, text, end + 1) !== null) return true;
  return ldWordEndsAt(text, ldWordBefore(text, start), ["def", "function"]);
}

function ldNamesIn(text, lo, hi, names, inLiteral) {
  for (const [at, name] of identTokens(text, lo, hi)) if (names.has(name) && !inLiteral(at)) return name;
  return null;
}

/** core._ld_outside: does text[lo:hi], a call's first argument, name a path outside the package? */
function ldOutside(text, lo, hi, reader, outside, inLiteral) {
  const first = text.slice(lo, hi);
  if (LD_OWN_FOLDER_RE.test(first)) return false;
  if (matchIn(LD_FS_ROOT_Y, first, 0) !== null) return true;
  if (reader && (matchIn(LD_ABSOLUTE_Y, first, 0) !== null || LD_HOME_RE.test(first) || LD_ABSOLUTE_IN_RE.test(first)
      || matchIn(LD_CRED_FILE_Y, first, 0) !== null)) return true;
  return outside.size > 0 && matchIn(LD_PATH_EXPR_Y, first, 0) !== null && ldNamesIn(text, lo, hi, outside, inLiteral) !== null;
}

/** core._ld_sources: [offset, end, open, kind, what] where text reads local data. */
function ldSources(text, inLiteral, outside, own) {
  const out = [];
  LD_ENV_ALL_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_ENV_ALL_G.exec(text)) !== null; k++) {
    if (k >= LD_MAX) break;
    if (inLiteral(m.index)) continue;
    const name = m.slice(1).find((g) => g !== undefined);
    let end = m.index + m[0].length;
    if (m[4] !== undefined || m[5] !== undefined) {           // a call's value: after the call
      end += callArgs(text.slice(end, cpForward(text, end, DD_ARG_SPAN))).length + 1;
    }
    if (name === undefined || ldTested(text, m.index, end)) continue;
    if (atStart(SH_IDENTITY_VAR_Y, name)) out.push([m.index, end, -1, "identity", name]);
    else if (SH_SECRET_VAR_RE.test(name) && !atStart(LD_ENV_QUIET_Y, name)) out.push([m.index, end, -1, "environment", name]);
  }
  LD_ENV_WHOLE_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_ENV_WHOLE_G.exec(text)) !== null; k++) {
    if (k >= LD_MAX) break;
    const end = m.index + m[0].length;
    if (inLiteral(m.index) || ldTested(text, m.index, end)) continue;
    const sel = matchAt(LD_ENV_SELECT_Y, text, end);
    if (sel !== null) {
      const at = end + sel[0].length;
      const cond = callArgs(text.slice(at, cpForward(text, at, DD_ARG_SPAN)));
      if (!LD_EXCLUDES_RE.test(cond) && !SH_SECRET_VAR_RE.test(cond)) continue;
    }
    out.push([m.index, end, -1, "environment", LD_WHOLE_ENV]);
  }
  LD_IDENTITY_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_IDENTITY_G.exec(text)) !== null; k++) {
    if (k >= LD_MAX) break;
    if (inLiteral(m.index)) continue;
    const end = m.index + m[0].length;
    const kind = LD_REPORT_NAMES.has(m[1]) ? "report" : "identity";
    const called = m[2] !== undefined || m[3] !== undefined;
    out.push([m.index, end, called ? end : -1, kind, m[1] || "user or host name"]);
  }
  const imported = new Map();                         // local name -> [kind, the module's name for it]
  if (text.includes("os")) {
    for (const [re, js] of [[LD_IMPORT_JS_G, true], [LD_IMPORT_PY_G, false]]) {
      re.lastIndex = 0;
      for (let m, k = 0; (m = re.exec(text)) !== null; k++) {
        if (k >= LD_MAX) break;
        const [mod, names] = js ? ["os", m[1] || m[2]] : [m[1], m[2]];
        for (const part of names.split(",")) {
          const n = matchIn(LD_IMPORT_NAME_Y, part, 0);
          if (n !== null && Object.hasOwn(LD_MODULE_NAMES[mod], n[1])) {
            const local = n[2] || n[1];
            if (!imported.has(local)) imported.set(local, [LD_MODULE_NAMES[mod][n[1]], n[1]]);
          }
        }
      }
    }
  }
  if (imported.size) {
    const uses = pyRe(DV_NAME_HEAD + "(" + [...imported.keys()].sort().map(reEscape).join("|") + String.raw`)\b(\s*\()?`, "g");
    for (let m, k = 0; (m = uses.exec(text)) !== null; k++) {
      if (k >= LD_MAX) break;
      if (inLiteral(m.index)) continue;
      const [kind, what] = imported.get(m[1]);
      const end = m.index + m[0].length;
      out.push([m.index, end, m[2] ? end : -1, kind, kind === "report" ? what : "user or host name"]);
    }
  }
  if (LD_READS_RE.test(text)) {
    LD_CALL_G.lastIndex = 0;
    for (let m, k = 0; (m = LD_CALL_G.exec(text)) !== null; k++) {
      if (k >= LD_MAX_CALLS || out.length >= LD_MAX * 3) break;
      const name = m[1];
      if (LD_NOT_READS.has(name) || inLiteral(m.index)) continue;
      const reader = LD_READERS.has(name);
      const names = reader || (m.indices[1][0] === m.index && own.has(name)) ? outside : new Set();
      const start = m.index + m[0].length;
      if (!reader && !names.size && matchAt(LD_FS_ROOT_Y, text, start) === null) continue;
      const args = callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN)));
      const first = firstArg(args);
      const lead = args.length - pyLstrip(args).length;
      if (ldOutside(text, start + lead, start + lead + first.length, reader, names, inLiteral)) {
        const plain = matchIn(LD_PLAIN_LITERAL_Y, first, 0);
        const what = plain !== null ? plain[2] : first;
        out.push([m.index, start + args.length, start, "file", cpPrefix(reader ? what : `${name}(${first})`, 60)]);
      }
      LD_CALL_G.lastIndex = m.index + m[0].length;
    }
  }
  LD_EXEC_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_EXEC_G.exec(text)) !== null; k++) {
    if (k >= LD_MAX) break;
    if (inLiteral(m.index)) continue;
    const argv = [m[2], ...[...m[3].matchAll(LD_ARGV_ITEM_G)].map((a) => a[1])];
    for (const [kind, what] of shOutputData(argv.join(" "), 0)) {
      out.push([m.index, m.index + m[0].length, m.indices[1][1], kind, what]);
      break;
    }
  }
  const metadata = LD_METADATA_NEEDLES.some((nd) => text.includes(nd));
  if (metadata || LD_PUBLIC_IP_RE.test(text)) {
    DD_FETCH_ALL_RE.lastIndex = 0;
    for (let f, k = 0; (f = DD_FETCH_ALL_RE.exec(text)) !== null; k++) {
      if (k >= LD_MAX) break;
      if (inLiteral(f.index)) continue;
      const start = f.index + f[0].length;
      const args = callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN)));
      if (metadata && LD_METADATA_RE.test(args)) {
        out.push([f.index, start + args.length, start, "credentials", "the instance's metadata"]);
      } else if (LD_PUBLIC_IP_RE.test(args)) {
        out.push([f.index, start + args.length, start, "address", "the machine's public IP address"]);
      }
      DD_FETCH_ALL_RE.lastIndex = start;
    }
  }
  return out;
}

/**
 * [offset, kind, what, inAddress] of the first send of data `text` reads from the machine, else null
 * (core.local_data_sent_at; core's comment above _LD_ENV_RE).
 */
export function localDataSentAt(text) {
  if (!LD_SEND_NEEDLES.some((nd) => text.includes(nd)) || !LD_NEEDLES.some((nd) => text.includes(nd))) return null;
  const inLiteral = ldLiteralTest(text);
  const assigns = [];                                 // [name, start, end] of what is assigned
  const arrows = [];                                  // [name, start, end] of what an arrow or a lambda returns
  DD_ASSIGN_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DD_ASSIGN_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    if (inLiteral(m.indices[1][0])) continue;
    const start = m.indices[2][0];
    const end = ldStatementEnd(text, start);
    if (matchIn(LD_FUNC_VALUE_Y, text, start, end) === null) assigns.push([m[1], start, end]);
    else {
      const body = matchIn(LD_ARROW_BODY_Y, text, start, end);
      if (body !== null) arrows.push([m[1], start + body[0].length, end]);
    }
  }
  DD_DESTRUCT_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DD_DESTRUCT_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    if (inLiteral(m.index)) continue;
    const end = ldStatementEnd(text, m.indices[2][0]);
    for (const part of m[1].split(",")) {
      const name = DD_DESTRUCT_NAME_RE.exec(pyStrip(part));
      if (name !== null) assigns.push([name[1], m.indices[2][0], end]);
    }
  }
  const plain = assigns.length;                       // (the assignments of a name itself)
  const options = [];                                 // the values given a request's option (`opts.headers = …`)
  LD_MEMBER_ASSIGN_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_MEMBER_ASSIGN_G.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    if (inLiteral(m.indices[1][0])) continue;
    const at = m.index + m[0].length;
    const end = ldStatementEnd(text, at);
    if (matchIn(LD_FUNC_VALUE_Y, text, at, end) !== null) continue;       // (a method: what it returns is its own)
    const option = [...m[2].matchAll(LD_MEMBER_G)].some((x) => LD_OPTION_KEYS.has(x[1] || x[2]));
    (option ? options : assigns).push([m[1], at, end]);
  }
  LD_COLLECT_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_COLLECT_G.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    if (inLiteral(m.indices[1][0])) continue;
    const at = m.index + m[0].length;
    assigns.push([m[1], at, at + callArgs(text.slice(at, cpForward(text, at, DD_ARG_SPAN))).length]);
  }
  const loops = [];
  DD_FOR_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = DD_FOR_ALL_RE.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    if (inLiteral(m.index)) continue;
    loops.push(m[2] !== undefined ? [m[1], m.indices[2][0], m.indices[2][1]] : [m[3], m.indices[4][0], m.indices[4][1]]);
  }
  // the names that hold a path outside the package: given one, or a path built on one
  const outside = new Set();
  for (const [name, lo, hi] of assigns.slice(0, plain)) {
    const value = pyStrip(text.slice(lo, hi));
    if (matchIn(LD_PATH_EXPR_Y, value, 0) !== null && !LD_OWN_FOLDER_RE.test(value)
        && (matchIn(LD_FS_ROOT_Y, value, 0) !== null || LD_HOME_RE.test(value))) outside.add(name);
  }
  for (let pass = 0; pass < (outside.size ? DD_PASSES : 0); pass++) {
    let grown = false;
    for (const [name, lo, hi] of assigns.slice(0, plain)) {
      if (!outside.has(name) && matchIn(LD_PATH_EXPR_Y, text, lo, hi) !== null && !searchIn(LD_OWN_FOLDER_RE, text, lo, hi)
          && ldNamesIn(text, lo, hi, outside, inLiteral) !== null) {
        outside.add(name);
        grown = true;
      }
    }
    if (!grown) break;
  }
  const funcs = [];                                   // [start, name]
  const params = new Map();                           // name -> its parameters
  LD_FUNC_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_FUNC_G.exec(text)) !== null; k++) {
    if (k >= DD_MAX_ASSIGNS) break;
    const name = m[1] || m[3] || m[5] || m[9];
    funcs.push([m.index, name]);
    const plist = [m[2], m[4], m[6], m[7], m[8], m[10]].find((g) => g !== undefined) ?? "";
    const names = [];
    for (const part of plist.split(",")) {
      const p = matchIn(LD_PARAM_Y, part, 0);
      if (p !== null && p[1] !== "self" && p[1] !== "cls") names.push(p[1]);
    }
    if (names.length && !params.has(name) && params.size < LD_MAX) params.set(name, names);
  }
  const funcStarts = funcs.map(([a]) => a);
  const callRe = params.size
    ? pyRe(DV_NAME_HEAD + "(" + [...params.keys()].sort().map(reEscape).join("|") + String.raw`)\s*\(`, "g") : null;
  const sources = ldSources(text, inLiteral, outside, new Set(funcs.map(([, name]) => name))).sort(tupleCmp);
  const metadataNames = assigns.filter(([, lo, hi]) => searchIn(LD_METADATA_RE, text, lo, hi)).map(([name]) => name);
  if (!sources.length && !metadataNames.length) return null;
  const sourceStarts = sources.map((s) => s[0]);
  const followed = new Map();                         // name -> [kind, what, through a parameter]
  const called = new Set();                           // the followed names of functions: their calls hold it
  // the path a read is given: what the read gives is the file's, not the path's
  const spans = [];
  LD_SEAL_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_SEAL_G.exec(text)) !== null; k++) {
    if (k >= LD_MAX) break;
    const start = m.index + m[0].length;
    const first = firstArg(callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN))));
    if (pyStrip(first)) spans.push([start, start + first.length]);
    LD_SEAL_G.lastIndex = start;
  }
  // and a program's options: the environment and the folder a child process is given are the program's
  LD_EXEC_SEND_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_EXEC_SEND_G.exec(text)) !== null; k++) {
    if (k >= LD_MAX) break;
    const start = m.index + m[0].length;
    if (!inLiteral(m.index)) {
      const args = callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN)));
      spans.push(...ldProcessOptions(text, start, start + args.length));
    }
    LD_EXEC_SEND_G.lastIndex = start;
  }
  spans.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const sealed = [];
  for (const [a, b] of spans) {
    if (sealed.length && a <= sealed[sealed.length - 1][1]) {
      const last = sealed[sealed.length - 1];
      last[1] = Math.max(last[1], b);
    } else sealed.push([a, b]);
  }
  const sealedStarts = sealed.map(([a]) => a);
  const isSealed = (pos) => {
    const k = lastAtOrBefore(sealedStarts, pos);
    return k >= 0 && pos < sealed[k][1];
  };
  const readIn = (spans, loose = false) => {
    for (const [lo, hi, address] of spans) {
      for (let k = firstAtOrAfter(sourceStarts, lo); k < sources.length && sources[k][0] < hi; k++) {
        const s = sources[k];
        if ((!address || loose || !LD_NOT_IN_ADDRESS.has(s[3]) || s[4] === LD_WHOLE_ENV) && !isSealed(s[0])) return [s[3], s[4], false];
      }
      if (followed.size) {
        for (const [at, name] of identTokens(text, lo, hi)) {
          const got = followed.get(name);
          if (got === undefined) continue;
          const end = at + name.length;
          if ((!address || loose || !LD_NOT_IN_ADDRESS.has(got[0]) || got[1] === LD_WHOLE_ENV)
              && !inLiteral(at) && !isSealed(at)
              && (!called.has(name) || matchAt(LD_CALLED_Y, text, end) !== null)
              && (got[1] !== LD_WHOLE_ENV || matchAt(LD_MEMBER_READ_Y, text, end) === null)
              && !ldTested(text, at, end)) return got;
        }
      }
    }
    return null;
  };
  for (const name of metadataNames) if (!followed.has(name)) followed.set(name, ["credentials", "the instance's metadata", false]);
  for (const [name, lo, hi] of assigns) {
    if (followed.has(name)) continue;
    const got = readIn(ldValueSpans(text, lo, hi));
    if (got !== null) followed.set(name, got);
  }
  for (const [, , opening, kind, what] of sources) {  // what a read gives: its callback, `with … as`, `.then(…)`
    if (opening < 0) continue;
    const args = callArgs(text.slice(opening, cpForward(text, opening, DD_ARG_SPAN)));
    for (const cb of args.matchAll(DD_ARG_CALLBACK_G)) {
      const name = cb[1] || cb[2] || cb[3];
      if (!followed.has(name) && !inLiteral(opening + cb.index)) followed.set(name, [kind, what, false]);
    }
    let pos = opening + args.length + 1;
    const as = matchAt(DD_AS_AT_RE, text, pos);
    if (as !== null && !followed.has(as[1])) followed.set(as[1], [kind, what, false]);
    for (let t = 0; t < DD_THEN_MAX; t++) {
      const h = matchAt(DD_THEN_HEAD_AT_RE, text, pos);
      if (h === null) break;
      const hEnd = h.index + h[0].length;
      const thenArgs = callArgs(text.slice(hEnd, cpForward(text, hEnd, DD_ARG_SPAN)));
      const param = DD_PARAM_AT_START_RE.exec(thenArgs);
      if (param !== null && !followed.has(param[1])) followed.set(param[1], [kind, what, false]);
      pos = hEnd + thenArgs.length + 1;
    }
  }
  const returns = [];                                 // [function, start, end] of what a function returns
  DD_RETURN_G.lastIndex = 0;
  for (let m, k = 0; (m = DD_RETURN_G.exec(text)) !== null; k++) {
    if (k >= DD_MAX_CALLS) break;
    const start = m.indices[1][0];
    const end = ldStatementEnd(text, start);
    const at = lastAtOrBefore(funcStarts, m.index);
    if (!inLiteral(m.index) && at >= 0 && matchIn(LD_FUNC_VALUE_Y, text, start, end) === null) returns.push([funcs[at][1], start, end]);
  }
  // the names given a value composed with a literal: a DNS lookup of one sends what it holds
  const composed = new Set();
  const follow = (name, got, lo, hi) => {
    followed.set(name, got);
    if (searchIn(QUOTE_CHAR_RE, text, lo, hi)) composed.add(name);
  };
  for (let pass = 0; pass < DD_PASSES; pass++) {
    let grown = false;
    for (const [name, lo, hi] of [...assigns, ...loops]) {
      if (followed.has(name)) continue;
      const got = readIn(ldValueSpans(text, lo, hi));
      if (got !== null) { follow(name, got, lo, hi); grown = true; }
    }
    for (const [name, lo, hi] of options) {
      if (followed.has(name)) continue;
      const got = readIn([[lo, hi, true]]);
      if (got !== null) { follow(name, got, lo, hi); grown = true; }
    }
    DD_CALLBACK_G.lastIndex = 0;
    for (let m, k = 0; (m = DD_CALLBACK_G.exec(text)) !== null; k++) {
      if (k >= DD_MAX_CALLS) break;
      if (followed.has(m[1]) && !followed.has(m[2]) && !inLiteral(m.index)) { followed.set(m[2], followed.get(m[1])); grown = true; }
    }
    // (what a function returns from its parameters depends on the call: not followed)
    for (const [name, lo, hi] of [...returns, ...arrows]) {
      if (followed.has(name)) continue;
      const got = readIn(ldValueSpans(text, lo, hi));
      if (got !== null && !got[2]) { follow(name, got, lo, hi); called.add(name); grown = true; }
    }
    if (callRe !== null) {                             // a function of the script's called with data: its parameters
      callRe.lastIndex = 0;
      for (let c, k = 0; (c = callRe.exec(text)) !== null; k++) {
        if (k >= LD_MAX) break;
        if (inLiteral(c.index)) continue;
        const start = c.index + c[0].length;
        const args = callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN)));
        for (const [param, lo, hi] of ldBound(text, start, args, params.get(c[1]))) {
          if (followed.has(param)) continue;
          const got = readIn(ldValueSpans(text, lo, hi));
          if (got !== null) { follow(param, [got[0], got[1], true], lo, hi); grown = true; }
        }
        callRe.lastIndex = start;
      }
    }
    if (!grown) break;
  }
  const found = [], inAddress = [];                   // sends of data; sends of what an address may hold
  const firstSend = (re, addresses, where = null, process = false, lookup = false) => {
    re.lastIndex = 0;
    for (let s, k = 0; (s = re.exec(text)) !== null; k++) {
      if (k >= LD_MAX) return;
      if (inLiteral(s.index)) continue;
      const start = s.index + s[0].length;
      const args = callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN)));
      const end = start + args.length;
      if (ldDefined(text, s.index, end)) {
        re.lastIndex = start;
        continue;
      }
      if (where !== null && !where.test(args) && !(lookup && ldNamesIn(text, start, end, composed, inLiteral) !== null)) {
        re.lastIndex = start;
        continue;
      }
      const spans = ldArgSpans(text, start, end, addresses < 0 ? args.length + 1 : addresses, process);
      let got = readIn(spans);
      if (got !== null) { found.push([s.index, got[0], got[1]]); return; }
      if (!inAddress.length) {
        got = readIn(spans, true);
        if (got !== null) inAddress.push([s.index, got[0], got[1]]);
      }
      re.lastIndex = start;
    }
  };
  firstSend(LD_SEND_G, 1);
  firstSend(LD_OPTIONS_SEND_G, 0);
  firstSend(LD_REQUEST_SEND_G, 2);
  firstSend(LD_ADDRESS_SEND_G, -1);
  firstSend(LD_LOOKUP_SEND_G, -1, QUOTE_CHAR_RE, false, true);
  firstSend(LD_EXEC_SEND_G, 0, LD_NET_PROGRAM_RE, true);
  const connections = [...new Set(assigns.slice(0, plain)
    .filter(([, lo, hi]) => searchIn(LD_CONNECTION_RE, text, lo, Math.min(hi, cpForward(text, lo, 300))))
    .map(([name]) => name))].sort();
  if (connections.length) firstSend(pyRe(DV_NAME_HEAD + "(?:" + connections.map(reEscape).join("|") + ")" + LD_WRITE_TAIL, "g"), 0);
  LD_HOST_BUILT_G.lastIndex = 0;
  for (let m, k = 0; (m = LD_HOST_BUILT_G.exec(text)) !== null; k++) {  // data resolved in a host name: sent
    if (k >= LD_MAX) break;
    const g = m[2] !== undefined ? 2 : m[3] !== undefined ? 3 : 4;
    const got = readIn([[m.indices[g][0], m.indices[g][1], true]]);
    if (got !== null) { found.push([m.index, got[0], got[1]]); break; }
  }
  if (!found.length) {                                // a connection written to as it is made: https.request(o).end(d)
    LD_CONNECTION_G.lastIndex = 0;
    for (let c, k = 0; (c = LD_CONNECTION_G.exec(text)) !== null; k++) {
      if (k >= LD_MAX || found.length) break;
      if (inLiteral(c.index)) continue;
      const start = c.index + c[0].length;
      const close = start + callArgs(text.slice(start, cpForward(text, start, DD_ARG_SPAN))).length;
      const w = matchAt(LD_WRITE_TAIL_Y, text, close + 1);
      if (w !== null) {
        const wEnd = w.index + w[0].length;
        const end = wEnd + callArgs(text.slice(wEnd, cpForward(text, wEnd, DD_ARG_SPAN))).length;
        const got = readIn(ldArgSpans(text, wEnd, end));
        if (got !== null) found.push([c.index, got[0], got[1]]);
      }
      LD_CONNECTION_G.lastIndex = start;
    }
  }
  if (found.length) { const [at, kind, what] = tupleMin(found); return [at, kind, what, false]; }
  if (inAddress.length) { const [at, kind, what] = tupleMin(inAddress); return [at, kind, what, true]; }
  return null;
}

// ---- commands a script runs, read as programs (0.1.8; core's comment above _SH_EXEC_LINE_RE) ----
const SH_EXEC_LINE_SRC = String.raw`\b(?:system|popen|execSync|exec|getoutput|getstatusoutput|run|call|check_call|check_output|Popen)\s*\(\s*`
  + String.raw`(?=[rbuRBUfF]{0,2}["'` + "`" + String.raw`]|[A-Za-z_$])`
  + String.raw`|\b(?:spawn|spawnSync|execFile|execFileSync|run|call|check_call|check_output|Popen)\s*\(\s*[\[(]?\s*`
  + String.raw`["'](?:/usr)?(?:/bin/)?(?:ba|z|da|k)?sh["']\s*,\s*[\[(]?\s*["']-c["']\s*,\s*(?=[rbuRBUfF]{0,2}["'` + "`" + String.raw`])`;
const SH_EXEC_LINE_G = pyRe(SH_EXEC_LINE_SRC, "g");
const SH_EXEC_MAX = 50, SH_CONCAT_MAX = 20;
const SH_ESCAPES = new Map([["n", "\n"], ["t", "\t"], ["r", "\r"], ["0", "\x00"], ["v", "\v"], ["f", "\f"], ["b", "\b"]]);
const SH_EXEC_NEEDLES = ["curl", "wget", "nc ", "ncat", "netcat", "socat", "telnet", "nslookup", "dig ", "host ", "ping"];

/** core._sh_literal_at: [value, end] of the string literal at text[i] (escapes decoded, holes \x02), else null. */
function shLiteralAt(text, i) {
  let j = i;
  while (j < text.length && j - i < 2 && "rbuRBUfF".includes(text[j])) j++;
  const prefix = text.slice(i, j).toLowerCase();
  i = j;
  if (i >= text.length || !"\"'`".includes(text[i])) return null;
  const q = text[i];
  const triple = q !== "`" && text.startsWith(q.repeat(3), i);
  const close = triple ? q.repeat(3) : q;
  const raw = prefix.includes("r"), fmt = prefix.includes("f"), tpl = q === "`";
  const out = [];
  let k = i + close.length, cp = close.length;         // cp: code points from the quote to k
  const n = text.length;
  const more = () => k < n && cp < HOOK_MAX_CHARS;
  const step = () => {                                 // the code point at k, and past it
    const c = text.charCodeAt(k);
    const w = c >= 0xd800 && c <= 0xdbff && k + 1 < n && (text.charCodeAt(k + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
    const s = text.slice(k, k + w);
    k += w;
    cp++;
    return s;
  };
  while (more()) {
    if (text.startsWith(close, k)) return [out.join(""), k + close.length];
    const ch = text[k];
    if (ch === "\n" && !triple && !tpl) return null;
    if (ch === "\\" && k + 1 < n && cp + 1 < HOOK_MAX_CHARS) {
      k++;
      cp++;
      const nxt = step();
      out.push(raw ? "\\" + nxt : (nxt === "\n" ? "" : (SH_ESCAPES.get(nxt) ?? nxt)));
      continue;
    }
    if ((tpl && text.startsWith("${", k)) || (fmt && ch === "{" && !text.startsWith("{{", k))) {
      let depth = 1;
      const w = tpl ? 2 : 1;
      k += w;
      cp += w;
      while (more() && depth) {
        const c = text[k];
        depth += c === "{" ? 1 : c === "}" ? -1 : 0;
        step();
      }
      out.push("\x02");
      continue;
    }
    if (fmt && (text.startsWith("{{", k) || text.startsWith("}}", k))) {
      out.push(ch);
      k += 2;
      cp += 2;
      continue;
    }
    out.push(step());
  }
  return null;
}

/** core._sh_literal_value: the value of the string literal at text[i], else null (exported for the parity tests). */
export function shLiteralValue(text, i) {
  const got = shLiteralAt(text, i);
  return got === null ? null : got[0];
}

/** core._sh_command_value: the command line an exec call's argument at text[i] builds (literals and names
 * given one joined with +), else null. */
function shCommandValue(text, i, values) {
  const parts = [];
  const n = text.length;
  const skip = () => { while (i < n && (text[i] === " " || text[i] === "\t" || text[i] === "\n")) i++; };
  while (parts.length < SH_CONCAT_MAX) {
    skip();
    const got = shLiteralAt(text, i);
    if (got !== null) {
      parts.push(got[0]);
      i = got[1];
    } else {
      const name = matchAt(IDENT_TOKEN_Y, text, i);
      if (name === null) break;
      const value = values.get(name[0]);
      if (value === undefined && !parts.length) return null;
      parts.push(value === undefined ? "\x02" : value);
      i = name.index + name[0].length;
    }
    skip();
    if (i >= n || text[i] !== "+") break;
    i++;
  }
  return parts.join("") || null;
}

/** core._exec_command_flows: [offset, reason] of what each command line text hands a shell gives. */
function execCommandFlows(text) {
  if (!SH_EXEC_NEEDLES.some((nd) => text.includes(nd))) return [];
  const out = [], walk = { commands: 0, complete: true };
  for (const [at, cmd] of execCommandLines(text)) {
    if (pipesDownloadToShell(cmd)) out.push([at, "pipes a download into a shell"]);
    if (cmd.split("\n").some(runsSubstitutedDownload)) out.push([at, DL_CATEGORY_REASON.run]);
    for (const r of shReasons(cmd, 0, true, walk)) out.push([at, r]);
  }
  return out;
}

let execLinesMemo = [null, null];
/**
 * core._exec_command_lines: [offset, command line] — what each exec call of `text` is handed as a command line
 * (a string literal, a name given one, or such pieces joined), and where; at most SH_EXEC_MAX.
 */
function execCommandLines(text) {
  if (execLinesMemo[0] === text) return execLinesMemo[1];
  const out = [];
  let values = null;                                   // name -> the string literal it is given
  SH_EXEC_LINE_G.lastIndex = 0;
  for (let m; (m = SH_EXEC_LINE_G.exec(text)) !== null;) {
    if (out.length >= SH_EXEC_MAX) break;
    const end = m.index + m[0].length;
    if (values === null) {
      values = new Map();
      DD_ASSIGN_ALL_RE.lastIndex = 0;
      for (let a, k = 0; (a = DD_ASSIGN_ALL_RE.exec(text)) !== null; k++) {
        if (k >= DD_MAX_ASSIGNS) break;
        const got = shLiteralAt(text, a.indices[2][0] + (a[2].length - pyLstrip(a[2]).length));
        if (got !== null && !values.has(a[1])) values.set(a[1], got[0]);
      }
    }
    const cmd = shCommandValue(text, end, values);
    if (cmd) out.push([m.index, cmd]);
    SH_EXEC_LINE_G.lastIndex = end;
  }
  execLinesMemo = [text, out];
  return out;
}

/** The reasons the command lines text hands a shell give (core.exec_command_reasons). */
export function execCommandReasons(text) {
  const reasons = [];
  for (const [, r] of execCommandFlows(text)) if (!reasons.includes(r)) reasons.push(r);
  return reasons;
}

// ---- persistence targets (0.1.7; core's comment above _PERSIST_AGENT_SRC) ----
// Where the 2025-26 worms made themselves stay: an AI agent's or editor's
// auto-run settings, a GitHub Actions workflow, an editor extension, a
// self-hosted runner; the shortcuts of programs on the machine. Reasons of
// the install-script test; a workflow that dumps every secret is one at
// import time too.
const PERSIST_AGENT_SRC =
  String.raw`(?:\.(?:claude|gemini)[/\\]settings(?:\.local)?|\.vscode[/\\](?:tasks|mcp)|\.cursor[/\\](?:hooks|mcp)` +
  String.raw`|(?<![\w.-])\.(?:mcp|claude))\.json(?![\w.-])`;
const PERSIST_AGENT_SPLIT_SRC =
  String.raw`["'` + "`" + String.raw`]\.(claude|gemini|vscode|cursor)["'` + "`" + String.raw`]\s{0,20}[,+/]\s{0,20}["'` + "`" +
  String.raw`](settings(?:\.local)?|tasks|hooks|mcp)\.json["'` + "`" + String.raw`]`;
const PERSIST_AGENT_PAIRS = new Map([["claude", ["settings", "settings.local"]], ["gemini", ["settings"]],
  ["vscode", ["tasks", "mcp"]], ["cursor", ["hooks", "mcp"]]]);
const PERSIST_WORKFLOW_SRC = String.raw`\.github[/\\]workflows\b|["'` + "`" + String.raw`]\.github["'` + "`" +
  String.raw`]\s{0,20}[,+/]\s{0,20}["'` + "`" + String.raw`]workflows\b`;
const EDITOR_DIRS = String.raw`(?:vscode(?:-insiders|-oss|-server)?|cursor|windsurf|vscodium|positron)`;
const PERSIST_EXT_DIR_SRC =
  String.raw`[/\\]\.` + EDITOR_DIRS + String.raw`[/\\]extensions\b` +
  String.raw`|["'` + "`" + String.raw`]\.` + EDITOR_DIRS + String.raw`["'` + "`" + String.raw`]\s{0,20}[,+/]\s{0,20}` +
  String.raw`["'` + "`" + String.raw`]extensions["'` + "`" + String.raw`]`;
const PERSIST_WRITE_SRC =
  String.raw`\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|outputFileSync|outputFile` +
  String.raw`|outputJsonSync|outputJson|writeJsonSync|writeJson|copyFileSync|copyFile|cpSync|renameSync|symlinkSync` +
  String.raw`|write_text|write_bytes|createOrUpdateFileContents)\s*\(|\bjson\.dump\s*\(|\bshutil\.(?:copy\w*|move)\s*\(` +
  String.raw`|\bopen\s*\([^()\n]{0,300}?["'][wax]b?\+?["']`;
const PERSIST_SHELL_WRITE_SRC =
  String.raw`>|\b(?:tee|cp|mv|install|ln|copy|xcopy)\s|\b(?:Set-Content|Out-File|Add-Content|Copy-Item|New-Item)\b` +
  String.raw`|\bgit\s+(?:add|commit)\b`;
const PERSIST_EXT_INSTALL_SRC = String.raw`--install-extension\b`;
const PERSIST_EXT_CLI_SRC =
  String.raw`(?:(?<![^\n])|[;&|(])[ \t]*(?:sudo[ \t]+)?(?:code|code-insiders|codium|cursor|windsurf|positron)(?:\.cmd|\.exe)?` +
  String.raw`[ \t]`;
const PERSIST_RUNNER_SRC = String.raw`actions/runner/releases|\bactions-runner-(?:linux|osx|win)-`;
const PERSIST_RUNNER_CONFIG_SRC = String.raw`\bconfig\.(?:sh|cmd)\b`;
const PERSIST_RUNNER_ARG_SRC = String.raw`--(?:token|url)\b`;
const SECRETS_DUMP_SRC = String.raw`\btoJSON\s*\(\s*secrets\s*\)`;
const PERSIST_AGENT_RE = pyRe(PERSIST_AGENT_SRC, "g");
const PERSIST_AGENT_SPLIT_RE = pyRe(PERSIST_AGENT_SPLIT_SRC, "g");
const PERSIST_WORKFLOW_RE = pyRe(PERSIST_WORKFLOW_SRC, "g");
const PERSIST_EXT_DIR_RE = pyRe(PERSIST_EXT_DIR_SRC, "g");
const PERSIST_WRITE_RE = pyRe(PERSIST_WRITE_SRC);
const PERSIST_SHELL_WRITE_RE = pyRe(PERSIST_SHELL_WRITE_SRC);
const PERSIST_EXT_INSTALL_RE = pyRe(PERSIST_EXT_INSTALL_SRC);
const PERSIST_EXT_CLI_RE = pyRe(PERSIST_EXT_CLI_SRC, "g");
const PERSIST_RUNNER_RE = pyRe(PERSIST_RUNNER_SRC);
const PERSIST_RUNNER_CONFIG_RE = pyRe(PERSIST_RUNNER_CONFIG_SRC, "g");
const PERSIST_RUNNER_ARG_RE = pyRe(PERSIST_RUNNER_ARG_SRC);
const SECRETS_DUMP_RE = pyRe(SECRETS_DUMP_SRC, "i");
const PERSIST_SECRETS_DUMP_G = pyRe(SECRETS_DUMP_SRC, "gi");
const PERSIST_MAX_LINES = 100;

/** posixpath.normpath of a relative path. */
function normpathRel(path) {
  const comps = [];
  for (const c of path.split("/")) {
    if (c === "" || c === ".") continue;
    if (c !== ".." || !comps.length || comps[comps.length - 1] === "..") comps.push(c);
    else comps.pop();
  }
  return comps.join("/") || ".";
}

/**
 * A hook's `target` joined with the directory `base` (relative to the scan
 * root), normalized; null when it is absolute or leaves the scan root.
 * Twin of core._tree_join.
 */
export function treeJoin(base, target) {
  target = target.replaceAll("\\", "/");
  if (target.startsWith("/") || /^[A-Za-z]:/.test(target)) return null;
  const joined = normpathRel(`${base || "."}/${target}`);
  if (joined === "." || joined === ".." || joined.startsWith("../")) return null;
  return joined;
}

/** re.search(text, pos) of a global pattern: the match at or after pos, or null. */
function searchFrom(re, text, pos = 0) {
  re.lastIndex = pos;
  return re.exec(text);
}

/** The first AI-agent or editor settings file text names, or null (core._persist_agent_file). */
function persistAgentFile(text) {
  const m = searchFrom(PERSIST_AGENT_RE, text);
  let found = m ? [m.index, m[0].replaceAll("\\", "/")] : null;
  PERSIST_AGENT_SPLIT_RE.lastIndex = 0;
  for (let k = 0, s; (s = PERSIST_AGENT_SPLIT_RE.exec(text)) !== null; k++) {
    if (k >= PERSIST_MAX_LINES || (found !== null && s.index > found[0])) break;
    if (PERSIST_AGENT_PAIRS.get(s[1]).includes(s[2])) {
      found = [s.index, `.${s[1]}/${s[2]}.json`];
      break;
    }
  }
  return found === null ? null : found[1];
}

/** A shell write on a line on which targetRe matches (core._shell_writes). */
function shellWrites(text, targetRe) {
  let m = searchFrom(targetRe, text);
  for (let lines = 0; m !== null && lines < PERSIST_MAX_LINES; lines++) {
    const start = text.lastIndexOf("\n", m.index) + 1;
    let end = text.indexOf("\n", m.index + m[0].length);
    if (end < 0) end = text.length;
    if (PERSIST_SHELL_WRITE_RE.test(text.slice(start, end))) return true;
    m = searchFrom(targetRe, text, end);
  }
  return false;
}

/**
 * A line on which firstRe matches and thenRe after it (core._after_on_line);
 * each line is read once. thenRe (no look-behind) is tested on the rest of
 * the line, as Python's pattern.search(text, pos, endpos) reads it.
 */
function afterOnLine(text, firstRe, thenRe) {
  let m = searchFrom(firstRe, text);
  while (m !== null) {
    const from = m.index + m[0].length;
    let end = text.indexOf("\n", from);
    if (end < 0) end = text.length;
    if (thenRe.test(text.slice(from, end))) return true;
    m = searchFrom(firstRe, text, end);
  }
  return false;
}

/** Does text name a target and write it (core._writes_named)? */
const writesNamed = (text, targetRe) => searchFrom(targetRe, text) !== null
  && (PERSIST_WRITE_RE.test(text) || shellWrites(text, targetRe));

/** A GitHub Actions workflow that hands every secret to a job, and the workflows directory (core.dumps_workflow_secrets). */
export function dumpsWorkflowSecrets(text) {
  return SECRETS_DUMP_RE.test(text) && searchFrom(PERSIST_WORKFLOW_RE, text) !== null;
}

// The shortcuts of programs on the machine rewritten (core's comment above _PERSIST_SHORTCUT_RE)
const PERSIST_SHORTCUT_SRC = String.raw`\bCreateShortcut\b|\.lnk\b`;
const PERSIST_SHORTCUT_RE = pyRe(PERSIST_SHORTCUT_SRC);
const SHORTCUT_FOUND_SRC = String.raw`['"` + "`" + String.raw`]\*?\.lnk['"` + "`" + "]";
const SHORTCUT_FOUND_RE = pyRe(SHORTCUT_FOUND_SRC, "i");
const SHORTCUT_SET_SRC = String.raw`\.\s*(?:Arguments|TargetPath)\s*\+?=(?!=)`;
const SHORTCUT_SET_RE = pyRe(SHORTCUT_SET_SRC);

// ---- programs set to start at login or boot (0.1.8; core's comment above _SVC_SYSTEMD_DIR_SRC) ----
// A systemd unit, a launchd agent, a cron job, a Windows Run key, a scheduled
// task, the Startup folder, an XDG autostart entry: each a place and a way to
// fill it in one install-time text.
const Q = "[\"'`]";
const SVC_SYSTEMD_DIR_SRC =
  String.raw`(?<!/run/)systemd[/\\](?:user|system)(?![\w.-])` +
  String.raw`|${Q}systemd${Q}\s{0,20}[,+/]\s{0,20}${Q}(?:user|system)${Q}`;
const SVC_UNIT_SRC = String.raw`ExecStart\s{0,20}=`;
const SVC_SYSTEMCTL_SRC =
  String.raw`\bsystemctl(?:[ \t]+-{1,2}[\w-]+)*[ \t]+(?:enable|reenable|link)\b` +
  String.raw`|${Q}systemctl${Q}\s{0,20},\s{0,20}(?:${Q}-{1,2}[\w-]+${Q}\s{0,20},\s{0,20}){0,4}${Q}` +
  String.raw`(?:enable|reenable|link)${Q}`;
const SVC_LAUNCHD_DIR_SRC = String.raw`\bLaunch(?:Agents|Daemons)\b`;
const SVC_PLIST_SRC = String.raw`\b(?:RunAtLoad|KeepAlive|ProgramArguments|StartInterval)\b`;
const SVC_LAUNCHCTL_SRC =
  String.raw`\blaunchctl(?:[ \t]+-{1,2}[\w-]+)*[ \t]+(?:load|bootstrap|enable|submit)\b` +
  String.raw`|${Q}launchctl${Q}\s{0,20},\s{0,20}(?:${Q}-{1,2}[\w-]+${Q}\s{0,20},\s{0,20}){0,4}${Q}` +
  String.raw`(?:load|bootstrap|enable|submit)${Q}`;
const SVC_CRONTAB_SRC =
  String.raw`\|[ \t]*(?:sudo[ \t]+)?crontab(?:[ \t]+-(?![\w-])|[ \t]*(?![^"'` + "`" + String.raw`)\n;&>]))` +
  String.raw`|\bcrontab[ \t]+(?:-(?![\w-])|["']?(?:[/~$]|\.\.?/))` +
  String.raw`|${Q}crontab${Q}\s{0,20},\s{0,20}(?!${Q}-[lre]${Q})[\w$"'` + "`" + "]";
const SVC_PYCRON_SRC = String.raw`\bCronTab\s{0,20}\(`;
const SVC_PYCRON_WRITE_SRC = String.raw`\.write\s{0,20}\(`;
const SVC_CRON_DIR_SRC =
  String.raw`/etc/cron\.(?:d|hourly|daily|weekly|monthly)(?![\w.-])|/etc/crontab(?![\w.-])|/var/spool/cron(?![\w.-])`;
const SVC_RUNKEY_SRC = String.raw`CurrentVersion(?:\\{1,2}|/)Run(?:Once(?:Ex)?|Services(?:Once)?)?(?!\w)`;
const SVC_REG_WRITE_SRC =
  String.raw`\breg(?:\.exe)?${Q}?(?:[ \t]+|\s{0,20},\s{0,20}\[?\s{0,20}${Q})add\b|\b(?:New|Set)-ItemProperty\b` +
  String.raw`|\bSetValueEx\b|\bSetValue\s{0,20}\(|\bputValue\b|\bRegSetValue|\bREG_(?:EXPAND_)?SZ\b` +
  String.raw`|\bKEY_(?:SET_VALUE|WRITE|ALL_ACCESS)\b`;
const SVC_SCHTASKS_SRC = String.raw`\bschtasks(?:\.exe)?${Q}?(?:[ \t]+|\s{0,20},\s{0,20}\[?\s{0,20}${Q})[/-]create\b`;
const SVC_TASK_API_SRC = String.raw`\bRegister-ScheduledTask\b`;
const SVC_TASK_COM_SRC = String.raw`\bSchedule\.Service\b`;
const SVC_TASK_REGISTER_SRC = String.raw`\bRegisterTaskDefinition\b`;
const SVC_STARTUP_SRC =
  String.raw`Start[ ]?Menu[/\\]{1,2}Programs[/\\]{1,2}Startup(?!\w)|\bshell:(?:common[ ]?)?startup\b` +
  String.raw`|\bCSIDL_(?:COMMON_)?STARTUP\b|\bSpecialFolder\.(?:Common)?Startup\b|\bwinshell\.startup\s{0,20}\(` +
  String.raw`|${Q}Programs${Q}\s{0,20}[,+/]\s{0,20}${Q}Startup${Q}`;
const SVC_AUTOSTART_SRC =
  String.raw`\.config[/\\]autostart(?![\w.-])|/etc/xdg/autostart(?![\w.-])` +
  String.raw`|${Q}\.config${Q}\s{0,20}[,+/]\s{0,20}${Q}autostart${Q}`;
const SVC_CMD_START_SRC =
  String.raw`(?:(?<![^\n])|[;&|(])[ \t]*(?:sudo[ \t]+)?` +
  String.raw`(?:systemctl|launchctl|crontab|[Ss][Cc][Hh][Tt][Aa][Ss][Kk][Ss](?:\.[Ee][Xx][Ee])?)(?![\w.-])`;
const SVC_SYSTEMD_DIR_RE = pyRe(SVC_SYSTEMD_DIR_SRC, "g");
const SVC_UNIT_RE = pyRe(SVC_UNIT_SRC);
const SVC_SYSTEMCTL_RE = pyRe(SVC_SYSTEMCTL_SRC);
const SVC_LAUNCHD_DIR_RE = pyRe(SVC_LAUNCHD_DIR_SRC, "g");
const SVC_PLIST_RE = pyRe(SVC_PLIST_SRC);
const SVC_LAUNCHCTL_RE = pyRe(SVC_LAUNCHCTL_SRC);
const SVC_CRONTAB_RE = pyRe(SVC_CRONTAB_SRC);
const SVC_PYCRON_RE = pyRe(SVC_PYCRON_SRC);
const SVC_PYCRON_WRITE_RE = pyRe(SVC_PYCRON_WRITE_SRC);
const SVC_CRON_DIR_RE = pyRe(SVC_CRON_DIR_SRC, "g");
const SVC_RUNKEY_RE = pyRe(SVC_RUNKEY_SRC, "gi");
const SVC_REG_WRITE_RE = pyRe(SVC_REG_WRITE_SRC, "i");
const SVC_SCHTASKS_RE = pyRe(SVC_SCHTASKS_SRC, "i");
const SVC_TASK_API_RE = pyRe(SVC_TASK_API_SRC, "i");
const SVC_TASK_COM_RE = pyRe(SVC_TASK_COM_SRC, "i");
const SVC_TASK_REGISTER_RE = pyRe(SVC_TASK_REGISTER_SRC);
const SVC_STARTUP_RE = pyRe(SVC_STARTUP_SRC, "gi");
const SVC_AUTOSTART_RE = pyRe(SVC_AUTOSTART_SRC, "g");
const SVC_CMD_START_RE = pyRe(SVC_CMD_START_SRC);
const SVC_LINE_MAX = 1000;
const SVC_RUNKEY_SPAN = 400;

/** A write call or a shell write on a short line on which targetRe matches (core._writes_on_line). */
function writesOnLine(text, targetRe) {
  let m = searchFrom(targetRe, text);
  for (let lines = 0; m !== null && lines < PERSIST_MAX_LINES; lines++) {
    const start = text.lastIndexOf("\n", m.index) + 1;
    let end = text.indexOf("\n", m.index + m[0].length);
    if (end < 0) end = text.length;
    const line = text.slice(start, end);
    if (!cpLongerThan(line, SVC_LINE_MAX) && (PERSIST_WRITE_RE.test(line) || PERSIST_SHELL_WRITE_RE.test(line))) return true;
    m = searchFrom(targetRe, text, end);
  }
  return false;
}

/** A registry write within SVC_RUNKEY_SPAN code points of a Run key (core._run_key_written). */
function runKeyWritten(text) {
  SVC_RUNKEY_RE.lastIndex = 0;
  for (let k = 0, m; (m = SVC_RUNKEY_RE.exec(text)) !== null; k++) {
    if (k >= PERSIST_MAX_LINES) break;
    const end = m.index + m[0].length;
    if (SVC_REG_WRITE_RE.test(text.slice(cpBack(text, m.index, SVC_RUNKEY_SPAN), cpForward(text, end, SVC_RUNKEY_SPAN)))) {
      return true;
    }
    if (m[0].length === 0) SVC_RUNKEY_RE.lastIndex++;
  }
  return false;
}

/** The reasons text sets a program to start at login or boot. Twin of core.service_reasons. */
export function serviceReasons(text) {
  const reasons = [];
  let runs = null;
  const runContext = () => {
    if (runs === null) runs = EXEC_CALL_RE.test(text) || SVC_CMD_START_RE.test(text);
    return runs;
  };
  const writes = PERSIST_WRITE_RE.test(text);
  if ((searchFrom(SVC_SYSTEMD_DIR_RE, text) !== null
       && ((writes && SVC_UNIT_RE.test(text)) || writesOnLine(text, SVC_SYSTEMD_DIR_RE)))
      || (SVC_SYSTEMCTL_RE.test(text) && runContext())) {
    reasons.push("installs a systemd service");
  }
  if ((searchFrom(SVC_LAUNCHD_DIR_RE, text) !== null
       && ((writes && SVC_PLIST_RE.test(text)) || writesOnLine(text, SVC_LAUNCHD_DIR_RE)))
      || (SVC_LAUNCHCTL_RE.test(text) && runContext())) {
    reasons.push("installs a launchd agent or daemon");
  }
  if ((SVC_CRONTAB_RE.test(text) && runContext())
      || (SVC_PYCRON_RE.test(text) && SVC_PYCRON_WRITE_RE.test(text))
      || writesOnLine(text, SVC_CRON_DIR_RE)) {
    reasons.push("adds a cron job");
  }
  if (runKeyWritten(text)) reasons.push("adds a program to a Windows Run key");
  if ((SVC_SCHTASKS_RE.test(text) && runContext()) || SVC_TASK_API_RE.test(text)
      || (SVC_TASK_COM_RE.test(text) && SVC_TASK_REGISTER_RE.test(text))) {
    reasons.push("creates a Windows scheduled task");
  }
  if (searchFrom(SVC_STARTUP_RE, text) !== null
      && (writes || PERSIST_SHORTCUT_RE.test(text) || shellWrites(text, SVC_STARTUP_RE))) {
    reasons.push("puts a program in the Windows Startup folder");
  }
  if (searchFrom(SVC_AUTOSTART_RE, text) !== null && (writes || shellWrites(text, SVC_AUTOSTART_RE))) {
    reasons.push("adds a desktop autostart entry");
  }
  return reasons;
}

/** The persistence-target reasons of the install-script test. Twin of core.persistence_reasons. */
export function persistenceReasons(text) {
  const reasons = [];
  const agent = persistAgentFile(text);
  if (agent !== null && (PERSIST_WRITE_RE.test(text) || shellWrites(text, PERSIST_AGENT_RE)
      || shellWrites(text, PERSIST_AGENT_SPLIT_RE))) {
    reasons.push(`writes an AI agent's or editor's auto-run settings (${agent})`);
  }
  if (dumpsWorkflowSecrets(text)) {
    reasons.push("carries a GitHub Actions workflow that dumps every repository secret");
  } else if (searchFrom(PERSIST_WORKFLOW_RE, text) !== null
      && (writesNamed(text, PERSIST_WORKFLOW_RE) || text.includes("/contents/"))) {
    reasons.push("writes a GitHub Actions workflow");
  }
  const install = PERSIST_EXT_INSTALL_RE.test(text);
  if ((install && (EXEC_CALL_RE.test(text) || afterOnLine(text, PERSIST_EXT_CLI_RE, PERSIST_EXT_INSTALL_RE)))
      || writesNamed(text, PERSIST_EXT_DIR_RE)) {
    reasons.push("installs an editor extension");
  }
  if (PERSIST_RUNNER_RE.test(text) || afterOnLine(text, PERSIST_RUNNER_CONFIG_RE, PERSIST_RUNNER_ARG_RE)) {
    reasons.push("registers the machine as a GitHub Actions self-hosted runner");
  }
  if (SHORTCUT_FOUND_RE.test(text) && text.includes("CreateShortcut") && SHORTCUT_SET_RE.test(text)) {
    reasons.push("rewrites the shortcuts of programs on the machine");
  }
  reasons.push(...serviceReasons(text));
  return reasons;
}

// ---- code that publishes packages (SC-SELF-PUBLISH, 0.1.8; core's comment above _PUBLISH_CMD_SRC) ----
// A publish command an exec call runs, an assignment to an object's name, and
// a write to package.json that names the object: code that renames its package
// and publishes it (the registry floods). An install script that publishes, or
// collects npm access tokens, fails the install-script test (the worms).
const BT = "`";
const PUBLISH_CMD_SRC =
  String.raw`\b(?:exec|execSync|execa|execaSync|execFile|execFileSync|spawn|spawnSync|system|popen|Popen|run|call` +
  String.raw`|check_call|check_output|getoutput)\s*\(\s*(?:\[\s*)?["'` + BT + String.raw`](?:[^"'` + BT + String.raw`\n]{0,80}?(?:&&|;|\|\|)\s*)?` +
  String.raw`(?:npx\s+)?(?:npm|pnpm|yarn|bun)(?:\.cmd)?(?:["'` + BT + String.raw`]\s*,\s*(?:\[\s*)?["'` + BT + String.raw`]|\s+)publish\b`;
const NAME_ASSIGN_SRC = String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\.\s*name|\[\s*["']name["']\s*\])\s*=(?![=>])`;
const MANIFEST_WRITE_SRC =
  String.raw`\b(?:writeFileSync|writeFile|outputJsonSync|outputJson|writeJsonSync|writeJson|outputFileSync` +
  String.raw`|outputFile|write_text|dump)\s*\(`;
const JS_IDENT_SRC = String.raw`(?<![\w$.])[A-Za-z_$][\w$]*`;
const NPM_TOKEN_READ_SRC =
  String.raw`\bnpm\s+config\s+get\s+[^\n"'` + BT + String.raw`;|&]{0,200}?_auth|\.npmrc\b[\s\S]{0,400}?_authToken` +
  String.raw`|_authToken[\s\S]{0,400}?\.npmrc\b`;
const PUBLISH_CMD_RE = pyRe(PUBLISH_CMD_SRC);
const NAME_ASSIGN_G = pyRe(NAME_ASSIGN_SRC, "g");
const MANIFEST_WRITE_G = pyRe(MANIFEST_WRITE_SRC, "g");
const JS_IDENT_G = pyRe(JS_IDENT_SRC, "g");
const NPM_TOKEN_READ_RE = pyRe(NPM_TOKEN_READ_SRC);
const SELF_PUB_SPAN = 300, SELF_PUB_MAX = 200;

/** The UTF-16 offset of the publish command of code that renames its package and publishes it, else -1. Twin of core.self_publish_at. */
export function selfPublishAt(text) {
  if (!text.includes("publish") || !text.includes("package.json")) return -1;
  const pub = PUBLISH_CMD_RE.exec(text);
  if (pub === null) return -1;
  const names = new Set();
  let k = 0;
  for (const m of text.matchAll(NAME_ASSIGN_G)) {
    if (k++ >= SELF_PUB_MAX) break;
    names.add(m[1]);
  }
  if (!names.size) return -1;
  k = 0;
  for (const w of text.matchAll(MANIFEST_WRITE_G)) {
    if (k++ >= SELF_PUB_MAX) break;
    const end = w.index + w[0].length;
    const args = text.slice(end, cpForward(text, end, SELF_PUB_SPAN));
    if (!args.includes("package.json") && !text.slice(cpBack(text, w.index, SELF_PUB_SPAN), w.index).includes("package.json")) continue;
    for (const m of args.matchAll(JS_IDENT_G)) if (names.has(m[0])) return pub.index;
  }
  return -1;
}

// ---- an install script that runs a DLL (0.1.8; core's comment above _DLL_LOADER_SRC) ----
const DLL_LOADER_SRC = String.raw`\b(?:rundll32|regsvr32)(?:\.exe)?\b`;
const DLL_NAME_SRC = String.raw`(?<![\w.\-])[\w.\-]*\.dll\b`;
const STRING_JOIN_SRC = String.raw`["']\s*\+\s*["']`;
const DLL_LOADER_RE = pyRe(DLL_LOADER_SRC, "i");
const DLL_NAME_G = pyRe(DLL_NAME_SRC, "gi");
const STRING_JOIN_G = pyRe(STRING_JOIN_SRC, "g");
const SYSTEM_DLLS = new Set(["url.dll", "shell32.dll", "user32.dll", "ieframe.dll", "dfshim.dll", "advpack.dll",
  "printui.dll", "keymgr.dll", "powrprof.dll", "zipfldr.dll", "shdocvw.dll", "shimgvw.dll"]);

/** `text` with adjacent string literals joined ('chi' + 'ld' reads 'child'). Twin of core.join_string_pieces. */
export function joinStringPieces(text) {
  return text.includes("+") ? text.replace(STRING_JOIN_G, "") : text;
}

/** The DLL `text` runs with rundll32 or regsvr32 (not one of Windows' own ordinary ones), else null. Twin of core.runs_dll. */
export function runsDll(text) {
  if (!text.includes("32") && !text.includes("+")) return null;
  for (const view of [text, joinStringPieces(text)]) {
    if (!DLL_LOADER_RE.test(view)) continue;
    for (const m of view.matchAll(DLL_NAME_G)) {
      let name = m[0];
      name = name.slice(name.lastIndexOf("/") + 1);
      name = name.slice(name.lastIndexOf("\\") + 1).toLowerCase();
      if (name && name !== ".dll" && !SYSTEM_DLLS.has(name)) return name;
    }
  }
  return null;
}

// ---- names in strings a file decodes as it runs (0.1.8; core's comment above _DV_MAX_LITERAL) ----
const DV_MAX_LITERAL = 400, DV_BODY = 400, DV_MAX_HELPERS = 8, DV_MAX_ARRAYS = 16, DV_MAX_CHARS = 4_000_000;
const DV_NOTE = " (in strings it decodes as it runs)";
const DV_LIT = String.raw`(?:'(?P<a>[^'\\\n]{1,400})'|"(?P<b>[^"\\\n]{1,400})"|` + BT + String.raw`(?P<c>[^` + BT + String.raw`\\\n$]{1,400})` + BT + ")";
const DV_JOIN_SRC = String.raw`'[ \t]*\+[ \t]*'|"[ \t]*\+[ \t]*"`;
const DV_BUFFER_SRC = String.raw`\bBuffer[ \t]*\.[ \t]*from[ \t]*\([ \t]*` + DV_LIT
  + String.raw`[ \t]*,[ \t]*['"` + BT + String.raw`](?P<enc>hex|base64)['"` + BT + String.raw`][ \t]*\)[ \t]*\.[ \t]*toString[ \t]*\([ \t]*`
  + String.raw`(?:['"` + BT + String.raw`](?:utf-?8|ascii|latin1|binary)['"` + BT + String.raw`])?[ \t]*\)`;
const DV_ATOB_SRC = String.raw`(?<![\w$.])atob[ \t]*\([ \t]*` + DV_LIT + String.raw`[ \t]*\)`;
const DV_PY_SRC = String.raw`\b(?:(?P<fh>bytes[ \t]*\.[ \t]*fromhex)|(?P<uh>(?:binascii[ \t]*\.[ \t]*)?unhexlify)`
  + String.raw`|(?:base64[ \t]*\.[ \t]*)?b64decode)[ \t]*\([ \t]*b?(?:'(?P<a>[^'\\\n]{1,400})'|"(?P<b>[^"\\\n]{1,400})")`
  + String.raw`[ \t]*\)[ \t]*\.[ \t]*decode[ \t]*\([^()\n]{0,20}\)`;
const DV_HELPER_SRC = String.raw`\bfunction[ \t]+(?P<a>[A-Za-z_$][\w$]*)[ \t]*\([ \t]*[A-Za-z_$][\w$]*[ \t]*\)`
  + String.raw`|\b(?:const|let|var)[ \t]+(?P<b>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*(?:function[ \t]*\([ \t]*`
  + String.raw`[A-Za-z_$][\w$]*[ \t]*\)|\(?[ \t]*[A-Za-z_$][\w$]*[ \t]*\)?[ \t]*=>)`
  + String.raw`|\bdef[ \t]+(?P<c>[A-Za-z_]\w*)[ \t]*\([ \t]*[A-Za-z_]\w*[ \t]*\)[ \t]*:`;
const DV_STR_ITEM_SRC = String.raw`'[^'\\\n]{0,400}'|"[^"\\\n]{0,400}"`;
const DV_ARRAY_SRC = String.raw`(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*\[(?P<items>(?:\s*(?:` + DV_STR_ITEM_SRC
  + String.raw`)\s*,){0,63}\s*(?:` + DV_STR_ITEM_SRC + String.raw`)\s*,?\s*)\]`;
const DV_MEMBER_SRC = String.raw`(?<=[\w$)\]])\[[ \t]*(?:'(?P<a>[A-Za-z_$][\w$]{0,63})'|"(?P<b>[A-Za-z_$][\w$]{0,63})")[ \t]*\]`;
const pyReG = (src, flags = "") => pyRe(src.replaceAll("(?P<", "(?<"), flags);
const DV_JOIN_G = pyRe(DV_JOIN_SRC, "g");
const DV_BUFFER_G = pyReG(DV_BUFFER_SRC, "g");
const DV_ATOB_G = pyReG(DV_ATOB_SRC, "g");
const DV_PY_G = pyReG(DV_PY_SRC, "g");
const DV_HELPER_G = pyReG(DV_HELPER_SRC, "g");
const DV_STR_ITEM_G = pyRe(DV_STR_ITEM_SRC, "g");
const DV_ARRAY_G = pyReG(DV_ARRAY_SRC, "g");
const DV_MEMBER_G = pyReG(DV_MEMBER_SRC, "g");
const DV_HEX_WHOLE = /^[0-9A-Fa-f]+$/;
const DV_B64_WHOLE = /^[A-Za-z0-9+/]+={0,2}$/;
const DV_NEEDLES = ["Buffer", "atob", "fromhex", "unhexlify", "b64decode", "fromCharCode", "hex", "base64", "chr", "byte"];
// home-made XOR decoders (0.1.8; core's comment above _DV_XOR_MIN_CALLS)
const DV_XOR_MIN_CALLS = 5, DV_XOR_MAX_CALLS = 64, DV_XOR_MIN_BYTES = 32, DV_XOR_MAX_KEYS = 256, DV_XOR_KEY_MAX = 32;
const DV_CALL_SRC = String.raw`(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)[ \t]*\([ \t]*` + DV_LIT + String.raw`[ \t]*\)`;
const DV_KEY_SRC = String.raw`'(?P<a>[^'\\\n]{1,32})'|"(?P<b>[^"\\\n]{1,32})"|` + BT + String.raw`(?P<c>[^` + BT
  + String.raw`\\\n$]{1,32})` + BT;
const DV_CALL_G = pyReG(DV_CALL_SRC, "g");
const DV_KEY_G = pyReG(DV_KEY_SRC, "g");
const PRINTABLE_ASCII = /^[ -~]+$/;
const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

/** The printable ASCII text a literal decodes to as hex or base64, else null. core._dv_decode. */
function dvDecode(kind, s) {
  let data;
  if (kind === "hex") {
    if (s.length % 2 || !DV_HEX_WHOLE.test(s)) return null;
    data = Buffer.from(s, "hex");
  } else {
    if (s.length % 4 || !DV_B64_WHOLE.test(s)) return null;
    data = Buffer.from(s, "base64");
  }
  if (!data.length || data.some((b) => b < 0x20 || b > 0x7e)) return null;
  return data.toString("latin1");
}

/** The bytes a literal holds as hex, or as base64 (padded; or unpadded, but not 4k+1 long), else null. core._dv_bytes. */
function dvBytes(s, kind) {
  if (kind === "hex") return s.length % 2 === 0 && DV_HEX_WHOLE.test(s) ? Buffer.from(s, "hex") : null;
  if (!DV_B64_WHOLE.test(s) || s.length % 4 === 1 || (s.includes("=") && s.length % 4)) return null;
  return Buffer.from(s, "base64");
}

/** Is every byte of data XORed with key (repeated) printable ASCII? core._dv_xor_printable. */
function dvXorPrintable(data, key) {
  for (let i = 0; i < data.length; i++) {
    const b = data[i] ^ key[i % key.length];
    if (b < 0x20 || b > 0x7e) return false;
  }
  return true;
}

/** Map name -> [kind, key]: the names view calls as XOR decoders, in the order of their first calls. core._dv_xor_decoders. */
function dvXorDecoders(view) {
  const calls = new Map();
  for (const m of view.matchAll(DV_CALL_G)) {
    let lits = calls.get(m.groups.name);
    if (lits === undefined) calls.set(m.groups.name, lits = []);
    if (lits.length < DV_XOR_MAX_CALLS) lits.push(m.groups.a || m.groups.b || m.groups.c);
  }
  const out = new Map();
  let keys = null;
  for (const [name, lits] of calls) {
    if (lits.length < DV_XOR_MIN_CALLS) continue;
    const kind = lits.every((x) => x.length % 2 === 0 && DV_HEX_WHOLE.test(x)) ? "hex" : "base64";
    const data = lits.map((x) => dvBytes(x, kind));
    const read = data.filter((d) => d !== null);
    if (read.length < DV_XOR_MIN_CALLS || read.reduce((n, d) => n + d.length, 0) < DV_XOR_MIN_BYTES) continue;
    if (keys === null) {
      keys = [];
      const seen = new Set();
      for (const k of view.matchAll(DV_KEY_G)) {
        const key = k.groups.a || k.groups.b || k.groups.c;
        if (seen.has(key) || !PRINTABLE_ASCII.test(key)) continue;
        seen.add(key);
        keys.push(Buffer.from(key, "latin1"));
        if (keys.length >= DV_XOR_MAX_KEYS) break;
      }
    }
    const allowed = Math.floor(lits.length / 10);   // calls that may stay unread
    for (const key of keys) {
      let bad = 0;
      for (const d of data) {
        if (d === null || !dvXorPrintable(d, key)) {
          if (++bad > allowed) break;
        }
      }
      if (bad <= allowed) { out.set(name, [kind, key]); break; }
    }
    if (out.size >= DV_MAX_HELPERS) break;
  }
  return out;
}

const dvQuote = (s) => "'" + s.replaceAll("\\", "\\\\").replaceAll("'", "\\'") + "'";
const dvLiteral = (g) => g.a || g.b || g.c;
const dvReplace = (kindOf) => (...args) => {
  const g = args[args.length - 1];
  const d = dvDecode(kindOf(g), dvLiteral(g));
  return d === null ? args[0] : dvQuote(d);
};

/** {name: 'hex'|'base64'}: the file's own decoding helpers. core._dv_helpers. */
function dvHelpers(text) {
  const out = new Map();
  for (const m of text.matchAll(DV_HELPER_G)) {
    const name = m.groups.a || m.groups.b || m.groups.c;
    if (out.has(name)) continue;
    const end = m.index + m[0].length;
    const body = text.slice(end, cpForward(text, end, DV_BODY));
    if ((body.includes("fromCharCode") && body.includes("parseInt") && body.includes("16")) || body.includes("'hex'")
        || body.includes('"hex"') || body.includes("fromhex(") || body.includes("unhexlify(")) out.set(name, "hex");
    else if (body.includes("base64") || body.includes("atob(") || body.includes("b64decode(")) out.set(name, "base64");
    else continue;
    if (out.size >= DV_MAX_HELPERS) break;
  }
  return out;
}

// ---- character codes (0.1.8; core's comment above _DV_CC_BODY) ----
const DV_CC_BODY = 600, DV_CC_MAX_PARAMS = 4, DV_CC_MAX_DECODERS = 8, DV_CC_MAX_CALLS = 256, DV_CC_MAX_CODES = 4096;
const DV_CC_MAX_WORK = 50_000, DV_CC_MAX_TOKENS = 64, DV_CC_MAX_DEPTH = 16, DV_CC_INT_MAX = 2147483647;
const DV_CC_INT = String.raw`(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})`;
const DV_CC_INTS = DV_CC_INT + String.raw`(?:[ \t]*,[ \t]*` + DV_CC_INT + String.raw`){0,399}[ \t]*,?`;
const DV_CC_LITERAL_SRC = String.raw`\bString[ \t]*\.[ \t]*fromCharCode[ \t]*(?:\([ \t]*(?:\.\.\.[ \t]*\[[ \t]*(?P<a>` + DV_CC_INTS
  + String.raw`)[ \t]*\]|(?P<b>` + DV_CC_INTS + String.raw`))[ \t]*\)|\.[ \t]*apply[ \t]*\([ \t]*(?:null|undefined|this|String)`
  + String.raw`[ \t]*,[ \t]*\[[ \t]*(?P<c>` + DV_CC_INTS + String.raw`)[ \t]*\][ \t]*\))`
  + String.raw`|(?:''|"")[ \t]*\.[ \t]*join[ \t]*\([ \t]*(?:map[ \t]*\([ \t]*chr[ \t]*,[ \t]*[\[(][ \t]*(?P<d>`
  + DV_CC_INTS + String.raw`)[ \t]*[\])][ \t]*\)|\[?[ \t]*chr[ \t]*\([ \t]*(?P<v>[A-Za-z_]\w*)[ \t]*\)[ \t]+for[ \t]+\5`
  + String.raw`[ \t]+in[ \t]+[\[(][ \t]*(?P<e>` + DV_CC_INTS + String.raw`)[ \t]*[\])][ \t]*\]?)[ \t]*\)`
  + String.raw`|\bbyte(?:s|array)[ \t]*\([ \t]*[\[(][ \t]*(?P<f>` + DV_CC_INTS + String.raw`)[ \t]*[\])][ \t]*\)[ \t]*\.[ \t]*decode`
  + String.raw`[ \t]*\([^()\n]{0,20}\)`;
const DV_CC_FUNC_SRC = String.raw`\bfunction[ \t]+(?P<a>[A-Za-z_$][\w$]*)[ \t]*\((?P<pa>[^()\n]{0,120})\)[ \t]*\{`
  + String.raw`|\b(?:const|let|var)[ \t]+(?P<b>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*(?:function\b[ \t]*(?:[A-Za-z_$][\w$]*)?[ \t]*`
  + String.raw`\((?P<pb>[^()\n]{0,120})\)[ \t]*\{|\((?P<pc>[^()\n]{0,120})\)[ \t]*=>)`
  + String.raw`|\bdef[ \t]+(?P<c>[A-Za-z_]\w*)[ \t]*\((?P<pd>[^()\n]{0,120})\)[ \t]*(?:->[^:\n]{0,80})?:`;
const DV_CC_SITE_SRC = String.raw`\bString[ \t]*\.[ \t]*fromCharCode[ \t]*\(|(?<![\w$.])chr[ \t]*\(`;
const DV_CC_FOR_SRC = String.raw`\bfor[ \t]*\([ \t]*(?:var|let)[ \t]+(?P<i>[A-Za-z_$][\w$]*)[ \t]*=[ \t]*0[ \t]*;[ \t]*\1[ \t]*<`
  + String.raw`[ \t]*(?P<d>[A-Za-z_$][\w$]*)[ \t]*\.[ \t]*length[ \t]*;`;
const DV_CC_MAP_SRC = String.raw`(?<![\w$.])(?P<d>[A-Za-z_$][\w$]*)[ \t]*(?P<split>\.[ \t]*split[ \t]*\([ \t]*(?:''|"")[ \t]*\)`
  + String.raw`[ \t]*)?\.[ \t]*map[ \t]*\([ \t]*(?:function\b[ \t]*(?:[A-Za-z_$][\w$]*)?[ \t]*\([ \t]*`
  + String.raw`(?P<e>[A-Za-z_$][\w$]*)(?:[ \t]*,[ \t]*(?P<i>[A-Za-z_$][\w$]*))?[ \t]*\)[ \t]*\{`
  + String.raw`|\([ \t]*(?P<e2>[A-Za-z_$][\w$]*)(?:[ \t]*,[ \t]*(?P<i2>[A-Za-z_$][\w$]*))?[ \t]*\)[ \t]*=>`
  + String.raw`|(?P<e3>[A-Za-z_$][\w$]*)[ \t]*=>)`;
const DV_CC_PYFOR_SRC = String.raw`\bfor[ \t]+(?P<i>[A-Za-z_]\w*)[ \t]+in[ \t]+range[ \t]*\([ \t]*len[ \t]*\([ \t]*`
  + String.raw`(?P<d>[A-Za-z_]\w*)[ \t]*\)[ \t]*\)`;
const DV_CC_PYITER_SRC = String.raw`\bfor[ \t]+(?:(?P<i>[A-Za-z_]\w*)[ \t]*,[ \t]*(?P<e>[A-Za-z_]\w*)[ \t]+in[ \t]+enumerate[ \t]*`
  + String.raw`\([ \t]*(?P<d>[A-Za-z_]\w*)[ \t]*\)|(?P<e2>[A-Za-z_]\w*)[ \t]+in[ \t]+(?P<d2>[A-Za-z_]\w*)`
  + String.raw`(?![\w$.(\[]))`;
const DV_CC_TOKEN_SRC = String.raw`[ \t]*(?:(?P<num>0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})|(?P<name>[A-Za-z_$][\w$]*)|(?P<op>>>>|<<|>>|[-+*%&|^~()\[\].,]))`;
const DV_CC_ARG_INT_SRC = String.raw`-?` + DV_CC_INT;
const DV_CC_ARG_STR_SRC = String.raw`'(?P<a>[ -&(-\[\]-~]{0,400})'|"(?P<b>[ !#-\[\]-~]{0,400})\"`;
const DV_CC_CALL_TAIL = String.raw`[ \t]*\((?P<args>(?:[^()'"\n]|'[^'\\\n]{0,400}'|"[^"\\\n]{0,400}"){0,20000})\)`;
const DV_CC_ARRAY_TAIL = String.raw`[ \t]*=[ \t]*[\[(]\s*(?P<items>` + DV_CC_INT + String.raw`(?:\s*,\s*` + DV_CC_INT
  + String.raw`){0,4095}\s*,?)\s*[\])]`;
const DV_CC_NAME_SRC = String.raw`[A-Za-z_$][\w$]*`;
const DV_NAME_HEAD = String.raw`(?<![\w$.])`;
const DV_MUTATED_TAIL = String.raw`\s*(?:\.\s*(?:push|pop|shift|unshift|splice|reverse|sort|fill`
  + String.raw`|copyWithin|append|insert|extend|remove)\s*\(|\[[^\]\n]{0,80}\]\s*=(?!=))`;
const DV_ASSIGNED_TAIL = String.raw`\s*=(?![=>])`;
const DV_INDEX_TAIL = String.raw`\s*\[\s*([0-9]{1,2})\s*\]`;
const DV_CC_BINARY = new Map([["|", 1], ["^", 2], ["&", 3], ["<<", 4], [">>", 4], [">>>", 4], ["+", 5], ["-", 5], ["*", 6],
  ["%", 6]]);
const DV_CC_LITERAL_G = pyReG(DV_CC_LITERAL_SRC, "g");
const DV_CC_FUNC_G = pyReG(DV_CC_FUNC_SRC, "g");
const DV_CC_SITE_G = pyRe(DV_CC_SITE_SRC, "g");
const DV_CC_FOR_G = pyReG(DV_CC_FOR_SRC, "g");
const DV_CC_MAP_G = pyReG(DV_CC_MAP_SRC, "g");
const DV_CC_MAP_Y = pyReG(DV_CC_MAP_SRC, "y");
const DV_CC_PYFOR_G = pyReG(DV_CC_PYFOR_SRC, "g");
const DV_CC_PYITER_G = pyReG(DV_CC_PYITER_SRC, "g");
const DV_CC_TOKEN_Y = pyReG(DV_CC_TOKEN_SRC, "y");
const DV_CC_INT_WHOLE = pyReG(String.raw`^(?:` + DV_CC_INT + String.raw`)\Z`);
const DV_CC_ARG_INT_WHOLE = pyReG(String.raw`^(?:` + DV_CC_ARG_INT_SRC + String.raw`)\Z`);
const DV_CC_ARG_STR_WHOLE = pyReG(String.raw`^(?:` + DV_CC_ARG_STR_SRC + String.raw`)\Z`);
const DV_CC_NAME_WHOLE = pyReG(String.raw`^(?:` + DV_CC_NAME_SRC + String.raw`)\Z`);
const CC_FAIL = new Error("character-code decoder: not read");

/** The value of an integer literal (decimal or 0x…), at most _DV_CC_INT_MAX; else CC_FAIL. core._cc_int_literal. */
function ccIntLiteral(s) {
  if (!DV_CC_INT_WHOLE.test(s)) throw CC_FAIL;
  const v = s[0] === "0" && (s[1] === "x" || s[1] === "X") ? parseInt(s.slice(2), 16) : parseInt(s, 10);
  if (v > DV_CC_INT_MAX) throw CC_FAIL;
  return v;
}

/** The integers of a comma-separated list (a trailing comma allowed). core._cc_ints. */
function ccInts(items) {
  const parts = items.split(",").map((p) => pyStrip(p));
  if (parts.length && parts[parts.length - 1] === "") parts.pop();
  return parts.map(ccIntLiteral);
}

/** The syntax tree of a transform, else null. core._cc_parse. */
function ccParse(expr) {
  const toks = [];
  let pos = 0;
  while (pos < expr.length) {
    DV_CC_TOKEN_Y.lastIndex = pos;
    const m = DV_CC_TOKEN_Y.exec(expr);
    if (m === null) {
      if (expr.slice(pos).replace(/^[ \t]+|[ \t]+$/g, "")) return null;
      break;
    }
    if (m.groups.num !== undefined) toks.push(["n", m.groups.num]);
    else if (m.groups.name !== undefined) toks.push(["v", m.groups.name]);
    else toks.push(["o", m.groups.op]);
    pos = m.index + m[0].length;
    if (toks.length > DV_CC_MAX_TOKENS) return null;
  }
  let at = 0;
  const peek = (value) => {
    if (at >= toks.length) return null;
    const tok = toks[at];
    return value === undefined || (tok[0] === "o" && tok[1] === value) ? tok : null;
  };
  const take = (value) => { if (peek(value) === null) throw CC_FAIL; at++; };
  const expression = (minPrec, depth) => {
    if (depth > DV_CC_MAX_DEPTH) throw CC_FAIL;
    let left = unary(depth);
    for (;;) {
      const tok = peek();
      if (tok === null || tok[0] !== "o" || !DV_CC_BINARY.has(tok[1]) || DV_CC_BINARY.get(tok[1]) < minPrec) return left;
      at++;
      left = ["b", tok[1], left, expression(DV_CC_BINARY.get(tok[1]) + 1, depth + 1)];
    }
  };
  const unary = (depth) => {
    const tok = peek();
    if (tok !== null && tok[0] === "o" && (tok[1] === "-" || tok[1] === "~" || tok[1] === "+")) {
      if (depth >= DV_CC_MAX_DEPTH) throw CC_FAIL;
      at++;
      return ["u", tok[1], unary(depth + 1)];
    }
    return postfix(depth);
  };
  const postfix = (depth) => {
    let node = primary(depth);
    for (;;) {
      if (peek("[") !== null) {
        at++;
        node = ["i", node, expression(1, depth + 1)];
        take("]");
      } else if (peek(".") !== null) {
        at++;
        const tok = peek();
        if (tok === null || tok[0] !== "v" || (tok[1] !== "charCodeAt" && tok[1] !== "length")) throw CC_FAIL;
        at++;
        if (tok[1] === "length") node = ["l", node];
        else {
          take("(");
          node = ["c", node, peek(")") !== null ? ["n", 0] : expression(1, depth + 1)];
          take(")");
        }
      } else return node;
    }
  };
  const primary = (depth) => {
    const tok = peek();
    if (tok === null) throw CC_FAIL;
    at++;
    if (tok[0] === "n") return ["n", ccIntLiteral(tok[1])];
    if (tok[0] === "v") {
      if ((tok[1] === "ord" || tok[1] === "len") && peek("(") !== null) {
        at++;
        const arg = expression(1, depth + 1);
        take(")");
        return [tok[1] === "ord" ? "o" : "l", arg];
      }
      return ["v", tok[1]];
    }
    if (tok[1] === "(") {
      const inner = expression(1, depth + 1);
      take(")");
      return inner;
    }
    throw CC_FAIL;
  };
  let tree;
  try {
    tree = expression(1, 0);
  } catch (e) {
    if (e === CC_FAIL) return null;
    throw e;
  }
  return at === toks.length ? tree : null;
}

/** The names a transform reads (added to `out`, a Set). core._cc_names. */
function ccNames(tree, out) {
  const kind = tree[0];
  if (kind === "v") out.add(tree[1]);
  else if (kind === "u") ccNames(tree[2], out);
  else if (kind === "b") { ccNames(tree[2], out); ccNames(tree[3], out); }
  else if (kind === "i" || kind === "c") { ccNames(tree[1], out); ccNames(tree[2], out); }
  else if (kind === "l" || kind === "o") ccNames(tree[1], out);
  return out;
}

const ccCheck = (v) => { if (v < -DV_CC_INT_MAX - 1 || v > DV_CC_INT_MAX) throw CC_FAIL; return v; };
const ccNum = (v) => { if (typeof v !== "number") throw CC_FAIL; return v; };

/** A function of the names' values that works a transform out: a number, or CC_FAIL. core._cc_compile. */
function ccCompile(tree) {
  const kind = tree[0];
  if (kind === "n") { const value = tree[1]; return () => value; }
  if (kind === "v") {
    const name = tree[1];
    return (env) => { if (!env.has(name)) throw CC_FAIL; return env.get(name); };
  }
  if (kind === "u") {
    const op = tree[1], arg = ccCompile(tree[2]);
    if (op === "-") return (env) => ccCheck(-ccNum(arg(env)));
    if (op === "~") return (env) => ~ccNum(arg(env));
    return (env) => ccNum(arg(env));
  }
  if (kind === "b") {
    const op = tree[1], left = ccCompile(tree[2]), right = ccCompile(tree[3]);
    return (env) => {
      const a = ccNum(left(env)), b = ccNum(right(env));
      switch (op) {
        case "+": return ccCheck(a + b);
        case "-": return ccCheck(a - b);
        case "*": return ccCheck(a * b);
        case "%": if (a < 0 || b <= 0) throw CC_FAIL; return a % b;
        case "&": return a & b;
        case "|": return a | b;
        case "^": return a ^ b;
        default: break;
      }
      if (b < 0 || b > 31) throw CC_FAIL;
      if (op === "<<") return ccCheck(a * 2 ** b);
      if (op === ">>>" && a < 0) throw CC_FAIL;
      return a >> b;
    };
  }
  if (kind === "i" || kind === "c") {
    const obj = ccCompile(tree[1]), index = ccCompile(tree[2]), chars = kind === "c";
    return (env) => {
      const seq = obj(env), k = ccNum(index(env));
      if (chars ? typeof seq !== "string" : typeof seq !== "string" && !Array.isArray(seq)) throw CC_FAIL;
      if (k < 0 || k >= seq.length) throw CC_FAIL;
      return chars ? seq.charCodeAt(k) : seq[k];
    };
  }
  if (kind === "l") {
    const obj = ccCompile(tree[1]);
    return (env) => {
      const seq = obj(env);
      if (typeof seq !== "string" && !Array.isArray(seq)) throw CC_FAIL;
      return seq.length;
    };
  }
  const arg = ccCompile(tree[1]);                               // "o": ord
  return (env) => {
    const ch = arg(env);
    if (typeof ch !== "string" || ch.length !== 1) throw CC_FAIL;
    return ch.charCodeAt(0);
  };
}

/** text[i:j] up to the ')' that closes the call opened just before i, and j (code points of limit), else null.
 * core._cc_balanced. */
function ccBalanced(text, i, limit) {
  let depth = 0, j = i, quote = null;
  const end = cpForward(text, i, limit);
  while (j < end) {
    const ch = text[j];
    if (quote !== null) {
      if (ch === "\\") { j += 2; continue; }
      if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"' || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) return ch === ")" ? [text.slice(i, j), j] : null;
      depth--;
    }
    j++;
  }
  return null;
}

/** The plain parameter names of a parameter list, else null. core._cc_params. */
function ccParams(s) {
  const names = pyStrip(s) ? s.split(",").map((p) => pyStrip(p)) : [];
  if (names.length < 1 || names.length > DV_CC_MAX_PARAMS || names.some((p) => !DV_CC_NAME_WHOLE.test(p))) return null;
  return new Set(names).size === names.length ? names : null;
}

/** [[offset, data, element, index, split, jsMap]]: the walks over a parameter a decoder's body holds. core._cc_walks. */
function ccWalks(body) {
  const out = [];
  for (const m of body.matchAll(DV_CC_FOR_G)) out.push([m.index, m.groups.d, null, m.groups.i, false, false]);
  for (const m of body.matchAll(DV_CC_MAP_G)) {
    out.push([m.index, m.groups.d, m.groups.e ?? m.groups.e2 ?? m.groups.e3, m.groups.i ?? m.groups.i2 ?? null,
      m.groups.split !== undefined, true]);
  }
  for (const m of body.matchAll(DV_CC_PYFOR_G)) out.push([m.index, m.groups.d, null, m.groups.i, false, false]);
  for (const m of body.matchAll(DV_CC_PYITER_G)) {
    out.push([m.index, m.groups.d ?? m.groups.d2, m.groups.e ?? m.groups.e2, m.groups.i ?? null, false, false]);
  }
  return out.sort((a, b) => a[0] - b[0]);
}

/** Map name -> decoder: the file's own character-code decoders, in the order of their transforms. core._cc_decoders. */
function ccDecoders(view) {
  const out = new Map();
  let heads = null, ends = null;
  for (const site of view.matchAll(DV_CC_SITE_G)) {
    if (heads === null) {
      heads = [...view.matchAll(DV_CC_FUNC_G)];
      ends = heads.map((h) => h.index + h[0].length);
    }
    let lo = 0, hi = ends.length;                          // the last function header that ends by the transform
    while (lo < hi) { const mid = (lo + hi) >> 1; if (ends[mid] <= site.index) lo = mid + 1; else hi = mid; }
    const k = lo - 1;
    if (k < 0 || site.index >= cpForward(view, ends[k], DV_CC_BODY)) continue;
    const head = heads[k];
    const name = head.groups.a ?? head.groups.b ?? head.groups.c;
    const params = ccParams(head.groups.pa ?? head.groups.pb ?? head.groups.pc ?? head.groups.pd);
    if (out.has(name) || params === null) continue;
    const got = ccBalanced(view, site.index + site[0].length, DV_CC_BODY);
    if (got === null) continue;
    const arg = pyStrip(got[0]);
    const body = view.slice(ends[k], cpForward(view, ends[k], DV_CC_BODY));
    let walks, expr;
    if (arg.startsWith("...")) {
      const spread = arg.slice(3).replace(/^[ \t]+/, "");
      DV_CC_MAP_Y.lastIndex = 0;
      const m = DV_CC_MAP_Y.exec(spread);
      if (m === null || m.groups.e !== undefined || !spread.endsWith(")")) continue;
      walks = [[0, m.groups.d, m.groups.e2 ?? m.groups.e3, m.groups.i2 ?? null, m.groups.split !== undefined, true]];
      expr = spread.slice(m[0].length, -1);
    } else {
      walks = ccWalks(body);
      expr = arg;
    }
    const tree = ccParse(expr);
    if (tree === null) continue;
    const names = ccNames(tree, new Set());
    for (const [, data, elem, index, split, jsMap] of walks) {
      const bound = new Set([elem, index].filter((v) => v));
      if (!params.includes(data) || ![...bound].some((v) => names.has(v)) || [...bound].some((v) => params.includes(v))
          || [...names].some((v) => !params.includes(v) && !bound.has(v))) continue;
      out.set(name, [params, params.indexOf(data), elem, index, split, jsMap, ccCompile(tree)]);
      break;
    }
    if (out.size >= DV_CC_MAX_DECODERS) break;
  }
  return out;
}

/** A call's literal argument (an integer, a list of integers, a string of printable ASCII), else CC_FAIL.
 * core._cc_argument. */
function ccArgument(s, view, arrays) {
  s = pyStrip(s);
  if (DV_CC_ARG_INT_WHOLE.test(s)) return s.startsWith("-") ? -ccIntLiteral(s.slice(1)) : ccIntLiteral(s);
  if (s.length >= 2 && "[(".includes(s[0]) && "])".includes(s[s.length - 1])) {
    if (pyStrip(s.slice(1, -1)) === "") throw CC_FAIL;
    return ccInts(s.slice(1, -1));
  }
  const m = DV_CC_ARG_STR_WHOLE.exec(s);
  if (m !== null) return m.groups.a ?? m.groups.b;
  if (DV_CC_NAME_WHOLE.test(s)) {
    if (!arrays.has(s)) {
      const esc = reEscape(s);
      const a = pyReG(DV_NAME_HEAD + esc + DV_CC_ARRAY_TAIL).exec(view);
      const once = [...view.matchAll(pyRe(DV_NAME_HEAD + esc + DV_ASSIGNED_TAIL, "g"))].length === 1;
      arrays.set(s, a === null || pyRe(DV_NAME_HEAD + esc + DV_MUTATED_TAIL).test(view) || !once
        ? null : ccInts(a.groups.items));
    }
    if (arrays.get(s) !== null) return arrays.get(s);
  }
  throw CC_FAIL;
}

/** The text a decoder gives for a call's arguments, else CC_FAIL; work ([codes left]) is spent. core._cc_run. */
function ccRun(decoder, args, work) {
  const [params, dataAt, elem, index, split, jsMap, fn] = decoder;
  if (args.length < params.length) throw CC_FAIL;
  const data = args[dataAt];
  const isStr = typeof data === "string";
  if ((!isStr && !Array.isArray(data)) || (jsMap && isStr !== split) || !data.length) throw CC_FAIL;
  if (data.length > DV_CC_MAX_CODES || data.length > work[0]) throw CC_FAIL;
  work[0] -= data.length;
  const env = new Map();
  params.forEach((p, k) => { if (k < args.length) env.set(p, args[k]); });
  let out = "";
  for (let k = 0; k < data.length; k++) {
    if (index) env.set(index, k);
    if (elem) env.set(elem, data[k]);
    const c = fn(env);
    if (typeof c !== "number" || c < 0x20 || c > 0x7e) throw CC_FAIL;
    out += String.fromCharCode(c);
  }
  return out;
}

/** A call's arguments split at their top-level commas (not in brackets or quotes). core._cc_split_args. */
function ccSplitArgs(s) {
  const parts = [];
  let depth = 0, start = 0, quote = null;
  for (let k = 0; k < s.length; k++) {
    const ch = s[k];
    if (quote !== null) { if (ch === quote) quote = null; }
    else if (ch === "'" || ch === '"') quote = ch;
    else if (ch === "[" || ch === "(") depth++;
    else if (ch === "]" || ch === ")") depth--;
    else if (ch === "," && depth === 0) { parts.push(s.slice(start, k)); start = k + 1; }
  }
  parts.push(s.slice(start));
  return parts;
}

/** The view with the character codes it holds and the calls of its own character-code decoders read as their text.
 * core._dv_char_codes. */
function dvCharCodes(view) {
  view = view.replace(DV_CC_LITERAL_G, (...args) => {
    const g = args[args.length - 1];
    const items = g.a ?? g.b ?? g.c ?? g.d ?? g.e ?? g.f;
    let codes;
    try { codes = ccInts(items); } catch (e) { if (e === CC_FAIL) return args[0]; throw e; }
    if (!codes.length || codes.some((c) => c < 0x20 || c > 0x7e)) return args[0];
    return dvQuote(String.fromCharCode(...codes));
  });
  const decoders = ccDecoders(view);
  if (!decoders.size) return view;
  const names = [...decoders.keys()].sort();
  const call = pyReG(DV_NAME_HEAD + "(?P<name>" + names.map(reEscape).join("|") + ")" + DV_CC_CALL_TAIL, "g");
  const arrays = new Map(), work = [DV_CC_MAX_WORK];
  let calls = 0;
  const source = view;
  return view.replace(call, (...args) => {
    const g = args[args.length - 1];
    if (calls >= DV_CC_MAX_CALLS) return args[0];
    calls++;
    try {
      const values = ccSplitArgs(g.args).map((a) => ccArgument(a, source, arrays));
      return dvQuote(ccRun(decoders.get(g.name), values, work));
    } catch (e) {
      if (e === CC_FAIL) return args[0];
      throw e;
    }
  });
}

/** The text read the way it reads once the strings it decodes as it runs are decoded. Twin of core.decoded_view. */
// ---- string arrays and proxy objects (0.1.8; core's comments above _SA_MAX_CHARS and _PX_MAX_ENTRIES) ----
/** pyReG, and Python's (?P=name) backreferences as JavaScript's \k<name>. */
const pyReB = (src, flags = "") => pyReG(src.replace(/\(\?P=(\w+)\)/g, "\\k<$1>"), flags);

const SA_MAX_CHARS = 16_000_000, SA_MAX_ARRAYS = 4, SA_MAX_ITEMS = 200_000, SA_MAX_CALLS = 1_000_000, SA_DEPTH = 8;
const SA_BODY = 3000, SA_LOOP_BACK = 20000, SA_HEX_MAX = 13, SA_DEC_MAX = 15;
const SA_IDENT = String.raw`[A-Za-z_$][\w$]*`;
const SA_ARRAY_FN_SRC = String.raw`function\s+(?P<fn>` + SA_IDENT + String.raw`)\s*\(\s*\)\s*\{\s*(?:var|const|let)\s+(?P<arr>`
  + SA_IDENT + String.raw`)\s*=\s*\[`;
const SA_LIT_SRC = String.raw`'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*"`;
const SA_SPACE_SRC = String.raw`\s*`;
const SA_OCT_SRC = String.raw`[0-3][0-7]{0,2}|[4-7][0-7]?`;
const SA_TAIL_HEAD = String.raw`\s*;?\s*`;
const SA_TAIL_MID = String.raw`\s*=\s*function\s*\(\s*\)\s*\{\s*return\s+`;
const SA_TAIL_END = String.raw`\s*;?\s*\}\s*;?\s*return\s+`;
const SA_TAIL_CALL = String.raw`\s*\(\s*\)\s*;?\s*\}`;
const SA_OFF = String.raw`(?P<off>[^;{}]{1,300})`;
const SA_ACC_A_HEAD = String.raw`function\s+(?P<g>` + SA_IDENT + String.raw`)\s*\(\s*(?P<p>` + SA_IDENT + String.raw`)\s*,\s*` + SA_IDENT
  + String.raw`\s*\)\s*\{\s*(?P=p)\s*=\s*(?P=p)\s*-\s*` + SA_OFF + String.raw`;\s*(?:var|const|let)\s+` + SA_IDENT
  + String.raw`\s*=\s*`;
const SA_ACC_B_HEAD = String.raw`function\s+(?P<g>` + SA_IDENT + String.raw`)\s*\(\s*` + SA_IDENT + String.raw`\s*,\s*` + SA_IDENT
  + String.raw`\s*\)\s*\{\s*(?:var|const|let)\s+` + SA_IDENT + String.raw`\s*=\s*`;
const SA_ACC_B_TAIL = String.raw`\s*\(\s*\)\s*;\s*return\s+(?P=g)\s*=\s*function\s*\(\s*(?P<p>` + SA_IDENT + String.raw`)\s*,\s*`
  + SA_IDENT + String.raw`\s*\)\s*\{\s*(?P=p)\s*=\s*(?P=p)\s*-\s*` + SA_OFF + ";";
const SA_CALL_TAIL = String.raw`\s*\(\s*\)`;
const SA_INVOKE_HEAD = String.raw`\}\s*\(\s*`;
const SA_INVOKE_TAIL = String.raw`\s*,\s*(?P<t>(?:[^;()]|\([^;()]*\)){1,200}?)\)\s*\)`;
const SA_INVOKE2_HEAD = String.raw`\}\s*\)\s*\(\s*`;
const SA_INVOKE2_TAIL = String.raw`\s*,\s*(?P<t>(?:[^;()]|\([^;()]*\)){1,200}?)\)`;
const SA_CHECKSUM_SRC = String.raw`try\s*\{\s*(?:var|const|let)\s+(?P<v>` + SA_IDENT + String.raw`)\s*=\s*(?P<e>[^;]{1,6000});\s*`
  + String.raw`if\s*\(\s*(?P=v)\s*===\s*` + SA_IDENT + String.raw`\s*\)\s*break`;
const SA_ALPHABET_SRC = String.raw`['"]([A-Za-z0-9+/=]{65})['"]`;
const SA_ALIAS_SRC = String.raw`(?<![\w$.])(` + SA_IDENT + String.raw`)\s*=\s*(` + SA_IDENT + String.raw`)\s*(?=[,;)\n}])`;
const SA_WRAPPER_SRC = String.raw`(?:\bfunction\s+(?P<n1>` + SA_IDENT + String.raw`)|(?<![\w$.])(?P<n2>` + SA_IDENT
  + String.raw`)\s*=\s*function(?:\s+` + SA_IDENT + String.raw`)?)\s*\((?P<params>[^()]{0,400})\)\s*\{\s*`
  + String.raw`return\s+(?P<target>` + SA_IDENT + String.raw`)\s*\((?P<args>[^()]{0,400})\)\s*;?\s*\}`;
const SA_PARAM_SRC = String.raw`\s*(` + SA_IDENT + String.raw`)\s*`;
const SA_OBJECT_SRC = String.raw`(?<![\w$.])(` + SA_IDENT + String.raw`)\s*=\s*\{`;
const SA_ENTRY_SRC = String.raw`\s*(?:(?P<k>` + SA_IDENT + String.raw`)|'(?P<k2>[^'\\\n]*)'|"(?P<k3>[^"\\\n]*)")\s*:\s*`
  + String.raw`(?P<v>-?\s*(?:0[xX][0-9a-fA-F]+|(?:0|[1-9]\d*)(?:\.\d+)?)|'(?:[^'\\\n]|\\[^\n])*'`
  + String.raw`|"(?:[^"\\\n]|\\[^\n])*")\s*(?P<end>[,}])`;
const SA_TOKEN_SRC = String.raw`\s*(?:(?P<num>0[xX][0-9a-fA-F]+|(?:0|[1-9]\d*)(?:\.\d*)?(?:[eE][-+]?\d+)?|\.\d+(?:[eE][-+]?\d+)?)`
  + String.raw`(?![\w$])|(?P<str>'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*")|(?P<name>`
  + SA_IDENT + String.raw`)|(?P<op>[-+*/()\[\].,]))`;
const SA_ARG_UNIT = String.raw`[^()'"\n]|'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*"`;
const SA_CALL_SRC = String.raw`(?<![\w$.])(` + SA_IDENT + String.raw`)\s*\(((?:` + SA_ARG_UNIT + String.raw`|\((?:` + SA_ARG_UNIT
  + String.raw`)*\)){1,400})\)`;
const SA_FUNCTION_TAIL_SRC = String.raw`function\s*$`;
const SA_DECIMAL_SRC = String.raw`[+-]?(?:\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)`;
const SA_ARRAY_FN_G = pyReG(SA_ARRAY_FN_SRC, "g");
const SA_LIT_Y = pyRe(SA_LIT_SRC, "y");
const SA_LIT_G = pyRe(SA_LIT_SRC, "g");
const SA_SPACE_Y = pyRe(SA_SPACE_SRC, "y");
const SA_OCT_Y = pyRe(SA_OCT_SRC, "y");
const SA_CHECKSUM_G = pyReB(SA_CHECKSUM_SRC, "g");
const SA_ALPHABET_G = pyRe(SA_ALPHABET_SRC, "g");
const SA_ALIAS_G = pyRe(SA_ALIAS_SRC, "g");
const SA_WRAPPER_G = pyReG(SA_WRAPPER_SRC, "g");
const SA_PARAM_WHOLE = pyReG(String.raw`^(?:` + SA_PARAM_SRC + String.raw`)\Z`);
const SA_OBJECT_G = pyRe(SA_OBJECT_SRC, "g");
const SA_ENTRY_Y = pyReG(SA_ENTRY_SRC, "y");
const SA_TOKEN_Y = pyReG(SA_TOKEN_SRC, "y");
const SA_CALL_G = pyRe(SA_CALL_SRC, "g");
const SA_FUNCTION_TAIL_RE = pyRe(SA_FUNCTION_TAIL_SRC);
const SA_DECIMAL_WHOLE = pyReG(String.raw`^(?:` + SA_DECIMAL_SRC + String.raw`)\Z`);
const SA_HEX = new Set("0123456789abcdefABCDEF");
const SA_ESCAPES = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v" };
const SA_JS_SPACE = new Set("\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009"
  + "\u200a\u2028\u2029\u202f\u205f\u3000\ufeff");
const SA_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** What the string-array reader cannot read (core._SaStop). */
class SaStop extends Error {}
const saStop = (why) => { throw new SaStop(why); };
const isHex = (s) => [...s].every((ch) => SA_HEX.has(ch));

/** core._sa_string: the value of a JavaScript string literal's body, else null. */
function saString(body) {
  if (!body.includes("\\")) return body;
  const out = [];
  let i = 0;
  const n = body.length;
  while (i < n) {
    const ch = body[i];
    if (ch !== "\\") { out.push(ch); i++; continue; }
    if (i + 1 >= n) return null;
    const e = body[i + 1];
    if (e === "x") {
      const h = body.slice(i + 2, i + 4);
      if (h.length !== 2 || !isHex(h)) return null;
      out.push(String.fromCharCode(parseInt(h, 16)));
      i += 4;
    } else if (e === "u") {
      if (body[i + 2] === "{") {
        const k = body.indexOf("}", i + 3);
        const h = k > 0 ? body.slice(i + 3, k) : "";
        if (!h || h.length > 6 || !isHex(h) || parseInt(h, 16) > 0x10ffff) return null;
        out.push(String.fromCodePoint(parseInt(h, 16)));
        i = k + 1;
      } else {
        const h = body.slice(i + 2, i + 6);
        if (h.length !== 4 || !isHex(h)) return null;
        out.push(String.fromCharCode(parseInt(h, 16)));
        i += 6;
      }
    } else if (e in SA_ESCAPES) {
      out.push(SA_ESCAPES[e]);
      i += 2;
    } else if (e >= "0" && e <= "7") {
      const m = matchAt(SA_OCT_Y, body, i + 1);
      out.push(String.fromCharCode(parseInt(m[0], 8)));
      i = i + 1 + m[0].length;
    } else {
      // (an escaped character outside the BMP is its two units)
      const cp = body.codePointAt(i + 1);
      const len = cp > 0xffff ? 2 : 1;
      out.push(body.slice(i + 1, i + 1 + len));
      i += 1 + len;
    }
  }
  return out.join("");
}

/** core._sa_strings: [values, end] of the string literals of an array literal whose '[' ends at text[i]; null if one is not. */
function saStrings(text, i) {
  const items = [], n = text.length;
  for (;;) {
    i += matchAt(SA_SPACE_Y, text, i)[0].length;
    if (i >= n) return null;
    if (text[i] === "]" && !items.length) return [items, i + 1];
    const m = matchAt(SA_LIT_Y, text, i);
    if (m === null || items.length >= SA_MAX_ITEMS) return null;
    const v = saString(m[0].slice(1, -1));
    if (v === null) return null;
    items.push(v);
    i = m.index + m[0].length;
    i += matchAt(SA_SPACE_Y, text, i)[0].length;
    if (i < n && text[i] === ",") { i++; continue; }
    if (i < n && text[i] === "]") return [items, i + 1];
    return null;
  }
}

/** core._sa_number: a number literal's value. */
function saNumber(s) {
  if (s.startsWith("0x") || s.startsWith("0X")) return s.length - 2 <= SA_HEX_MAX ? parseInt(s.slice(2), 16) : NaN;
  return Number(s);
}

/** core._sa_to_number: JavaScript's ToNumber of a number or a string (as core reads it). */
function saToNumber(v) {
  if (typeof v === "number") return v;
  let i = 0, j = v.length;
  while (i < j && SA_JS_SPACE.has(v[i])) i++;
  while (j > i && SA_JS_SPACE.has(v[j - 1])) j--;
  const s = v.slice(i, j);
  if (!s) return 0;
  const pre = s.slice(0, 2).toLowerCase();
  if ((pre === "0x" || pre === "0b" || pre === "0o") && s.length > 2) {
    const body = s.slice(2);
    const ok = pre === "0x" ? isHex(body) : pre === "0b" ? /^[01]+$/.test(body) : /^[0-7]+$/.test(body);
    if (!ok || body.length > SA_HEX_MAX) return NaN;
    return parseInt(body, pre === "0x" ? 16 : pre === "0b" ? 2 : 8);
  }
  if (s === "Infinity" || s === "+Infinity") return Infinity;
  if (s === "-Infinity") return -Infinity;
  if (/^[\x00-\x7f]*$/.test(s) && SA_DECIMAL_WHOLE.test(s)) return Number(s);
  return NaN;
}

/** core._sa_to_string: ToString of a string, or of an integer under 1e21. */
function saToString(v) {
  if (typeof v === "string") return v;
  if (v === v && v === Math.trunc(v) && Math.abs(v) < 1e21) return String(v === 0 ? 0 : v);
  return saStop("number text");
}

/** core._sa_parse_int: parseInt(v) (radix 10, or 16 after 0x), as core reads it. */
function saParseInt(v) {
  if (typeof v !== "string") return NaN;
  let i = 0;
  const n = v.length;
  while (i < n && SA_JS_SPACE.has(v[i])) i++;
  let sign = 1;
  if (i < n && (v[i] === "+" || v[i] === "-")) { sign = v[i] === "-" ? -1 : 1; i++; }
  let radix = 10;
  if (v.slice(i, i + 2) === "0x" || v.slice(i, i + 2) === "0X") { radix = 16; i += 2; }
  let j = i;
  while (j < n && ((v[j] >= "0" && v[j] <= "9") || (radix === 16 && SA_HEX.has(v[j])))) j++;
  if (j === i || j - i > (radix === 16 ? SA_HEX_MAX : SA_DEC_MAX)) return NaN;
  return sign * parseInt(v.slice(i, j), radix);
}

/** core._sa_tokens: an expression's tokens, [kind, value]. */
function saTokens(src) {
  const out = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const m = matchAt(SA_TOKEN_Y, src, i);
    if (m === null || m[0].length === 0) {
      if (pyStrip(src.slice(i)) === "") break;
      saStop("token");
    }
    const g = m.groups;
    if (g.num !== undefined) out.push(["n", saNumber(g.num)]);
    else if (g.str !== undefined) {
      const v = saString(g.str.slice(1, -1));
      if (v === null) saStop("string");
      out.push(["s", v]);
    } else if (g.name !== undefined) out.push(["i", g.name]);
    else out.push(["o", g.op]);
    i = m.index + m[0].length;
  }
  return out;
}

/** core._sa_parse: an expression's tree (a list of them, comma-separated: `many`). */
function saParse(toks, consts, many = false) {
  let pos = 0;
  const peek = () => (pos < toks.length ? toks[pos] : null);
  const isOp = (t, op) => t !== null && t[0] === "o" && t[1] === op;
  const take = () => { const t = peek(); if (t === null) saStop("syntax"); pos++; return t; };
  const takeOp = (op) => { const t = take(); if (!isOp(t, op)) saStop("syntax"); return t; };
  const constant = (name, key) => {
    const table = consts.get(name);
    if (table === undefined || !table.has(key)) saStop("constant");
    return table.get(key);
  };
  const primary = () => {
    const t = take();
    if (t[0] === "n" || t[0] === "s") return t;
    if (isOp(t, "(")) { const v = additive(); takeOp(")"); return v; }
    if (t[0] !== "i") saStop("primary");
    const nxt = peek();
    if (isOp(nxt, ".")) {
      take();
      const key = take();
      if (key[0] !== "i") saStop("key");
      return constant(t[1], key[1]);
    }
    if (isOp(nxt, "[")) {
      take();
      const key = take();
      takeOp("]");
      if (key[0] !== "s") saStop("key");
      return constant(t[1], key[1]);
    }
    if (isOp(nxt, "(")) {
      take();
      const args = [];
      if (!isOp(peek(), ")")) {
        for (;;) {
          args.push(additive());
          if (!isOp(peek(), ",")) break;
          take();
        }
      }
      takeOp(")");
      if (t[1] === "parseInt") {
        if (args.length !== 1 || args[0][0] !== "call") saStop("parseInt");
        return ["pi", args[0][1], args[0][2]];
      }
      return ["call", t[1], args];
    }
    return ["var", t[1]];
  };
  const unary = () => {
    const t = peek();
    if (isOp(t, "-")) { take(); return ["neg", unary()]; }
    if (isOp(t, "+")) { take(); return ["pos", unary()]; }
    return primary();
  };
  const mult = () => {
    let v = unary();
    while (isOp(peek(), "*") || isOp(peek(), "/")) v = [take()[1], v, unary()];
    return v;
  };
  const additive = () => {
    let v = mult();
    while (isOp(peek(), "+") || isOp(peek(), "-")) v = [take()[1], v, mult()];
    return v;
  };
  let out;
  if (many) {
    out = [];
    if (toks.length) {
      for (;;) {
        out.push(additive());
        if (!isOp(peek(), ",")) break;
        take();
      }
    }
  } else out = additive();
  if (pos !== toks.length) saStop("rest");
  return out;
}

/** core._sa_value: a tree's JavaScript value (a number or a string). */
function saValue(tree, env, call) {
  const k = tree[0];
  if (k === "n" || k === "s") return tree[1];
  if (k === "var") {
    if (!env.has(tree[1])) saStop("free name");
    return env.get(tree[1]);
  }
  if (k === "neg") return -saToNumber(saValue(tree[1], env, call));
  if (k === "pos") return saToNumber(saValue(tree[1], env, call));
  if (k === "+") {
    const a = saValue(tree[1], env, call), b = saValue(tree[2], env, call);
    if (typeof a === "string" || typeof b === "string") return saToString(a) + saToString(b);
    return a + b;
  }
  if (k === "-" || k === "*" || k === "/") {
    const a = saToNumber(saValue(tree[1], env, call)), b = saToNumber(saValue(tree[2], env, call));
    return k === "-" ? a - b : k === "*" ? a * b : a / b;
  }
  if (call === null) saStop("call");
  const got = call(tree[1], tree[2].map((a) => saValue(a, env, call)));
  return k === "pi" ? saParseInt(got) : got;
}

const hasSurrogate = (s) => /[\ud800-\udfff]/.test(s);

/** core._sa_atob: the accessor's base64 over its alphabet, read as UTF-8; null where that throws or leaves the BMP. */
function saAtob(s, alphabet) {
  const out = [];
  let bc = 0, bs = 0;
  for (const ch of s) {
    const v = alphabet.indexOf(ch);
    if (v < 0) continue;
    bs = bc % 4 ? bs * 64 + v : v;
    bc++;
    if ((bc - 1) % 4) out.push(255 & (bs >> ((-2 * bc) & 6)));
  }
  let text;
  try {
    text = SA_UTF8.decode(new Uint8Array(out));
  } catch {
    return null;
  }
  return hasSurrogate(text) ? null : text;
}

/** core._sa_rc4: the accessor's RC4 with `key` over its base64, else null. */
function saRc4(s, key, alphabet) {
  const data = saAtob(s, alphabet);
  if (data === null || typeof key !== "string" || !key || hasSurrogate(key)) return null;
  const box = Array.from({ length: 256 }, (_, i) => i);
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + box[i] + key.charCodeAt(i % key.length)) % 256;
    [box[i], box[j]] = [box[j], box[i]];
  }
  let i = 0;
  j = 0;
  const out = [];
  for (let y = 0; y < data.length; y++) {
    i = (i + 1) % 256;
    j = (j + box[i]) % 256;
    [box[i], box[j]] = [box[j], box[i]];
    out.push(String.fromCharCode(data.charCodeAt(y) ^ box[(box[i] + box[j]) % 256]));
  }
  const text = out.join("");
  return hasSurrogate(text) ? null : text;
}

/** core._sa_consts: {name: {key: ['n', v] | ['s', v]}}: the objects of constants text assigns. */
function saConsts(text) {
  const out = new Map();
  SA_OBJECT_G.lastIndex = 0;
  for (let m; (m = SA_OBJECT_G.exec(text)) !== null;) {
    let i = m.index + m[0].length;
    let table = new Map();
    for (;;) {
      const e = matchAt(SA_ENTRY_Y, text, i);
      if (e === null) { table = null; break; }
      const g = e.groups;
      const key = g.k ?? g.k2 ?? g.k3 ?? "";
      const v = g.v;
      if (v[0] === "'" || v[0] === '"') {
        const val = saString(v.slice(1, -1));
        if (val === null) { table = null; break; }
        table.set(key, ["s", val]);
      } else {
        const neg = v.startsWith("-");
        const num = saNumber(pyStrip(v.replace(/^-+/, "")));
        table.set(key, ["n", neg ? -num : num]);
      }
      i = e.index + e[0].length;
      if (g.end === "}") break;
    }
    if (table !== null && table.size) out.set(m[1], out.has(m[1]) ? null : table);
    SA_OBJECT_G.lastIndex = m.index + m[0].length;
  }
  for (const [k, v] of [...out]) if (v === null) out.delete(k);
  return out;
}

/** core._SaAccessor: a string array's accessor. */
class SaAccessor {
  constructor(fn, items, off, alphabet) {
    Object.assign(this, { fn, items, off, alphabet, kind: "plain", rot: 0, memo: new Map() });
  }

  read(idx, key, kind = null, rot = null) {
    if (idx === null || idx === undefined) return null;
    kind = kind ?? this.kind;
    rot = rot ?? this.rot;
    const n = this.items.length;
    const i = saToNumber(idx) - this.off;
    if (i !== i || !(i >= 0 && i < n) || i !== Math.trunc(i)) return null;
    const k = (i + rot) % n;
    const mk = k + "\u0000" + (key === null ? "\u0001" : typeof key === "string" ? "s" + key : "n" + String(key)) + "\u0000" + kind;
    if (!this.memo.has(mk)) {
      const s = this.items[k];
      this.memo.set(mk, kind === "plain" ? s : kind === "base64" ? saAtob(s, this.alphabet) : saRc4(s, key, this.alphabet));
    }
    return this.memo.get(mk);
  }
}

/** core._sa_quote: a single-quoted literal on one row. */
function saQuote(s) {
  return "'" + s.replaceAll("\\", "\\\\").replaceAll("'", "\\'").replaceAll("\n", "\\n").replaceAll("\r", "\\r")
    .replaceAll("\u2028", "\\u2028").replaceAll("\u2029", "\\u2029") + "'";
}

/** A search of text[pos:hi] that sees before pos (Python's pattern.search(text, pos, hi)). */
function searchUpTo(g, text, pos, hi = text.length) {
  g.lastIndex = pos;
  return g.exec(hi === text.length ? text : text.slice(0, hi));
}

/** core._dv_string_arrays: `text` with the calls that read a string array read as their strings. */
function dvStringArrays(text) {
  if ((text.length > SA_MAX_CHARS && cpLen(text) > SA_MAX_CHARS) || !text.includes("function")) return text;
  const arrays = [];
  SA_ARRAY_FN_G.lastIndex = 0;
  for (let m; (m = SA_ARRAY_FN_G.exec(text)) !== null;) {
    const end = m.index + m[0].length;
    const got = saStrings(text, end);
    SA_ARRAY_FN_G.lastIndex = end;
    if (got === null || !got[0].length) continue;
    const fn = reEscape(m.groups.fn), arr = reEscape(m.groups.arr);
    const tail = pyRe(SA_TAIL_HEAD + fn + SA_TAIL_MID + arr + SA_TAIL_END + fn + SA_TAIL_CALL, "y");
    if (matchAt(tail, text, got[1]) === null) continue;
    arrays.push([m.groups.fn, got[0]]);
    if (arrays.length >= SA_MAX_ARRAYS) break;
  }
  if (!arrays.length) return text;
  const consts = saConsts(text);
  const accessors = new Map();
  for (const [fn, items] of arrays) {
    const esc = reEscape(fn);
    for (const rx of [pyReB(SA_ACC_A_HEAD + esc + SA_CALL_TAIL, "g"), pyReB(SA_ACC_B_HEAD + esc + SA_ACC_B_TAIL, "g")]) {
      for (const m of text.matchAll(rx)) {
        let off;
        try {
          off = saToNumber(saValue(saParse(saTokens(m.groups.off), consts), new Map(), null));
        } catch (e) {
          if (e instanceof SaStop) continue;
          throw e;
        }
        if (off !== off || !Number.isFinite(off) || off !== Math.trunc(off)) continue;
        const end = m.index + m[0].length;
        const a = searchUpTo(SA_ALPHABET_G, text, end, cpForward(text, end, SA_BODY));
        accessors.set(m.groups.g, new SaAccessor(fn, items, off, a === null ? null : a[1]));
      }
    }
  }
  if (!accessors.size) return text;
  const aliases = new Map(), wrappers = new Map();
  SA_ALIAS_G.lastIndex = 0;
  for (let m; (m = SA_ALIAS_G.exec(text)) !== null;) {
    if (!aliases.has(m[1])) aliases.set(m[1], new Set());
    aliases.get(m[1]).add(m[2]);
  }
  for (const m of text.matchAll(SA_WRAPPER_G)) {
    const g = m.groups;
    const raw = pyStrip(g.params) ? g.params.split(",") : [];
    const params = raw.map((x) => SA_PARAM_WHOLE.exec(x)).filter((p) => p !== null).map((p) => p[1]);
    let args;
    try {
      if (params.length !== raw.length) saStop("parameters");
      args = saParse(saTokens(g.args), consts, true);
    } catch (e) {
      if (e instanceof SaStop) continue;
      throw e;
    }
    const name = g.n1 ?? g.n2;
    if (!wrappers.has(name)) wrappers.set(name, []);
    wrappers.get(name).push([params, g.target, args]);
  }
  const resolve = (name, args, depth = 0) => {
    if (depth > SA_DEPTH) saStop("deep");
    const acc = accessors.get(name);
    if (acc !== undefined) return [acc, args.length ? args[0] : null, args.length > 1 ? args[1] : null];
    const given = aliases.get(name) ?? new Set(), wraps = wrappers.get(name) ?? [];
    if (given.size + wraps.length !== 1) saStop("not one");
    if (given.size) return resolve([...given][0], args, depth + 1);
    const [params, target, targs] = wraps[0];
    if (args.length < params.length) saStop("arity");
    const env = new Map(params.map((p, i) => [p, args[i]]));
    return resolve(target, targs.map((a) => saValue(a, env, null)), depth + 1);
  };
  for (const [name, acc] of [...accessors]) {
    const fn = reEscape(acc.fn);
    let inv = pyReG(SA_INVOKE_HEAD + fn + SA_INVOKE_TAIL).exec(text);
    if (inv === null) inv = pyReG(SA_INVOKE2_HEAD + fn + SA_INVOKE2_TAIL).exec(text);
    if (inv === null) { acc.kind = acc.alphabet !== null ? "base64" : "plain"; continue; }
    let loop = null;
    const lo = cpBack(text, inv.index, SA_LOOP_BACK), region = text.slice(0, inv.index);
    SA_CHECKSUM_G.lastIndex = lo;
    for (let m; (m = SA_CHECKSUM_G.exec(region)) !== null;) { loop = m; SA_CHECKSUM_G.lastIndex = m.index + Math.max(1, m[0].length); }
    let tree, target;
    const terms = [];                                    // [term, index, key]: the parseInt calls, resolved once
    try {
      if (loop === null) saStop("no checksum");
      target = saToNumber(saValue(saParse(saTokens(inv.groups.t), consts), new Map(), null));
      tree = saParse(saTokens(loop.groups.e), consts);
      const collect = (t) => {
        if (t[0] === "pi") {
          const got = resolve(t[1], t[2].map((a) => saValue(a, new Map(), null)));
          if (got[0] !== acc) saStop("another accessor");
          terms.push([t, got[1], got[2]]);
        } else if (t[0] === "neg" || t[0] === "pos") collect(t[1]);
        else if (t[0] === "+" || t[0] === "-" || t[0] === "*" || t[0] === "/") { collect(t[1]); collect(t[2]); }
        else if (t[0] !== "n") saStop("term");
      };
      collect(tree);
    } catch (e) {
      if (!(e instanceof SaStop)) throw e;
      accessors.delete(name);
      continue;
    }
    let chosen = null;
    for (const kind of acc.alphabet !== null ? ["plain", "base64", "rc4"] : ["plain"]) {
      for (let rot = 0; rot < acc.items.length; rot++) {
        const vals = new Map();
        for (const [t, idx, key] of terms) {             // (a term that is NaN makes the checksum NaN)
          const v = saParseInt(acc.read(idx, key, kind, rot));
          if (v !== v) break;
          vals.set(t, v);
        }
        if (vals.size < terms.length) continue;
        const num = (t) => {
          const k = t[0];
          if (k === "n") return t[1];
          if (k === "pi") return vals.get(t);
          if (k === "neg") return -num(t[1]);
          if (k === "pos") return num(t[1]);
          const a = num(t[1]), b = num(t[2]);
          return k === "+" ? a + b : k === "-" ? a - b : k === "*" ? a * b : a / b;
        };
        if (num(tree) === target) { chosen = [kind, rot]; break; }
      }
      if (chosen !== null) break;
    }
    if (chosen === null) accessors.delete(name);
    else [acc.kind, acc.rot] = chosen;
  }
  if (!accessors.size) return text;
  const callers = new Set(accessors.keys()), queue = [...accessors.keys()], givenTo = new Map();
  for (const [name, given] of aliases) {
    if (given.size === 1 && !wrappers.has(name)) {
      const to = [...given][0];
      if (!givenTo.has(to)) givenTo.set(to, []);
      givenTo.get(to).push(name);
    }
  }
  for (const [name, wraps] of wrappers) {
    if (wraps.length === 1 && !aliases.has(name)) {
      const to = wraps[0][1];
      if (!givenTo.has(to)) givenTo.set(to, []);
      givenTo.get(to).push(name);
    }
  }
  while (queue.length) {
    for (const name of givenTo.get(queue.pop()) ?? []) {
      if (!callers.has(name)) { callers.add(name); queue.push(name); }
    }
  }
  const out = [];
  let pos = 0, read = 0;
  while (read < SA_MAX_CALLS) {
    SA_CALL_G.lastIndex = pos;
    const m = SA_CALL_G.exec(text);
    if (m === null) break;
    const nameEnd = m.index + m[1].length;
    let s = null;
    if (callers.has(m[1]) && !SA_FUNCTION_TAIL_RE.test(text.slice(cpBack(text, m.index, 9), m.index))) {
      try {
        const args = saParse(saTokens(m[2]), consts, true).map((a) => saValue(a, new Map(), null));
        const [acc, idx, key] = resolve(m[1], args);
        s = acc.read(idx, key);
      } catch (e) {
        if (!(e instanceof SaStop)) throw e;
      }
    }
    if (s === null) { out.push(text.slice(pos, nameEnd)); pos = nameEnd; continue; }   // (the calls in its arguments are read on)
    out.push(text.slice(pos, m.index), saQuote(s));
    pos = m.index + m[0].length;
    read++;
  }
  out.push(text.slice(pos));
  return out.join("");
}

const PX_MAX_ENTRIES = 256, PX_MAX_USES = 1_000_000, PX_DEPTH = 32, PX_ARGS = 4000;
const PX_OBJECT_SRC = String.raw`(?<![\w$.])(` + SA_IDENT + String.raw`)\s*=\s*\{`;
const PX_KEY_SRC = String.raw`\s*(?:(?P<k>` + SA_IDENT + String.raw`)|'(?P<k2>[^'\\\n]*)'|"(?P<k3>[^"\\\n]*)")\s*:\s*`;
const PX_FUNCTION_SRC = String.raw`function\s*(?:` + SA_IDENT + String.raw`\s*)?\((?P<params>[^()]{0,400})\)\s*\{`
  + String.raw`(?:\s*(?:var|const|let)\s+` + SA_IDENT + String.raw`\s*=\s*` + SA_IDENT + String.raw`\s*;)*`
  + String.raw`\s*return\s+(?P<e>[^;{}]{1,400}?)\s*;?\s*\}`;
const PX_BINARY_SRC = String.raw`\s*(` + SA_IDENT + String.raw`)(?:\s*(===|!==|==|!=|<=|>=|<<|>>>|>>|&&|\|\||\*\*|[-+*/%<>&|^])\s*`
  + String.raw`|\s+(instanceof|in)\s+)(` + SA_IDENT + String.raw`)\s*`;
const PX_CALL_SRC = String.raw`\s*(` + SA_IDENT + String.raw`)\s*\((?P<a>[^()]*)\)\s*`;
const PX_REF_CALL_SRC = String.raw`\s*(?P<o>` + SA_IDENT + String.raw`)\s*\[\s*(?:'(?P<k>[^'\\\n]*)'|"(?P<k2>[^"\\\n]*)")\s*\]`
  + String.raw`\s*\((?P<a>[^()]*)\)\s*`;
const PX_REF_SRC = String.raw`(?P<o>` + SA_IDENT + String.raw`)\s*\[\s*(?:'(?P<k>[^'\\\n]*)'|"(?P<k2>[^"\\\n]*)")\s*\]`;
const PX_STRINGS_SRC = String.raw`(?:'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*")`
  + String.raw`(?:\s*\+\s*(?:'(?:[^'\\\n]|\\[^\n])*'|"(?:[^"\\\n]|\\[^\n])*"))*`;
const PX_END_SRC = String.raw`\s*([,}])`;
const PX_USE_SRC = String.raw`(?<![\w$.])(` + SA_IDENT + String.raw`)\s*\[\s*(?:'([^'\\\n]*)'|"([^"\\\n]*)")\s*\]`;
const PX_OPEN_SRC = String.raw`\s*\(`;
const PX_OBJECT_G = pyRe(PX_OBJECT_SRC, "g");
const PX_KEY_Y = pyReG(PX_KEY_SRC, "y");
const PX_FUNCTION_Y = pyReG(PX_FUNCTION_SRC, "y");
const PX_BINARY_WHOLE = pyReG(String.raw`^(?:` + PX_BINARY_SRC + String.raw`)\Z`);
const PX_CALL_WHOLE = pyReG(String.raw`^(?:` + PX_CALL_SRC + String.raw`)\Z`);
const PX_REF_CALL_WHOLE = pyReG(String.raw`^(?:` + PX_REF_CALL_SRC + String.raw`)\Z`);
const PX_REF_Y = pyReG(PX_REF_SRC, "y");
const PX_STRINGS_Y = pyRe(PX_STRINGS_SRC, "y");
const PX_END_Y = pyRe(PX_END_SRC, "y");
const PX_USE_G = pyRe(PX_USE_SRC, "g");
const PX_OPEN_Y = pyRe(PX_OPEN_SRC, "y");

/** core._px_params: a parameter list's names, else null. */
function pxParams(src) {
  if (!pyStrip(src)) return [];
  const names = src.split(",").map((p) => SA_PARAM_WHOLE.exec(p));
  return names.some((n) => n === null) ? null : names.map((n) => n[1]);
}
const sameList = (a, b) => a !== null && b !== null && a.length === b.length && a.every((x, i) => x === b[i]);

/** core._px_entries: {key: entry} of the object literal whose '{' ends at text[i] when every entry is a proxy, else null. */
function pxEntries(text, i) {
  const out = new Map();
  for (;;) {
    const k = matchAt(PX_KEY_Y, text, i);
    if (k === null || out.size >= PX_MAX_ENTRIES) return null;
    const key = k.groups.k ?? k.groups.k2 ?? k.groups.k3 ?? "";
    i = k.index + k[0].length;
    const f = matchAt(PX_FUNCTION_Y, text, i);
    const s = f === null ? matchAt(PX_STRINGS_Y, text, i) : null;
    const r = f === null && s === null ? matchAt(PX_REF_Y, text, i) : null;
    let entry;
    if (f !== null) {
      const params = pxParams(f.groups.params), body = f.groups.e;
      if (params === null || new Set(params).size !== params.length) return null;
      const b = PX_BINARY_WHOLE.exec(body), c = PX_CALL_WHOLE.exec(body), rc = PX_REF_CALL_WHOLE.exec(body);
      if (b !== null && params.length === 2 && b[1] === params[0] && b[4] === params[1]) entry = ["op", b[2] ?? b[3]];
      else if (c !== null && params.length && c[1] === params[0] && sameList(pxParams(c.groups.a), params.slice(1))) {
        entry = ["call", params.length - 1];
      } else if (rc !== null && sameList(pxParams(rc.groups.a), params)) {
        entry = ["refcall", rc.groups.o, rc.groups.k ?? rc.groups.k2, params.length];
      } else return null;
      i = f.index + f[0].length;
    } else if (s !== null) {
      const parts = [...s[0].matchAll(SA_LIT_G)].map((x) => saString(x[0].slice(1, -1)));
      if (parts.some((p) => p === null)) return null;
      entry = ["str", parts.join("")];
      i = s.index + s[0].length;
    } else if (r !== null) {
      entry = ["ref", r.groups.o, r.groups.k ?? r.groups.k2];
      i = r.index + r[0].length;
    } else return null;
    out.set(key, entry);
    const e = matchAt(PX_END_Y, text, i);
    if (e === null) return null;
    i = e.index + e[0].length;
    if (e[1] === "}") return out;
  }
}

/** core._px_args: [end, [[start, end]]] of the arguments of the call whose '(' ends at text[i], else null. */
function pxArgs(text, i, hi) {
  const parts = [];
  let depth = 0, start = i, j = i, quote = null;
  const end = Math.min(hi, cpForward(text, i, PX_ARGS));
  while (j < end) {
    const ch = text[j];
    if (quote !== null) {
      if (ch === "\\") { j += 2; continue; }
      if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"' || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) {
        if (ch !== ")") return null;
        if (pyStrip(text.slice(start, j)) || parts.length) parts.push([start, j]);
        return [j, parts];
      }
      depth--;
    } else if (ch === "," && depth === 0) { parts.push([start, j]); start = j + 1; }
    j++;
  }
  return null;
}

const countNl = (s) => { let n = 0; for (const ch of s) if (ch === "\n") n++; return n; };

/** core._dv_proxies: `text` with the proxy objects' uses read as what they stand for. */
function dvProxies(text) {
  if (!text.includes("function") || !text.includes("[")) return text;
  const objects = new Map();
  PX_OBJECT_G.lastIndex = 0;
  for (let m; (m = PX_OBJECT_G.exec(text)) !== null;) {
    const entries = pxEntries(text, m.index + m[0].length);
    if (entries !== null && entries.size) objects.set(m[1], objects.has(m[1]) ? null : entries);
    PX_OBJECT_G.lastIndex = m.index + m[0].length;
  }
  for (const [k, v] of [...objects]) if (v === null) objects.delete(k);
  if (!objects.size) return text;
  const final = (entry) => {
    let depth = 0;
    while (entry && (entry[0] === "ref" || entry[0] === "refcall") && depth <= PX_DEPTH) {
      const target = objects.get(entry[1])?.get(entry[2]);
      if (target === undefined) return null;
      if (entry[0] === "refcall" && (target[0] === "str" || (target[0] === "call" && target[1] + 1 !== entry[3])
          || (target[0] === "op" && entry[3] !== 2))) return null;
      entry = target;
      depth++;
    }
    return entry && (entry[0] === "call" || entry[0] === "op" || entry[0] === "str") ? entry : null;
  };
  let uses = 0;
  // Python's _PX_USE_RE.search(text, pos, hi): a match of text[:hi] that sees before pos
  const useIn = (pos, hi) => {
    for (;;) {
      PX_USE_G.lastIndex = pos;
      const m = PX_USE_G.exec(text);
      if (m === null || m.index >= hi) return null;
      if (m.index + m[0].length <= hi) return m;
      pos = m.index + 1;
    }
  };
  const rewrite = (lo, hi, depth) => {
    const out = [];
    let pos = lo;
    while (uses < PX_MAX_USES) {
      const m = useIn(pos, hi);
      if (m === null) break;
      const end = m.index + m[0].length;
      let entry = objects.get(m[1])?.get(m[2] !== undefined ? m[2] : m[3]);
      entry = entry !== undefined ? final(entry) : null;
      if (entry === null) { out.push(text.slice(pos, end)); pos = end; continue; }
      if (entry[0] === "str") {
        out.push(text.slice(pos, m.index), saQuote(entry[1]));
        pos = end;
        uses++;
        continue;
      }
      let o = matchAt(PX_OPEN_Y, text, end);
      if (o !== null && end + o[0].length > hi) o = null;
      const got = o !== null && depth < PX_DEPTH ? pxArgs(text, end + o[0].length, hi) : null;
      const want = entry[0] === "call" ? entry[1] + 1 : 2;
      if (got === null || got[1].length !== want) { out.push(text.slice(pos, end)); pos = end; continue; }
      const args = got[1].map(([a, b]) => pyStrip(rewrite(a, b, depth + 1)));
      const read = entry[0] === "call" ? args[0] + "(" + args.slice(1).join(", ") + ")"
        : "(" + args[0] + " " + entry[1] + " " + args[1] + ")";
      out.push(text.slice(pos, m.index), read, "\n".repeat(countNl(text.slice(m.index, got[0] + 1)) - countNl(read)));
      pos = got[0] + 1;
      uses++;
    }
    out.push(text.slice(pos, hi));
    return out.join("");
  };
  return rewrite(0, text.length, 0);
}

export function decodedView(text) {
  const base = dvProxies(dvStringArrays(text));
  if (base === text) {                                // (no string array or proxy object read)
    if (text.length > DV_MAX_CHARS && cpLen(text) > DV_MAX_CHARS) return text;
    if (!DV_NEEDLES.some((n) => text.includes(n))) return text;
  }
  const joined = base.includes("+") ? base.replace(DV_JOIN_G, "") : base;
  let view = joined;
  // (a longer text with a string array: its strings only)
  if (!(base.length > DV_MAX_CHARS && cpLen(base) > DV_MAX_CHARS) && DV_NEEDLES.some((n) => base.includes(n))) {
    view = dvDecoders(view);
  }
  if (view === joined && base === text) return text;  // nothing decoded: literals joined alone are no reading of their own
  return dvArraysAndMembers(view);
}

/** core._dv_decoders: the decoders' calls on literals read as their text. */
function dvDecoders(view) {
  if (view.includes("Buffer")) view = view.replace(DV_BUFFER_G, dvReplace((g) => g.enc));
  if (view.includes("atob")) view = view.replace(DV_ATOB_G, dvReplace(() => "base64"));
  if (view.includes("fromhex") || view.includes("unhexlify") || view.includes("b64decode")) {
    view = view.replace(DV_PY_G, dvReplace((g) => (g.fh || g.uh ? "hex" : "base64")));
  }
  const helpers = dvHelpers(view);
  if (helpers.size) {
    const names = [...helpers.keys()].sort();
    const call = pyReG(String.raw`(?<![\w$.])(?P<name>` + names.map(reEscape).join("|") + String.raw`)[ \t]*\([ \t]*`
      + DV_LIT + String.raw`[ \t]*\)`, "g");
    view = view.replace(call, dvReplace((g) => helpers.get(g.name)));
  }
  if (view.includes("^")) {
    const xors = dvXorDecoders(view);
    if (xors.size) {
      const names = [...xors.keys()].sort();
      const call = pyReG(String.raw`(?<![\w$.])(?P<name>` + names.map(reEscape).join("|") + String.raw`)[ \t]*\([ \t]*`
        + DV_LIT + String.raw`[ \t]*\)`, "g");
      view = view.replace(call, (...args) => {
        const g = args[args.length - 1];
        const [kind, key] = xors.get(g.name);
        const d = dvBytes(dvLiteral(g), kind);
        if (d === null || !dvXorPrintable(d, key)) return args[0];
        return dvQuote(Buffer.from(d.map((b, i) => b ^ key[i % key.length])).toString("latin1"));
      });
    }
  }
  if (view.includes("fromCharCode") || view.includes("chr") || view.includes("byte")) view = dvCharCodes(view);
  return view;
}

/** The last steps of core._decoded_view: constant arrays read where indexed, members named by literals. */
function dvArraysAndMembers(view) {
  let arrays = 0;
  for (const m of [...view.matchAll(DV_ARRAY_G)]) {
    if (arrays >= DV_MAX_ARRAYS) break;
    const name = m.groups.name;
    const items = [...m.groups.items.matchAll(DV_STR_ITEM_G)].map((x) => x[0]);
    const esc = reEscape(name);
    const mutated = pyRe(DV_NAME_HEAD + esc + DV_MUTATED_TAIL).test(view);
    if (mutated || [...view.matchAll(pyRe(DV_NAME_HEAD + esc + DV_ASSIGNED_TAIL, "g"))].length !== 1) continue;
    arrays++;
    view = view.replace(pyRe(DV_NAME_HEAD + esc + DV_INDEX_TAIL, "g"),
      (whole, i) => (Number(i) < items.length ? items[Number(i)] : whole));
  }
  return view.includes("[") ? view.replace(DV_MEMBER_G, (...args) => { const g = args[args.length - 1]; return "." + (g.a || g.b); }) : view;
}

// ---- scripts a script starts with node or python (0.1.8; core's comment above _SPAWN_MAX_DEPTH) ----
export const SPAWN_MAX_DEPTH = 3, SPAWN_MAX_FILES = 20;
const SPAWN_NAME_DEPTH = 3, SPAWN_MAX_TARGETS = 8, SPAWN_MAX_NAMED = 32;
const SPAWN_CALL_SRC = String.raw`\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*(?:process\s*\.\s*execPath|process\s*\.\s*argv\s*\[\s*0\s*\]`
  + String.raw`|['"` + BT + String.raw`](?:node|nodejs|(?P<rt>bun|deno))(?:\.exe)?['"` + BT + String.raw`]|(?P<js>[A-Za-z_$][\w$]*))\s*,\s*\[|\bfork\s*\(`
  + String.raw`|\b(?:Popen|run|call|check_call|check_output)\s*\(\s*\[\s*(?:sys\s*\.\s*executable`
  + String.raw`|['"]python[0-9.]*(?:\.exe)?['"]|(?P<py>[A-Za-z_]\w*))\s*,`;
const SPAWN_SCRIPT_EXT_SRC = String.raw`\.(?:[cm]?[jt]s|[jt]sx|py)$`;
const SPAWN_SCRIPT_EXT_RE = pyRe(SPAWN_SCRIPT_EXT_SRC, "i");
const SPAWN_STR_SRC = String.raw`str\s*\(\s*([A-Za-z_]\w*)\s*\)`;
const SPAWN_LIT_SRC = String.raw`'(?P<a>[^'"` + BT + String.raw`\n$\\]{1,200})'|"(?P<b>[^'"` + BT + String.raw`\n$\\]{1,200})"|`
  + BT + String.raw`(?P<c>[^'"` + BT + String.raw`\n$\\]{1,200})` + BT;
const SPAWN_CONCAT_SRC = String.raw`__dirname\s*\+\s*(?:'/?(?P<a>[^'"` + BT + String.raw`\n$\\]{1,200})'|"/?(?P<b>[^'"` + BT
  + String.raw`\n$\\]{1,200})"|` + BT + String.raw`/?(?P<c>[^'"` + BT + String.raw`\n$\\]{1,200})` + BT + String.raw`)|`
  + BT + String.raw`\$\{\s*__dirname\s*\}/(?P<t>[^` + BT + String.raw`$\n\\]{1,200})` + BT;
const SPAWN_DIR_SRC = String.raw`__dirname|os\s*\.\s*path\s*\.\s*dirname\s*\(\s*(?:os\s*\.\s*path\s*\.\s*(?:abspath|realpath)`
  + String.raw`\s*\(\s*)?__file__\s*\)?\s*\)|Path\s*\(\s*__file__\s*\)\s*(?:\.\s*resolve\s*\(\s*\))?\s*\.\s*parent`
  + String.raw`(?:\s*\.\s*resolve\s*\(\s*\))?|(?:path\s*\.\s*)?dirname\s*\(\s*(?:url\s*\.\s*)?fileURLToPath\s*\(`
  + String.raw`\s*import\s*\.\s*meta\s*\.\s*url\s*\)\s*\)|import\s*\.\s*meta\s*\.\s*dirname`;
const SPAWN_JOIN_SRC = String.raw`(?:path\s*\.\s*(?:join|resolve)|os\s*\.\s*path\s*\.\s*join)\s*\(`;
const SPAWN_NAME_SRC = String.raw`[A-Za-z_$][\w$]*`;
const SPAWN_CALL_G = pyReG(SPAWN_CALL_SRC, "g");
const whole = (src) => pyReG(String.raw`^(?:` + src + String.raw`)\Z`);
const SPAWN_LIT_WHOLE = whole(SPAWN_LIT_SRC);
const SPAWN_CONCAT_WHOLE = whole(SPAWN_CONCAT_SRC);
const SPAWN_DIR_WHOLE = whole(SPAWN_DIR_SRC);
const SPAWN_NAME_WHOLE = whole(SPAWN_NAME_SRC);
const SPAWN_STR_WHOLE = whole(SPAWN_STR_SRC);
const SPAWN_JOIN_AT = pyRe(SPAWN_JOIN_SRC, "y");
const SPAWN_NO_SCRIPT_FLAGS = new Set(["-m", "-c", "-e", "-p", "--eval", "--print"]);
const SPAWN_VALUE_FLAGS = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader", "-W", "-X"]);

/** A call's or a list's arguments from text[i] to what closes it, split at top-level commas; [] if unclosed. core._spawn_args. */
function spawnArgs(text, i, limit = 400) {
  const args = [];
  let depth = 0, start = i, j = i, quote = null;
  const end = cpForward(text, i, limit);
  while (j < end) {
    const ch = text[j];
    if (quote !== null) {
      if (ch === "\\") { j += 2; continue; }
      if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"' || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0) { args.push(text.slice(start, j)); return args.map((a) => pyStrip(a)); }
      depth--;
    } else if (ch === "," && depth === 0) { args.push(text.slice(start, j)); start = j + 1; }
    // a character outside the BMP is two units here and one in Python: step over its low half
    j += text.charCodeAt(j) >= 0xd800 && text.charCodeAt(j) <= 0xdbff && j + 1 < text.length ? 2 : 1;
  }
  return [];
}

const litValue = (m) => (m === null ? null : m.groups.a ?? m.groups.b ?? m.groups.c);

/** The operands of `expr` split at its top-level '/' (Python's `Path / 'x'`). core._spawn_pieces. */
function spawnPieces(expr) {
  const pieces = [];
  let depth = 0, start = 0, quote = null, j = 0;
  while (j < expr.length) {
    const ch = expr[j];
    if (quote !== null) {
      if (ch === "\\") { j += 2; continue; }
      if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"' || ch === "`") quote = ch;
    else if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "/" && depth === 0) { pieces.push(pyStrip(expr.slice(start, j))); start = j + 1; }
    j++;
  }
  pieces.push(pyStrip(expr.slice(start)));
  return pieces;
}

/** [base, path] of a path joined from `parts`: a path or the script's own directory, then literals. core._spawn_join. */
function spawnJoin(parts, text, names) {
  const head = spawnPath(parts[0], text, names);
  if (head === null) return null;
  const segs = [head[1]];
  for (const part of parts.slice(1)) {
    const piece = spawnPath(part, text, names);
    if (piece === null || piece[0] !== "cwd") return null;
    segs.push(piece[1]);
  }
  return [head[0], segs.join("/")];
}

/** [base, path] a script argument names ('dir', its path '.' for the directory itself, or 'cwd'), else null. core._spawn_path. */
function spawnPath(expr, text, names) {
  expr = pyStrip(expr);
  const lit = litValue(SPAWN_LIT_WHOLE.exec(expr));
  if (lit != null) return lit.startsWith("-") ? null : ["cwd", lit];
  const c = SPAWN_CONCAT_WHOLE.exec(expr);
  if (c !== null) return ["dir", c.groups.a ?? c.groups.b ?? c.groups.c ?? c.groups.t];
  if (SPAWN_DIR_WHOLE.test(expr)) return ["dir", "."];
  const str = SPAWN_STR_WHOLE.exec(expr);
  if (str !== null) return spawnPath(str[1], text, names);
  SPAWN_JOIN_AT.lastIndex = 0;
  const j = SPAWN_JOIN_AT.exec(expr);
  if (j !== null) {
    const parts = spawnArgs(expr, j[0].length);
    if (!parts.length || !pyRstrip(expr).endsWith(")")) return null;
    return spawnJoin(parts, text, names);
  }
  if (expr.includes("/")) {
    const pieces = spawnPieces(expr);
    if (pieces.length > 1 && pieces.every((x) => x)) return spawnJoin(pieces, text, names);
  }
  if (SPAWN_NAME_WHOLE.test(expr) && names > 0) {
    const am = pyReG(String.raw`(?<![\w$.])` + reEscape(expr) + String.raw`\s*=(?![=>])\s*(?P<e>[^\n;]{1,300})`).exec(text);
    if (am !== null) {
      const value = am.groups.e;
      const parts = spawnArgs(value + ")", 0);
      return spawnPath(parts.length ? parts[0] : value, text, names - 1);
    }
  }
  return null;
}

/**
 * [[base, path]]: the package scripts `text` starts with node or python, at most SPAWN_MAX_TARGETS: read as
 * written, then with the strings it decodes as it runs decoded (decodedView), so a path it hides is followed too.
 * Twin of core.spawned_scripts.
 */
export function spawnedScripts(text) {
  const out = spawnedScriptsOf(text);
  if (out.length < SPAWN_MAX_TARGETS) {
    const view = decodedView(text);
    if (view !== text) {
      for (const t of spawnedScriptsOf(view)) {
        if (!out.some(([b, p]) => b === t[0] && p === t[1])) {
          out.push(t);
          if (out.length >= SPAWN_MAX_TARGETS) break;
        }
      }
    }
  }
  return out;
}

/** spawnedScripts' reading of one text. core._spawned_scripts. */
function spawnedScriptsOf(text) {
  if (!["spawn", "execFile", "fork", "Popen", "run", "call", "check_"].some((n) => text.includes(n))) return [];
  const out = [];
  let namedCalls = 0;
  for (const m of text.matchAll(SPAWN_CALL_G)) {
    const named = m.groups.js !== undefined || m.groups.py !== undefined;
    if (named && ++namedCalls > SPAWN_MAX_NAMED) continue;
    const args = spawnArgs(text, m.index + m[0].length);
    let skip = false;
    let runs = JS_RUNTIMES.get(m.groups.rt ?? "") ?? new Set();                 // `bun run x.js`
    for (const arg of args.slice(0, 6)) {
      if (skip) { skip = false; continue; }
      const value = litValue(SPAWN_LIT_WHOLE.exec(arg));
      if (value != null && value.startsWith("-")) {
        const flag = value.split("=")[0];
        if (SPAWN_NO_SCRIPT_FLAGS.has(flag)) break;
        skip = SPAWN_VALUE_FLAGS.has(flag) && !value.includes("=");
        continue;
      }
      if (value != null && runs.has(value)) { runs = new Set(); continue; }
      const target = spawnPath(arg, text, SPAWN_NAME_DEPTH);
      if (target !== null) {
        const raw = target[1].replaceAll("\\", "/");
        if (!raw.startsWith("/")) {
          const path = normpathRel(raw);
          if (path !== "." && path !== "" && !out.some(([b, p]) => b === target[0] && p === path)
              && (!named || SPAWN_SCRIPT_EXT_RE.test(pyEnd(path)))) out.push([target[0], path]);
        }
      }
      break;
    }
    if (out.length >= SPAWN_MAX_TARGETS) break;
  }
  return out;
}

/**
 * Reasons an install-time script looks hostile ([] if none): read as written,
 * and again with the strings it decodes as it runs decoded.
 * Twin of lazaret.scanner.core.install_script_risk.
 */
export function installScriptRisk(text, shell = true, command = false) {
  const reasons = installScriptRiskOf(text, shell, command);
  const view = decodedView(text);
  if (view !== text) for (const r of installScriptRiskOf(view, shell, command)) if (!reasons.includes(r)) reasons.push(r + DV_NOTE);
  return reasons;
}

// A shell script (0.1.8; core's comment above _SH_NOT_SHELL_RE): its #! line names a shell, or nothing in it
// is JavaScript or Python.
const SH_NOT_SHELL_SRC = String.raw`\brequire\s*\(|(?<![^\n])[ \t]*(?:import|from)[ \t]+[\w.{*]|\bdef[ \t]+\w+\s*\(|=>`
  + String.raw`|(?<![^\n])[ \t]*(?:const|let|var|class)[ \t]+[A-Za-z_$]|\bconsole\s*\.\s*log\b|\bmodule\s*\.\s*exports\b`
  + String.raw`|\bprocess\s*\.\s*(?:env|argv|exit)\b|\bprint\s*\(|\bos\s*\.\s*(?:system|environ|popen)\b`;
const SH_NOT_SHELL_RE = pyRe(SH_NOT_SHELL_SRC);
const SH_SCRIPT_MAX_CHARS = 1_000_000;
/** Is text JavaScript or Python rather than shell (core._code_text)? A command in code runs when an exec call is
 * handed it. */
function codeText(text) {
  if (text.startsWith("#!")) {
    const lang = shebangLang(text);
    if (lang !== null) return lang !== "sh";
  }
  return SH_NOT_SHELL_RE.test(text);
}
/** Is text a shell script (core._shell_text)? */
function shellText(text) {
  if (cpLongerThan(text, SH_SCRIPT_MAX_CHARS)) return false;
  if (text.startsWith("#!")) return shebangLang(text) === "sh";
  return !SH_NOT_SHELL_RE.test(text);
}

// What an install script sends is read as a flow; a service a list names is where the data goes, a label on
// a send the flow found (0.1.8; core's comment above _SEND_REASONS).
const SEND_REASONS = [...Object.values(LD_REASONS), ...Object.values(SH_DATA_REASONS), SH_BEACON_REASON,
  "sends the machine's user or host name", "sends data to a webhook whose secret", "collects files from several credential folders"];
const RAW_IP_URL_SRC = String.raw`https?://(?:\d{1,3}\.){3}\d{1,3}\b`;
const RAW_IP_URL_RE = pyRe(RAW_IP_URL_SRC, "i");
/** The data-capture or exfiltration service text names (a match), else null (core._destination). */
function destination(text) {
  return captureService(text) ?? EXFIL_SERVICE_RE.exec(text);
}
/** The label of where a script that sends data sends it, else null (core._destination_label). */
function destinationLabel(text) {
  const m = destination(text);
  return m === null ? null : `contacts an address typical of data exfiltration (${cpPrefix(m[0], 40)})`;
}
/** Adds to reasons the label of where the data goes, when one of them sends it (core._label_sends). */
function labelSends(text, reasons) {
  if (reasons.some((r) => SEND_REASONS.some((p) => r.startsWith(p)))) {
    const label = destinationLabel(text);
    if (label !== null && !reasons.includes(label)) reasons.push(label);
  }
}

function installScriptRiskOf(text, shell = true, command = false) {
  const reasons = [];
  // a download piped or substituted into a shell, and PowerShell: in code, where an exec call is handed them
  const code = !command && codeText(text);
  const rows = text.includes("curl") || text.includes("wget") ? text.split("\n") : [];
  if (code ? rows.some((row) => pipesDownloadToShell(row) && EXEC_CALL_RE.test(row)) : pipesDownloadToShell(text)) {
    reasons.push("pipes a download into a shell");
  }
  const substituted = rows.some((row) => runsSubstitutedDownload(row) && (!code || EXEC_CALL_RE.test(row)));
  const received = receivedCodeKind(text);
  if (substituted) reasons.push(DL_CATEGORY_REASON.run);
  else if (received !== null) reasons.push(DL_CATEGORY_REASON[received[1]]);
  const ps = powershellRisk(text);
  if (ps.length && (!code || powershellRunAt(text) >= 0)) reasons.push(...ps);
  if ((received === null || received[1] !== "run") && !substituted && stagerAt(text) >= 0) {
    reasons.push("carries a script that downloads and runs code");
  }
  if (reverseShellAt(text) >= 0) reasons.push("opens a reverse shell");
  const host = HOST_INFO_RE.exec(text);
  for (const [, reason] of exfilSigns(text, host)) if (!reasons.includes(reason)) reasons.push(reason);
  const ipUrl = RAW_IP_URL_RE.exec(text);
  const ip = ipUrl !== null ? cpPrefix(ipUrl[0], 40) : rawIpConnect(text);
  if (ip !== null) reasons.push(`contacts an address typical of data exfiltration (${ip})`);
  if (runsOwnSourceAt(text) >= 0) reasons.push("runs code it reads back from its own file or a data file shipped with it");
  // (0.1.8) data read from the machine and sent, whatever the address; the commands the script runs, read as
  // programs; where the data goes
  const flow = localDataSentAt(text);
  if (flow !== null) {
    const [, kind, what, inAddress] = flow;
    const reason = LD_REASONS[kind] + (kind === "environment" || kind === "file" || kind === "report" ? ` (${cpPrefix(what, 60)})` : "");
    if (!reasons.some((r) => r.startsWith(LD_REASONS[kind])) && (!inAddress || captureService(text) !== null)) reasons.push(reason);
  }
  pushNew(reasons, execCommandReasons(text));
  if (shell && shellText(text)) pushNew(reasons, shReasons(text, 0, false, { commands: 0, complete: true }));
  labelSends(text, reasons);
  reasons.push(...persistenceReasons(text));
  if (PUBLISH_CMD_RE.test(text)) reasons.push("publishes a package to a registry (npm publish)");
  if (NPM_TOKEN_READ_RE.test(text)) reasons.push("collects npm access tokens");
  const dll = runsDll(text);
  if (dll !== null) reasons.push(`runs a DLL with rundll32 or regsvr32 (${cpPrefix(dll, 40)})`);
  // a script it downloads, or decodes, written to a file and run with a shell or an interpreter
  const dropped = downloadsAndRuns(text);
  if (dropped !== null) {
    const interp = PY_RUN_RE.test(text) ? "Python" : dropped[1];
    if (interp) reasons.push(`downloads a script and runs it with ${interp}`);
  }
  const decoded = decodesAndRuns(text);
  if (decoded !== null) {
    const interp = PY_RUN_RE.test(text) ? "Python" : decoded[1];
    reasons.push(interp ? `writes code it decodes to a file and runs it with ${interp}` : "writes a file it decodes and runs it");
  }
  return reasons;
}

// What code that runs on import sends is read as a flow (0.1.8; core's comment above _IMPORT_SENT_REASONS)
const IMPORT_SENT_REASONS = {
  address: "sends the machine's public IP address to a data-capture service",
  identity: "sends the machine's user or host name to a data-capture service",
  report: "sends what local commands report about the machine to a data-capture service",
  environment: "reads credentials or the whole environment and sends them to an exfiltration service",
  credentials: "reads credentials or the whole environment and sends them to an exfiltration service",
  file: "reads local files and sends them to an exfiltration service",
};
const IMPORT_SENT_IP_REASONS = {
  address: "sends the machine's public IP address to an IP address",
  identity: "sends the machine's user or host name to an IP address",
  report: "sends what local commands report about the machine to an IP address",
  environment: "reads credentials or the whole environment and sends them to an IP address",
  credentials: "reads credentials or the whole environment and sends them to an IP address",
  file: "reads local files and sends them to an IP address",
};
const CRED_STORE_SRC = String.raw`\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\.git-credentials|Local Storage`;
const CRED_STORE_RE = pyRe(CRED_STORE_SRC, "i");
const PUBLIC_KEY_FILE_SRC = String.raw`\.pub\b|known_hosts`;           // what .ssh holds that is no secret
const PUBLIC_KEY_FILE_RE = pyRe(PUBLIC_KEY_FILE_SRC, "i");

/** "\n" characters in text[start:end] (Python's text.count("\n", start, end)). */
function countNewlines(text, start, end) {
  let count = 0;
  for (let k = text.indexOf("\n", start); k !== -1 && k < end; k = text.indexOf("\n", k + 1)) count++;
  return count;
}

// Import-time reasons that are CRITICAL wherever found (core._STRONG_IMPORT_REASONS,
// import_time_severity), the data-capture services and the Python run of a download.
const STRONG_IMPORT_REASONS = [
  "runs code it receives over the network", "runs a downloaded script through a shell",
  "runs an encoded PowerShell command", "runs PowerShell that", "carries a script that downloads and runs code",
  "opens a reverse shell", "reads credentials or the whole environment and sends them to",
  "sends the machine's user or host name to a data-capture service", "downloads a script and runs it with",
  "writes code it decodes to a file and runs it with", "runs code it reads back from its own file",
  "carries a GitHub Actions workflow that dumps every repository secret",
  "sends data to a webhook whose secret is written in the code",
  "sends what local commands report about the machine to", "reads local files and sends them to an exfiltration service",
  "sends the machine's public IP address to", "sends the machine's user or host name to an IP address",
  "reads credentials or the whole environment and sends them to an IP address",
  "reads local files and sends them to an IP address",
  "collects files from several credential folders", "sends the machine's user or host name to an address it hides",
  "sends the machine's user or host name in a DNS lookup",
  "sends the machine's user or host name to an address it fetches", "runs a cryptocurrency miner"];
const CAPTURE_SERVICE_SRC = String.raw`webhook\.site|typedwebhook\.tools|oastify\.com|burpcollaborator|\binteract\.sh|\boast[\w.-]*\.(?:pro|live|site`
  + String.raw`|online|fun|me|com)\b|pipedream\.net|requestbin\.(?:com|net|io)\b|\brequestb\.in\b|requestcatcher\.com`
  + String.raw`|hookbin\.com|postb\.in\b|beeceptor\.com`
  + String.raw`|dnslog\.cn|ceye\.io|canarytokens`;
const CAPTURE_SERVICE_RE = pyRe(CAPTURE_SERVICE_SRC, "i");
// an ngrok tunnel's own address counts as one (0.1.8; core's comment above _NGROK_TUNNEL_RE)
const NGROK_TUNNEL_SRC = String.raw`\b[a-z0-9][a-z0-9-]{2,62}\.ngrok(?:-free)?\.(?:app|io|dev)\b|\b\d+\.tcp(?:\.[a-z]{2,3})?\.ngrok\.io\b`;
const NGROK_TUNNEL_RE = pyRe(NGROK_TUNNEL_SRC);
/** The first data-capture service text names, else an ngrok tunnel's address, else null (core.capture_service). */
function captureService(text) {
  let m = CAPTURE_SERVICE_RE.exec(text);
  if (m === null && text.includes("ngrok")) m = NGROK_TUNNEL_RE.exec(text);
  return m;
}
const PY_RUN_SRC = String.raw`\[\s*(?:\w*sys\.executable|["']python[\d.w]*(?:\.exe)?["'])\s*,|\bstart\s+pythonw?\b`
  + String.raw`|\b(?:system|popen|getoutput|run|call|Popen)\s*\(\s*f?["']python[\d.w]*(?:\.exe)?\s`;
const PY_RUN_RE = pyRe(PY_RUN_SRC);
/** 'CRITICAL' when one of importTimeRisk's reasons is a strong one, else 'MAJOR' (core.import_time_severity). */
export function importTimeSeverity(reasons) {
  return reasons.some((r) => STRONG_IMPORT_REASONS.some((p) => r.startsWith(p))) ? "CRITICAL" : "MAJOR";
}

// Prose is not import-time code, and PowerShell counts at import time only as
// an argument of an exec call (core's comment above _PY_DOC_HEAD_RE).
const PY_DOC_HEAD_SRC = String.raw`[ \t]*[rRuUbB]{0,2}\Z`;
const PY_DOC_HEAD_RE = pyRe(PY_DOC_HEAD_SRC, "y");          // on the head alone, from 0: core's match(text, ls, s)
const PY_JOINS = "([{,=+-*/%&|^<>~@\\.\"'";
const BRACKET_SRC = String.raw`[()\[\]{}]`;
const PS_EXEC_BACK = 300;
const PS_EXEC_MAX_NAMES = 200;
const EXEC_CALL_ALL_RE = pyRe(EXEC_CALL_SRC, "g");
const SPACE_TAB_SRC = String.raw`[ \t]*`;
const SPACE_TAB_RE = pyRe(SPACE_TAB_SRC, "y");

/** The spans of `literals` that stand alone as statements (core._py_statement_literals). */
function pyStatementLiterals(text, literals, comments) {
  const out = [];
  const marks = [...literals.map(([s, e]) => [s, e, 1]), ...comments.map(([s, e]) => [s, e, 0])]
    .sort((a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2]);
  let depth = 0, pos = 0, last = "";
  for (const [s, e, isLiteral] of marks) {
    if (s < pos) continue;
    const k = text.slice(pos, s).lastIndexOf("\n");
    const ls = k >= 0 ? pos + k + 1 : (pos === 0 ? 0 : -1);   // -1: a mark before it on its line
    let prior = last;                          // the last code character before the literal's line
    if (ls > pos) {
      const code = pyRstrip(text.slice(pos, ls));
      if (code) prior = code[code.length - 1];
    }
    for (let i = pos; i < s; i++) {
      const c = text.charCodeAt(i);
      if (c === 40 || c === 91 || c === 123) depth++;
      else if (c === 41 || c === 93 || c === 125) depth = Math.max(0, depth - 1);
    }
    const code = pyRstrip(text.slice(pos, s));
    if (code) last = code[code.length - 1];
    pos = e;
    if (!isLiteral) continue;
    if (e > s) last = text[e - 1];
    SPACE_TAB_RE.lastIndex = e;
    SPACE_TAB_RE.test(text);
    const j = SPACE_TAB_RE.lastIndex;
    PY_DOC_HEAD_RE.lastIndex = 0;
    if (ls >= 0 && depth === 0 && (!prior || !PY_JOINS.includes(prior)) && PY_DOC_HEAD_RE.test(text.slice(ls, s))
        && !(ls >= 2 && text[ls - 2] === "\\") && (j === text.length || text[j] === "\n" || text[j] === "#")) {
      out.push([s, e]);
    }
  }
  return out;
}

/** `text` with the characters of `spans` (sorted, disjoint) made spaces, its line breaks kept (core._blank). */
function blank(text, spans) {
  if (!spans.length) return text;
  const parts = [];
  let p = 0;
  for (let [s, e] of spans) {
    s = Math.max(s, p);
    if (e <= s) continue;
    parts.push(text.slice(p, s), text.slice(s, e).split("\n").map((row) => " ".repeat(cpLen(row))).join("\n"));
    p = e;
  }
  parts.push(text.slice(p));
  return parts.join("");
}

/** `text` (a Python or JavaScript file) with its prose blanked, unless it reads its own source (core._import_code). */
export function importCode(text, lang) {
  if (readsOwnSource(text)) return text;
  const literals = lang === "py" ? [] : null;
  const comments = commentSpans(text, lang, null, { literals });
  let spans = [...comments];
  if (literals && literals.length) {
    spans = [...spans, ...pyStatementLiterals(text, literals, comments)].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  }
  return blank(text, spans);
}

/** Is a call whose '(' comes just before `rest` still open at its end? (core._call_open) */
function callOpen(rest) {
  let depth = 1;
  for (let i = 0; i < rest.length; i++) {
    const c = rest.charCodeAt(i);
    if (c === 40 || c === 91 || c === 123) depth++;
    else if ((c === 41 || c === 93 || c === 125) && --depth === 0) return false;
  }
  return true;
}

/** The offset of the first PowerShell name that is an argument of an exec call, else -1 (core._powershell_run_at). */
function powershellRunAt(text) {
  PS_ALL_RE.lastIndex = 0;
  for (let m, k = 0; (m = PS_ALL_RE.exec(text)) !== null; k++) {
    if (k >= PS_EXEC_MAX_NAMES) break;
    const window = text.slice(cpBack(text, m.index, PS_EXEC_BACK), m.index);
    EXEC_CALL_ALL_RE.lastIndex = 0;
    for (let c; (c = EXEC_CALL_ALL_RE.exec(window)) !== null;) {
      if (callOpen(window.slice(c.index + c[0].length))) return m.index;
    }
  }
  for (const [at, cmd] of execCommandLines(text)) {       // a command line handed over by a name given it
    PS_ALL_RE.lastIndex = 0;
    if (PS_ALL_RE.test(cmd)) return at;
  }
  return -1;
}

/**
 * [reasons, line]: why code that runs on import looks hostile by the weaker
 * test (core's comment above _IMPORT_HARVEST_RE) — [] if not — and the
 * 1-based line of the first sign (null when there is none). `text` has \n
 * line endings; `lang` "py" or "js" reads it without its prose. Twin of
 * lazaret.scanner.core.import_time_risk.
 */
export function importTimeRisk(text, lang = null) {
  const [reasons, first] = importTimeReading(text, lang);
  let line = first;
  const view = decodedView(text);
  if (view !== text) {
    const [more, at] = importTimeReading(view, lang);
    for (const r of more) if (!reasons.includes(r)) { reasons.push(r + DV_NOTE); line ??= at; }
  }
  return [reasons, line];
}

function importTimeReading(text, lang) {
  let [reasons, line] = importTimeRiskOf(text);
  if (reasons.length && (lang === "py" || lang === "js")) {
    const code = importCode(text, lang);
    if (code !== text) [reasons, line] = importTimeRiskOf(code);
  }
  return [reasons, line];
}

/** [offset, kind, what, inAddress] of the first local data text sends (its flow, then the command lines it hands
 * a shell), else null (core._import_flow). */
function importFlow(text) {
  const flow = localDataSentAt(text);
  if (flow !== null) return flow;
  for (const [at, reason] of execCommandFlows(text)) {
    for (const [kind, sent] of Object.entries(SH_DATA_REASONS)) {
      if (reason.startsWith(sent)) return [at, kind === "lookup-identity" ? "identity" : kind, reason.slice(sent.length + 2, -1), false];
    }
  }
  return null;
}

function importTimeRiskOf(text) {
  const reasons = [];
  let line = null;
  const flow = importFlow(text);
  if (flow !== null) {
    const [at, kind, what, inAddress] = flow;
    // a data-capture service for any local data; a service a client talks to with its user's key for what no
    // client sends (core's comment)
    const harvest = !inAddress && ((kind === "environment" && what === LD_WHOLE_ENV) || kind === "credentials"
      || (kind === "file" && CRED_STORE_RE.test(what) && !PUBLIC_KEY_FILE_RE.test(what)));
    const dest = captureService(text) ?? (harvest ? EXFIL_SERVICE_RE.exec(text) : null);
    const ip = dest === null && !inAddress ? PUBLIC_IP_URL_RE.exec(text) : null;
    if (dest !== null) reasons.push(`${IMPORT_SENT_REASONS[kind]} (${cpPrefix(dest[0], 40)})`);
    else if (ip !== null) reasons.push(`${IMPORT_SENT_IP_REASONS[kind]} (${ip[0].slice(ip[0].indexOf("//") + 2)})`);
    else if (harvest && kind !== "credentials") reasons.push("reads credentials or the whole environment and sends data over the network");
    if (reasons.length) line = countNewlines(text, 0, at) + 1;
  }
  if (text.includes("curl") || text.includes("wget")) {
    // the rows of text.split("\n"), one at a time
    let piped = false;
    for (let start = 0, i = 0; ; i++) {
      const nl = text.indexOf("\n", start);
      const row = nl === -1 ? text.slice(start) : text.slice(start, nl);
      if (runsDownloadThroughShell(row)) {
        reasons.push("runs a downloaded script through a shell");
        line ??= i + 1;
        piped = true;
        break;
      }
      if (nl === -1) break;
      start = nl + 1;
    }
    if (!piped) {                     // (0.1.8) or a command line built in names, handed to an exec call
      for (const [at, r] of execCommandFlows(text)) {
        if (r === "pipes a download into a shell" || r === DL_CATEGORY_REASON.run) {
          reasons.push("runs a downloaded script through a shell");
          line ??= countNewlines(text, 0, at) + 1;
          break;
        }
      }
    }
  }
  const received = receivedCodeKind(text);
  if (received !== null) {
    reasons.push(DL_CATEGORY_REASON[received[1]]);
    line ??= received[0];
  }
  const dropped = downloadsAndRuns(text);
  if (dropped !== null) {
    const interp = PY_RUN_RE.test(text) ? "Python" : dropped[1];
    reasons.push(interp ? `downloads a script and runs it with ${interp}` : "downloads a file and then runs it");
    line ??= dropped[0];
  }
  const decoded = decodesAndRuns(text);
  if (decoded !== null) {
    const interp = PY_RUN_RE.test(text) ? "Python" : decoded[1];
    reasons.push(interp ? `writes code it decodes to a file and runs it with ${interp}` : "writes a file it decodes and runs it");
    line ??= decoded[0];
  }
  const signs = [];                          // [offset, reason] of the shapes no library needs
  const ps = powershellRisk(text);
  if (ps.length) {
    const at = powershellRunAt(text);
    if (at >= 0) signs.push([at, ps[0]]);
  }
  if (received === null || received[1] !== "run") {
    const at = stagerAt(text);
    if (at >= 0) signs.push([at, "carries a script that downloads and runs code"]);
  }
  const rs = reverseShellAt(text);
  if (rs >= 0) signs.push([rs, "opens a reverse shell"]);
  const host = HOST_INFO_RE.exec(text);
  const own = runsOwnSourceAt(text);
  if (own >= 0) signs.push([own, "runs code it reads back from its own file or a data file shipped with it"]);
  if (dumpsWorkflowSecrets(text)) {
    signs.push([searchFrom(PERSIST_SECRETS_DUMP_G, text).index, "carries a GitHub Actions workflow that dumps every repository secret"]);
  }
  signs.push(...exfilSigns(text, host));
  for (const [at, reason] of signs) {
    reasons.push(reason);
    line ??= countNewlines(text, 0, at) + 1;
  }
  return [reasons, line];
}

// SC-AGENT-HIJACK: a dependency that launches the user's own AI coding agent
// in an autonomous mode (the s1ngularity / Nx attack; see core). Twins of
// core.agent_hijack / core.agent_hijack_in_command; the tables are core's.
const AGENT_NAMES = String.raw`claude|gemini|codex|aider|cline|opencode|cursor-agent|amazon-?q|qchat|q`;
// In code a spawned binary is a string literal (require a quote before it, so a
// minified variable named q is not one); an install-hook command is a bare
// shell string, so there the binary is a shell token (see core).
export const AGENT_BIN_SRC = String.raw`(?<=["'])(?:` + AGENT_NAMES + String.raw`)(?=["'\s])`;
export const AGENT_BIN_CMD_SRC = String.raw`(?<![\w./-])(?:` + AGENT_NAMES + String.raw`)(?![\w./-])`;
export const AGENT_FLAG_SRC =
  String.raw`--(?:dangerously-skip-permissions|yolo|trust-all-tools|dangerously-bypass-approvals-and-sandbox` +
  String.raw`|full-auto|yes-always|allow-all-tools)(?![\w-])|--(?:approval-mode|permission-mode)[=\s]+(?:yolo|bypassPermissions)`;
const AGENT_BIN_RE = pyRe(AGENT_BIN_SRC);
const AGENT_BIN_CMD_RE = pyRe(AGENT_BIN_CMD_SRC);
const AGENT_FLAG_RE = pyRe(AGENT_FLAG_SRC);

/** [agent, flag, line] for the first line of dependency code that hands a known AI-agent CLI, with a
 * confirmation-off flag, to an exec/spawn call, else null. Twin of core.agent_hijack. */
export function agentHijack(text) {
  if (!AGENT_FLAG_RE.test(text)) return null;
  const rows = text.split("\n");
  for (let i = 0; i < rows.length; i++) {
    if (!EXEC_CALL_RE.test(rows[i])) continue;
    const flag = AGENT_FLAG_RE.exec(rows[i]), binm = AGENT_BIN_RE.exec(rows[i]);
    if (flag && binm) return [binm[0].replace(/^['"]|['"]$/g, ""), flag[0], i + 1];
  }
  return null;
}

/** [agent, flag] when an install-hook COMMAND launches the agent itself (the shell is the exec), else null.
 * Twin of core.agent_hijack_in_command. */
export function agentHijackInCommand(cmd) {
  const flag = AGENT_FLAG_RE.exec(cmd), binm = AGENT_BIN_CMD_RE.exec(cmd);
  return flag && binm ? [binm[0].replace(/^['"]|['"]$/g, ""), flag[0]] : null;
}

/**
 * Files Node tries for a path it is asked to run or load.
 * Twin of lazaret.scanner.core.node_candidates.
 */
export function nodeCandidates(rel) {
  let end = rel.length;
  while (end > 0 && rel[end - 1] === "/") end--;                    // rel.rstrip("/")
  rel = rel.slice(0, end);
  return [rel, rel + ".js", rel + ".cjs", rel + ".mjs", rel + ".json", rel + ".node",
    rel + "/index.js", rel + "/index.cjs", rel + "/index.mjs", rel + "/index.json"];
}

// ---- Scripts by their #! line ------------------------------------------------
// core._SHEBANG_RE (the first line only: [ \t], never \s) and _SHEBANG_JS_NAMES
const SHEBANG_SRC = String.raw`^#![ \t]*(\S+)(?:[ \t]+(?:-\S+[ \t]+)*(\S+))?`;
const SHEBANG_RE = pyRe(SHEBANG_SRC);
const SHEBANG_JS_NAMES = new Set(["node", "nodejs", "bun", "deno", "ts-node", "tsx"]);
const programName = (path) => path.slice(path.lastIndexOf("/") + 1).toLowerCase();

/**
 * "js" | "py" | "sh" | null: the language a script runs as, by its #! line.
 * Twin of lazaret.scanner.core.shebang_lang.
 */
export function shebangLang(text) {
  const m = SHEBANG_RE.exec(text);
  if (!m) return null;
  let prog = programName(m[1]);
  if (prog === "env" && m[2]) prog = programName(m[2]);
  if (SHEBANG_JS_NAMES.has(prog)) return "js";
  if (PYTHON_NAME_RE.test(pyEnd(prog))) return "py";
  if (SHELL_NAMES.has(prog)) return "sh";
  return null;
}

/**
 * core's pattern text and re flags, and its name sets, for everything above
 * that twins one of core's module-level constants: the Python parity test
 * (tests/architecture/test_js_parity_hooks.py) holds them to core's.
 */
export const PY_TWINS = {
  patterns: {
    _PYTHON_NAME_RE: [PYTHON_NAME_SRC, "i"], _SCRIPT_EXT_RE: [SCRIPT_EXT_SRC, "i"],
    _ENV_ASSIGN_RE: [ENV_ASSIGN_SRC, ""], _NODE_E_RE: [NODE_E_SRC, ""], _LOCAL_REQUIRE_RE: [LOCAL_REQUIRE_SRC, ""],
    _RUNTIME_SCRIPT_RE: [RUNTIME_SCRIPT_SRC, "i"],
    _NETWORK_RE: [NETWORK_SRC, "m"], _EXFIL_SERVICE_RE: [EXFIL_SERVICES_SRC, "i"],
    _PIPE_SCAN_RE: [PIPE_SCAN_SRC, ""],
    _EXEC_CALL_RE: [EXEC_CALL_SRC, ""], _SHEBANG_RE: [SHEBANG_SRC, ""],
    _AGENT_BIN_RE: [AGENT_BIN_SRC, ""], _AGENT_BIN_CMD_RE: [AGENT_BIN_CMD_SRC, ""], _AGENT_FLAG_RE: [AGENT_FLAG_SRC, ""],
    _DL_SUBST_RE: [DL_SUBST_SRC, ""], _DL_SUBST_NEEDLE_RE: [DL_SUBST_NEEDLE_SRC, ""],
    _PS_RE: [PS_SRC, "i"], _PS_ENCODED_RE: [PS_ENCODED_SRC, "i"], _PS_CRADLE_RE: [PS_CRADLE_SRC, "i"],
    _PS_DOWNLOAD_FILE_RE: [PS_DOWNLOAD_FILE_SRC, "i"], _PS_START_RE: [PS_START_SRC, "i"],
    _REVSHELL_DUP2_RE: [REVSHELL_DUP2_SRC, ""], _REVSHELL_SHELL_RE: [REVSHELL_SHELL_SRC, ""],
    _REVSHELL_LINE_RE: [REVSHELL_LINE_SRC, ""], _REVSHELL_JS_SPAWN_RE: [REVSHELL_JS_SPAWN_SRC, ""],
    _REVSHELL_JS_PIPE_RE: [REVSHELL_JS_PIPE_SRC, ""], _REVSHELL_JS_NET_RE: [REVSHELL_JS_NET_SRC, ""],
    _HOST_INFO_RE: [HOST_INFO_SRC, ""], _CAPTURE_SERVICE_RE: [CAPTURE_SERVICE_SRC, "i"], _PY_RUN_RE: [PY_RUN_SRC, ""],
    _PY_DOC_HEAD_RE: [PY_DOC_HEAD_SRC, ""], _BRACKET_RE: [BRACKET_SRC, ""], _SPACE_TAB_RE: [SPACE_TAB_SRC, ""],
    _SELF_READ_RE: [SELF_READ_SRC, ""], _SIBLING_DATA_RE: [SIBLING_DATA_SRC, ""], _SELF_RUN_RE: [SELF_RUN_SRC, ""],
    _SIBLING_PATH_RE: [SIBLING_PATH_SRC, ""], _PATH_READ_RE: [PATH_READ_SRC, ""], _READ_HEAD_RE: [READ_HEAD_SRC, ""],
    _READ_CALLBACK_RE: [READ_CALLBACK_SRC, ""], _READ_THEN_RE: [READ_THEN_SRC, ""],
    _SELF_READ_ASSIGN_RE: [SELF_READ_ASSIGN_SRC, ""], _IDENT_TOKEN_RE: [IDENT_TOKEN_SRC, ""],
    _PERSIST_AGENT_RE: [PERSIST_AGENT_SRC, ""], _PERSIST_AGENT_SPLIT_RE: [PERSIST_AGENT_SPLIT_SRC, ""],
    _PERSIST_WORKFLOW_RE: [PERSIST_WORKFLOW_SRC, ""], _PERSIST_EXT_DIR_RE: [PERSIST_EXT_DIR_SRC, ""],
    _PERSIST_WRITE_RE: [PERSIST_WRITE_SRC, ""], _PERSIST_SHELL_WRITE_RE: [PERSIST_SHELL_WRITE_SRC, ""],
    _PERSIST_EXT_INSTALL_RE: [PERSIST_EXT_INSTALL_SRC, ""], _PERSIST_EXT_CLI_RE: [PERSIST_EXT_CLI_SRC, ""],
    _PERSIST_RUNNER_RE: [PERSIST_RUNNER_SRC, ""], _PERSIST_RUNNER_CONFIG_RE: [PERSIST_RUNNER_CONFIG_SRC, ""],
    _PERSIST_RUNNER_ARG_RE: [PERSIST_RUNNER_ARG_SRC, ""], _SHORTCUT_FOUND_RE: [SHORTCUT_FOUND_SRC, "i"], _SHORTCUT_SET_RE: [SHORTCUT_SET_SRC, ""],
    _SECRETS_DUMP_RE: [SECRETS_DUMP_SRC, "i"],
    _PUBLISH_CMD_RE: [PUBLISH_CMD_SRC, ""], _NAME_ASSIGN_RE: [NAME_ASSIGN_SRC, ""],
    _MANIFEST_WRITE_RE: [MANIFEST_WRITE_SRC, ""], _JS_IDENT_RE: [JS_IDENT_SRC, ""],
    _NPM_TOKEN_READ_RE: [NPM_TOKEN_READ_SRC, ""], _DLL_LOADER_RE: [DLL_LOADER_SRC, "i"],
    _DLL_NAME_RE: [DLL_NAME_SRC, "i"], _STRING_JOIN_RE: [STRING_JOIN_SRC, ""],
    _DV_JOIN_RE: [DV_JOIN_SRC, ""], _DV_BUFFER_RE: [DV_BUFFER_SRC, ""], _DV_ATOB_RE: [DV_ATOB_SRC, ""],
    _DV_PY_RE: [DV_PY_SRC, ""], _DV_HELPER_RE: [DV_HELPER_SRC, ""], _DV_STR_ITEM_RE: [DV_STR_ITEM_SRC, ""],
    _DV_ARRAY_RE: [DV_ARRAY_SRC, ""], _DV_MEMBER_RE: [DV_MEMBER_SRC, ""],
    _DV_CALL_RE: [DV_CALL_SRC, ""], _DV_KEY_RE: [DV_KEY_SRC, ""],
    _DV_CC_LITERAL_RE: [DV_CC_LITERAL_SRC, ""], _DV_CC_FUNC_RE: [DV_CC_FUNC_SRC, ""], _DV_CC_SITE_RE: [DV_CC_SITE_SRC, ""],
    _DV_CC_FOR_RE: [DV_CC_FOR_SRC, ""], _DV_CC_MAP_RE: [DV_CC_MAP_SRC, ""], _DV_CC_PYFOR_RE: [DV_CC_PYFOR_SRC, ""],
    _DV_CC_PYITER_RE: [DV_CC_PYITER_SRC, ""], _DV_CC_TOKEN_RE: [DV_CC_TOKEN_SRC, ""],
    _DV_CC_ARG_INT_RE: [DV_CC_ARG_INT_SRC, ""], _DV_CC_ARG_STR_RE: [DV_CC_ARG_STR_SRC, ""],
    _DV_CC_NAME_RE: [DV_CC_NAME_SRC, ""], _DV_CC_INT_RE: [DV_CC_INT, ""],
    _SH_ENV_REF_RE: [SH_ENV_REF_SRC, "i"], _SH_IDENTITY_VAR_RE: [SH_IDENTITY_VAR_SRC, "i"],
    _SH_PATH_VAR_RE: [SH_PATH_VAR_SRC, "i"], _SH_SECRET_VAR_RE: [SH_SECRET_VAR_SRC, "i"], _SH_URL_RE: [SH_URL_SRC, ""],
    _SH_HOST_RE: [SH_HOST_SRC, ""], _SH_FLAG_A_OR_N_RE: [SH_FLAG_A_OR_N_SRC, ""],
    _SCRIPT_INTERP_RE: [SCRIPT_INTERP_SRC, ""], _SCRIPT_LOAD_RE: [SCRIPT_LOAD_SRC, ""], _DECODE_CALL_RE: [DECODE_CALL_SRC, ""],
    _SPAWN_CALL_RE: [SPAWN_CALL_SRC, ""], _SPAWN_SCRIPT_EXT_RE: [SPAWN_SCRIPT_EXT_SRC, "i"], _SPAWN_STR_RE: [SPAWN_STR_SRC, ""],
    _SA_ARRAY_FN_RE: [SA_ARRAY_FN_SRC, ""], _SA_LIT_RE: [SA_LIT_SRC, ""], _SA_SPACE_RE: [SA_SPACE_SRC, ""],
    _SA_OCT_RE: [SA_OCT_SRC, ""], _SA_CHECKSUM_RE: [SA_CHECKSUM_SRC, ""], _SA_ALPHABET_RE: [SA_ALPHABET_SRC, ""],
    _SA_ALIAS_RE: [SA_ALIAS_SRC, ""], _SA_WRAPPER_RE: [SA_WRAPPER_SRC, ""], _SA_PARAM_RE: [SA_PARAM_SRC, ""],
    _SA_OBJECT_RE: [SA_OBJECT_SRC, ""], _SA_ENTRY_RE: [SA_ENTRY_SRC, ""], _SA_TOKEN_RE: [SA_TOKEN_SRC, ""],
    _SA_CALL_RE: [SA_CALL_SRC, ""], _SA_FUNCTION_TAIL_RE: [SA_FUNCTION_TAIL_SRC, ""], _SA_DECIMAL_RE: [SA_DECIMAL_SRC, ""],
    _PX_OBJECT_RE: [PX_OBJECT_SRC, ""], _PX_KEY_RE: [PX_KEY_SRC, ""], _PX_FUNCTION_RE: [PX_FUNCTION_SRC, ""],
    _PX_BINARY_RE: [PX_BINARY_SRC, ""], _PX_CALL_RE: [PX_CALL_SRC, ""], _PX_REF_CALL_RE: [PX_REF_CALL_SRC, ""],
    _PX_REF_RE: [PX_REF_SRC, ""], _PX_STRINGS_RE: [PX_STRINGS_SRC, ""], _PX_END_RE: [PX_END_SRC, ""],
    _PX_USE_RE: [PX_USE_SRC, ""], _PX_OPEN_RE: [PX_OPEN_SRC, ""], _SPAWN_LIT_RE: [SPAWN_LIT_SRC, ""], _SPAWN_CONCAT_RE: [SPAWN_CONCAT_SRC, ""],
    _SPAWN_DIR_RE: [SPAWN_DIR_SRC, ""], _SPAWN_JOIN_RE: [SPAWN_JOIN_SRC, ""], _SPAWN_NAME_RE: [SPAWN_NAME_SRC, ""],
    _REVSHELL_NGROK_TCP_RE: [REVSHELL_NGROK_TCP_SRC, "i"], _REVSHELL_ARG_SHELL_RE: [REVSHELL_ARG_SHELL_SRC, ""],
    _REVSHELL_ARGS_RE: [REVSHELL_ARGS_SRC, ""],
    _PUBLIC_IP_URL_RE: [PUBLIC_IP_URL_SRC, ""], _CRED_DIR_RE: [CRED_DIR_SRC, ""],
    _B64_URL_LITERAL_RE: [B64_URL_LITERAL_SRC, ""], _DNS_CALL_RE: [DNS_CALL_SRC, ""],
    _DNS_BUILT_NAME_RE: [DNS_BUILT_NAME_SRC, ""], _DNS_TEMPLATE_RE: [DNS_TEMPLATE_SRC, ""], _DNS_SUM_RE: [DNS_SUM_SRC, ""],
    _DNS_FORMAT_RE: [DNS_FORMAT_SRC, ""], _DNS_LITERAL_RE: [DNS_LITERAL_SRC, ""], _DNS_VALUE_RE: [DNS_VALUE_SRC, ""],
    _DNS_NAME_RE: [DNS_NAME_SRC, ""], _DNS_SHELL_ID_RE: [DNS_SHELL_ID_SRC, "i"], _DNS_SHELL_CMD_RE: [DNS_SHELL_CMD_SRC, ""],
    _DNS_CMD_SUM_RE: [DNS_CMD_SUM_SRC, ""], _DNS_CMD_TEMPLATE_RE: [DNS_CMD_TEMPLATE_SRC, ""],
    _DNS_SHELL_CUT_RE: [DNS_SHELL_CUT_SRC, ""], _DNS_SHELL_LEFT_RE: [DNS_SHELL_LEFT_SRC, ""],
    _DNS_SHELL_RIGHT_RE: [DNS_SHELL_RIGHT_SRC, ""], _DNS_SHELL_HOST_RE: [DNS_SHELL_HOST_SRC, ""],
    _DD_FETCH_RE: [DD_FETCH_SRC, ""], _DD_SEND_RE: [DD_SEND_SRC, ""], _DD_DATA_RE: [DD_DATA_SRC, "i"],
    _DD_URL_RE: [DD_URL_SRC, ""], _DD_URL_IN_RE: [DD_URL_IN_SRC, ""], _DD_ASSIGN_RE: [DD_ASSIGN_SRC, ""],
    _DD_DESTRUCT_RE: [DD_DESTRUCT_SRC, ""], _DD_DESTRUCT_NAME_RE: [DD_DESTRUCT_NAME_SRC, ""], _DD_FOR_RE: [DD_FOR_SRC, ""],
    _DD_CALLBACK_RE: [DD_CALLBACK_SRC, ""], _DD_ARG_CALLBACK_RE: [DD_ARG_CALLBACK_SRC, ""],
    _DD_THEN_HEAD_RE: [DD_THEN_HEAD_SRC, ""], _DD_PARAM_RE: [DD_PARAM_SRC, ""], _DD_AS_RE: [DD_AS_SRC, ""],
    _DD_RETURN_RE: [DD_RETURN_SRC, ""], _DD_FUNC_RE: [DD_FUNC_SRC, ""],
    _IP_LITERAL_RE: [IP_LITERAL_SRC, ""], _RAW_CONNECT_RE: [RAW_CONNECT_SRC, ""],
    _MONERO_ADDR_RE: [MONERO_ADDR_SRC, ""], _MINER_ARG_RE: [MINER_ARG_SRC, ""], _NGROK_TUNNEL_RE: [NGROK_TUNNEL_SRC, ""],
    _PERSIST_SHORTCUT_RE: [PERSIST_SHORTCUT_SRC, ""],
    _SVC_SYSTEMD_DIR_RE: [SVC_SYSTEMD_DIR_SRC, ""], _SVC_UNIT_RE: [SVC_UNIT_SRC, ""],
    _SVC_SYSTEMCTL_RE: [SVC_SYSTEMCTL_SRC, ""], _SVC_LAUNCHD_DIR_RE: [SVC_LAUNCHD_DIR_SRC, ""],
    _SVC_PLIST_RE: [SVC_PLIST_SRC, ""], _SVC_LAUNCHCTL_RE: [SVC_LAUNCHCTL_SRC, ""],
    _SVC_CRONTAB_RE: [SVC_CRONTAB_SRC, ""], _SVC_PYCRON_RE: [SVC_PYCRON_SRC, ""],
    _SVC_PYCRON_WRITE_RE: [SVC_PYCRON_WRITE_SRC, ""], _SVC_CRON_DIR_RE: [SVC_CRON_DIR_SRC, ""],
    _SVC_RUNKEY_RE: [SVC_RUNKEY_SRC, "i"], _SVC_REG_WRITE_RE: [SVC_REG_WRITE_SRC, "i"],
    _SVC_SCHTASKS_RE: [SVC_SCHTASKS_SRC, "i"], _SVC_TASK_API_RE: [SVC_TASK_API_SRC, "i"],
    _SVC_TASK_COM_RE: [SVC_TASK_COM_SRC, "i"], _SVC_TASK_REGISTER_RE: [SVC_TASK_REGISTER_SRC, ""],
    _SVC_STARTUP_RE: [SVC_STARTUP_SRC, "i"], _SVC_AUTOSTART_RE: [SVC_AUTOSTART_SRC, ""],
    _SVC_CMD_START_RE: [SVC_CMD_START_SRC, ""],
    // (0.1.8) exfiltration as a data flow, a webhook's secret, commands read as programs, shell scripts
    _LD_ENV_RE: [LD_ENV_SRC, ""], _LD_ENV_ALL_RE: [LD_ENV_ALL_SRC, ""], _LD_MEMBER_READ_RE: [LD_MEMBER_READ_SRC, ""],
    _LD_ENV_SELECT_RE: [LD_ENV_SELECT_SRC, ""], _LD_EXCLUDES_RE: [LD_EXCLUDES_SRC, ""],
    _LD_TEST_AFTER_RE: [LD_TEST_AFTER_SRC, ""], _LD_BODY_RE: [LD_BODY_SRC, ""],
    _PUBLIC_KEY_FILE_RE: [PUBLIC_KEY_FILE_SRC, "i"],
    _LD_ENV_QUIET_RE: [LD_ENV_QUIET_SRC, "i"], _LD_IDENTITY_RE: [LD_IDENTITY_SRC, ""],
    _LD_IMPORT_JS_RE: [LD_IMPORT_JS_SRC, ""], _LD_IMPORT_PY_RE: [LD_IMPORT_PY_SRC, ""],
    _LD_IMPORT_NAME_RE: [LD_IMPORT_NAME_SRC, ""], _LD_PUBLIC_IP_RE: [LD_PUBLIC_IP_SRC, ""], _LD_CALL_RE: [LD_CALL_SRC, ""],
    _LD_READS_RE: [LD_READS_SRC, ""], _LD_ABSOLUTE_RE: [LD_ABSOLUTE_SRC, ""], _LD_ABSOLUTE_IN_RE: [LD_FS_ROOT_SRC, ""],
    _LD_FS_ROOT_RE: [LD_FS_ROOT_ANY_SRC, ""], _LD_HOME_RE: [LD_HOME_SRC, ""], _LD_OWN_FOLDER_RE: [LD_OWN_FOLDER_SRC, ""],
    _LD_CRED_FILE_RE: [LD_CRED_FILE_SRC, ""], _LD_PLAIN_LITERAL_RE: [LD_PLAIN_LITERAL_SRC, ""],
    _LD_PATH_EXPR_RE: [LD_PATH_EXPR_SRC, ""], _LD_EXEC_RE: [LD_EXEC_SRC, ""], _LD_ARGV_ITEM_RE: [LD_ARGV_ITEM_SRC, ""],
    _LD_METADATA_RE: [LD_METADATA_SRC, ""], _LD_FUNC_RE: [LD_FUNC_SRC, ""], _LD_PARAM_RE: [LD_PARAM_SRC, ""],
    _LD_MEMBER_ASSIGN_RE: [LD_MEMBER_ASSIGN_SRC, ""], _LD_MEMBER_RE: [LD_MEMBER_SRC, ""],
    _LD_FUNC_VALUE_RE: [LD_FUNC_VALUE_SRC, ""], _LD_ARROW_BODY_RE: [LD_ARROW_BODY_SRC, ""], _LD_CALLED_RE: [LD_CALLED_SRC, ""],
    _LD_SEAL_RE: [LD_SEAL_SRC, ""], _LD_COLLECT_RE: [LD_COLLECT_SRC, ""], _LD_CONNECTION_RE: [LD_CONNECTION_SRC, ""],
    _LD_WRITE_TAIL_RE: [LD_WRITE_TAIL, ""], _LD_HOST_BUILT_RE: [LD_HOST_BUILT_SRC, ""], _LD_SEND_RE: [LD_SEND_SRC, ""],
    _LD_OPTIONS_SEND_RE: [LD_OPTIONS_SEND_SRC, ""], _LD_REQUEST_SEND_RE: [LD_REQUEST_SEND_SRC, ""],
    _LD_EXEC_SEND_RE: [LD_EXEC_SEND_SRC, ""], _LD_NET_PROGRAM_RE: [LD_NET_PROGRAM_SRC, ""],
    _LD_ADDRESS_SEND_RE: [LD_ADDRESS_SEND_SRC, ""], _LD_LOOKUP_SEND_RE: [LD_LOOKUP_SEND_SRC, ""],
    _LD_KWARG_RE: [LD_KWARG_SRC, ""], _LD_KEY_RE: [LD_KEY_SRC, ""], _QUOTE_CHAR_RE: [QUOTE_CHAR_SRC, ""],
    _SE_URL_RE: [SE_URL_SRC, ""], _SE_SEGMENT_RE: [SE_SEGMENT_SRC, ""], _SE_HOLE_RE: [SE_HOLE_SRC, ""],
    _SE_REQUEST_RE: [SE_REQUEST_SRC, ""], _SH_EXEC_LINE_RE: [SH_EXEC_LINE_SRC, ""], _SH_NOT_SHELL_RE: [SH_NOT_SHELL_SRC, ""],
    _RAW_IP_URL_RE: [RAW_IP_URL_SRC, "i"], _CRED_STORE_RE: [CRED_STORE_SRC, "i"], _SH_VAR_NAME_RE: [SH_VAR_NAME_SRC, ""],
    ...RECEIVED_TWINS,
  },
  sets: {
    _SA_HEX: [...SA_HEX], _SA_JS_SPACE: [...SA_JS_SPACE],
    _HOOK_SEPARATORS: [...HOOK_SEPARATORS], _HOOK_REDIRECTS: [...HOOK_REDIRECTS],
    _HOOK_WRAPPERS: [...HOOK_WRAPPERS], _NODE_NAMES: [...NODE_NAMES], _SHELL_NAMES: [...SHELL_NAMES],
    _NODE_CODE_FLAGS: [...NODE_CODE_FLAGS], _NODE_PRELOAD_FLAGS: [...NODE_PRELOAD_FLAGS],
    _NODE_VALUE_FLAGS: [...NODE_VALUE_FLAGS], _SHEBANG_JS_NAMES: [...SHEBANG_JS_NAMES],
    _DL_NEEDLES: DL_NEEDLES, _DL_RUN_NEEDLES: DL_RUN_NEEDLES, _DL_DESERIAL_NEEDLES: DL_DESERIAL_NEEDLES,
    _DL_IMPORT_NEEDLES: DL_IMPORT_NEEDLES, _DL_SINK_NEEDLES: DL_SINK_NEEDLES, _DL_ALIAS_NEEDLES: DL_ALIAS_NEEDLES,
    _DL_FILE_WRITE_NEEDLES: DL_FILE_WRITE_NEEDLES, _DL_PATHRUN_NEEDLES: DL_PATHRUN_NEEDLES,
    _DL_PY_NET_MODULES: DL_PY_NET_MODULES,
    _DL_NOT_NAMES: DL_NOT_NAMES, _DL_PREFIX_CHARS: DL_PREFIX_CHARS, _DL_DEFINING: DL_DEFINING,
    _DL_CALLEE_CHARS: DL_CALLEE_CHARS,
    _STAGER_RUN_NEEDLES: STAGER_RUN_NEEDLES, _STAGER_NET_NEEDLES: STAGER_NET_NEEDLES,
    _STRONG_IMPORT_REASONS: STRONG_IMPORT_REASONS, _PY_JOINS: [...PY_JOINS], _SYSTEM_DLLS: [...SYSTEM_DLLS],
    _SPAWN_NO_SCRIPT_FLAGS: [...SPAWN_NO_SCRIPT_FLAGS], _SPAWN_VALUE_FLAGS: [...SPAWN_VALUE_FLAGS],
    _CRED_SWEEP_NEEDLES: CRED_SWEEP_NEEDLES, _PUBLIC_RESOLVERS: [...PUBLIC_RESOLVERS],
    _MINER_ARG_NEEDLES: MINER_ARG_NEEDLES,
    _LD_READERS: [...LD_READERS], _LD_NOT_READS: [...LD_NOT_READS], _LD_OPTION_KEYS: [...LD_OPTION_KEYS],
    _LD_PROCESS_KEYS: [...LD_PROCESS_KEYS], _LD_NOT_IN_ADDRESS: [...LD_NOT_IN_ADDRESS], _LD_NEEDLES: LD_NEEDLES,
    _LD_SEND_NEEDLES: LD_SEND_NEEDLES, _LD_METADATA_NEEDLES: LD_METADATA_NEEDLES, _SE_NEEDLES: SE_NEEDLES,
    _SH_EXEC_NEEDLES: SH_EXEC_NEEDLES, _SH_DECLARE: [...SH_DECLARE],
    _REVSHELL_ARGS_NEEDLES: REVSHELL_ARGS_NEEDLES, _SELF_SHELL_RUNNERS: SELF_SHELL_RUNNERS,
    _DNS_LOCAL_TLDS: [...DNS_LOCAL_TLDS],
    ...Object.fromEntries(Object.entries({ _SH_HTTP: SH_HTTP, _SH_RAW: SH_RAW, _SH_LOOKUP: SH_LOOKUP, _SH_SHELLS: SH_SHELLS,
      _SH_EVAL: SH_EVAL, _SH_CMD: SH_CMD, _SH_IDENTITY: SH_IDENTITY, _SH_ENVIRONMENT: SH_ENVIRONMENT,
      _SH_FILE_READERS: SH_FILE_READERS, _SH_LISTINGS: SH_LISTINGS, _SH_FILTERS: SH_FILTERS,
      _SH_SCRIPTED_FILTERS: SH_SCRIPTED_FILTERS, _SH_ECHO: SH_ECHO, _SH_XARGS_SHORT_VALUE: SH_XARGS_SHORT_VALUE,
      _SH_XARGS_LONG_VALUE: SH_XARGS_LONG_VALUE, _SH_NOOPS: SH_NOOPS, _SH_KEYWORDS: SH_KEYWORDS,
      _SH_STATUS_KEYWORDS: SH_STATUS_KEYWORDS, _SH_CURL_SHORT_VALUE: SH_CURL_SHORT_VALUE,
      _SH_CURL_LONG_VALUE: SH_CURL_LONG_VALUE, _SH_CURL_DATA: SH_CURL_DATA, _SH_CURL_META: SH_CURL_META,
      _SH_CURL_UPLOAD: SH_CURL_UPLOAD, _SH_CURL_OUTPUT: SH_CURL_OUTPUT, _SH_CURL_REMOTE_NAME: SH_CURL_REMOTE_NAME,
      _SH_WGET_SHORT_VALUE: SH_WGET_SHORT_VALUE, _SH_WGET_LONG_VALUE: SH_WGET_LONG_VALUE, _SH_WGET_DATA: SH_WGET_DATA,
      _SH_WGET_META: SH_WGET_META, _SH_WGET_UPLOAD: SH_WGET_UPLOAD, _SH_WGET_OUTPUT: SH_WGET_OUTPUT, _SH_NULL: SH_NULL,
    }).map(([k, v]) => [k, [...v]])),
  },
  // pattern text core composes further at run time
  strings: { _DV_NAME_HEAD: DV_NAME_HEAD, _DV_MUTATED_TAIL: DV_MUTATED_TAIL, _DV_ASSIGNED_TAIL: DV_ASSIGNED_TAIL,
    _DV_INDEX_TAIL: DV_INDEX_TAIL, _DV_CC_CALL_TAIL: DV_CC_CALL_TAIL, _DV_CC_ARRAY_TAIL: DV_CC_ARRAY_TAIL,
    _SH_BEACON_REASON: SH_BEACON_REASON, _LD_WHOLE_ENV: LD_WHOLE_ENV, _LD_FS_ROOT_SRC: LD_FS_ROOT_SRC,
    _LD_WRITE_TAIL: LD_WRITE_TAIL, _SA_IDENT: SA_IDENT, _SA_TAIL_HEAD: SA_TAIL_HEAD, _SA_TAIL_MID: SA_TAIL_MID,
    _SA_TAIL_END: SA_TAIL_END, _SA_TAIL_CALL: SA_TAIL_CALL, _SA_OFF: SA_OFF, _SA_ACC_A_HEAD: SA_ACC_A_HEAD,
    _SA_ACC_B_HEAD: SA_ACC_B_HEAD, _SA_ACC_B_TAIL: SA_ACC_B_TAIL, _SA_CALL_TAIL: SA_CALL_TAIL,
    _SA_INVOKE_HEAD: SA_INVOKE_HEAD, _SA_INVOKE_TAIL: SA_INVOKE_TAIL, _SA_INVOKE2_HEAD: SA_INVOKE2_HEAD,
    _SA_INVOKE2_TAIL: SA_INVOKE2_TAIL, _SA_ARG_UNIT: SA_ARG_UNIT },
  tables: { _DV_CC_BINARY: Object.fromEntries(DV_CC_BINARY), _SH_DATA_REASONS: SH_DATA_REASONS,
    _SH_REDIRECT_OPS: SH_REDIRECT_OPS, _LD_REASONS: LD_REASONS, _LD_MODULE_NAMES: LD_MODULE_NAMES,
    _IMPORT_SENT_REASONS: IMPORT_SENT_REASONS, _IMPORT_SENT_IP_REASONS: IMPORT_SENT_IP_REASONS,
    _SH_ESCAPES: Object.fromEntries(SH_ESCAPES), _SEND_REASONS: SEND_REASONS, _LD_TEST_BEFORE: LD_TEST_BEFORE,
    _SA_ESCAPES: SA_ESCAPES },
  maps: Object.fromEntries([["_PERSIST_AGENT_PAIRS", PERSIST_AGENT_PAIRS], ["_WRAPPER_VALUE_OPTIONS", WRAPPER_VALUE_OPTIONS],
    ["_WRAPPER_CHDIR_OPTIONS", WRAPPER_CHDIR_OPTIONS], ["_WRAPPER_COMMAND_OPTIONS", WRAPPER_COMMAND_OPTIONS],
    ["_JS_RUNTIMES", JS_RUNTIMES]]
    .map(([name, map]) => [name, Object.fromEntries([...map].map(([k, v]) => [k, [...v].sort()]))])),
  limits: { HOOK_MAX_CHARS, HOOK_MAX_COMMANDS, HOOK_MAX_TARGETS, HOOK_MAX_PATH, ...DL_LIMITS, _DL_ALIAS_MAX: DL_ALIAS_MAX,
    _PS_ENCODED_MAX: PS_ENCODED_MAX, _STAGER_MIN: STAGER_MIN, _STAGER_MAX_LITERALS: STAGER_MAX_LITERALS,
    _PS_EXEC_BACK: PS_EXEC_BACK, _PS_EXEC_MAX_NAMES: PS_EXEC_MAX_NAMES, _SELF_READ_PASSES: SELF_READ_PASSES,
    _SELF_READ_MAX_CALLS: SELF_READ_MAX_CALLS, _SELF_READ_ARG_SPAN: SELF_READ_ARG_SPAN,
    _SELF_READ_MAX_ASSIGNS: SELF_READ_MAX_ASSIGNS, _SELF_READ_THEN_SPAN: SELF_READ_THEN_SPAN, _LITERAL_SPANS_MAX: LITERAL_SPANS_MAX,
    _PERSIST_MAX_LINES: PERSIST_MAX_LINES, _SVC_LINE_MAX: SVC_LINE_MAX, _SVC_RUNKEY_SPAN: SVC_RUNKEY_SPAN,
    _SELF_PUB_SPAN: SELF_PUB_SPAN, _SELF_PUB_MAX: SELF_PUB_MAX,
    _DV_MAX_LITERAL: DV_MAX_LITERAL, _DV_BODY: DV_BODY, _DV_MAX_HELPERS: DV_MAX_HELPERS, _DV_MAX_ARRAYS: DV_MAX_ARRAYS,
    _DV_MAX_CHARS: DV_MAX_CHARS, _DV_XOR_MIN_CALLS: DV_XOR_MIN_CALLS, _DV_XOR_MAX_CALLS: DV_XOR_MAX_CALLS,
    _DV_XOR_MIN_BYTES: DV_XOR_MIN_BYTES, _DV_XOR_MAX_KEYS: DV_XOR_MAX_KEYS, _DV_XOR_KEY_MAX: DV_XOR_KEY_MAX,
    _SPAWN_MAX_DEPTH: SPAWN_MAX_DEPTH, _SPAWN_MAX_FILES: SPAWN_MAX_FILES,
    _SPAWN_NAME_DEPTH: SPAWN_NAME_DEPTH, _SPAWN_MAX_TARGETS: SPAWN_MAX_TARGETS, _SPAWN_MAX_NAMED: SPAWN_MAX_NAMED,
    _SA_MAX_CHARS: SA_MAX_CHARS, _SA_MAX_ARRAYS: SA_MAX_ARRAYS, _SA_MAX_ITEMS: SA_MAX_ITEMS, _SA_MAX_CALLS: SA_MAX_CALLS,
    _SA_DEPTH: SA_DEPTH, _SA_BODY: SA_BODY, _SA_LOOP_BACK: SA_LOOP_BACK, _SA_HEX_MAX: SA_HEX_MAX, _SA_DEC_MAX: SA_DEC_MAX,
    _PX_MAX_ENTRIES: PX_MAX_ENTRIES, _PX_MAX_USES: PX_MAX_USES, _PX_DEPTH: PX_DEPTH, _PX_ARGS: PX_ARGS,
    _SE_MIN_DISTINCT: SE_MIN_DISTINCT, _SE_MAX: SE_MAX,
    _CRED_SWEEP_SPAN: CRED_SWEEP_SPAN, _CRED_SWEEP_MIN: CRED_SWEEP_MIN, _CRED_SWEEP_MAX: CRED_SWEEP_MAX,
    _RAW_CONNECT_SPAN: RAW_CONNECT_SPAN, _IP_LITERAL_MAX: IP_LITERAL_MAX,
    _DNS_LOOKUP_MAX: DNS_LOOKUP_MAX, _DNS_ARG_SPAN: DNS_ARG_SPAN, _DNS_ASSIGN_SPAN: DNS_ASSIGN_SPAN,
    _DNS_SHELL_SPAN: DNS_SHELL_SPAN, _DD_PASSES: DD_PASSES, _DD_MAX_CALLS: DD_MAX_CALLS, _DD_ARG_SPAN: DD_ARG_SPAN,
    _DD_MAX_ASSIGNS: DD_MAX_ASSIGNS, _DD_THEN_MAX: DD_THEN_MAX,
    _DV_CC_BODY: DV_CC_BODY, _DV_CC_MAX_PARAMS: DV_CC_MAX_PARAMS, _DV_CC_MAX_DECODERS: DV_CC_MAX_DECODERS,
    _DV_CC_MAX_CALLS: DV_CC_MAX_CALLS, _DV_CC_MAX_CODES: DV_CC_MAX_CODES, _DV_CC_MAX_WORK: DV_CC_MAX_WORK,
    _DV_CC_MAX_TOKENS: DV_CC_MAX_TOKENS, _DV_CC_MAX_DEPTH: DV_CC_MAX_DEPTH, _DV_CC_INT_MAX: DV_CC_INT_MAX,
    _SH_MAX_DEPTH: SH_MAX_DEPTH, _LD_MAX: LD_MAX, _LD_MAX_CALLS: LD_MAX_CALLS, _LD_STATEMENT_SPAN: LD_STATEMENT_SPAN,
    _SH_EXEC_MAX: SH_EXEC_MAX, _SH_CONCAT_MAX: SH_CONCAT_MAX, _SH_SCRIPT_MAX_CHARS: SH_SCRIPT_MAX_CHARS },
};
