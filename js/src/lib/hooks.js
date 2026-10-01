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
function nodeScript(args) {
  const preloads = [];
  let i = 0;
  while (i < args.length) {
    const a = args[i];
    if (a === "--") return [i + 1 < args.length ? args[i + 1] : null, preloads, null];
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
    return [a, preloads, null];
  }
  return [null, preloads, null];
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
const BACKTICK = "`";                                  // (a String.raw template cannot hold one as itself)
const SECRET_SOURCE_SRC =
  String.raw`JSON\.stringify\(\s*process\.env|Object\.(?:keys|entries|values)\(\s*process\.env|` +
  String.raw`\.npmrc|[/\\]\.ssh\b|~/\.ssh\b|id_rsa|id_ed25519|\.aws[/\\]|~/\.aws\b|\.git-credentials|` +
  String.raw`\.docker[/\\]config\.json|\.kube[/\\]config|Local Storage[/\\]leveldb|\.pypirc|\.netrc\b|` +
  // Python: the whole environment, not one variable
  String.raw`\bdict\(\s*os\.environ\s*\)|\bos\.environ\.(?:items|keys|values|copy)\(\s*\)|` +
  String.raw`json\.dumps\(\s*(?:dict\(\s*)?os\.environ|\b(?:str|repr)\(\s*os\.environ\s*\)|` +
  String.raw`\{\s*\*\*\s*os\.environ|\burlencode\(\s*(?:dict\(\s*)?os\.environ|\bos\.environb\b` +
  // shell: the whole environment piped or redirected somewhere
  String.raw`|(?:^|[\s;&(${BACKTICK}])(?:env|printenv|set)\s*(?:\|(?!\|)|>)|\$\(\s*(?:env|printenv)\s*\)|` +
  String.raw`${BACKTICK}\s*(?:env|printenv)\s*${BACKTICK}`;
// With the m flag JavaScript's ^ also matches after \r, U+2028 and U+2029,
// where re.M's does not; each is in Python's \s, so [\s;&(`] matches one
// character earlier and a search finds a match exactly when core's does.
const SECRET_SOURCE_RE = pyRe(SECRET_SOURCE_SRC, "im");
// RequestBin by its host names only (0.1.8; core's comment above _EXFIL_SERVICES)
const EXFIL_SERVICES_SRC =
  String.raw`pastebin\.com|\bngrok|webhook\.site|` +
  String.raw`discord(?:app)?\.com/api/webhooks|api\.telegram\.org|oastify\.com|burpcollaborator|` +
  String.raw`\binteract\.sh|\boast\.(?:pro|live|site|online|fun|me)\b|requestbin\.(?:com|net|io)\b|\brequestb\.in\b|` +
  String.raw`pipedream\.net|transfer\.sh|\.onion\b`;
const EXFIL_DEST_SRC = String.raw`https?://(?:\d{1,3}\.){3}\d{1,3}\b|` + EXFIL_SERVICES_SRC;
const EXFIL_DEST_RE = pyRe(EXFIL_DEST_SRC, "i");
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
  + String.raw`|\b(?:getoutput|check_output|getstatusoutput|execSync|popen)\s*\(\s*\[?\s*["'](?:whoami|hostname|id|uname`
  + String.raw`|ifconfig|ipconfig|systeminfo)\b`
  + String.raw`|(?:\$\(|` + "`" + String.raw`)\s*(?:whoami|hostname|id|uname|ifconfig|ip\s+a|pwd|ls|cat\s+/etc/passwd|ps)\b`
  + String.raw`|\bos\.(?:hostname|userInfo)\s*[,)]`
  // (0.1.8) through the module itself or a name taken from it (core's comment)
  + String.raw`|\brequire\(\s*["'](?:node:)?os["']\s*\)\s*\.\s*(?:hostname|userInfo)\b`
  + String.raw`|\b(?:const|let|var|import)\s*\{[^{}\n]{0,200}\b(?:hostname|userInfo)\b[^{}\n]{0,200}\}\s*`
  + String.raw`(?:=\s*require\(\s*|from\s*)["'](?:node:)?os["']`
  + String.raw`|\bfrom\s+(?:socket|getpass)\s+import\s+[^\n]{0,200}\b(?:gethostname|getfqdn|getuser)\b`;
const HOST_INFO_RE = pyRe(HOST_INFO_SRC);
/** True when `text` collects the machine's user or host name and sends data over the network (core.sends_host_info). */
export function sendsHostInfo(text) {
  return HOST_INFO_RE.test(text) && (NETWORK_RE.test(text) || EXFIL_SERVICE_RE.test(text));
}

// Exfiltration shapes (0.1.8; core's comment above _CHAT_SECRET_RE): a chat
// bot or webhook whose secret is written in the code, credential files sent
// to a raw IP address, a sweep of several credential folders, the host name
// sent to a base64-hidden address or in a DNS name the code builds, the
// public IP address sent to a data-capture service, a copy of the whole
// environment serialized, a miner, and (install time only) a raw socket to a
// hard-coded IP address.
const CHAT_SECRET_SRC = String.raw`(?<![0-9])\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])`
  + String.raw`|\b[Dd]iscord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,80}`
  + String.raw`|\bhooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}(?![A-Za-z0-9])`;
const CHAT_SECRET_NEEDLES = [":AA", "webhooks/", "hooks.slack.com"];   // one is in every match (core's twin)
const TELEGRAM_API_SRC = String.raw`api\.telegram\.org`;
const CRED_FILE_SRC = String.raw`["'` + "`" + String.raw`](?:~[/\\]|\.[/\\])?\.(?:env|npmrc|pypirc|netrc|git-credentials)["'` + "`" + "]"
  + String.raw`|\.aws[/\\]credentials\b|[/\\]\.ssh[/\\]id_\w+|\.docker[/\\]config\.json|\.kube[/\\]config\b`;
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
const PUBLIC_IP_LOOKUP_SRC = String.raw`\bapi(?:64)?\.ipify\.org\b|\bip-api\.com\b|\bipinfo\.io\b|\bifconfig\.me\b|\bicanhazip\.com\b`
  + String.raw`|\bcheckip\.amazonaws\.com\b|\bipapi\.co\b|\bident\.me\b|\bapi\.myip\.com\b|\bwtfismyip\.com\b`;
const ENV_COPY_SRC = String.raw`(?<![\w$.])([A-Za-z_$][\w$]*)\s{0,40}=\s{0,40}(?:dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\s*\)`
  + String.raw`|\{\s*\*\*\s*os\.environ\s*\}|\{\s*\.\.\.\s*process\.env\s*\}|Object\.assign\(\s*\{\s*\}\s*,\s*process\.env\s*\))`;
const IP_LITERAL_SRC = String.raw`["'](?!(?:127|0|255)\.)((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))["']`;
const RAW_CONNECT_SRC = String.raw`\b(?:socket\.create_connection|net\.connect|net\.createConnection|connect(?:_ex)?)\s*\(|\bnew\s+net\.Socket\b`;
const MONERO_ADDR_SRC = String.raw`(?<![A-Za-z0-9])[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?(?![A-Za-z0-9])`;
const MINER_ARG_SRC = String.raw`["'](?:-o|--url)["']|\bstratum\+(?:tcp|ssl|tls)://|--donate-level\b|\b(?:xmrig|XMRig|XMRIG)\b`;
const MINER_ARG_NEEDLES = ["'-o'", '"-o"', "'--url'", '"--url"', "stratum+", "--donate-level", "xmrig", "XMRig", "XMRIG"];
const CHAT_SECRET_RE = pyRe(CHAT_SECRET_SRC, "g");
const TELEGRAM_API_RE = pyRe(TELEGRAM_API_SRC, "i");
const CRED_FILE_RE = pyRe(CRED_FILE_SRC);
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
const PUBLIC_IP_LOOKUP_RE = pyRe(PUBLIC_IP_LOOKUP_SRC);
const PUBLIC_IP_LOOKUP_NEEDLES = ["ipify.org", "ip-api.com", "ipinfo.io", "ifconfig.me", "icanhazip.com",
  "checkip.amazonaws.com", "ipapi.co", "ident.me", "api.myip.com", "wtfismyip.com"];
const ENV_COPY_RE = pyRe(ENV_COPY_SRC, "g");
const ENV_COPY_ANCHOR_SRC = String.raw`dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\s*\)|\*\*\s*os\.environ|\.\.\.\s*process\.env`
  + String.raw`|Object\.assign\(\s*\{\s*\}\s*,\s*process\.env`;
const ENV_COPY_ANCHOR_RE = pyRe(ENV_COPY_ANCHOR_SRC);
const IP_LITERAL_RE = pyRe(IP_LITERAL_SRC, "g");
const RAW_CONNECT_RE = pyRe(RAW_CONNECT_SRC);
const MONERO_ADDR_RE = pyRe(MONERO_ADDR_SRC);
const MINER_ARG_RE = pyRe(MINER_ARG_SRC);
const CHAT_SECRET_MAX = 50;
const CHAT_SECRET_MIN_DISTINCT = 10;
const CRED_SWEEP_NEEDLES = [".ssh", ".aws", ".azure", ".gnupg", ".docker", ".kube", ".ethereum", ".electrum", ".bitcoin",
  ".solana", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".config", ".password-store", ".vault-token", ".terraform.d"];
const CRED_SWEEP_SPAN = 400;
const CRED_SWEEP_MIN = 3;
const CRED_SWEEP_MAX = 200;
const ENV_COPY_MAX = 20;
const RAW_CONNECT_SPAN = 600;
const IP_LITERAL_MAX = 100;
const PUBLIC_RESOLVERS = new Set(["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
  "208.67.222.222", "208.67.220.220"]);
const distinct = (s) => new Set(s).size;

/** [offset, reason] of the first chat bot or webhook secret of text in a file that makes network calls, else null (core.chat_secret_at). */
export function chatSecretAt(text) {
  if (!CHAT_SECRET_NEEDLES.some((nd) => text.includes(nd))) return null;
  if (!NETWORK_RE.test(text)) return null;
  CHAT_SECRET_RE.lastIndex = 0;
  let k = 0;
  for (let m; (m = CHAT_SECRET_RE.exec(text)) !== null; k++) {
    if (k >= CHAT_SECRET_MAX) break;
    const found = m[0];
    if (found.startsWith("discord") || found.startsWith("Discord")) {
      const parts = found.split("/");
      const [hook, secret] = parts.slice(-2);
      if (distinct(secret) >= CHAT_SECRET_MIN_DISTINCT) {
        return [m.index, `sends data to a Discord webhook whose token is written in the code (webhook ${hook})`];
      }
    } else if (found.startsWith("hooks.")) {
      const [team, , secret] = found.split("/").slice(-3);
      if (distinct(secret) >= CHAT_SECRET_MIN_DISTINCT && pyStripChars(team, "T0")) {
        return [m.index, `sends data to a Slack webhook whose key is written in the code (${team})`];
      }
    } else {
      const colon = found.indexOf(":");
      const bot = found.slice(0, colon);
      const secret = found.slice(colon + 1);
      if (distinct(secret) >= CHAT_SECRET_MIN_DISTINCT && TELEGRAM_API_RE.test(text)) {
        return [m.index, `sends data to a Telegram bot whose token is written in the code (bot ${bot})`];
      }
    }
  }
  return null;
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

/** Where text serializes a copy of the whole environment it made, else -1 (core.env_copy_serialized_at). */
export function envCopySerializedAt(text) {
  if ((!text.includes("os.environ") && !text.includes("process.env")) || !ENV_COPY_ANCHOR_RE.test(text)) return -1;
  ENV_COPY_RE.lastIndex = 0;
  let k = 0;
  for (let m; (m = ENV_COPY_RE.exec(text)) !== null; k++) {
    if (k >= ENV_COPY_MAX) break;
    const use = pyRe(String.raw`\b(?:urlencode|dumps|stringify|b64encode|str)\(\s*` + reEscape(m[1]) + String.raw`\s*[,)]`, "g");
    const u = searchFrom(use, text, m.index + m[0].length);
    if (u) return u.index;
  }
  return -1;
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
  const chat = chatSecretAt(text);
  if (chat !== null) signs.push(chat);
  let net = null;                                     // NETWORK_RE's answer, searched once when needed
  const network = () => (net === null ? (net = NETWORK_RE.test(text)) : net);
  const ip = PUBLIC_IP_URL_RE.exec(text);
  if (ip) {
    const cred = CRED_FILE_RE.exec(text);
    if (cred && network()) {
      signs.push([cred.index, `reads credential files and sends data to an IP address (${ip[0].slice(ip[0].indexOf("//") + 2)})`]);
    }
  }
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
  } else if (PUBLIC_IP_LOOKUP_NEEDLES.some((nd) => text.includes(nd))) {
    const lookup = PUBLIC_IP_LOOKUP_RE.exec(text);
    if (lookup) {
      const capture = captureService(text);
      if (capture) {
        signs.push([lookup.index, `sends the machine's public IP address to a data-capture service (${cpPrefix(capture[0], 40)})`]);
      }
    }
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

// ---- persistence targets (0.1.7; core's comment above _PERSIST_AGENT_SRC) ----
// Where the 2025-26 worms made themselves stay: an AI agent's or editor's
// auto-run settings, a GitHub Actions workflow, an editor extension, a
// self-hosted runner; and the Bun loader of the Shai-Hulud worms. Reasons of
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
const BUN_RELEASES_SRC = String.raw`oven-sh/bun/releases`;
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
const BUN_RELEASES_RE = pyRe(BUN_RELEASES_SRC, "i");
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

// A browser's shortcuts rewritten to load an extension (core's comment above _PERSIST_SHORTCUT_RE)
const PERSIST_SHORTCUT_SRC = String.raw`\bCreateShortcut\b|\.lnk\b`;
const PERSIST_SHORTCUT_RE = pyRe(PERSIST_SHORTCUT_SRC);

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
  if (BUN_RELEASES_RE.test(text) && EXEC_CALL_RE.test(text)) {
    reasons.push("downloads the Bun runtime from GitHub and runs code with it");
  }
  if (text.includes("--load-extension") && PERSIST_SHORTCUT_RE.test(text)) {
    reasons.push("rewrites browser shortcuts to load an extension");
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
const DV_NEEDLES = ["Buffer", "atob", "fromhex", "unhexlify", "b64decode", "fromCharCode", "hex", "base64"];
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

/** The text read the way it reads once the strings it decodes as it runs are decoded. Twin of core.decoded_view. */
export function decodedView(text) {
  if (text.length > DV_MAX_CHARS && cpLen(text) > DV_MAX_CHARS) return text;
  if (!DV_NEEDLES.some((n) => text.includes(n))) return text;
  const joined = text.includes("+") ? text.replace(DV_JOIN_G, "") : text;
  let view = joined;
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
  if (view === joined) return text;                  // nothing decoded: literals joined alone are no reading of their own
  let arrays = 0;
  for (const m of [...view.matchAll(DV_ARRAY_G)]) {
    if (arrays >= DV_MAX_ARRAYS) break;
    const name = m.groups.name;
    const items = [...m.groups.items.matchAll(DV_STR_ITEM_G)].map((x) => x[0]);
    const esc = reEscape(name);
    const mutated = pyRe(String.raw`(?<![\w$.])` + esc + String.raw`\s*(?:\.\s*(?:push|pop|shift|unshift|splice|reverse|sort|fill`
      + String.raw`|copyWithin|append|insert|extend|remove)\s*\(|\[[^\]\n]{0,80}\]\s*=(?!=))`).test(view);
    if (mutated || [...view.matchAll(pyRe(String.raw`(?<![\w$.])` + esc + String.raw`\s*=(?![=>])`, "g"))].length !== 1) continue;
    arrays++;
    view = view.replace(pyRe(String.raw`(?<![\w$.])` + esc + String.raw`\s*\[\s*([0-9]{1,2})\s*\]`, "g"),
      (whole, i) => (Number(i) < items.length ? items[Number(i)] : whole));
  }
  return view.includes("[") ? view.replace(DV_MEMBER_G, (...args) => { const g = args[args.length - 1]; return "." + (g.a || g.b); }) : view;
}

// ---- scripts a script starts with node or python (0.1.8; core's comment above _SPAWN_MAX_DEPTH) ----
export const SPAWN_MAX_DEPTH = 3, SPAWN_MAX_FILES = 20;
const SPAWN_NAME_DEPTH = 3, SPAWN_MAX_TARGETS = 8;
const SPAWN_CALL_SRC = String.raw`\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*(?:process\s*\.\s*execPath|process\s*\.\s*argv\s*\[\s*0\s*\]`
  + String.raw`|['"` + BT + String.raw`](?:node|nodejs)(?:\.exe)?['"` + BT + String.raw`])\s*,\s*\[|\bfork\s*\(`
  + String.raw`|\b(?:Popen|run|call|check_call|check_output)\s*\(\s*\[\s*(?:sys\s*\.\s*executable`
  + String.raw`|['"]python[0-9.]*(?:\.exe)?['"])\s*,`;
const SPAWN_LIT_SRC = String.raw`'(?P<a>[^'"` + BT + String.raw`\n$\\]{1,200})'|"(?P<b>[^'"` + BT + String.raw`\n$\\]{1,200})"|`
  + BT + String.raw`(?P<c>[^'"` + BT + String.raw`\n$\\]{1,200})` + BT;
const SPAWN_CONCAT_SRC = String.raw`__dirname\s*\+\s*(?:'/?(?P<a>[^'"` + BT + String.raw`\n$\\]{1,200})'|"/?(?P<b>[^'"` + BT
  + String.raw`\n$\\]{1,200})"|` + BT + String.raw`/?(?P<c>[^'"` + BT + String.raw`\n$\\]{1,200})` + BT + String.raw`)|`
  + BT + String.raw`\$\{\s*__dirname\s*\}/(?P<t>[^` + BT + String.raw`$\n\\]{1,200})` + BT;
const SPAWN_DIR_SRC = String.raw`__dirname|os\s*\.\s*path\s*\.\s*dirname\s*\(\s*(?:os\s*\.\s*path\s*\.\s*(?:abspath|realpath)`
  + String.raw`\s*\(\s*)?__file__\s*\)?\s*\)|Path\s*\(\s*__file__\s*\)\s*(?:\.\s*resolve\s*\(\s*\))?\s*\.\s*parent`;
const SPAWN_JOIN_SRC = String.raw`(?:path\s*\.\s*(?:join|resolve)|os\s*\.\s*path\s*\.\s*join)\s*\(`;
const SPAWN_NAME_SRC = String.raw`[A-Za-z_$][\w$]*`;
const SPAWN_CALL_G = pyRe(SPAWN_CALL_SRC, "g");
const whole = (src) => pyReG(String.raw`^(?:` + src + String.raw`)\Z`);
const SPAWN_LIT_WHOLE = whole(SPAWN_LIT_SRC);
const SPAWN_CONCAT_WHOLE = whole(SPAWN_CONCAT_SRC);
const SPAWN_DIR_WHOLE = whole(SPAWN_DIR_SRC);
const SPAWN_NAME_WHOLE = whole(SPAWN_NAME_SRC);
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

/** [base, path] a script argument names ('dir' or 'cwd'), else null. core._spawn_path. */
function spawnPath(expr, text, names) {
  expr = pyStrip(expr);
  const lit = litValue(SPAWN_LIT_WHOLE.exec(expr));
  if (lit != null) return lit.startsWith("-") ? null : ["cwd", lit];
  const c = SPAWN_CONCAT_WHOLE.exec(expr);
  if (c !== null) return ["dir", c.groups.a ?? c.groups.b ?? c.groups.c ?? c.groups.t];
  SPAWN_JOIN_AT.lastIndex = 0;
  const j = SPAWN_JOIN_AT.exec(expr);
  if (j !== null) {
    const parts = spawnArgs(expr, j[0].length);
    if (!parts.length || !pyRstrip(expr).endsWith(")")) return null;
    let base, segs;
    if (SPAWN_DIR_WHOLE.test(parts[0])) { base = "dir"; segs = []; }
    else {
      const head = spawnPath(parts[0], text, names);
      if (head === null) return null;
      [base, segs] = [head[0], [head[1]]];
    }
    for (const part of parts.slice(1)) {
      const v = litValue(SPAWN_LIT_WHOLE.exec(part));
      if (v == null) return null;
      segs.push(v);
    }
    return segs.length ? [base, segs.join("/")] : null;
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

/** [[base, path]]: the package scripts `text` starts with node or python. Twin of core.spawned_scripts. */
export function spawnedScripts(text) {
  if (!["spawn", "execFile", "fork", "Popen", "run", "call", "check_"].some((n) => text.includes(n))) return [];
  const out = [];
  for (const m of text.matchAll(SPAWN_CALL_G)) {
    const args = spawnArgs(text, m.index + m[0].length);
    let skip = false;
    for (const arg of args.slice(0, 6)) {
      if (skip) { skip = false; continue; }
      const value = litValue(SPAWN_LIT_WHOLE.exec(arg));
      if (value != null && value.startsWith("-")) {
        const flag = value.split("=")[0];
        if (SPAWN_NO_SCRIPT_FLAGS.has(flag)) break;
        skip = SPAWN_VALUE_FLAGS.has(flag) && !value.includes("=");
        continue;
      }
      const target = spawnPath(arg, text, SPAWN_NAME_DEPTH);
      if (target !== null) {
        const raw = target[1].replaceAll("\\", "/");
        if (!raw.startsWith("/")) {
          const path = normpathRel(raw);
          if (path !== "." && path !== "" && !out.some(([b, p]) => b === target[0] && p === path)) out.push([target[0], path]);
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
export function installScriptRisk(text) {
  const reasons = installScriptRiskOf(text);
  const view = decodedView(text);
  if (view !== text) for (const r of installScriptRiskOf(view)) if (!reasons.includes(r)) reasons.push(r + DV_NOTE);
  return reasons;
}

function installScriptRiskOf(text) {
  const reasons = [];
  const network = NETWORK_RE.test(text);
  if (network && SECRET_SOURCE_RE.test(text)) {
    reasons.push("reads environment variables or credential files and sends data over the network");
  }
  const dest = EXFIL_DEST_RE.exec(text);
  if (dest) reasons.push(`contacts an address typical of data exfiltration (${cpPrefix(dest[0], 40)})`);
  if (pipesDownloadToShell(text)) reasons.push("pipes a download into a shell");
  const substituted = (text.includes("curl") || text.includes("wget")) && text.split("\n").some(runsSubstitutedDownload);
  const received = receivedCodeKind(text);
  if (substituted) reasons.push(DL_CATEGORY_REASON.run);
  else if (received !== null) reasons.push(DL_CATEGORY_REASON[received[1]]);
  reasons.push(...powershellRisk(text));
  if ((received === null || received[1] !== "run") && !substituted && stagerAt(text) >= 0) {
    reasons.push("carries a script that downloads and runs code");
  }
  if (reverseShellAt(text) >= 0) reasons.push("opens a reverse shell");
  const host = HOST_INFO_RE.exec(text);
  if (host && (NETWORK_RE.test(text) || EXFIL_SERVICE_RE.test(text))) {               // sendsHostInfo
    reasons.push("sends the machine's user or host name over the network");
  }
  for (const [, reason] of exfilSigns(text, host)) if (!reasons.includes(reason)) reasons.push(reason);
  if (dest === null) {
    const ip = rawIpConnect(text);
    if (ip !== null) reasons.push(`contacts an address typical of data exfiltration (${ip})`);
  }
  if (runsOwnSourceAt(text) >= 0) reasons.push("runs code it reads back from its own file or a data file shipped with it");
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

// core's _IMPORT_HARVEST_RE ends in `(?i:Local Storage)[/\\]leveldb`: only
// "Local Storage" ignores case. Node 22 has no inline flag groups, so that
// alternative is matched in two steps, "Local Storage" with re.I and then,
// case-sensitive, what must follow it; the search's start is the earlier of
// that and the rest of the pattern's (a search only reports where it starts).
const IMPORT_HARVEST_REST_SRC =
  String.raw`JSON\.stringify\(\s*process\.env\s*[,)]|` +
  String.raw`\bjson\.dumps\(\s*(?:dict\(\s*)?os\.environ\s*[,)]|\b(?:str|repr)\(\s*os\.environ\s*\)|` +
  String.raw`\burlencode\(\s*(?:dict\(\s*)?os\.environ\s*[,)]|` +
  String.raw`[/\\]\.ssh[/\\]id_|\bid_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\.git-credentials`;
const LOCAL_STORAGE_SRC = "Local Storage";
const LEVELDB_SRC = String.raw`[/\\]leveldb`;
const IMPORT_HARVEST_SRC = IMPORT_HARVEST_REST_SRC + `|(?i:${LOCAL_STORAGE_SRC})` + LEVELDB_SRC;
const IMPORT_HARVEST_REST_RE = pyRe(IMPORT_HARVEST_REST_SRC);
const LOCAL_STORAGE_RE = pyRe(LOCAL_STORAGE_SRC, "gi");
const LEVELDB_RE = pyRe(LEVELDB_SRC, "y");

// core._IMPORT_HARVEST_NEEDLES: every match contains one of them, so a text
// with none is not searched
const IMPORT_HARVEST_NEEDLES = ["process.env", "os.environ", "id_", ".git-credentials", "leveldb"];

/** Where text harvests: core._import_harvest_at (_IMPORT_HARVEST_RE, else a copy of the environment it serializes), or -1. */
function importHarvestStart(text) {
  const at = importHarvestReStart(text);
  return at !== -1 ? at : envCopySerializedAt(text);
}

/** Where core's _IMPORT_HARVEST_RE.search(text) starts, or -1. */
function importHarvestReStart(text) {
  if (!IMPORT_HARVEST_NEEDLES.some((needle) => text.includes(needle))) return -1;
  const rest = IMPORT_HARVEST_REST_RE.exec(text);
  const limit = rest ? rest.index : text.length;
  LOCAL_STORAGE_RE.lastIndex = 0;
  for (let m; (m = LOCAL_STORAGE_RE.exec(text)) !== null && m.index < limit;) {
    LEVELDB_RE.lastIndex = m.index + m[0].length;
    if (LEVELDB_RE.test(text)) return m.index;
    LOCAL_STORAGE_RE.lastIndex = m.index + 1;
  }
  return rest ? rest.index : -1;
}

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
  "sends data to a Telegram bot whose token", "sends data to a Discord webhook whose token",
  "sends data to a Slack webhook whose key", "reads credential files and sends data to an IP address",
  "collects files from several credential folders", "sends the machine's user or host name to an address it hides",
  "sends the machine's user or host name in a DNS lookup", "sends the machine's public IP address to a data-capture",
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

function importTimeRiskOf(text) {
  const reasons = [];
  let line = null;
  const harvest = importHarvestStart(text);
  if (harvest !== -1) {
    const service = EXFIL_SERVICE_RE.exec(text);
    if (service) {
      reasons.push("reads credentials or the whole environment and sends them to "
        + `an exfiltration service (${cpPrefix(service[0], 40)})`);
    } else if (NETWORK_RE.test(text)) {
      reasons.push("reads credentials or the whole environment and sends data over the network");
    }
    if (reasons.length) line = countNewlines(text, 0, harvest) + 1;
  }
  if (text.includes("curl") || text.includes("wget")) {
    // the rows of text.split("\n"), one at a time
    for (let start = 0, i = 0; ; i++) {
      const nl = text.indexOf("\n", start);
      const row = nl === -1 ? text.slice(start) : text.slice(start, nl);
      if (runsDownloadThroughShell(row)) {
        reasons.push("runs a downloaded script through a shell");
        line ??= i + 1;
        break;
      }
      if (nl === -1) break;
      start = nl + 1;
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
  if (host) {
    const capture = captureService(text);
    if (capture) signs.push([host.index, `sends the machine's user or host name to a data-capture service (${cpPrefix(capture[0], 40)})`]);
  }
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
    _NETWORK_RE: [NETWORK_SRC, "m"], _SECRET_SOURCE_RE: [SECRET_SOURCE_SRC, "im"],
    _EXFIL_DEST_RE: [EXFIL_DEST_SRC, "i"], _EXFIL_SERVICE_RE: [EXFIL_SERVICES_SRC, "i"],
    _PIPE_SCAN_RE: [PIPE_SCAN_SRC, ""], _IMPORT_HARVEST_RE: [IMPORT_HARVEST_SRC, ""],
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
    _PERSIST_RUNNER_ARG_RE: [PERSIST_RUNNER_ARG_SRC, ""], _BUN_RELEASES_RE: [BUN_RELEASES_SRC, "i"],
    _SECRETS_DUMP_RE: [SECRETS_DUMP_SRC, "i"],
    _PUBLISH_CMD_RE: [PUBLISH_CMD_SRC, ""], _NAME_ASSIGN_RE: [NAME_ASSIGN_SRC, ""],
    _MANIFEST_WRITE_RE: [MANIFEST_WRITE_SRC, ""], _JS_IDENT_RE: [JS_IDENT_SRC, ""],
    _NPM_TOKEN_READ_RE: [NPM_TOKEN_READ_SRC, ""], _DLL_LOADER_RE: [DLL_LOADER_SRC, "i"],
    _DLL_NAME_RE: [DLL_NAME_SRC, "i"], _STRING_JOIN_RE: [STRING_JOIN_SRC, ""],
    _DV_JOIN_RE: [DV_JOIN_SRC, ""], _DV_BUFFER_RE: [DV_BUFFER_SRC, ""], _DV_ATOB_RE: [DV_ATOB_SRC, ""],
    _DV_PY_RE: [DV_PY_SRC, ""], _DV_HELPER_RE: [DV_HELPER_SRC, ""], _DV_STR_ITEM_RE: [DV_STR_ITEM_SRC, ""],
    _DV_ARRAY_RE: [DV_ARRAY_SRC, ""], _DV_MEMBER_RE: [DV_MEMBER_SRC, ""],
    _DV_CALL_RE: [DV_CALL_SRC, ""], _DV_KEY_RE: [DV_KEY_SRC, ""],
    _SCRIPT_INTERP_RE: [SCRIPT_INTERP_SRC, ""], _SCRIPT_LOAD_RE: [SCRIPT_LOAD_SRC, ""], _DECODE_CALL_RE: [DECODE_CALL_SRC, ""],
    _SPAWN_CALL_RE: [SPAWN_CALL_SRC, ""], _SPAWN_LIT_RE: [SPAWN_LIT_SRC, ""], _SPAWN_CONCAT_RE: [SPAWN_CONCAT_SRC, ""],
    _SPAWN_DIR_RE: [SPAWN_DIR_SRC, ""], _SPAWN_JOIN_RE: [SPAWN_JOIN_SRC, ""], _SPAWN_NAME_RE: [SPAWN_NAME_SRC, ""],
    _REVSHELL_NGROK_TCP_RE: [REVSHELL_NGROK_TCP_SRC, "i"], _REVSHELL_ARG_SHELL_RE: [REVSHELL_ARG_SHELL_SRC, ""],
    _REVSHELL_ARGS_RE: [REVSHELL_ARGS_SRC, ""], _CHAT_SECRET_RE: [CHAT_SECRET_SRC, ""],
    _TELEGRAM_API_RE: [TELEGRAM_API_SRC, "i"], _CRED_FILE_RE: [CRED_FILE_SRC, ""],
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
    _PUBLIC_IP_LOOKUP_RE: [PUBLIC_IP_LOOKUP_SRC, ""], _ENV_COPY_RE: [ENV_COPY_SRC, ""],
    _IP_LITERAL_RE: [IP_LITERAL_SRC, ""], _RAW_CONNECT_RE: [RAW_CONNECT_SRC, ""], _ENV_COPY_ANCHOR_RE: [ENV_COPY_ANCHOR_SRC, ""],
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
    ...RECEIVED_TWINS,
  },
  sets: {
    _HOOK_SEPARATORS: [...HOOK_SEPARATORS], _HOOK_REDIRECTS: [...HOOK_REDIRECTS],
    _HOOK_WRAPPERS: [...HOOK_WRAPPERS], _NODE_NAMES: [...NODE_NAMES], _SHELL_NAMES: [...SHELL_NAMES],
    _NODE_CODE_FLAGS: [...NODE_CODE_FLAGS], _NODE_PRELOAD_FLAGS: [...NODE_PRELOAD_FLAGS],
    _NODE_VALUE_FLAGS: [...NODE_VALUE_FLAGS], _SHEBANG_JS_NAMES: [...SHEBANG_JS_NAMES],
    _IMPORT_HARVEST_NEEDLES: IMPORT_HARVEST_NEEDLES,
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
    _PUBLIC_IP_LOOKUP_NEEDLES: PUBLIC_IP_LOOKUP_NEEDLES, _MINER_ARG_NEEDLES: MINER_ARG_NEEDLES,
    _REVSHELL_ARGS_NEEDLES: REVSHELL_ARGS_NEEDLES, _SELF_SHELL_RUNNERS: SELF_SHELL_RUNNERS,
    _DNS_LOCAL_TLDS: [...DNS_LOCAL_TLDS],
  },
  maps: Object.fromEntries([["_PERSIST_AGENT_PAIRS", PERSIST_AGENT_PAIRS], ["_WRAPPER_VALUE_OPTIONS", WRAPPER_VALUE_OPTIONS],
    ["_WRAPPER_CHDIR_OPTIONS", WRAPPER_CHDIR_OPTIONS], ["_WRAPPER_COMMAND_OPTIONS", WRAPPER_COMMAND_OPTIONS]]
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
    _SPAWN_NAME_DEPTH: SPAWN_NAME_DEPTH, _SPAWN_MAX_TARGETS: SPAWN_MAX_TARGETS,
    _CHAT_SECRET_MAX: CHAT_SECRET_MAX, _CHAT_SECRET_MIN_DISTINCT: CHAT_SECRET_MIN_DISTINCT,
    _CRED_SWEEP_SPAN: CRED_SWEEP_SPAN, _CRED_SWEEP_MIN: CRED_SWEEP_MIN, _CRED_SWEEP_MAX: CRED_SWEEP_MAX,
    _ENV_COPY_MAX: ENV_COPY_MAX, _RAW_CONNECT_SPAN: RAW_CONNECT_SPAN, _IP_LITERAL_MAX: IP_LITERAL_MAX,
    _DNS_LOOKUP_MAX: DNS_LOOKUP_MAX, _DNS_ARG_SPAN: DNS_ARG_SPAN, _DNS_ASSIGN_SPAN: DNS_ASSIGN_SPAN,
    _DNS_SHELL_SPAN: DNS_SHELL_SPAN, _DD_PASSES: DD_PASSES, _DD_MAX_CALLS: DD_MAX_CALLS, _DD_ARG_SPAN: DD_ARG_SPAN,
    _DD_MAX_ASSIGNS: DD_MAX_ASSIGNS, _DD_THEN_MAX: DD_THEN_MAX },
};
