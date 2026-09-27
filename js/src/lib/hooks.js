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

import { pyRe, pyStrip, isPySpace } from "./pycompat.js";
import { PIPE_SCAN_SRC, EXEC_CALL_SRC, pipesDownloadToShell, runsDownloadThroughShell } from "./shellpipe.js";

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
const EXFIL_SERVICES_SRC =
  String.raw`pastebin\.com|\bngrok|webhook\.site|` +
  String.raw`discord(?:app)?\.com/api/webhooks|api\.telegram\.org|oastify\.com|burpcollaborator|` +
  String.raw`\binteract\.sh|\boast\.(?:pro|live|site|online|fun|me)\b|requestbin|pipedream\.net|` +
  String.raw`transfer\.sh|\.onion\b`;
const EXFIL_DEST_SRC = String.raw`https?://(?:\d{1,3}\.){3}\d{1,3}\b|` + EXFIL_SERVICES_SRC;
const EXFIL_DEST_RE = pyRe(EXFIL_DEST_SRC, "i");
const EXFIL_SERVICE_RE = pyRe(EXFIL_SERVICES_SRC, "i");              // the named ones, no raw IPs
/** The first n code points of s (Python's s[:n]). */
function cpPrefix(s, n) {
  let i = 0;
  for (let k = 0; k < n && i < s.length; k++) {
    const c = s.charCodeAt(i);
    i += c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00 ? 2 : 1;
  }
  return s.slice(0, i);
}

/**
 * Reasons an install-time script looks hostile ([] if none).
 * Twin of lazaret.scanner.core.install_script_risk.
 */
export function installScriptRisk(text) {
  const reasons = [];
  const network = NETWORK_RE.test(text);
  if (network && SECRET_SOURCE_RE.test(text)) {
    reasons.push("reads environment variables or credential files and sends data over the network");
  }
  const dest = EXFIL_DEST_RE.exec(text);
  if (dest) reasons.push(`contacts an address typical of data exfiltration (${cpPrefix(dest[0], 40)})`);
  if (pipesDownloadToShell(text)) reasons.push("pipes a download into a shell");
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

/** Where core's _IMPORT_HARVEST_RE.search(text) starts, or -1. */
function importHarvestStart(text) {
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

/**
 * [reasons, line]: why code that runs on import looks hostile by the weaker
 * test (core's comment above _IMPORT_HARVEST_RE) — [] if not — and the
 * 1-based line of the first sign (null when there is none). `text` has \n
 * line endings. Twin of lazaret.scanner.core.import_time_risk.
 */
export function importTimeRisk(text) {
  const reasons = [];
  let line = null;
  const harvest = importHarvestStart(text);
  if (harvest !== -1 && (NETWORK_RE.test(text) || EXFIL_SERVICE_RE.test(text))) {
    reasons.push("reads credentials or the whole environment and sends data over the network");
    line = countNewlines(text, 0, harvest) + 1;
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
  return [reasons, line];
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
  },
  sets: {
    _HOOK_SEPARATORS: [...HOOK_SEPARATORS], _HOOK_REDIRECTS: [...HOOK_REDIRECTS],
    _HOOK_WRAPPERS: [...HOOK_WRAPPERS], _NODE_NAMES: [...NODE_NAMES], _SHELL_NAMES: [...SHELL_NAMES],
    _NODE_CODE_FLAGS: [...NODE_CODE_FLAGS], _NODE_PRELOAD_FLAGS: [...NODE_PRELOAD_FLAGS],
    _NODE_VALUE_FLAGS: [...NODE_VALUE_FLAGS], _SHEBANG_JS_NAMES: [...SHEBANG_JS_NAMES],
    _IMPORT_HARVEST_NEEDLES: IMPORT_HARVEST_NEEDLES,
  },
  maps: Object.fromEntries([["_WRAPPER_VALUE_OPTIONS", WRAPPER_VALUE_OPTIONS],
    ["_WRAPPER_CHDIR_OPTIONS", WRAPPER_CHDIR_OPTIONS], ["_WRAPPER_COMMAND_OPTIONS", WRAPPER_COMMAND_OPTIONS]]
    .map(([name, map]) => [name, Object.fromEntries([...map].map(([k, v]) => [k, [...v].sort()]))])),
  limits: { HOOK_MAX_CHARS, HOOK_MAX_COMMANDS, HOOK_MAX_TARGETS, HOOK_MAX_PATH },
};
