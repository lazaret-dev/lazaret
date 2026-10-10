// Where a program Lazaret runs is (the Python package's lazaret.scanner.programs): the first of PATH's folders that
// holds it, as a shell finds it, though only among the folders PATH names by an absolute path. Never the current folder.
//
// Given a bare name, Node's child_process (libuv) looks in the child's working folder first on Windows, as
// CreateProcess does, and on every system an empty or relative PATH entry names the current folder. `lazaret hook`
// runs git in a repository's folder, which could hold a git.exe of its own that would then run in the real one's place
// (the Go/Rust review's GO-8, Oct 4, 2026; GitPython's CVE-2023-40590 is the same hazard). A zero-dependency leaf.

import { accessSync, statSync, constants as C } from "node:fs";
import { posix, win32 } from "node:path";

/** Windows' own list when PATHEXT is not set. */
export const WINDOWS_PATHEXT = ".COM;.EXE;.BAT;.CMD";
/** The search path when the environment has none: the system's (its CS_PATH, which Python's os.confstr gives; on
 * Windows, Python's os.defpath). */
const defaultPath = (windows) => (windows ? ".;C:\\bin"
  : process.platform === "darwin" ? "/usr/bin:/bin:/usr/sbin:/sbin" : "/bin:/usr/bin");

const isWindows = () => process.platform === "win32";

/** os.path.normpath: the path normalized, without a separator at its end (unless it is a root). */
function normpath(flavor, d) {
  const n = flavor.normalize(d);
  const root = flavor.parse(n).root;
  return n.length > root.length ? n.replace(flavor === win32 ? /[\\/]+$/ : /\/+$/, "") : n;
}

/** An environment variable's value: on Windows its name in any case, as Windows reads it (a copy of process.env is a
 * plain object, whose keys keep the case they had: `Path`). */
function envValue(env, name, windows) {
  if (Object.hasOwn(env, name)) return env[name];
  if (!windows) return undefined;
  const key = Object.keys(env).find((k) => k.toUpperCase() === name);
  return key === undefined ? undefined : env[key];
}

/** `s` without the double quotes at either end, Python's s.strip('"') (a loop: /^"+|"+$/ takes quadratic time on
 * a long run of them). */
function stripQuotes(s) {
  let a = 0, b = s.length;
  while (a < b && s[a] === '"') a++;
  while (b > a && s[b - 1] === '"') b--;
  return a === 0 && b === s.length ? s : s.slice(a, b);
}

/**
 * PATH's folders a program is looked up in, in order and once each: those named by an absolute path (on Windows, one
 * with a drive and a root, or a share). `path` is a PATH value (programs.folders).
 */
export function folders(path, { windows = isWindows() } = {}) {
  const seen = new Set(), found = [];
  for (let d of String(path ?? "").split(windows ? ";" : ":")) {
    let key;
    if (windows) {
      d = stripQuotes(d.trim());
      // a drive and a root (`C:x` is relative to C:'s current folder), or a share
      if (!/^[A-Za-z]:[\\/]/.test(d) && !/^[\\/]{2}[^\\/]/.test(d)) continue;
      key = normpath(win32, d).toLowerCase();
    } else {
      if (!d || !posix.isAbsolute(d)) continue;
      key = normpath(posix, d);
    }
    if (!seen.has(key)) {
      seen.add(key);
      found.push(d);
    }
  }
  return found;
}

/** The file names a program is found under: on Windows, the name with each of PATHEXT's extensions, unless it has one. */
export function fileNames(name, { windows = isWindows(), pathext } = {}) {
  if (!windows) return [name];
  const exts = String(pathext || WINDOWS_PATHEXT).split(";").filter(Boolean);
  if (exts.some((e) => name.toLowerCase().endsWith(e.toLowerCase()))) return [name];
  return exts.map((e) => name + e);
}

/**
 * The full path of the program `name` (a bare name: one with a folder or a drive in it is refused) in PATH's absolute
 * folders, or null when none of them holds it (programs.find). `env` is where PATH (and on Windows PATHEXT) is read.
 */
export function findProgram(name, { env = process.env, windows = isWindows() } = {}) {
  if (!name || name.includes("/") || (windows && (name.includes("\\") || /^[A-Za-z]:/.test(name)))) return null;
  const path = envValue(env, "PATH", windows);
  const pathext = windows ? envValue(env, "PATHEXT", windows) : undefined;
  const join = windows ? win32.join : posix.join;
  for (const d of folders(path === undefined ? defaultPath(windows) : path, { windows })) {
    for (const n of fileNames(name, { windows, pathext })) {
      const p = join(d, n);
      try {
        if (!statSync(p).isFile()) continue;
        accessSync(p, C.X_OK);
        return p;
      } catch { /* not here */ }
    }
  }
  return null;
}
