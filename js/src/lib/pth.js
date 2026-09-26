// .pth files (SC-PTH-EXEC) — twin of lazaret.scanner.core.pth_issues, the
// check the registry runs on archive members. site.py executes every line of
// a .pth file in site-packages that starts with 'import' at EVERY interpreter
// start, so project and --deps scans check each .pth file they meet. A .pth
// file is not a source file: no other rule runs on it.

import { mkIssue } from "./issue.js";
import { pyRe } from "./pycompat.js";

export const PTH_EXEC_RE = pyRe("\\b(?:exec|eval|compile)\\s*\\(|\\b(?:b64decode|b32decode|b85decode|a85decode|fromhex|unhexlify)\\b|\\.decode\\s*\\(|\\bmarshal\\.loads\\b|\\bzlib\\.decompress\\b|\\bcodecs\\.decode\\b|\\\\x[0-9a-fA-F]{2}");

// The line boundaries Python's str.splitlines() adds to \n, \r and \r\n.
const SPLITLINES_BREAK_RE = /[\v\f\x1c-\x1e\x85\u2028\u2029]/;
const isImport = (s) => s.startsWith("import ") || s.startsWith("import\t");

/**
 * SC-PTH-EXEC for each `import` line of a .pth file: CRITICAL when the line
 * also executes or decodes code, MAJOR otherwise (setuptools' distutils shim
 * and namespace .pth files are this shape: listed for review). Lines are
 * taken both ways site.py splits them: at \n, \r and \r\n (Python 3.10,
 * 3.11, early 3.12), and with str.splitlines() (3.13+, recent 3.12), which
 * also breaks at \v, \f, \x1c-\x1e, \x85, U+2028 and U+2029. A finding is
 * reported at the physical (\n) line holding the statement, once per line.
 */
export function pthIssues(path, text) {
  const out = [];
  const lines = (text.includes("\r") ? text.replace(/\r\n?/g, "\n") : text).split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!isImport(line) && !line.split(SPLITLINES_BREAK_RE).some(isImport)) continue;
    const hostile = PTH_EXEC_RE.test(line);
    out.push(mkIssue({ id: "SC-PTH-EXEC", name: "Code in a .pth file", type: "HOTSPOT",
      sev: hostile ? "CRITICAL" : "MAJOR",
      msg: ".pth line runs code at every Python start" + (hostile ? " and executes or decodes a payload." : "."),
      why: "site.py executes .pth lines that start with 'import' whenever the interpreter starts, whether or not the package is imported — a persistence and execution vector that needs no install hook.",
      fix: "Find out why the package ships executable .pth code; remove it if unexplained.",
      ref: "CWE-506 · Supply chain" }, path, i + 1, lines));
  }
  return out;
}
