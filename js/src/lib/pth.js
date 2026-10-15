// .pth files (SC-PTH-EXEC): core.pth_issues, the engine's for both packages (BR-7 step 3 d, 0.1.9: binary.rs), the
// check the registry runs on archive members. site.py executes every line of a .pth file in site-packages that
// starts with 'import' at EVERY interpreter start, so project and --deps scans check each .pth file they meet. A
// .pth file is not a source file: no other rule runs on it.

import { call, issuesOf } from "./native.js";
import { REDACT } from "./redact.js";

/**
 * SC-PTH-EXEC for each `import` line of a .pth file: CRITICAL when the line's code executes or decodes a payload, or
 * does what the install-script and import-time tests look for (the engine's pth_line_risk, which reads `exec('…')`
 * of a plain literal as the literal's code: coverage's a1_coverage.pth); MAJOR otherwise (setuptools' distutils shim
 * and namespace .pth files are this shape: listed for review). Lines are taken both ways site.py splits them: at
 * \n, \r and \r\n (Python 3.10, 3.11, early 3.12), and with str.splitlines() (3.13+, recent 3.12), which also
 * breaks at \v, \f, \x1c-\x1e, \x85, U+2028 and U+2029. A finding is reported at the physical (\n) line holding
 * the statement, once per line.
 */
export function pthIssues(path, text) {
  return issuesOf(path, call("pth_issues", { redact: REDACT.on, neumaier: false }, text));
}
