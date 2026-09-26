// Review regressions: places the npm engine read input differently from the
// Python engine. Every expectation was checked against the Python engine on
// the same input; both CLIs are compared in
// python/tests/architecture/test_js_parity_lexing.py. Fixtures are inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";
import { pyExt } from "../src/lib/binary.js";

function scanTree(files, args = []) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-parity-"));
  try {
    for (const [name, data] of Object.entries(files)) {
      mkdirSync(dirname(join(d, name)), { recursive: true });
      writeFileSync(join(d, name), data);
    }
    const code = run(["check", d, "--no-html", ...args], { out: () => {}, err: () => {}, env: {} });
    const text = readFileSync(join(d, "lazaret-report.json"), "utf8");
    const rep = JSON.parse(text);
    return { code, text, rep, found: rep.issues.map((i) => `${i.file.replaceAll("\\", "/")}:${i.line} ${i.rule}`).sort() };
  } finally { rmSync(d, { recursive: true, force: true }); }
}

// fs.js and binary.js took extensions from Node's extname, which says ".js"
// for "..js"; Python's os.path.splitext gives "" (all the dots before the
// last one are leading). So src/..js, src/...py and an empty src/..so were
// JavaScript, Python and a compiled artifact in npm only (a CRITICAL
// S-OSCMD-PY: gate FAIL here, PASS in Python).
test("extensions follow os.path.splitext", () => {
  for (const [name, ext] of [["..js", ""], ["...py", ""], [".bashrc", ""], ["src/..so", ""], ["a.js", ".js"],
    [".a.js", ".js"], ["a..js", ".js"], ["a.", "."], ["x/.y", ""], ["a/b.c/d", ""]]) assert.equal(pyExt(name), ext, name);
  const { found, rep } = scanTree({
    "src/..js": "var a = 1;\nconsole.log(a);\n",
    "src/...py": 'import os\nos.system("echo hi")\n',
    "src/..so": "",
    "ok.py": "x = 1\n",
  });
  assert.deepEqual(found, []);
  assert.equal(rep.metrics.files, 1);
  assert.equal(rep.pass, true);
});
