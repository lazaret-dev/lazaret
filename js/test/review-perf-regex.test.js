// Review regressions: rule patterns that backtracked quadratically inside ONE
// regex call (the per-file time budget is checked between lines and passes,
// so it could not stop them). S-JWT-NONE's `\s*\[?\s*` split a run of spaces
// every way ('algorithm:' + 200,000 spaces: ~22 s), and the dependency-mode
// decode flow's sink pattern retried a long identifier from every position
// inside it ('a' x 200,000 after a decode: ~20 s). B-EMPTY-CATCH's pattern
// had the same flaw; this engine runs it through the linear emptyCatchScan,
// kept here as a guard. Each input now takes milliseconds; the bound is
// generous. Inputs are inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const LIMIT_MS = 4000;
const CASES = {
  "S-JWT-NONE: 'algorithm:' + 200,000 spaces": ["js", "opts = {algorithm:" + " ".repeat(200000), false],
  "S-JWT-NONE: 'algorithm=' + 200,000 spaces (py)": ["py", "opts = dict(algorithm=" + " ".repeat(200000), false],
  "decode flow: a decode, then 'a' x 200,000": ["js", "const d = atob(x);\n" + "a".repeat(200000), true],
  "B-EMPTY-CATCH: 'catch' + 150,000 newlines": ["js", "try { f() } catch" + "\n".repeat(150000), false],
  "SC-OFFSCREEN-CODE: 'x;' + 200,000 spaces": ["js", "x;" + " ".repeat(200000), false],
  "SC-OFFSCREEN-CODE: ')' + 200,000 spaces + code (py)": ["py", ")" + " ".repeat(200000) + ";exec(1)", false],
  "SC-SELF-PUBLISH: needles + 'a' x 200,000": ["js", "exec('npm publish'); w('package.json'); " + "a".repeat(200000) + ".nam = 1", true],
};

for (const [label, [lang, content, dep]] of Object.entries(CASES)) {
  test(`linear: ${label}`, () => {
    const t0 = performance.now();
    const issues = scanFile({ name: `t.${lang}`, content, lang, dep });
    const ms = performance.now() - t0;
    assert.ok(ms < LIMIT_MS, `${label}: ${ms.toFixed(0)} ms`);
    assert.ok(!issues.some((i) => i.rule === "SC-TRUNCATED"), `${label} hit the time backstop`);
  });
}

const found = (content, lang, dep = false) => scanFile({ name: `t.${lang}`, content, lang, dep })
  .filter((i) => ["B-EMPTY-CATCH", "S-JWT-NONE", "SC-EVAL-DECODE"].includes(i.rule)).map((i) => [i.rule, i.line]);

test("the rewritten patterns find what they found before", () => {
  assert.deepEqual(found("try { f() } catch (e) {}\ntry { g() } catch\n{\n}\n", "js"),
    [["B-EMPTY-CATCH", 1], ["B-EMPTY-CATCH", 2]]);
  assert.deepEqual(found("jwt.verify(t, k, {algorithms: [ 'none' ]})\n", "js"), [["S-JWT-NONE", 1]]);
  assert.deepEqual(found("jwt.decode(t, algorithms=['none'])\n", "py"), [["S-JWT-NONE", 1]]);
  const flow = "const cp = require('child_process');\nconst d = atob(p);\ncp.exec(d);\nwindow.eval(d);\nre.exec(d);\n";
  assert.deepEqual(found(flow, "js", true), [["SC-EVAL-DECODE", 3], ["SC-EVAL-DECODE", 4]]);
});

test("a sink's receiver is a whole identifier: `\u00e9cp` is not the child_process alias `cp`", () => {
  assert.deepEqual(found("const cp = require('child_process');\nconst d = atob(p);\n\u00e9cp.exec(d);\n", "js", true), []);
});
