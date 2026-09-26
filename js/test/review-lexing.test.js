// Review regressions: the comment lexer and what is built on it. Every
// expectation here was checked against the Python engine
// (lazaret.scanner.core.scan_file) on the same input; the CLIs are compared in
// python/tests/architecture/test_js_parity_lexing.py. Fixtures are inert
// strings — nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const LIMIT_MS = 4000;
const rules = (content, lang, { dep = false, name = `t.${lang}` } = {}) =>
  scanFile({ name, content, lang, dep }).map((i) => `${i.rule}@${i.line}`).sort();

// jsText tested every comment span of a line for each \u escape, and the
// suppression check every span for each marker match: O(n²) on one line
// (`x=1;` + `/**/a` x 20,000: 2.2 s, x 60,000: ~20 s), beyond the reach
// of the per-file time budget. Both now walk the sorted spans once.
function timed(content) {
  const t0 = performance.now();
  const issues = scanFile({ name: "a.js", content, lang: "js" });
  const ms = performance.now() - t0;
  assert.ok(ms < LIMIT_MS, `${ms.toFixed(0)} ms`);
  assert.ok(!issues.some((i) => i.rule === "SC-TRUNCATED"), "hit the time backstop");
  return issues.map((i) => `${i.rule}@${i.line}`).sort();
}

test("linear: \\u escapes between comments on one line", () => {
  timed("x=1;" + "/**/\\u0061".repeat(60000) + "\n");
});

test("linear: marker look-alikes in strings between comments", () => {
  // every "// nosec" sits in a string: none suppresses the eval
  assert.ok(timed("x=1;" + "'// nosec'/**/".repeat(60000) + "eval(a)\n").includes("S-EVAL-JS@1"));
});

test("comment and escape handling is unchanged", () => {
  const src = "a = 1; /* c */ \\u0065val(x) /* d */ \\u0065val(y) // nosec\n/**/\\u0065val(z)\n";
  assert.deepEqual(rules(src, "js"), ["S-EVAL-JS@2"]);
});
