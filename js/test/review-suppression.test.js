// Review regressions: suppression markers and comment detection (shared
// semantics 1 and 2; review finding 1). Every expectation here was checked
// against the Python engine (lazaret.scanner.core.scan_file) on the same
// input. Fixtures are inert strings — nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const rules = (content, lang, { dep = false, name = `t.${lang}` } = {}) =>
  scanFile({ name, content, lang, dep }).map((i) => `${i.rule}@${i.line}`).sort();

test("nosec never hides a supply-chain (SC-*) finding", () => {
  // was: JS honored `// nosec` on SC-EVAL-DECODE → gate PASSED
  assert.deepEqual(rules("eval(atob(payload)); // nosec\n", "js"), ["SC-EVAL-DECODE@1"]);
});

test("nothing is suppressible in dependency files", () => {
  const r = rules('const password = "hunter2hunter2"; // nosec\neval(atob(p)); // nosec\n', "js",
    { dep: true, name: "node_modules/x/a.js" });
  assert.deepEqual(r, ["S-SECRET@1", "SC-EVAL-DECODE@2"]);
});

test("a marker inside a string literal is not a comment", () => {
  assert.deepEqual(rules('x = "# nosec"; eval(y)\n', "py"), ["S-EVAL-PY@1"]);
  assert.deepEqual(rules("eval(y); const s = '// nosec';\n", "js"), ["S-EVAL-JS@1"]);
  assert.deepEqual(rules("s = '''\n# nosec\n'''\neval(y)\n", "py"), ["S-EVAL-PY@4"]);
  assert.deepEqual(rules("const s = `\n// nosec\n`; eval(y)\n", "js"), ["S-EVAL-JS@3"]);
});

test("SQL `--` comments count only in .sql files", () => {
  assert.deepEqual(rules("-- nosec\neval(y)\n", "js"), ["S-EVAL-JS@2"]);
  assert.deepEqual(rules("GRANT ALL ON t TO PUBLIC;\n", "sql"), ["SQL-GRANT-ALL@1", "SQL-GRANT-PUBLIC@1"]);
  assert.deepEqual(rules("-- nosec\nGRANT ALL ON t TO PUBLIC;\n", "sql"), []);
});

test("marker grammar: reasons, NOSONAR, rule lists", () => {
  assert.deepEqual(rules("eval(y)  # nosec - reviewed\n", "py"), []);
  assert.deepEqual(rules("eval(y); // nosec: reviewed\n", "js"), []);
  assert.deepEqual(rules("eval(y) // NOSONAR\n", "js"), []);
  assert.deepEqual(rules("eval(y) /* nosec */\n", "js"), ["S-EVAL-JS@1"]);   // not a # // -- marker
  // a rule list suppresses exactly those rules (SC-* never)
  assert.deepEqual(rules("eval(atob(x)); // lazaret-ignore: S-EVAL-JS\n", "js"), ["SC-EVAL-DECODE@1", "T-CODE@1"]);
  assert.deepEqual(rules("eval(y); // lazaret-ignore: S-NEWFUNC\n", "js"), ["S-EVAL-JS@1"]);
  assert.deepEqual(rules("eval(y); // lazaret-ignore: S-NEWFUNC, S-EVAL-JS\n", "js"), []);
});

test("the line above counts only when it is a standalone comment line", () => {
  assert.deepEqual(rules("// nosec\neval(y)\n", "js"), []);
  assert.deepEqual(rules("foo(); // nosec\neval(y)\n", "js"), ["S-EVAL-JS@2"]);
});

test("comment state is tracked across lines (spec 1)", () => {
  assert.deepEqual(rules("/**/eval(y)\n", "js"), ["S-EVAL-JS@1"]);          // not a comment line
  assert.deepEqual(rules("/*\neval(y)\n*/\n", "js"), []);                   // inside a block comment
  assert.deepEqual(rules("a = b\n * eval(y)\n", "js"), ["S-EVAL-JS@2"]);    // ` *` without an open block
  assert.deepEqual(rules('s = "#"; eval(x)\n', "py"), ["S-EVAL-PY@1"]);
});

test("U+2028 / U+2029 end a line in JS (code after a // comment is code)", () => {
  assert.deepEqual(rules("// c\u2028eval(y)\n", "js"), ["S-EVAL-JS@2"]);
  assert.deepEqual(rules("// c\u2029eval(y)\n", "js"), ["S-EVAL-JS@2"]);
});
