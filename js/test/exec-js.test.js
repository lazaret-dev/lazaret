// S-EXEC-JS leaves out a call on a regex (0.1.9; the engine's scanfile.rs exec_js_regex, which the npm package runs
// through its WebAssembly build; python/tests/scanner/test_exec_js.py has the same cases). A regex literal the lexer
// reads as one, or a name the file assigns a whole regex and nothing else; every other receiver counts as before,
// wherever it came from. Benign code only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/scanner/scan.js";

const CP = "const cp = require('child_process');\n";
// RUN stands for exec, so that Lazaret's scan of its own sources does not read these strings as calls
const lines = (content) => scanFile({ path: "x.js", content: content.replaceAll("RUN", "exec"), lang: "js" })
  .filter((i) => i.rule === "S-EXEC-JS").map((i) => i.line);

test("a call on a regex is left out", () => {
  assert.deepEqual(lines(CP + "const d = /^[A-Za-z]:/i.RUN(p);\n"), []);
  assert.deepEqual(lines("const m = /a(b)\\/c/g . RUN(s);\n"), []);
  assert.deepEqual(lines("const RE = /a(b)/g;\nlet m;\nwhile ((m = RE.RUN(text))) use(m);\n"), []);
  assert.deepEqual(lines(CP + "const re = new RegExp(x);\nconst m = re.RUN(line);\n"), []);
  assert.deepEqual(lines(CP + "let re = RegExp('(' + x + ')', 'g') // why\n, n = 0;\nre?.RUN(line);\n"), []);
  assert.deepEqual(lines("let re = /x/g\nre.lastIndex = 0\nre.RUN(s)\n"), []);
});

test("another name or a member is not", () => {
  assert.deepEqual(lines(CP + "const re = /x/;\nconfig.re.RUN(cmd);\n"), [3]);
  assert.deepEqual(lines(CP + "const re = /x/;\nconfig. re.RUN(cmd);\n"), [3]);
  assert.deepEqual(lines("const re = /x/;\nmy_re.RUN(cmd);\n"), [2]);
});

test("shell calls still count, wherever the receiver came from", () => {
  assert.deepEqual(lines(CP + "cp.RUN(cmd);\ncp.RUNSync(cmd);\nrunner?.RUN(cmd);\n"), [2, 3, 4]);
  assert.deepEqual(lines("const { exec } = require('child_process');\nRUN('ls ' + dir);\n"), [2]);
  assert.deepEqual(lines("RUN(cmd);\n"), [1]);
  assert.deepEqual(lines("require('./run').RUN(cmd);\n"), [1]);
  assert.deepEqual(lines("const c = require('./run');\nc.RUN(cmd);\n"), [2]);
  assert.deepEqual(lines("const c = require('child_' + 'process');\nc.RUN(cmd);\n"), [2]);
  assert.deepEqual(lines("db.RUN(sql + where);\n"), [1]);
});

test("a name also assigned something else, or a regex that is not the whole value", () => {
  assert.deepEqual(lines(CP + "let re = /x/;\nre = cp;\nre.RUN(cmd);\n"), [4]);
  assert.deepEqual(lines(CP + "let re = /x/;\nre &&= cp;\nre.RUN(cmd);\n"), [4]);
  assert.deepEqual(lines(CP + "const re = /x/ && cp;\nre.RUN(cmd);\n"), [3]);
  assert.deepEqual(lines(CP + "const re = /x/\n  && cp;\nre.RUN(cmd);\n"), [4]);
  assert.deepEqual(lines(CP + "const re = new RegExp(x) || cp;\nre.RUN(cmd);\n"), [3]);
  assert.deepEqual(lines("const ig = require('child_process');\nx = \"(/\" + 1 /ig.RUN(cmd);\n"), [2]);
});

test("unclosed constructors on one line take linear time", () => {
  // each `RegExp(` is read to its `)` within the pack's _REGEX_CTOR_REACH steps (test_exec_js has the numbers)
  const start = performance.now();
  assert.deepEqual(lines("a=RegExp((".repeat(32000) + "\nb.RUN(c);\n"), [2]);
  assert.ok(performance.now() - start < 5000);
});
