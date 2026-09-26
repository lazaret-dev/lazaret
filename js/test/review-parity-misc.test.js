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

// linear.js tested S-CHMOD's tail on the 63 characters after the comma, where
// the Python pattern's \s* is unbounded: 80 spaces before 0o777 hid it here.
test("S-CHMOD: any amount of whitespace before the mode", () => {
  const { found } = scanTree({ "c.py": "os.chmod(p," + " ".repeat(80) + "0o777)\nos.chmod(q,\t\t0o644)\n" });
  assert.deepEqual(found, ["c.py:1 S-CHMOD"]);
});

// Python's re.I folds İ (U+0130) and ı (U+0131) to i; /iu does not, and two
// prefilters had no u flag (ſ and K were not s and k): these were
// Python-only. pyRe now folds as re.I does; a suppression marker must be
// ASCII in both engines (for a marker, matching less fails closed).
test("case folds as Python's re.I; markers are ASCII", () => {
  const { found } = scanTree({
    "n.sql": "SELECT a FROM t WİTH (NOLOCK);\n",
    "d.sql": "ſET @q = 'SELECT 1 ' + @x;\n",
    "e.sql": "EXECUTE İMMEDIATE 'x' || y;\n",
    "m.js": "eval(a) // noſec\neval(b) // lazaret-ıgnore\neval(c) // NOSONAR\n"
      + "eval(d) // nosec: S-EVAL-JS, ſ-X\neval(e) // nosec: S-EVAL-JS\n",
  });
  assert.deepEqual(found, ["d.sql:1 SQL-DYNAMIC", "e.sql:1 SQL-DYNAMIC", "m.js:1 S-EVAL-JS", "m.js:2 S-EVAL-JS",
    "m.js:4 S-EVAL-JS", "n.sql:1 SQL-NOLOCK"]);
});

// Node's regexes and ICU, and Python's re and unicodedata, classify code
// points by their own Unicode version: U+10D4A is a letter in Node 22 and
// on Python 3.14, unassigned on 3.10-3.13, so `\u{10d4a}eval(x)` in a .py
// file was S-EVAL-PY on 3.11-3.13 only. Both engines now read source text in
// Unicode 13.0 (Python 3.10's): a later code point is U+FFFD (lib/unicode13.js).
test("source text is read in Unicode 13.0", () => {
  const { found, rep } = scanTree({
    "u.py": "\u{10d4a}eval(x)\nexec\u{10d4a}(y)\n",
    "u.js": "a = 1;\n\\u{10D4A}eval(x)\n\\u200deval(y)\n\\u30fbeval(z)\n",
    "s.py": "x = eval(y)  # \u{1fae0} \u{1f600}\n",
  });
  assert.deepEqual(found, ["s.py:1 S-EVAL-PY", "u.js:2 S-EVAL-JS", "u.js:3 S-EVAL-JS", "u.js:4 S-EVAL-JS", "u.py:1 S-EVAL-PY"]);
  assert.equal(rep.issues.find((i) => i.file === "s.py").snippet[0], "x = eval(y)  # \ufffd \u{1f600}");
});
