// Review regressions: places the npm engine read input differently from the
// Python engine. Every expectation was checked against the Python engine on
// the same input; both CLIs are compared in
// python/tests/architecture/test_js_parity_lexing.py. Fixtures are inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run, scanManifest, buildResult, jsonRenderer } from "../src/index.js";
import { pyExt } from "../src/lib/binary.js";
import { pyJsonParse, jsonErrorWhere } from "../src/lib/pyjson.js";
import { parseArgs, pyInt } from "../src/cli.js";

function scanTree(files, args = [], env = {}) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-parity-"));
  try {
    for (const [name, data] of Object.entries(files)) {
      mkdirSync(dirname(join(d, name)), { recursive: true });
      writeFileSync(join(d, name), data);
    }
    const out = [];
    const code = run(["check", d, "--no-html", ...args], { out: (l) => out.push(l), err: (l) => out.push(l), env });
    const text = readFileSync(join(d, "lazaret-report.json"), "utf8");
    const rep = JSON.parse(text);
    return { code, out, text, rep, found: rep.issues.map((i) => `${i.file.replaceAll("\\", "/")}:${i.line} ${i.rule}`).sort() };
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

// The npm engine's linear.js (through 0.1.8) tested S-CHMOD's tail on the 63
// characters after the comma, where the Python pattern's \s* is unbounded: 80
// spaces before 0o777 hid it here.
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
  // line 3's invisible U+200D glued to eval is also a look-alike name (SC-HOMOGLYPH); u.py's U+FFFD is no
  // Python the taint pass can read (a Q-FLOW-SKIPPED note, as in Python)
  assert.deepEqual(found, ["s.py:1 S-EVAL-PY", "u.js:2 S-EVAL-JS", "u.js:3 S-EVAL-JS", "u.js:3 SC-HOMOGLYPH",
    "u.js:4 S-EVAL-JS", "u.py:1 Q-FLOW-SKIPPED", "u.py:1 S-EVAL-PY"]);
  assert.equal(rep.issues.find((i) => i.file === "s.py").snippet[0], "x = eval(y)  # \ufffd \u{1f600}");
});

// A trailing comma in a root package.json: Python 3.13+ reports it at the
// comma ("line 3 column 21" below), 3.10-3.12 and this engine at the bracket
// after it ("line 4 column 1"), so SC-MANIFEST-UNPARSEABLE's message depended
// on the Python version. Both engines report the comma now, on every Python.
test("a JSON trailing comma is reported at the comma, as Python 3.13+ does", () => {
  const where = (text) => jsonErrorWhere(text, pyJsonParse(text).pos);
  for (const [text, at] of [['{"a": 1,}', "line 1 column 8"], ['{"a": 1,\n}', "line 1 column 8"],
    ["[1, ]", "line 1 column 3"], ["[1,\n\t\r ]", "line 1 column 3"], ['{"a": [[],]}', "line 1 column 10"],
    // not a trailing comma: where every Python reports it
    ['{"a": 1,]', "line 1 column 9"], ["[1,}", "line 1 column 4"], ["[1,,]", "line 1 column 4"],
    ["{,}", "line 1 column 2"], ["[1,\f]", "line 1 column 4"], ['{"a": 1,', "line 1 column 9"]]) {
    assert.equal(where(text), at, JSON.stringify(text));
  }
  const r = scanManifest("package.json", '{\n  "name": "app",\n  "version": "1.0.0",\n}\n');
  assert.deepEqual(r.map((i) => [i.rule, i.msg]), [["SC-MANIFEST-UNPARSEABLE",
    "package.json could not be parsed (JSONDecodeError: line 3 column 21); its install hooks could not be checked."]]);
});

// cli.js read --excerpt-width and --max-source-bytes with /^[-+]?\d+$/ (and
// LAZARET_MAX_SOURCE_BYTES with an ASCII-only pattern) where the Python
// engine calls int(): `--max-source-bytes 2_000_000` or `--excerpt-width
// 1_00` was a usage error (exit 2) here and a scan there. They are read as
// int() reads them now, and an excerpt is cut as text[:width] also for a
// negative width (it came out empty here).
test("integer options are read as Python's int() reads them", () => {
  for (const [text, want] of [["1_00", 100], [" +1_0\n", 10], ["\u0661\u0660\u0660", 100], ["\uff11\uff12", 12],
    ["\u{1d7d8}\u{1d7e1}", 9], ["-5", -5], ["007", 7], ["\xa07\u3000", 7], ["1__0", null], ["_1", null], ["1_", null],
    ["+_1", null], ["- 1", null], ["0x10", null], ["1e3", null], ["1.0", null], ["", null], ["\ufeff1", null],
    ["1\x1c", null], ["1".repeat(4300) + "_", null], ["1_".repeat(4300) + "1", null]]) {
    assert.equal(pyInt(text), want, JSON.stringify(text));
  }
  assert.ok(pyInt("1".repeat(4300)) > 1e300);                       // the 4300-digit limit is inclusive
  assert.deepEqual(parseArgs(["d", "--excerpt-width", "1_00", "--max-source-bytes= 2_000_000 "]).opts,
    { exclude: [], excerptWidth: 100, maxSourceBytes: 2000000 });
  assert.throws(() => parseArgs(["d", "--max-source-bytes", "-1_0"]), /expected a positive number of bytes, got '-1_0'/);
  assert.throws(() => parseArgs(["d", "--excerpt-width", "it's"]), /invalid int value: "it's"/);

  const line = "x = eval(y)  # abcdef\n";
  const r = scanTree({ "a.py": line }, ["--excerpt-width", "1_0", "--max-source-bytes", "2_000_000"]);
  assert.equal(r.code, 0);
  assert.ok(r.out.includes("      » x = eval(y…"), r.out.join("\n"));
  const neg = scanTree({ "a.py": line }, ["--excerpt-width", "-3"]);
  assert.ok(neg.out.includes("      » x = eval(y)  # abc…"), neg.out.join("\n"));   // Python: line[:-3] + "…"
  const env = scanTree({ "a.py": line }, [], { LAZARET_MAX_SOURCE_BYTES: "\u0661_\u0660" });   // 10 bytes
  assert.deepEqual(env.found, ["a.py:1 SC-TRUNCATED"]);
});

// buildResult counted findings per file with perFile[file] += 1: a file named
// __proto__ (a root binary, SC-BINARY) set the object's prototype instead and
// was missing from perFile, and a file named 7 or 10 came first, where the
// Python engine's dict keeps the order of the sorted findings. metrics.dupPct
// is a float in Python (0.0, 100.0) and was written as 0 / 100 here.
test("perFile holds every file in Python's order; dupPct is written as a float", () => {
  const elf = Buffer.concat([Buffer.from("\x7fELF\x02\x01\x01\x00", "latin1"), Buffer.alloc(600)]);
  const { text, rep, out } = scanTree({ ["__proto__"]: elf, "7": elf, "10": elf, "b.js": "eval(b)\n", "src/a.js": "eval(a)\n" });
  const block = /\n {2}"perFile": \{\n([\s\S]*?)\n {2}\}/.exec(text)[1];
  assert.deepEqual(block.split("\n").map((l) => l.trim().replaceAll("\\\\", "/")),    // "src\\a.js" on Windows
    ['"b.js": 1,', '"src/a.js": 1,', '"10": 1,', '"7": 1,', '"__proto__": 1']);
  assert.equal(Object.keys(rep.perFile).length, 5);
  assert.match(text, /\n {4}"dupPct": 0\.0,?\n/);
  assert.ok(out.includes("  2 files · 2 lines of code · 0.0% duplication"), out.join("\n"));
  const res = buildResult("/p", [], []);
  for (const [dup, written] of [[100, "100.0"], [12.5, "12.5"], [33.3, "33.3"], [0, "0.0"]]) {
    res.metrics.dupPct = dup;
    assert.equal(JSON.parse(jsonRenderer(res)).metrics.dupPct, dup);
    assert.match(jsonRenderer(res), new RegExp(`\n {4}"dupPct": ${written.replace(".", "\\.")},?\n`));
  }
});
