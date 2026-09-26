// Review: pthIssues split .pth files at \n only. Python 3.13's site.py (and
// recent 3.12 releases) iterates `pth_content.splitlines()`, which also ends
// a line at \v, \f, \x1c-\x1e, \x85, U+2028 and U+2029: `# path notes\f
// import sys; print("PTH-MARKER-LINE-RAN")` gave no finding while
// python3.13 ran the import. Both splittings are checked now (twin of
// core.pth_issues); a statement is reported at its physical line. Inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, pthIssues } from "../src/index.js";

const SEPARATORS = ["\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"];
const markerLine = (n) => `# path notes${SEPARATORS[n]}import sys; print("PTH-MARKER-${n}")\n`;

test("every splitlines boundary starts a statement", () => {
  SEPARATORS.forEach((sep, n) => {
    assert.deepEqual(pthIssues("n.pth", markerLine(n)).map((i) => [i.line, i.sev]), [[1, "MAJOR"]], `U+${sep.codePointAt(0).toString(16)}`);
  });
});

test("physical lines and severity", () => {
  const text = "./lib\nx\x85import zlib; zlib.decompress(b)\n./a\u2028./b\n"
    + "import os\f./c\n# a\vimport a\x1cimport b\nimports\x1dimportlib\n";
  const got = pthIssues("m.pth", text);
  assert.deepEqual(got.map((i) => [i.line, i.sev]), [[2, "CRITICAL"], [4, "MAJOR"], [5, "MAJOR"]]);
  assert.equal(got[0].snippet[1], "x\x85import zlib; zlib.decompress(b)");
});

test("the review tree fails the gate", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-pth-split-"));
  try {
    writeFileSync(join(d, "notes.pth"), '# path notes\x0cimport sys; print("PTH-MARKER-LINE-RAN")\n');
    writeFileSync(join(d, "plain.pth"), 'import sys; print("PTH-MARKER-LINE-RAN")\n');
    const err = [];
    assert.equal(run(["check", d, "-q", "--no-html", "--ci"], { out: () => {}, err: (s) => err.push(s), env: {} }), 1, err.join("\n"));
    const issues = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).issues;
    assert.deepEqual(issues.map((i) => [i.rule, i.file, i.line]).sort(), [["SC-PTH-EXEC", "notes.pth", 1], ["SC-PTH-EXEC", "plain.pth", 1]]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
