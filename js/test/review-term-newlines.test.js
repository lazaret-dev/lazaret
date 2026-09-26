// Review: a newline in a file name could forge terminal output. sanitizeTerm
// keeps LF, and the report printed file paths through it: a file named
// "zz\n\n  Quality gate:  PASSED \n::notice::…\n  x.py" printed a fake
// "Quality gate: PASSED" line and a `::notice::` GitHub workflow command at
// column 0. Paths, labels, report paths and error messages now go through
// sanitizeTermLine, which also maps LF, U+2028 and U+2029 (twin of
// core.sanitize_term_line; python/tests/scanner/test_review_term_newlines.py
// compares the two). sanitizeTerm itself is unchanged.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, sanitizeTerm, sanitizeTermLine } from "../src/index.js";

const HOSTILE = "zz\n\n  Quality gate:  PASSED \n::notice::marker-from-a-file-name\n  x.py";

test("sanitizeTermLine maps every line break; sanitizeTerm keeps LF", () => {
  for (const ch of ["\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]) {
    assert.equal(sanitizeTermLine(`a${ch}b`), "a·b", ch.codePointAt(0).toString(16));
  }
  assert.equal(sanitizeTermLine("a\tb \x1b[31m"), "a\tb ·[31m");
  assert.equal(sanitizeTerm("a\nb"), "a\nb");
});

test("a hostile file name or link target prints on one line", { skip: process.platform === "win32" }, () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-term-nl-"));
  try {
    writeFileSync(join(d, "app.py"), "import os\nos.system(cmd)\n");
    writeFileSync(join(d, HOSTILE), "# TODO marker\n");
    symlinkSync("x\n::notice::from-a-link-target\ny", join(d, "link"));
    const out = [];
    assert.equal(run(["check", d, "--no-json", "--no-html"], { out: (s) => out.push(s), err: () => {}, env: {} }), 0);
    const lines = out.join("\n").split("\n");
    assert.deepEqual(lines.filter((l) => l.startsWith("::")), []);
    assert.deepEqual(lines.filter((l) => l.trimStart().startsWith("Quality gate")), ["  Quality gate: FAILED"]);
    assert.ok(lines.some((l) => l.includes("zz··  Quality gate:  PASSED ·::notice::marker-from-a-file-name·  x.py:1")), lines.join("\n"));
  } finally { rmSync(d, { recursive: true, force: true }); }
});
