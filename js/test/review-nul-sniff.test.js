// Review follow-up: the BOM-less UTF-16 sniff must not swallow a UTF-8 file
// that merely has a NUL near the top. `/*\0*/eval(atob("…"))` used to
// decode as UTF-16-BE garbage in the npm engine and scan clean, while the
// Python engine (core._text_is_plausible) read it as UTF-8. The fixtures
// are inert text: nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/index.js";
import { decodeSource, textIsPlausible } from "../src/lib/encoding.js";

const NUL_TOP = Buffer.from('/*\0*/eval(atob("Y29uc29sZS5sb2coMSk="))\n', "latin1");

test("a NUL in the first bytes of a UTF-8 file is not taken for UTF-16", () => {
  const dec = decodeSource(NUL_TOP);
  assert.equal(dec.encoding, "utf-8");
  assert.equal(dec.reported, false);
  assert.equal(dec.text, '/*\0*/eval(atob("Y29uc29sZS5sb2coMSk="))\n');
});

test("genuine BOM-less UTF-16 (LE and BE) is still decoded and reported", () => {
  const le = Buffer.from("import os\nos.system(input())\n", "utf16le");
  const be = Buffer.from(le).swap16();
  for (const [buf, enc] of [[le, "utf-16-le"], [be, "utf-16-be"]]) {
    const dec = decodeSource(buf, { py: true });
    assert.equal(dec.encoding, enc);
    assert.equal(dec.reported, true);
    assert.equal(dec.text, "import os\nos.system(input())\n");
  }
});

test("textIsPlausible: >= 70% of the first 2048 code points are printable ASCII / TAB / LF / CR", () => {
  assert.equal(textIsPlausible(""), false);
  assert.equal(textIsPlausible("a".repeat(7) + "\u4e00".repeat(3)), true);    // exactly 70%
  assert.equal(textIsPlausible("a".repeat(69) + "\u4e00".repeat(31)), false);
  assert.equal(textIsPlausible("\t\r\n ~"), true);
  assert.equal(textIsPlausible("\x7f\x1f\x80"), false);
  // characters, not UTF-16 code units (as Python counts): the first 2048
  // code points are 600 astral + 1448 ASCII = 70.7%; the first 2048 code
  // units would hold only 848 ASCII
  assert.equal(textIsPlausible("\u{1F600}".repeat(600) + "a".repeat(5000)), true);
  // only the first 2048 characters count
  assert.equal(textIsPlausible("a".repeat(2048) + "\u4e00".repeat(10000)), true);
});

test("both a NUL-top .js and a BOM-less UTF-16LE .py are scanned for what they say", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-nul-"));
  try {
    writeFileSync(join(d, "nul-top.js"), NUL_TOP);
    writeFileSync(join(d, "le16.py"), Buffer.from("import os\nos.system(input())\n", "utf16le"));
    const code = run(["check", d, "--no-html"], { out: () => {}, err: () => {}, env: {} });
    assert.equal(code, 0);
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    const got = rep.issues.map((i) => `${i.file}:${i.line} ${i.rule}`).sort();
    assert.deepEqual(got, [
      "le16.py:1 Q-ENCODING",
      "le16.py:2 S-OSCMD-PY",
      "le16.py:2 T-CMD",
      "nul-top.js:1 S-EVAL-JS",
      "nul-top.js:1 SC-EVAL-DECODE",
      "nul-top.js:1 T-CODE",
    ]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
