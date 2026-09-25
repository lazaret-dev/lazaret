// Review regressions: source encoding sniffing and PEP 263 cookies (review
// finding 12; shared semantics 4 and 15). A UTF-16 `eval(…)` used to decode
// as mojibake and scan clean. The same tree gives the identical issue
// multiset in the Python CLI. The UTF-7 fixtures are inert text (never run).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/index.js";

const enc16 = (s, be = false) => {
  const b = Buffer.from(s, "utf16le");
  if (be) b.swap16();
  return b;
};

function scanTree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-enc-"));
  try {
    for (const [name, data] of Object.entries(files)) writeFileSync(join(d, name), data);
    const code = run(["check", d, "--no-html"], { out: () => {}, err: () => {}, env: {} });
    assert.equal(code, 0);
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    return rep.issues.map((i) => `${i.file}:${i.line} ${i.rule} ${i.rule === "Q-ENCODING" ? i.msg : ""}`.trim()).sort();
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const q = (enc) => `Q-ENCODING Source file is not UTF-8 (detected ${enc}); decoded explicitly.`;

test("BOMs and BOM-less UTF-16 are decoded and reported (Q-ENCODING)", () => {
  const got = scanTree({
    "le_bom.js": Buffer.concat([Buffer.from([0xff, 0xfe]), enc16("eval(a)\n")]),
    "be_bom.js": Buffer.concat([Buffer.from([0xfe, 0xff]), enc16("eval(b)\n", true)]),
    "le_nobom.js": enc16("eval(c)\n"),
    "be_nobom.py": enc16("eval(d)\n", true),
    "u8bom.js": Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("eval(e)\n")]),
    "plain.py": "x = 1\n",
  });
  assert.deepEqual(got, [
    `be_bom.js:1 ${q("utf-16-be")}`, "be_bom.js:1 S-EVAL-JS",
    `be_nobom.py:1 ${q("utf-16-be")}`, "be_nobom.py:1 S-EVAL-PY",
    `le_bom.js:1 ${q("utf-16-le")}`, "le_bom.js:1 S-EVAL-JS",
    `le_nobom.js:1 ${q("utf-16-le")}`, "le_nobom.js:1 S-EVAL-JS",
    `u8bom.js:1 ${q("utf-8-sig")}`, "u8bom.js:1 S-EVAL-JS",
  ]);
});

test("a UTF-7 coding cookie is SC-UTF7 and the UTF-7-decoded text is what gets scanned", () => {
  // `+AAo-` is a newline in UTF-7: the "comment" hides a second line of code
  const got = scanTree({
    "utf7.py": "# -*- coding: utf-7 -*-\n# harmless comment +AAo-eval(f)\n",
    "cookie_line2.py": "#!/usr/bin/env python\n# vim: set fileencoding=utf7 :\n# +AAo-eval(i)\n",
    "cookie_line3.py": "x = 1\n# coding: utf-7\n# +AAo-eval(j)\n",          // line 3: not a cookie
  });
  assert.deepEqual(got, [
    `cookie_line2.py:1 ${q("utf-7")}`, "cookie_line2.py:2 SC-UTF7", "cookie_line2.py:4 S-EVAL-PY",
    `utf7.py:1 ${q("utf-7")}`, "utf7.py:1 SC-UTF7", "utf7.py:3 S-EVAL-PY",
  ]);
});

test("other cookies decode with that codec; an unknown codec reads as UTF-8", () => {
  const got = scanTree({
    "latin1.py": Buffer.concat([Buffer.from("# coding: latin-1\ns = '"), Buffer.from([0xe9]), Buffer.from("'\neval(g)\n")]),
    "unknown.py": "# coding: no-such-codec\neval(h)\n",
  });
  assert.deepEqual(got, [
    `latin1.py:1 ${q("iso8859-1")}`, "latin1.py:3 S-EVAL-PY",           // Python's canonical codec name
    `unknown.py:1 ${q("no-such-codec")}`, "unknown.py:2 S-EVAL-PY",
  ]);
});
