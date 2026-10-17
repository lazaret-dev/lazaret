// Review regressions: PEP 263 coding cookies and the codecs they name. The
// decoding is the engine's for both packages (BR-7 step 4 b: decode/; held to
// Python's codecs by python/tests/architecture/test_decode_engine.py): here,
// that a scan reads files through it. The UTF-7 fixtures are inert text (never
// run).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/index.js";
import { decodeSource } from "../src/lib/encoding.js";

function scanTree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-codecs-"));
  try {
    for (const [name, data] of Object.entries(files)) writeFileSync(join(d, name), data);
    run(["check", d, "--no-html"], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    return rep.issues.map((i) => `${i.file}:${i.line} ${i.rule}${i.rule === "Q-ENCODING" ? " " + i.msg : ""}`).sort();
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const q = (enc) => `Q-ENCODING Source file is not UTF-8 (detected ${enc}); decoded explicitly.`;
const latin1 = (s) => Buffer.from(s, "latin1");

// findCookie counted "\r\n" as two line breaks, so with Windows line endings
// it only ever looked at line 1: a cookie on line 2 (after a shebang) was
// missed — no Q-ENCODING / SC-UTF7 (CRITICAL), and latin-1 read as UTF-8.
test("a coding cookie on line 2 of a CRLF file is found", () => {
  const utf7 = decodeSource(latin1("#!/usr/bin/env python\r\n# coding: utf-7\r\nx = 1\r\n"), "py").info;
  assert.deepEqual([utf7.encoding, utf7.utf7, utf7.cookieLine], ["utf-7", true, 2]);
  for (const eol of ["\r\n", "\r", "\n"]) {
    const l1 = decodeSource(latin1(`#!/usr/bin/env python${eol}# coding: latin-1${eol}s = '\xe9'${eol}`), "py");
    assert.deepEqual([l1.info.encoding, l1.info.cookieLine], ["iso8859-1", 2], JSON.stringify(eol));
    assert.ok(l1.text.includes("'é'"));
  }
  // line 3 is too late, whatever the line endings
  assert.equal(decodeSource(latin1("x = 1\r\n\r\n# coding: latin-1\r\n"), "py").info.reported, false);
  assert.deepEqual(scanTree({
    "crlf7.py": latin1("#!/usr/bin/env python\r\n# coding: utf-7\r\nx = 1 # +AAo-eval(x)\r\n"),
  }), ["crlf7.py:1 " + q("utf-7"), "crlf7.py:2 SC-UTF7", "crlf7.py:4 S-EVAL-PY"]);
});

test("a codec cookie decodes as in Python, the CJK and ISO-2022 codecs too; one not decoded is SC-TRUNCATED", () => {
  assert.deepEqual(scanTree({
    "ebcdic.py": "# coding: cp037\nprint(1)\nx = eval(input())\n",
    "dos.py": latin1("# coding: cp437\nx = eval(y)  # \x82t\x82\n"),
    "jis.py": Buffer.concat([latin1("# coding: iso2022_jp\n# \x1b$B4A;z\x1b(B\nx = eval(y)\n")]),
    "idna.py": "# coding: idna\nx = eval(y)\n",
    "uesc.py": "# coding: unicode_escape\n# \\x0aeval(z)\n",
  }), [
    "dos.py:1 " + q("cp437"), "dos.py:2 S-EVAL-PY",
    "ebcdic.py:1 " + q("cp037"), "ebcdic.py:1 Q-FLOW-SKIPPED",      // (the Python taint pass can't read it, as in Python)
    "idna.py:1 " + q("idna"), "idna.py:1 SC-TRUNCATED", "idna.py:2 S-EVAL-PY",
    "jis.py:1 " + q("iso2022_jp"), "jis.py:3 S-EVAL-PY",
    "uesc.py:1 " + q("unicode-escape"), "uesc.py:1 SC-ESCAPE-CODEC", "uesc.py:3 S-EVAL-PY",   // see review-escape-codecs
  ]);
});
