// Review regressions: PEP 263 coding cookies and the codecs they name. Every
// expectation was checked against the Python engine
// (lazaret.scanner.core.decode_source / encoding_issues); both CLIs are
// compared in python/tests/architecture/test_js_parity_lexing.py. The UTF-7
// fixtures are inert text (never run).

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
  const utf7 = decodeSource(latin1("#!/usr/bin/env python\r\n# coding: utf-7\r\nx = 1\r\n"), { py: true });
  assert.deepEqual([utf7.encoding, utf7.utf7, utf7.cookieLine], ["utf-7", true, 2]);
  for (const eol of ["\r\n", "\r", "\n"]) {
    const l1 = decodeSource(latin1(`#!/usr/bin/env python${eol}# coding: latin-1${eol}s = '\xe9'${eol}`), { py: true });
    assert.deepEqual([l1.encoding, l1.cookieLine], ["iso8859-1", 2], JSON.stringify(eol));
    assert.ok(l1.text.includes("'é'"));
  }
  // line 3 is too late, whatever the line endings
  assert.equal(decodeSource(latin1("x = 1\r\n\r\n# coding: latin-1\r\n"), { py: true }).reported, false);
  assert.deepEqual(scanTree({
    "crlf7.py": latin1("#!/usr/bin/env python\r\n# coding: utf-7\r\nx = 1 # +AAo-eval(x)\r\n"),
  }), ["crlf7.py:1 " + q("utf-7"), "crlf7.py:2 SC-UTF7", "crlf7.py:4 S-EVAL-PY"]);
});

// 63 codecs Python decodes had no TextDecoder label: the engine said
// "detected cp037" and then read the file as UTF-8, so the EBCDIC file below
// gave S-EVAL-PY and T-CODE here and nothing in Python. Single-byte codecs now
// decode with Python's own tables (src/lib/codecs.js, generated); any codec
// this engine cannot decode exactly as Python does is read as UTF-8 by both
// engines with SC-TRUNCATED.
test("single-byte codecs decode with Python's tables", () => {
  const got = (cookie, bytes) => decodeSource(Buffer.concat([latin1(`# coding: ${cookie}\n`), Buffer.from(bytes)]), { py: true });
  assert.equal(got("cp437", [0x82, 0xb0]).text.slice(-2), "é░");
  assert.equal(got("cp1252", [0x80, 0x81, 0x9f]).text.slice(-3), "€\ufffdŸ");  // 0x81 is undefined in Python
  assert.equal(got("iso8859_16", [0xa1, 0xa4]).text.slice(-2), "Ą€");         // no TextDecoder label
  assert.equal(got("cp866", [0x1a, 0x7f]).text.slice(-2), "\x1a\x7f");         // ICU's ibm866 swaps these
  assert.equal(got("palmos", [0x9b]).text.slice(-1), "\u203a");                // as Python 3.13+
  const w = got("windows-874", [0x80]);                                         // an alias only 3.14 has
  assert.deepEqual([w.encoding, w.text.slice(-1)], ["cp874", "€"]);
});

test("a codec cookie decodes the same as in Python; one no engine decodes is SC-TRUNCATED", () => {
  assert.deepEqual(scanTree({
    "ebcdic.py": "# coding: cp037\nprint(1)\nx = eval(input())\n",
    "dos.py": latin1("# coding: cp437\nx = eval(y)  # \x82t\x82\n"),
    "u32.py": "# coding: utf-32\nx = eval(y)\n",
    "uesc.py": "# coding: unicode_escape\n# \\x0aeval(z)\n",
  }), [
    "dos.py:1 " + q("cp437"), "dos.py:2 S-EVAL-PY",
    "ebcdic.py:1 " + q("cp037"), "ebcdic.py:1 Q-FLOW-SKIPPED",      // (the Python taint pass can't read it, as in Python)
    "u32.py:1 " + q("utf-32"), "u32.py:1 SC-TRUNCATED", "u32.py:2 S-EVAL-PY",
    "uesc.py:1 " + q("unicode-escape"), "uesc.py:1 SC-ESCAPE-CODEC", "uesc.py:3 S-EVAL-PY",   // see review-escape-codecs
  ]);
});
