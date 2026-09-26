// Escape codecs (twin of python/tests/scanner/test_review_escape_codecs.py,
// which also checks decodeEscapes against CPython case by case). Python
// decodes the escape sequences of a file whose cookie names unicode_escape or
// raw_unicode_escape before it reads the code: `# \x0aeval(z)` is a comment
// and then eval(z). This engine read such a file as UTF-8; now it decodes it
// as Python does, the cookie is SC-ESCAPE-CODEC (CRITICAL), and a \N{name}
// escape (no Unicode name table here) or an escape Python rejects is read as
// UTF-8 with SC-TRUNCATED. All fixtures are inert text.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/index.js";
import { decodeEscapes, decodeSource } from "../src/lib/encoding.js";

const bytes = (s) => Buffer.from(s, "latin1");

test("decodeEscapes decodes as CPython's codecs do", () => {
  // expectations computed with bytes.decode() on CPython 3.10, 3.12 and 3.14
  assert.equal(decodeEscapes(bytes("a\\x41\\u00e9\\U0001F600\\101\\7777\\q\\\\\\'\\\"\\a\\b\\f\\n\\r\\t\\v\\\nz\xe9"), false),
    "aA\xe9\u{1F600}A\u01ff7\\q\\'\"\x07\x08\x0c\n\r\t\x0bz\xe9");
  assert.equal(decodeEscapes(bytes("\\ud83d\\ude00 \\udc80"), false), "\ufffd\ufffd \ufffd");   // surrogates: U+FFFD each
  assert.equal(decodeEscapes(bytes("\\\\u0041 \\u0041 \\x41 \\N{X} \\"), true), "\\\\u0041 A \\x41 \\N{X} \\");
  for (const bad of ["\\N{LATIN SMALL LETTER A}", "\\x4", "\\u12", "\\U00110000", "abc\\"])
    assert.equal(decodeEscapes(bytes(bad), false), null, bad);
  for (const bad of ["\\u12", "\\U00110000"]) assert.equal(decodeEscapes(bytes(bad), true), null, bad);
  assert.equal(decodeEscapes(bytes("\\\\N{X}"), false), "\\N{X}");                            // an escaped backslash
});

test("a cookie naming an escape codec: decoded, SC-ESCAPE-CODEC, SC-TRUNCATED when it can't be", () => {
  const dec = decodeSource(bytes("# coding: unicode_escape\n# \\x0aeval(z)\n\\x6fs.system(1)\n"), { py: true });
  assert.deepEqual([dec.text, dec.encoding, dec.escapes, dec.undecoded],
    ["# coding: unicode_escape\n# \neval(z)\nos.system(1)\n", "unicode-escape", true, undefined]);
  const d = mkdtempSync(join(tmpdir(), "lazaret-esc-"));
  try {
    writeFileSync(join(d, "u.py"), "# coding: unicode_escape\n# \\x0aeval(z)\n");
    writeFileSync(join(d, "r.py"), "# coding: raw_unicode_escape\n# \\x0aexec(z)\n# \\u000aeval(z)\n");
    writeFileSync(join(d, "n.py"), "#!/usr/bin/env python\n# coding: unicode_escape\n# \\N{X}eval(z)\n");
    run(["check", d, "--no-html"], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    const got = rep.issues.filter((i) => i.rule !== "Q-ENCODING").map((i) => `${i.file}:${i.line} ${i.rule} ${i.sev}`).sort();
    assert.deepEqual(got, [
      "n.py:1 SC-TRUNCATED CRITICAL", "n.py:2 SC-ESCAPE-CODEC CRITICAL",
      "r.py:1 SC-ESCAPE-CODEC CRITICAL", "r.py:4 S-EVAL-PY CRITICAL",
      "u.py:1 SC-ESCAPE-CODEC CRITICAL", "u.py:3 S-EVAL-PY CRITICAL",
    ]);
    assert.equal(rep.issues.find((i) => i.rule === "SC-ESCAPE-CODEC" && i.file === "u.py").msg,
      "Python source declares unicode-escape; code can hide in escape sequences.");
  } finally { rmSync(d, { recursive: true, force: true }); }
});
