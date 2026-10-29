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
import { decodeSource } from "../src/lib/encoding.js";

const NUL_TOP = Buffer.from('/*\0*/eval(atob("Y29uc29sZS5sb2coMSk="))\n', "latin1");

// The sniff and its plausibility test are the engine's (decode/mod.rs' tests; core's through
// tests/architecture/test_decode_engine.py); here, that the package reads files through it.
test("decodeSource is the engine's: a NUL-top UTF-8 file stays UTF-8, BOM-less UTF-16 is read", () => {
  const dec = decodeSource(NUL_TOP, "js");
  assert.deepEqual([dec.info.encoding, dec.info.reported, dec.text],
    ["utf-8", false, '/*\0*/eval(atob("Y29uc29sZS5sb2coMSk="))\n']);
  const le = decodeSource(Buffer.from("import os\r\nos.system(input())\n", "utf16le"), "py");
  assert.deepEqual([le.info.encoding, le.info.reported, le.text], ["utf-16-le", true, "import os\nos.system(input())\n"]);
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
