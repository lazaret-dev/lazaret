// Final review: SC-EVAL-DECODE missed `exec(__import__("base64").b64decode("…"))`
// and `eval(__import__('codecs').decode(…))` — the decoder prefix allowed
// dotted names only. The prefix grammar now also allows `__import__("mod").`
// and `importlib.import_module("mod").` segments, and a module-qualified
// decoder may name its module that way (twin of core's SC-EVAL-DECODE and
// _DECODE_CALL_RE; tests/scanner/test_review_eval_decode_import.py). Inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const FLAGGED = [
  'exec(__import__("base64").b64decode("cHJpbnQoMSk="))',
  "eval(__import__('codecs').decode(s, 'rot13'))",
  'exec(importlib.import_module("zlib").decompress(b))',
  "exec(importlib.import_module( 'base64' ).b64decode(x))",
  "exec(__import__('marshal').loads(b))",
  "exec(__import__('binascii').unhexlify(h))",
  'exec( __import__("base64") . b64decode ( p ) )',
  'eval(__import__("zlib").decompress(__import__("base64").b64decode(z)))',
  "exec(base64.b64decode(x))",
];
const NOT_FLAGGED = [
  'exec(__import__("os").system("x"))',
  "eval(__import__('json').loads(s))",
  "exec(importlib.import_module('codecs').lookup(n))",
  "decoded = __import__('base64').b64decode(p)",
];
const at = (issues) => issues.filter((i) => i.rule === "SC-EVAL-DECODE").map((i) => [i.line, i.msg]);

test("decoders reached through an inline import are flagged", () => {
  for (const src of FLAGGED) assert.deepEqual(at(scanFile({ name: "m.py", lang: "py", content: src + "\n" })).map(([l]) => l), [1], src);
  const multi = 'x = 1\nexec(\n    __import__("base64").b64decode(p))\n';
  assert.deepEqual(at(scanFile({ name: "m.py", lang: "py", content: multi })).map(([l]) => l), [2]);
});

test("other inline-import calls are not decoders", () => {
  for (const src of NOT_FLAGGED) assert.deepEqual(at(scanFile({ name: "m.py", lang: "py", content: src + "\n" })), [], src);
});

test("dependency mode follows an inline-import decode through variables", () => {
  const flows = [
    ['p = __import__("base64").b64decode(s)\nq = 1\nexec(p)\n', 3, 1],
    ["d = __import__('codecs').decode(s, 'rot13'); eval(d)\n", 1, 1],
    ["z = importlib.import_module('zlib').decompress(b)\nrun = z\nexec(run)\n", 3, 1],
  ];
  for (const [src, line, assigned] of flows) {
    assert.deepEqual(at(scanFile({ name: "dep.py", lang: "py", content: src, dep: true })),
      [[line, `Decoded payload (assigned at line ${assigned}) reaches a code-execution sink.`]], src);
  }
});

test("the prefix grammar stays linear", () => {
  for (const src of ["exec(" + "__import__('x').".repeat(50_000), "exec(__import__('".repeat(50_000),
    "exec(importlib.import_module('q').".repeat(30_000), "x = " + "__import__('codecs')".repeat(50_000)]) {
    const t0 = performance.now();
    scanFile({ name: "m.py", lang: "py", content: src + "\n" });
    scanFile({ name: "dep.py", lang: "py", content: src + "\n", dep: true });
    const ms = performance.now() - t0;
    assert.ok(ms < 8000, `${src.slice(0, 30)}: ${ms.toFixed(0)} ms`);
  }
});
