// Review regressions: per-rule caps, snippet clipping and very large finding
// counts (shared semantics 7; review finding 2). Expectations match
// the Python engine's cap_issues / clip_snippet_line on the same input.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const count = (issues, rule) => issues.filter((i) => i.rule === rule).length;

test("no per-file budget: rules after 500 low-value findings still run", () => {
  // was: the 500-issue budget stopped every later rule, incl. SC-*: PASSED
  const content = "// TODO x\n".repeat(500) + 'Function(Buffer.from(p,"base64").toString())()\n';
  const r = scanFile({ name: "t.js", content, lang: "js" });
  assert.deepEqual(r.filter((i) => i.rule === "SC-EVAL-DECODE").map((i) => i.line), [501]);
  assert.equal(count(r, "Q-TODO"), 200);
  const cap = r.find((i) => i.rule === "Q-CAPPED");
  assert.equal(cap.msg, "300 more Q-TODO findings omitted");
  assert.equal(cap.sev, "INFO");
  assert.equal(cap.line, 201);                     // at the first omitted finding
});

test("MINOR findings are capped per rule; security findings never are", () => {
  const minor = scanFile({ name: "t.js", content: "console.log(a)\n".repeat(300), lang: "js" });
  assert.equal(count(minor, "Q-CONSOLE"), 200);
  assert.deepEqual(minor.filter((i) => i.rule === "Q-CAPPED").map((i) => i.msg), ["100 more Q-CONSOLE findings omitted"]);
  const sec = scanFile({ name: "t.js", content: "eval(a)\n".repeat(600), lang: "js" });
  assert.equal(count(sec, "S-EVAL-JS"), 600);
  assert.equal(count(sec, "Q-CAPPED"), 0);
});

test("snippet lines are clipped to 240 characters, windowed around the match", () => {
  const long = "x = 1; ".repeat(700) + "eval(q);" + " y = 2;".repeat(700);
  const r = scanFile({ name: "t.js", content: `a\n${long}\nb\n`, lang: "js" });
  const ev = r.find((i) => i.rule === "S-EVAL-JS");
  const flagged = ev.snippet[ev.line - ev.snipStart];
  assert.equal(Array.from(flagged).length, 240);
  assert.ok(flagged.startsWith("… 1; x = 1;"), flagged);
  assert.ok(flagged.endsWith("y…"), flagged);
  assert.ok(flagged.includes("eval(q);"));
  for (const i of r) for (const s of i.snippet) assert.ok(Array.from(s).length <= 240);
  // another finding on the same line (not windowed on eval) is clipped from the start
  const ll = r.find((i) => i.rule === "Q-LONGLINE");
  assert.ok(ll.snippet[1].startsWith("x = 1; x = 1;") && ll.snippet[1].endsWith("x…"));
});
