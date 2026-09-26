// Final review: a new quadratic and an ineffective time backstop.
//
// clipLine did Array.from(<whole line>) (and mkIssue cpLen(line.slice(0,
// col))) once per finding, so N findings on one long line cost O(N x line):
// 2.5k / 5k / 10k / 20k repeats of `try{}catch(e){}` on ONE line took
// 1.1 / 3.5 / 12.6 / > 44 s (the original engine: 1.7 s at 20k). Clipping is
// now O(window) per finding (a cached code-point view per line) with output
// identical to Python's code-point-based clip_snippet_line.
//
// The 30 s per-file backstop was checked only between rules, so one text
// rule's per-match loop ran to the end (a 2 s budget: 13.5 s, all 10k
// findings). The deadline is now checked inside per-match loops too; the
// backstop tests below use a fake clock (every Date.now() read is 1 ms
// later), so they are deterministic on any machine.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile, setScanTimeBudget } from "../src/index.js";
import { clipLine, mkIssue, cpIndexOf, SNIPPET_MAX, SNIPPET_LEAD } from "../src/lib/issue.js";
import { cpIndex } from "../src/lib/pycompat.js";
import { registerScanContext } from "../src/lib/redact.js";
import { SECRET_SKIP_RE } from "../src/scanner/engine.js";

// Python's clip_snippet_line on code points (the reference the engines share)
function referenceClip(text, col = null) {
  const cps = Array.from(text);
  const n = cps.length;
  if (n <= SNIPPET_MAX) return text;
  let start = col == null ? 0 : Math.max(0, col - SNIPPET_LEAD);
  start = Math.min(start, n - (SNIPPET_MAX - 1));
  const head = start > 0 ? "…" : "";
  const end = start + SNIPPET_MAX - head.length;
  if (end < n) return head + cps.slice(start, end - 1).join("") + "…";
  return head + cps.slice(start).join("");
}

test("clipLine output is Python's code-point clipping (astral characters, lone surrogates)", () => {
  const pieces = ["a", "é", "\u{1F600}", "\ud800", "\udc00", "\u{10FFFF}", " "];
  let seed = 7;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  for (let t = 0; t < 1500; t++) {
    const len = 180 + rnd(500), kinds = 1 + rnd(pieces.length);
    let s = "";
    for (let i = 0; i < len; i++) s += pieces[rnd(kinds)];
    for (const off of [null, 0, rnd(s.length + 1), s.length, s.length + 3]) {
      const col = off === null ? null : cpIndex(s, off);
      assert.equal(clipLine(s, col), referenceClip(s, col));
      if (off !== null) assert.equal(cpIndexOf(s, off), cpIndex(s, off));
    }
  }
});

test("20,000 findings on one 300 KB line: O(window) snippets", () => {
  const line = "try{}catch(e){}".repeat(20_000);
  const lines = ["// header", line, "// footer"];
  registerScanContext(lines, SECRET_SKIP_RE);       // as scanFile does: each line is redacted once
  const t0 = performance.now();
  for (let k = 0; k < 20_000; k++) {
    const issue = mkIssue({ id: "B-EMPTY-CATCH", name: "n", type: "BUG", sev: "MAJOR", msg: "m", why: "w", fix: "f", ref: "r" },
      "t.js", 2, lines, k * 15 + 5);
    if (k === 19_999) assert.ok(issue.snippet[1].includes("catch(e){}") && issue.snippet[1].startsWith("…"));
  }
  const ms = performance.now() - t0;
  assert.ok(ms < 5000, `${ms.toFixed(0)} ms (was quadratic: minutes)`);
});

test("one line of 2.5k-20k `try{}catch(e){}` repeats scans in linear time", () => {
  for (const n of [2_500, 5_000, 10_000, 20_000]) {
    const t0 = performance.now();
    const issues = scanFile({ name: "t.js", lang: "js", content: "try{}catch(e){}".repeat(n) });
    const ms = performance.now() - t0;
    assert.ok(ms < 4000, `${n} repeats: ${ms.toFixed(0)} ms (was 1.1 / 3.5 / 12.6 / > 44 s)`);
    assert.equal(issues.filter((i) => i.rule === "B-EMPTY-CATCH").length, 1);
    assert.ok(!issues.some((i) => i.rule === "SC-TRUNCATED"));
  }
});

/** Run fn with a fake clock: each Date.now() read is 1 ms after the previous one. */
function withTickingClock(budgetMs, fn) {
  const realNow = Date.now;
  let t = 0;
  Date.now = () => t++;
  setScanTimeBudget(budgetMs);
  try { return fn(); } finally { Date.now = realNow; setScanTimeBudget(); }
}

test("the time backstop stops a text rule's per-match loop", () => {
  const n = 20_000;
  // one clock read per line in the line loop, then one per 256 text-rule
  // matches: the budget runs out ~40 reads into B-EMPTY-CATCH's matches
  const issues = withTickingClock(n + 40, () =>
    scanFile({ name: "t.js", lang: "js", content: "try{}catch(e){}\n".repeat(n) }));
  assert.equal(issues.filter((i) => i.rule === "SC-TRUNCATED").length, 1);
  const cap = issues.find((i) => i.rule === "Q-CAPPED");
  const total = issues.filter((i) => i.rule === "B-EMPTY-CATCH").length + (cap ? Number(cap.msg.split(" ")[0]) : 0);
  assert.ok(total > 0 && total < n, `${total} of ${n} matches reported before the stop (was: all of them)`);
});

test("the time backstop stops the dependency decode flow inside one long line", () => {
  // one line holding thousands of statements (dependency mode)
  const content = "var d = atob(p); ".repeat(5000) + "\n";
  const issues = withTickingClock(5, () => scanFile({ name: "dep.js", lang: "js", content, dep: true }));
  assert.equal(issues.filter((i) => i.rule === "SC-TRUNCATED").length, 1);
});
