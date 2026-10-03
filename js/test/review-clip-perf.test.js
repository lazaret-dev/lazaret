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
// findings). Since 0.1.8 the pattern rules are the native engine's, which
// a work budget bounds instead (the steps of its regex matcher): a file that
// spends it is SC-TRUNCATED, tested below with a small budget.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";
import { clipLine, mkIssue, cpIndexOf, SNIPPET_MAX, SNIPPET_LEAD } from "../src/lib/issue.js";
import { cpIndex } from "../src/lib/pycompat.js";
import { setWorkBudget } from "../src/lib/native.js";
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

test("a file that spends the native engine's work budget is SC-TRUNCATED", () => {
  // the pattern rules and the families are the native engine's (0.1.8): a work
  // budget, not the clock, stops it; the file is reported as not fully scanned
  setWorkBudget(2000);           // (the steps of the searches that take thousands: one long line's)
  try {
    for (const dep of [false, true]) {
      const issues = scanFile({ name: "t.js", lang: "js", content: "var d = atob(p); eval(d); ".repeat(1000) + "\n", dep });
      assert.deepEqual(issues.filter((i) => i.rule === "SC-TRUNCATED").map((i) => i.msg),
        ["File not fully scanned: reading it spent the engine's work budget (a pattern that backtracks without "
          + "end on this text)."], `dep: ${dep}`);
    }
  } finally {
    setWorkBudget();
  }
  assert.ok(!scanFile({ name: "t.js", lang: "js", content: "var d = atob(p); eval(d);\n" }).some((i) => i.rule === "SC-TRUNCATED"));
});
