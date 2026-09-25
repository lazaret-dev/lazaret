// Review regression: duplication keyed on f.name, which CLI files lack, so
// every file shared the key "undefined:<line>" and dupPct came out at half
// the Python value (review finding 14). The CLI numbers below equal the
// Python CLI's metrics for the same tree.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { computeMetrics, run } from "../src/index.js";

const block = Array.from({ length: 8 }, (_, i) => `v${i} = compute(${i})\n`).join("");

test("computeMetrics keys duplicate lines per file (path or name)", () => {
  const a = { content: "# header\n" + block, lang: "py" };
  const b = { content: block + "z = 1\n", lang: "py" };
  // CLI-shaped entries (path only) and library-shaped entries (name only)
  for (const key of ["path", "name"]) {
    const m = computeMetrics([{ ...a, [key]: "a.py" }, { ...b, [key]: "b.py" }]);
    assert.deepEqual(m, { files: 2, depFiles: 0, ncloc: 17, comments: 1, dupPct: 94.1 }, key);
  }
});

test("CLI dupPct matches the Python engine", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-dup-"));
  try {
    writeFileSync(join(d, "a.py"), "# header\n" + block);
    writeFileSync(join(d, "b.py"), block + "z = 1\n");
    writeFileSync(join(d, "c.js"), "/* x */\nconst a = 1;\n");
    assert.equal(run(["check", d, "--no-html", "-q"], { out: () => {}, err: () => {}, env: {} }), 0);
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    assert.deepEqual(rep.metrics, { files: 3, depFiles: 0, ncloc: 18, comments: 2, dupPct: 88.9 });
  } finally { rmSync(d, { recursive: true, force: true }); }
});
