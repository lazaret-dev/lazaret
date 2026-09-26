// Review: two reports could be given the same file. `--sarif
// lazaret-report.json` (the default JSON report's name) wrote the SARIF log
// and then replaced it with the JSON report, exit 0; `--json X --html X`
// failed with exit 3 only after the whole scan. Destinations that resolve to
// one file ('..', relative and absolute spellings, a symlinked directory)
// are refused with the other pre-scan checks (twin of
// reports.check_distinct_paths): exit 3, nothing scanned or written.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, validateReportPaths, ReportPathError } from "../src/index.js";

function cli(args) {
  const out = [], err = [];
  const code = run(args, { out: (s) => out.push(s), err: (s) => err.push(s), env: {} });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

test("spellings of one file are refused", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-collide-"));
  try {
    mkdirSync(join(d, "sub"));
    const same = [[join(d, "r.json"), join(d, "r.json")], [join(d, "r.json"), `${d}/sub/../r.json`],
      [join(d, "sub", "r.json"), `${d}/./sub/r.json`]];
    if (process.platform !== "win32") {
      symlinkSync(join(d, "sub"), join(d, "link"));
      same.push([join(d, "sub", "r.json"), join(d, "link", "r.json")]);
    }
    for (const [a, b] of same) {
      assert.throws(() => validateReportPaths({ json: a, sarif: b }),
        (e) => e instanceof ReportPathError && e.message.includes("JSON and SARIF reports would both be written to"), `${a} ${b}`);
    }
    validateReportPaths({ json: join(d, "r.json"), html: join(d, "r.html") });
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("--sarif on the default JSON name, and --json X --html X, exit 3 before the scan", () => {
  const root = mkdtempSync(join(tmpdir(), "lazaret-collide-root-"));
  const outDir = mkdtempSync(join(tmpdir(), "lazaret-collide-out-"));
  try {
    writeFileSync(join(root, "a.py"), "import os\nos.system(cmd)\n");
    let r = cli(["check", root, "--out-dir", outDir, "--sarif", "lazaret-report.json"]);
    assert.equal(r.code, 3, r.out);                                             // was 0
    assert.match(r.err, /reports would both be written to/);
    assert.doesNotMatch(r.out, /Lazaret scan/);
    r = cli(["check", root, "--out-dir", outDir, "--json", "X", "--html", `${outDir}/sub/../X`]);
    assert.equal(r.code, 3, r.err);
    assert.match(r.err, /the JSON and HTML reports would both be written to/);
    assert.doesNotMatch(r.out, /Lazaret scan/);                                 // was: after the full scan
    assert.deepEqual(readdirSync(outDir), []);
    r = cli(["check", root, "--out-dir", outDir, "--no-json", "--no-html", "--sarif", "lazaret-report.json"]);
    assert.equal(r.code, 0, r.err);
    assert.equal(JSON.parse(readFileSync(join(outDir, "lazaret-report.json"), "utf8")).version, "2.1.0");
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});
