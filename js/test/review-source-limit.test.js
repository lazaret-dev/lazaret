// Project and --deps scans read source files up to 16,000,000 bytes (twin of
// tests/scanner/test_review_source_limit.py). At the old 2,000,000-byte
// limit, --deps reported SC-TRUNCATED (CRITICAL, fails the gate) for
// typescript's lib/typescript.js (9.1 MB) and other single-file bundles.
// --max-source-bytes and LAZARET_MAX_SOURCE_BYTES change the limit.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, collectFiles } from "../src/index.js";

const B64 = '"Y29uc29sZS5sb2coMSk="';
const BUNDLE = "var a = function (b) { return b + 1; };\n".repeat(60_000) + `eval(atob(${B64}));\n`;

function project() {
  const d = mkdtempSync(join(tmpdir(), "lazaret-limit-"));
  mkdirSync(join(d, "node_modules", "big", "dist"), { recursive: true });
  writeFileSync(join(d, "a.js"), "var x = 1;\n");
  writeFileSync(join(d, "node_modules", "big", "dist", "index.js"), BUNDLE);
  writeFileSync(join(d, "node_modules", "big", "package.json"), '{"name": "big", "version": "1.0.0"}');
  return d;
}
function scan(d, args = [], env = {}) {
  const err = [];
  const code = run(["check", d, "--deps", "--no-html", "--quiet", "--force-overwrite", ...args],
    { out: () => {}, err: (s) => err.push(s), env });
  const rep = code === 2 ? null : JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
  return { code, rep, err: err.join("\n") };
}
const rulesIn = (rep, file) => new Set(rep.issues.filter((i) => i.file.replaceAll("\\", "/") === file).map((i) => i.rule));
const BIG = "node_modules/big/dist/index.js";
const MSG = `File not fully scanned: ${BUNDLE.length.toLocaleString("en-US")} bytes exceeds the 2,000,000-byte file limit.`;

test("the default reads a large bundle to its last line", () => {
  const d = project();
  try {
    const found = rulesIn(scan(d).rep, BIG);
    assert.ok(found.has("SC-EVAL-DECODE"));
    assert.ok(!found.has("SC-TRUNCATED"));
    assert.equal(collectFiles(d, { includeDeps: true }).binaryIssues.length, 0);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("--max-source-bytes and LAZARET_MAX_SOURCE_BYTES set the limit", () => {
  const d = project();
  try {
    for (const [args, env] of [[["--max-source-bytes", "2000000"], {}], [[], { LAZARET_MAX_SOURCE_BYTES: " 2_000_000 " }]]) {
      const { code, rep } = scan(d, args, env);
      assert.equal(code, 0);
      assert.deepEqual(rep.issues.filter((i) => i.rule === "SC-TRUNCATED").map((i) => i.msg), [MSG]);
      assert.equal(scan(d, [...args, "--ci"], env).code, 1);
    }
    // the option wins over the variable; a bad variable is ignored
    assert.ok(!rulesIn(scan(d, ["--max-source-bytes", "3000000"], { LAZARET_MAX_SOURCE_BYTES: "2000000" }).rep, BIG).has("SC-TRUNCATED"));
    for (const v of ["0", "-5", "abc", "1e6"])
      assert.ok(!rulesIn(scan(d, [], { LAZARET_MAX_SOURCE_BYTES: v }).rep, BIG).has("SC-TRUNCATED"), v);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("a bad --max-source-bytes is a usage error, worded as the Python engine words it", () => {
  const d = project();
  try {
    for (const v of ["0", "-5", "abc", "1e6", ""]) {
      const { code, err } = scan(d, [`--max-source-bytes=${v}`]);
      assert.equal(code, 2, v);
      assert.match(err, new RegExp(`argument --max-source-bytes: expected a positive number of bytes, got '${v}'`));
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});
