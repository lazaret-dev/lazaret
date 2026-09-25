// Review regressions: the CLI argument parser and exit codes (review
// findings 3 and 16/17; shared semantics 10). Exit codes: 0 ok (or gate failed
// without --ci), 1 gate failed with --ci or SC-MANIFEST-DEPTH, 2 usage,
// 3 report output error, 5 internal error.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, parseArgs } from "../src/index.js";

function capture(argv, io = {}) {
  const out = [], err = [];
  const code = run(argv, { out: (s) => out.push(s), err: (s) => err.push(s), ...io });
  return { code, out: out.join("\n"), err: err.join("\n") };
}
function project(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-cli-"));
  for (const [rel, text] of Object.entries(files)) {
    const p = join(d, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, text);
  }
  return d;
}

test("the --out-dir value is consumed, not taken as the target (both spellings)", () => {
  // was: `check --out-dir X src` scanned X; `--out-dir=X` was ignored
  const d = project({ "src/a.js": "eval(y)\n" });
  try {
    for (const argv of [["check", "--out-dir", join(d, "out"), join(d, "src"), "-q"],
      ["check", `--out-dir=${join(d, "out")}`, join(d, "src"), "-q"]]) {
      rmSync(join(d, "out"), { recursive: true, force: true });
      mkdirSync(join(d, "out"));
      const r = capture(argv);
      assert.equal(r.code, 0, r.err);
      assert.deepEqual(readdirSync(join(d, "out")).sort(), ["lazaret-report.html", "lazaret-report.json"]);
      const rep = JSON.parse(readFileSync(join(d, "out", "lazaret-report.json"), "utf8"));
      assert.deepEqual(rep.issues.map((i) => i.rule), ["S-EVAL-JS"]);
      assert.deepEqual(readdirSync(join(d, "src")), ["a.js"]);          // nothing written into the scan root
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("bare `lazaret <dir>`, -q before the directory, --deps alias", () => {
  const d = project({ "a.js": "eval(y)\n" });
  try {
    assert.equal(capture(["-q", d, "--no-json", "--no-html"]).code, 0);
    assert.equal(capture([d, "--deps", "--no-json", "--no-html", "-q"]).code, 0);
    assert.deepEqual(parseArgs(["--deps"]).opts.deps, true);
    assert.deepEqual(parseArgs(["--include-deps"]).opts.deps, true);
    assert.deepEqual(parseArgs(["--exclude", "a", "--exclude=b"]).opts.exclude, ["a", "b"]);
    assert.deepEqual(parseArgs(["--", "-dir"]).positional, ["-dir"]);
    assert.equal(parseArgs(["--no-h"]).opts.noHtml, true);              // unique prefix, like argparse
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("usage errors exit 2 before anything is scanned", () => {
  const d = project({ "a.js": "eval(y)\n" });
  try {
    const cases = [
      [["check", d, "--bogus"], /unrecognized arguments: --bogus/],
      [["check", d, "--taint-config", "x.json"], /only supported by the Python engine/],
      [["check", d, "--no"], /ambiguous option/],
      [["check", d, "--json"], /expected one argument/],
      [["check", d, "--excerpt-width", "abc"], /invalid int value/],
      [["check", d, d], /unrecognized arguments/],
      [["check"], /the following arguments are required: directory/],
      [["--no-html=1", d], /ignored explicit argument/],
      [["check", join(d, "a.js")], /is not a directory/],
      [["check", join(d, "missing")], /does not exist/],
    ];
    for (const [argv, re] of cases) {
      const r = capture(argv);
      assert.equal(r.code, 2, `${argv.join(" ")} → ${r.code} ${r.err}`);
      assert.match(r.err, re);
      assert.equal(r.out, "");                                           // no scan output
    }
    assert.deepEqual(readdirSync(d), ["a.js"]);                          // no reports written
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("an empty directory is a usage error (exit 2), like the Python CLI", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-empty-"));
  try {
    const r = capture(["check", d]);
    assert.equal(r.code, 2);
    assert.match(r.err, /nothing to scan/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("--exclude prunes a directory by name and reports it (Q-SKIPPED-TREE)", () => {
  const d = project({ "keep/a.js": "eval(y)\n", "gen/b.js": "eval(z)\n" });
  try {
    const r = capture(["check", d, "--exclude", "gen", "--no-html"]);
    assert.equal(r.code, 0, r.err);
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    assert.deepEqual(rep.issues.map((i) => [i.rule, i.file]).sort(),
      [["Q-SKIPPED-TREE", "gen"], ["S-EVAL-JS", join("keep", "a.js")]]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("gate failure: exit 0 without --ci, 1 with --ci", () => {
  const d = project({ "a.js": "eval(y)\n" });
  try {
    assert.equal(capture(["check", d, "--no-json", "--no-html"]).code, 0);
    assert.equal(capture(["check", d, "--no-json", "--no-html", "--ci"]).code, 1);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("SC-MANIFEST-DEPTH is the one finding that forces exit 1 without --ci", () => {
  const d = project({ "package.json": '{"a":' + "[".repeat(5000) + "]".repeat(5000) + "}" });
  try {
    const r = capture(["check", d, "--no-html"]);
    assert.equal(r.code, 1, r.err);
    const rep = JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8"));
    assert.deepEqual(rep.issues.map((i) => [i.rule, i.sev]), [["SC-MANIFEST-DEPTH", "CRITICAL"]]);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("an internal error exits 5 with `error: internal:`, never a stack trace or exit 1", () => {
  const d = project({ "a.js": "eval(y)\n" });
  try {
    const r = capture(["check", d, "--no-json", "--no-html"], { out: () => { throw new TypeError("boom"); }, env: {} });
    assert.equal(r.code, 5);
    assert.match(r.err, /^error: internal: TypeError: boom\n {2}\(this is a Lazaret bug, not a scan result; set LAZARET_DEBUG=1 for a traceback\)$/);
    assert.doesNotMatch(r.err, /at .*\.js:\d+/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
