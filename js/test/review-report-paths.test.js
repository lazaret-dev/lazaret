// Review regressions: report-path safety (review finding 4; twin of
// lazaret.scanner.reports validate_out_dir / _validate_path / is_our_report /
// write_report). Every refusal happens BEFORE the scan and exits 3.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync, symlinkSync, statSync, chmodSync, existsSync, readdirSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, isOurReport } from "../src/index.js";

const POSIX = process.platform !== "win32";

function capture(argv) {
  const out = [], err = [];
  const code = run(argv, { out: (s) => out.push(s), err: (s) => err.push(s), env: {} });
  return { code, out: out.join("\n"), err: err.join("\n") };
}
function project() {
  const d = mkdtempSync(join(tmpdir(), "lazaret-rp-"));
  writeFileSync(join(d, "a.js"), "eval(y)\n");
  return d;
}
const scanned = (r) => /Quality gate/.test(r.out);

test("a FIFO at the report path is refused before the scan (no hang)", { skip: !POSIX }, () => {
  const d = project();
  try {
    try { execFileSync("mkfifo", [join(d, "lazaret-report.json")]); } catch { return; }   // no mkfifo: nothing to test
    const r = capture(["check", d, "--no-html"]);
    assert.equal(r.code, 3);
    assert.match(r.err, /special file/);
    assert.ok(!scanned(r));
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("a symlink at the report path (e.g. to /dev/zero) is refused", { skip: !POSIX }, () => {
  const d = project();
  try {
    symlinkSync("/dev/zero", join(d, "lazaret-report.json"));
    const r = capture(["check", d, "--no-html", "--force-overwrite"]);   // even with --force-overwrite
    assert.equal(r.code, 3);
    assert.match(r.err, /is a symlink/);
    assert.ok(!scanned(r));
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("a directory at the report path is exit 3, not an uncaught EISDIR", () => {
  const d = project();
  try {
    mkdirSync(join(d, "lazaret-report.html"));
    const r = capture(["check", d, "--no-json"]);
    assert.equal(r.code, 3);
    assert.match(r.err, /is a directory/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("device paths and unusable --out-dir values fail fast with exit 3", { skip: !POSIX }, () => {
  const d = project();
  try {
    let r = capture(["check", d, "--no-html", "--json", "/dev/stdout"]);
    assert.equal(r.code, 3);
    assert.match(r.err, /device file/);
    r = capture(["check", d, "--out-dir", join(d, "missing")]);
    assert.equal(r.code, 3);
    assert.match(r.err, /does not exist/);
    r = capture(["check", d, "--out-dir", join(d, "a.js")]);
    assert.equal(r.code, 3);
    assert.match(r.err, /is not a directory/);
    if (existsSync("/proc/self")) {
      r = capture(["check", d, "--out-dir", "/proc"]);                 // was: ENOENT after the full scan
      assert.equal(r.code, 3);
      assert.ok(!scanned(r));
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("a foreign file is refused before scanning and left untouched; --force-overwrite replaces it", () => {
  const d = project();
  try {
    writeFileSync(join(d, "lazaret-report.json"), '{"precious": true}\n');
    let r = capture(["check", d, "--no-html"]);
    assert.equal(r.code, 3);
    assert.match(r.err, /refusing to overwrite/);
    assert.ok(!scanned(r));                                               // refused BEFORE the scan
    assert.equal(readFileSync(join(d, "lazaret-report.json"), "utf8"), '{"precious": true}\n');
    // a marker that is not the first key is not ours
    writeFileSync(join(d, "lazaret-report.json"), '{"x": 1, "generatedBy": "lazaret-cli-1"}');
    assert.equal(capture(["check", d, "--no-html"]).code, 3);
    r = capture(["check", d, "--no-html", "--force-overwrite"]);
    assert.equal(r.code, 0, r.err);
    assert.equal(JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).generatedBy, "lazaret-cli-1");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("provenance is a bounded prefix match: large reports and Python-engine HTML are ours", () => {
  const d = project();
  try {
    // > 64 KiB JSON report: the marker is the first key, the rest is never parsed
    const big = join(d, "big.json");
    writeFileSync(big, '{"generatedBy": "lazaret-cli-1", "pad": "' + "x".repeat(200000) + '"}');
    assert.equal(isOurReport(big, "json"), true);
    writeFileSync(big, '{"generatedBy": "lazaret-cli-1", "pad": "' + "x".repeat(200000));   // truncated
    assert.equal(isOurReport(big, "json"), true);
    // the Python engine's HTML report carries the marker as a <meta> tag in <head>
    const html = join(d, "lazaret-report.html");
    writeFileSync(html, '<!doctype html>\n<html><head><meta charset="utf-8">\n<meta name="generatedBy" content="lazaret-cli-1">\n<title>x</title></head><body></body></html>\n');
    assert.equal(isOurReport(html, "html"), true);
    const r = capture(["check", d, "--no-json"]);
    assert.equal(r.code, 0, r.err);
    // a marker in the body of some other page is not ours
    writeFileSync(html, "<html><head><title>mine</title></head><body><meta name=\"generatedBy\" content=\"lazaret-cli-1\"></body></html>");
    assert.equal(isOurReport(html, "html"), false);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("rewriting an existing report keeps its file mode; no temp files are left", { skip: !POSIX }, () => {
  const d = project();
  try {
    assert.equal(capture(["check", d, "--no-html"]).code, 0);
    const p = join(d, "lazaret-report.json");
    chmodSync(p, 0o640);
    assert.equal(capture(["check", d, "--no-html"]).code, 0);
    assert.equal(statSync(p).mode & 0o777, 0o640);
    const leftovers = readdirSync(d).filter((n) => n.startsWith(".lazaret"));
    assert.deepEqual(leftovers, []);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
