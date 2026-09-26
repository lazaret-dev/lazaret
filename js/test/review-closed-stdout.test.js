// Review: a closed stdout must not lose the scan. The Python CLI printed the
// terminal report before writing the reports and died on BrokenPipeError
// (`lazaret --ci dir | head -n 2`: exit 5, no JSON or HTML report). The npm
// CLI prints through console.log, which ignores EPIPE: these tests hold it
// to writing both reports and exiting with the gate's code when the reader
// has gone before the first line, leaves after two lines, or stdout is
// closed at start.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin/lazaret.js", import.meta.url));
const MANY = "import os\n" + Array.from({ length: 1500 }, (_, n) => `os.system(cmd_${n})\n`).join("");

function tree() {
  const root = mkdtempSync(join(tmpdir(), "lazaret-epipe-"));
  const out = mkdtempSync(join(tmpdir(), "lazaret-epipe-out-"));
  writeFileSync(join(root, "many.py"), MANY);
  return { root, out };
}
const reports = (out) => readdirSync(out).filter((n) => n.startsWith("lazaret-report")).sort();

/** Run the CLI; `readLines` lines of stdout are read, then the pipe is closed. */
function runClosing(args, readLines) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let err = "", seen = "";
    child.stderr.on("data", (d) => { err += d; });
    if (readLines === 0) child.stdout.destroy();
    else {
      child.stdout.on("data", (d) => {
        seen += d;
        if (seen.split("\n").length > readLines) child.stdout.destroy();
      });
    }
    child.on("error", reject);
    child.on("close", (code) => resolvePromise({ code, err }));
  });
}

for (const [label, readLines] of [["before the first line", 0], ["after two lines", 2]]) {
  test(`reader gone ${label}: both reports, the gate's exit code`, async () => {
    const { root, out } = tree();
    try {
      const r = await runClosing(["check", root, "--ci", "--out-dir", out], readLines);
      assert.equal(r.code, 1, r.err);
      assert.doesNotMatch(r.err, /internal/);
      assert.deepEqual(reports(out), ["lazaret-report.html", "lazaret-report.json"]);
      const r0 = await runClosing(["check", root, "--out-dir", out], readLines);
      assert.equal(r0.code, 0, r0.err);
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(out, { recursive: true, force: true });
    }
  });
}

test("stdout closed at start", { skip: process.platform === "win32" }, async () => {
  const { root, out } = tree();
  try {
    const code = await new Promise((res, rej) => {
      const child = spawn("/bin/sh", ["-c", 'exec "$0" "$@" >&-', process.execPath, BIN, "check", root, "--ci", "--out-dir", out],
        { stdio: ["ignore", "ignore", "ignore"] });
      child.on("error", rej);
      child.on("close", res);
    });
    assert.equal(code, 1);
    assert.deepEqual(reports(out), ["lazaret-report.html", "lazaret-report.json"]);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
});
