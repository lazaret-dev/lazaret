"""D-12b and D-9c (0.1.9): a --deps scan gives the tests each installed package's names, as the registry and the
guard give a release's (repo's _declared_names and _own_name).

A --deps scan's import-time test was given no names, so D-12's install at import of a package the release does not
depend on (crypto-hash-sdk 1.0.1's `npm install prettier-sdk`) was judged in the registry and the guard and not in
an installed tree; and D-9's test, given no name, would read a package's code written into its own folder
(`require.resolve('<its name>/…')`) as another package's. Now an installed npm package's import-time test is given
its package.json's names (its own and those it depends on, of every kind) and its name as its own, which its install
scripts' test is given too; an installed Python distribution's files, the Name and Requires-Dist of the *.dist-info
whose RECORD lists their top-level module or package. Where neither is known, the tests read as before.

The npm package's twin is js/src/deps.js (InstalledNames). Payloads are inert: hosts are .invalid, nothing is
installed or run.
"""
import json
import os
import shutil
import tempfile
import unittest

from lazaret.scanner import core

CHS = ("const { execSync } = require('child_process');\n(function () {\n  try {\n"
       "    execSync('npm uninstall prettier-sdk && npm install prettier-sdk', { stdio: 'ignore', windowsHide: true });\n"
       "  } catch (e) { }\n})();\nmodule.exports = 1;\n")
PIP = "import subprocess, sys\nsubprocess.check_call([sys.executable, '-m', 'pip', 'install', 'evil-pkg'])\n"
INSTALLS = "installs packages the release does not depend on"
GEN = ("const fs = require('fs');\nconst path = require('path');\n"
       "const base = require.resolve('PKG/package.json').replace('/package.json', '');\n"
       "fs.writeFileSync(path.join(base, 'lib', 'gen.js'), 'module.exports = 1;\\n');\nmodule.exports = 1;\n")
REWRITES = "rewrites another package's code"


def pkg(name, **fields):
    return json.dumps({"name": name, "version": "1.0.0", **fields})


def scan(files):
    root = tempfile.mkdtemp(prefix="lz-names-")
    try:
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
        return core.scan_project(root, include_deps=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def found(res, rule):
    return [(i["file"].replace(os.sep, "/"), i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == rule]


class NpmTests(unittest.TestCase):
    def test_an_install_at_import_of_what_it_does_not_declare(self):
        for base in ("node_modules/hash-sdk", "node_modules/@s/hash-sdk", "node_modules/a/node_modules/hash-sdk"):
            with self.subTest(base):
                res = scan({"package.json": pkg("app"), base + "/package.json": pkg(base.rsplit("node_modules/", 1)[1]),
                            base + "/index.js": CHS})
                ((file, sev, msg),) = found(res, "SC-IMPORT-RISK")
                self.assertEqual((file, sev), (base + "/index.js", "CRITICAL"))
                self.assertIn(INSTALLS + " (prettier-sdk)", msg)

    def test_what_it_declares_and_where_its_names_are_not_known(self):
        for key in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            with self.subTest(key):
                res = scan({"node_modules/hash-sdk/package.json": pkg("hash-sdk", **{key: {"prettier-sdk": "^1"}}),
                            "node_modules/hash-sdk/index.js": CHS})
                self.assertEqual(found(res, "SC-IMPORT-RISK"), [])
        # no package.json: its names are not known
        self.assertEqual(found(scan({"node_modules/hash-sdk/index.js": CHS}), "SC-IMPORT-RISK"), [])

    def test_its_own_folder_is_its_own(self):
        own = scan({"node_modules/gen-pkg/package.json": pkg("gen-pkg"),
                    "node_modules/gen-pkg/index.js": GEN.replace("PKG", "gen-pkg")})
        self.assertEqual(found(own, "SC-IMPORT-RISK"), [])
        other = scan({"node_modules/gen-pkg/package.json": pkg("gen-pkg"),
                      "node_modules/gen-pkg/index.js": GEN.replace("PKG", "other-pkg")})
        ((file, sev, msg),) = found(other, "SC-IMPORT-RISK")
        self.assertEqual((file, sev), ("node_modules/gen-pkg/index.js", "CRITICAL"))
        self.assertIn(REWRITES + " (other-pkg)", msg)

    def test_its_install_script_writing_its_own_folder(self):
        def hook(target):
            res = scan({"node_modules/gen-pkg/package.json": pkg("gen-pkg", scripts={"postinstall": "node gen.js"}),
                        "node_modules/gen-pkg/gen.js": GEN.replace("PKG", target)})
            return [(sev, msg) for file, sev, msg in found(res, "SC-INSTALL-HOOK")
                    if file == "node_modules/gen-pkg/package.json"]
        ((sev, msg),) = hook("gen-pkg")
        self.assertNotIn(REWRITES, msg)
        ((sev, msg),) = hook("other-pkg")
        self.assertEqual(sev, "CRITICAL")
        self.assertIn(REWRITES + " (other-pkg)", msg)


class PythonTests(unittest.TestCase):
    SITE = "site-packages/"

    def files(self, requires=""):
        return {self.SITE + "evil/__init__.py": PIP,
                self.SITE + "evil-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: evil\nVersion: 1.0\n"
                                                           + requires + "\nA description.\n",
                self.SITE + "evil-1.0.dist-info/RECORD": "evil/__init__.py,sha256=x,1\nevil-1.0.dist-info/METADATA,,\n"}

    def test_an_install_at_import_of_what_it_does_not_require(self):
        ((file, sev, msg),) = found(scan(self.files()), "SC-IMPORT-RISK")
        self.assertEqual((file, sev), (self.SITE + "evil/__init__.py", "CRITICAL"))
        self.assertIn(INSTALLS + " (evil-pkg)", msg)

    def test_what_it_requires_and_where_its_names_are_not_known(self):
        self.assertEqual(found(scan(self.files("Requires-Dist: evil-pkg>=1; extra == 'x'\n")), "SC-IMPORT-RISK"), [])
        # no .dist-info lists it
        self.assertEqual(found(scan({self.SITE + "evil/__init__.py": PIP}), "SC-IMPORT-RISK"), [])


class NamesTests(unittest.TestCase):
    def test_the_registrys_readings(self):
        self.assertEqual(core.npm_declared_names({"name": "x", "dependencies": {"a": "1"}, "bundleDependencies": ["b"],
                                                  "devDependencies": {"c": "1"}, "peerDependencies": {"d": "1"}}),
                         {"x", "a", "b", "c", "d"})
        self.assertEqual(core.metadata_declared_names("Name: x\nRequires-Dist: a (>=1)\nRequires-Dist: b[s]; extra == 'y'"
                                                      "\n\nRequires-Dist: not-a-header\n"), ({"x", "a", "b"}, 2))


if __name__ == "__main__":
    unittest.main()
