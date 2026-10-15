"""0.1.8: dependencies a package declares that nothing in it uses
(registry/unused_deps.py, SC-UNUSED-DEPENDENCY).

The @mastra compromise changed no code: each hijacked release gained a
dependency on easy-day-js that no file named. A registry scan of an npm
release lists such a dependency (INFO: packages also keep ones their build
inlined), unless it is one of npm's most-downloaded packages or of the
package's own scope; a brand-new one is SC-NEW-DEPENDENCY, CRITICAL
(tests/registry/test_new_dependency.py). Since D-5 (0.1.9) a PyPI
release's requirements too, read against its imports by the names a
distribution is commonly imported as. Archives are built in memory;
package names are made up; nothing runs.
"""
import json
import unittest
from unittest import mock

from lazaret.registry import repo, unused_deps as U
from tests.registry._review_support import issues, scan_npm, tarball


def pkg(deps, name="@acme/files", **fields):
    return json.dumps({"name": name, "version": "1.0.0", "dependencies": deps, **fields}, indent=2)


def unused_msgs(res):
    return [(i["sev"], i["line"], i["msg"]) for i in issues(res, "SC-UNUSED-DEPENDENCY")]


class InterfaceTests(unittest.TestCase):
    def test_unused_with_a_normalizer(self):
        self.assertEqual(U.unused(["serde-json", "tokio", "proc-macro1"], ["serde_json", "tokio"], U.crate_key),
                         ["proc-macro1"])
        self.assertEqual(U.unused(["a", "b", "a"], []), ["a", "b"])
        self.assertEqual(U.unused([], ["a"]), [])

    def test_npm_package_of_a_specifier(self):
        for spec, want in (("lodash/fp", "lodash"), ("@scope/name/sub/x.js", "@scope/name"), ("left-pad", "left-pad"),
                           ("./local", None), ("/abs", None), ("node:fs", None), ("#internal", None),
                           ("https://x.invalid/m.js", None), ("@scope", None), ("", None)):
            with self.subTest(spec):
                self.assertEqual(U.npm_package(spec), want)

    def test_quoted_as_a_module_name(self):
        for text in ("require('easy-day-js')", 'import x from "easy-day-js/sub"', "await import(`easy-day-js`)",
                     "@import '~easy-day-js/base.css';", b"require(\"easy-day-js\")"):
            with self.subTest(text):
                self.assertTrue(U.quoted_in("easy-day-js", [text]))
        for text in ("easy-day-js", "'easy-day-jsx'", "'my-easy-day-js'", "// easy-day-js is great", "'easy-day-js",
                     b"easy-day-js"):
            with self.subTest(text):
                self.assertFalse(U.quoted_in("easy-day-js", [text]))

    def test_npm_unused(self):
        manifest = {"name": "x", "dependencies": {
            "used-lib": "1", "gyp-tool": "1", "styles": "1", "@types/node": "1", "local": "file:../local",
            "ms": "2", "scripted": "1", "preset": "1", "nothing": "1", "aliased": "npm:real-name@1"},
            "scripts": {"postinstall": "scripted --build"}, "babel": {"presets": ["preset"]},
            "description": "items for nothing-at-all"}
        texts = ["const a = require('used-lib');\nconst items = [];\n", "{'include_dirs': ['<!(node -p \"require('gyp-tool')\")']}",
                 b"@import '~styles/base';"]
        self.assertEqual(U.npm_unused(manifest, texts), [("ms", "2"), ("nothing", "1"), ("aliased", "npm:real-name@1")])
        self.assertEqual(U.npm_registry_name("aliased", "npm:real-name@1"), "real-name")
        self.assertEqual(U.npm_registry_name("plain", "^1"), "plain")


class RegistryTests(unittest.TestCase):
    def test_a_dependency_no_file_names(self):
        res = scan_npm({"package.json": pkg({"tiny-helper": "^1", "easy-day-js": "^1.11.21", "tslib": "^2",
                                             "@acme/inner": "^1"}),
                        "index.js": "module.exports = require('tiny-helper');\n"})
        self.assertEqual(unused_msgs(res), [(
            "INFO", 6, 'Depends on "easy-day-js", which no file of the package names: installing the package '
                       "installs it, and runs its install scripts, for nothing the package does.")])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_several(self):
        res = scan_npm({"package.json": pkg({f"stray-{i}": "1" for i in range(7)}), "index.js": "1;\n"})
        self.assertEqual([m for _s, _l, m in unused_msgs(res)], [
            'Depends on 7 packages no file of the package names ("stray-0", "stray-1", "stray-2", "stray-3", '
            '"stray-4" and 2 more): installing the package installs them, and runs their install scripts, for '
            "nothing the package does."])

    def test_named_anywhere_is_used(self):
        res = scan_npm({"package.json": pkg({"cli-dep": "1", "data-dep": "1", "style-dep": "1", "bin-dep": "1"},
                                            scripts={"build": "cli-dep compile"}),
                        "config.json": '{"plugins": ["data-dep"]}', "theme.scss": "@import '~style-dep/x';\n",
                        "bin/run": "#!/usr/bin/env node\nrequire('bin-dep');\n"})
        self.assertEqual(unused_msgs(res), [])

    def test_the_registry_name_of_an_alias(self):
        data = tarball({"package.json": pkg({"day": "npm:easy-day-js@1"}), "index.js": "1;\n"})
        r = repo._scan_artifact(data, "tgz", "npm", False, None)
        self.assertEqual(r["unusedDependencies"], ["easy-day-js"])
        self.assertEqual([i["msg"].split(",")[0] for i in issues(r, "SC-UNUSED-DEPENDENCY")],
                         ['Depends on "day"'])

    def test_not_when_a_text_was_not_read(self):
        files = {"package.json": pkg({"easy-day-js": "1"}), "index.js": "1;\n", "big.js": "x = 1;\n" * 400}
        with mock.patch.object(repo, "MAX_MEMBER", 1000):
            r = repo._scan_artifact(tarball(files), "tgz", "npm", False, None)
        self.assertEqual((r["unusedDependencies"], issues(r, "SC-UNUSED-DEPENDENCY")), ([], []))



# ---------------- PyPI (D-5) ----------------

META = "Metadata-Version: 2.1\nName: acme-files\nVersion: 1.0\n"


def wheel_files(requires, modules, extra=None):
    """A wheel of acme_files: METADATA with `requires`, and {path: text} modules."""
    meta = META + "".join(f"Requires-Dist: {r}\n" for r in requires) + "\nA description.\n"
    return {"acme_files-1.0.dist-info/METADATA": meta, "acme_files/__init__.py": "", **modules, **(extra or {})}


class PypiInterfaceTests(unittest.TestCase):
    def test_the_names_a_distribution_is_imported_as(self):
        self.assertEqual(U.pypi_import_keys("python-dateutil"), {"python-dateutil", "dateutil"})
        self.assertEqual(U.pypi_import_keys("PyYAML"), {"pyyaml", "yaml"})
        self.assertEqual(U.pypi_import_keys("pyjwt"), {"pyjwt", "jwt"})
        self.assertIn("redis", U.pypi_import_keys("redis-py"))
        self.assertIn("acme", U.pypi_import_keys("acme-sdk"))
        self.assertEqual(U.pypi_used_keys(["google.cloud.storage"]),
                         {"google", "google-cloud", "google-cloud-storage"})

    def test_pypi_unused(self):
        declared = ["requests", "python-dateutil", "PyYAML", "google-cloud-storage", "typing_extensions", "easy-day",
                    "quoted-plugin", "Easy_Day", "types-requests", "acme-stubs"]
        imports = ["requests.adapters", "dateutil.parser", "yaml", "google.cloud.storage", "typing_extensions"]
        texts = ["from importlib.metadata import version\nversion('quoted-plugin')\n"]
        self.assertEqual(U.pypi_unused(declared, imports, texts), ["easy-day"])

    def test_the_modules_of_a_distributions_files(self):
        self.assertEqual(U.pypi_modules(["pkg/__init__.py", "pkg/sub.py", "mod.py", "fast.cpython-312-x86_64-linux-gnu.so",
                                         "pkg-1.0.dist-info/RECORD", "pkg-1.0.data/purelib/other/__init__.py",
                                         "hook.pth", "README.md"]), {"pkg", "mod", "fast", "other"})
        self.assertEqual(U.pypi_modules(["setup.py", "PKG-INFO", "src/acme_x/__init__.py", "tests/test_a.py",
                                         "docs/conf.py", "tool.py"], sdist=True), {"acme-x", "tool"})
        self.assertEqual(U.pypi_modules(["setup.py", "PKG-INFO", "setup.cfg"], sdist=True), set())


class PypiRegistryTests(unittest.TestCase):
    def test_a_requirement_no_module_imports(self):
        from tests.registry._review_support import scan_wheel
        res = scan_wheel(wheel_files(["requests>=2", "python-dateutil", "easy-day (>=0.1)", "pytest-mock; extra == 'test'"],
                                     {"acme_files/core.py": "import requests\nfrom dateutil import parser\n"}))
        self.assertEqual(unused_msgs(res), [(
            "INFO", 6, 'Requires "easy-day", which no module of the release imports by the names it is commonly '
                       "imported as: installing the release installs it, and builds it if it is an sdist, for nothing "
                       "the release does.")])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_the_files_scan_gives_the_modules_its_code_imports(self):
        from tests.registry._review_support import zipball
        data = zipball(wheel_files(["easy-day"], {"acme_files/core.py": "import os.path\nfrom .x import y\n"
                                                                        "import importlib\n"
                                                                        "importlib.import_module('json')\n"}))
        r = repo._scan_artifact(data, "zip", "wheel", False, None)
        self.assertEqual(r["unusedDependencies"], ["easy-day"])
        self.assertEqual(r["importedModules"], ["importlib", "json", "os"])

    def test_what_is_a_use(self):
        from tests.registry._review_support import scan_sdist
        # an import of the name, of a chain of it, a quoted name; setup.py's install_requires is no use
        res = scan_sdist({"PKG-INFO": META + "Requires-Dist: acme-plugins\nRequires-Dist: zope.interface\n"
                                            "Requires-Dist: entry-pointed\nRequires-Dist: declared-only\n",
                          "setup.py": "from setuptools import setup\nsetup(install_requires=['declared-only'])\n",
                          "acme/__init__.py": "import acme_plugins\nfrom zope.interface import Interface\n",
                          "setup.cfg": "[options.entry_points]\nx = 'entry-pointed'\n",
                          "acme/data.json": '{"plugin": "entry-pointed"}'})
        self.assertEqual([m.split(",")[0] for _s, _l, m in unused_msgs(res)], ['Requires "declared-only"'])

    def test_several_and_popular_ones(self):
        from tests.registry._review_support import scan_wheel
        res = scan_wheel(wheel_files([f"stray-{i}" for i in range(6)] + ["numpy", "beautifulsoup4"],
                                     {"acme_files/core.py": "x = 1\n"}))
        self.assertEqual([m for _s, _l, m in unused_msgs(res)], [
            'Requires 6 distributions no module of the release imports by the names they are commonly imported as '
            '("stray-0", "stray-1", "stray-2", "stray-3", "stray-4" and 1 more): installing the release installs '
            "them, and builds those that are sdists, for nothing the release does."])

    def test_not_when_a_text_was_not_read(self):
        from tests.registry._review_support import zipball
        files = wheel_files(["easy-day"], {"acme_files/big.py": "x = 1\n" * 400})
        with mock.patch.object(repo, "MAX_MEMBER", 1000):
            r = repo._scan_artifact(zipball(files), "zip", "wheel", False, None)
        self.assertEqual((r["unusedDependencies"], r["importedModules"], issues(r, "SC-UNUSED-DEPENDENCY")),
                         ([], None, []))


if __name__ == "__main__":
    unittest.main()
