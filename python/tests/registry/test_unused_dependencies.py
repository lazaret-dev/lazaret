"""0.1.8: dependencies a package declares that nothing in it uses
(registry/unused_deps.py, SC-UNUSED-DEPENDENCY).

The @mastra compromise changed no code: each hijacked release gained a
dependency on easy-day-js that no file named. A registry scan of an npm
release lists such a dependency (INFO: packages also keep ones their build
inlined), unless it is one of npm's most-downloaded packages or of the
package's own scope; a brand-new one is SC-NEW-DEPENDENCY, CRITICAL
(tests/registry/test_new_dependency.py). Archives are built in memory;
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

    def test_python_releases_are_not_read(self):
        from tests.registry._review_support import scan_sdist
        res = scan_sdist({"setup.py": "from setuptools import setup\nsetup(name='x', install_requires=['stray'])\n",
                          "PKG-INFO": "Name: x\nVersion: 1.0\nRequires-Dist: stray\n"})
        self.assertEqual(unused_msgs(res), [])


if __name__ == "__main__":
    unittest.main()
