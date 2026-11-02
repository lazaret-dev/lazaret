"""Engine parity for Gradle wrapper jars (FP-GRADLE-WRAPPER): the Python CLI and the npm CLI report the same findings
(rule, file, line, severity, message), metrics, gate and exit code on a tree of genuine wrappers
(tests/fixtures/gradle-wrapper), changed ones (a byte changed, a class added), one for what may be the next release
of Gradle and one for a version no release will have, one without its properties, a genuine one over plain HTTP, jars elsewhere or under another name, and a dependency's under --deps. The expectations
are in tests/scanner/test_review_gradle_wrapper.py; this holds the packages to each other. Inert. Skipped where the
npm engine is not built (node, and npm run build in js/).
"""
import collections
import os
import tempfile
import unittest

from tests.architecture.test_js_parity import DERIVED, NPM_READY, NPM_SKIP, both, derived, issue_key
from tests.scanner.test_review_gradle_wrapper import JAR, PROPS, genuine, next_release, one_byte, props, with_class


def wrapper_tree():
    return {
        f"a/{JAR}": genuine("4.10.3"), f"a/{PROPS}": props("4.10.3"),
        f"b/{JAR}": genuine("8.14"), f"b/{PROPS}": props("9.4.1"),
        f"c/{JAR}": one_byte(genuine("9.8")), f"c/{PROPS}": props("9.8.1"),
        f"d/{JAR}": with_class(genuine("8.14")), f"d/{PROPS}": props("8.14"),
        f"e/{JAR}": one_byte(genuine("9.8")), f"e/{PROPS}": props("99.0.0"),
        f"f/{JAR}": one_byte(genuine("9.8")),
        f"g/{JAR}": one_byte(genuine("9.8")), f"g/{PROPS}": props("9.9-20261022000000+0000"),
        f"h/{JAR}": one_byte(genuine("9.8")), f"h/{PROPS}": props(next_release()),
        f"i/{JAR}": genuine("8.14"), f"i/{PROPS}": props("8.14").replace("https\\://services.gradle.org", "http\\://192.0.2.1"),
        "libs/gradle-wrapper.jar": one_byte(genuine("9.8")),
        "app.js": "require('pkg')\n", "package.json": '{"dependencies": {"pkg": "1.0.0"}}',
        "node_modules/pkg/package.json": '{"name": "pkg", "version": "1.0.0"}',
        "node_modules/pkg/index.js": "module.exports = 1\n",
        f"node_modules/pkg/android/{JAR}": genuine("8.14"), f"node_modules/pkg/android/{PROPS}": props("8.14"),
        f"node_modules/pkg/other/{JAR}": one_byte(genuine("8.14")),
    }


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class GradleWrapperParityTests(unittest.TestCase):
    maxDiff = None

    def assert_same(self, deps):
        with tempfile.TemporaryDirectory() as root:
            for rel, data in wrapper_tree().items():
                path = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as fh:
                    fh.write(data.encode("utf-8") if isinstance(data, str) else data)
            (js_exit, js, js_err), (py_exit, py, py_err) = both(root, deps=deps)
        self.assertIsNotNone(js, f"JS wrote no report (exit {js_exit}): {js_err[-500:]}")
        self.assertIsNotNone(py, f"Python wrote no report (exit {py_exit}): {py_err[-500:]}")
        js_c = collections.Counter(issue_key(i) for i in js["issues"])
        py_c = collections.Counter(issue_key(i) for i in py["issues"])
        self.assertEqual({"only the JS engine reports": sorted((js_c - py_c).elements()),
                          "only the Python engine reports": sorted((py_c - js_c).elements())},
                         {"only the JS engine reports": [], "only the Python engine reports": []})
        self.assertEqual(js["metrics"], py["metrics"])
        for field in DERIVED:
            self.assertEqual(derived(js, field), derived(py, field), field)
        self.assertEqual(js_exit, py_exit)
        return {(i["file"].replace("\\", "/"), i["rule"], i["sev"]) for i in py["issues"] if i["rule"].startswith("SC-")}

    def test_wrappers(self):
        self.assertEqual(self.assert_same(deps=False), {
            (f"c/{JAR}", "SC-GRADLE-WRAPPER", "CRITICAL"), (f"d/{JAR}", "SC-GRADLE-WRAPPER", "CRITICAL"),
            (f"e/{JAR}", "SC-GRADLE-WRAPPER", "CRITICAL"), (f"f/{JAR}", "SC-GRADLE-WRAPPER", "CRITICAL"),
            (f"g/{JAR}", "SC-GRADLE-WRAPPER", "MAJOR"), (f"h/{JAR}", "SC-GRADLE-WRAPPER", "MAJOR"),
            (f"i/{JAR}", "SC-GRADLE-WRAPPER", "MAJOR"), ("libs/gradle-wrapper.jar", "SC-BINARY", "MAJOR")})

    def test_wrappers_with_deps(self):
        got = self.assert_same(deps=True)
        self.assertIn((f"node_modules/pkg/other/{JAR}", "SC-GRADLE-WRAPPER", "CRITICAL"), got)
        self.assertFalse(any(f == f"node_modules/pkg/android/{JAR}" for f, _, _ in got))


if __name__ == "__main__":
    unittest.main()
