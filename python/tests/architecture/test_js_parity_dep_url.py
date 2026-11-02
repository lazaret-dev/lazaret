"""Engine parity for SC-DEP-URL (D-14, 0.1.9): the Python CLI and the npm CLI report the same findings (rule, file,
line, severity, message), metrics, gate and exit code on a tree with dependencies given as plain-http URLs and at
raw IP addresses, in a project's own manifests, a workspace's, a dependency's root manifest and a fixture's, with and
without --deps. The expectations themselves are in tests/scanner/test_dep_url.py and js/test/dep-url.test.js; this
only holds the engines to each other. Inert manifests: hosts are .invalid or TEST-NET addresses. Skipped where the
npm engine is not built (node, and npm run build in js/).
"""
import collections
import json
import tempfile
import unittest

from tests.architecture.test_js_parity import DERIVED, NPM_READY, NPM_SKIP, both, derived, issue_key
from tests.architecture.test_js_parity_lexing import write_tree


def manifest(name, **fields):
    return json.dumps({"name": name, "version": "1.0.0", **fields}, indent=2)


TREE = {
    "package.json": manifest("app", dependencies={"a": "^1", "b": "http:\x2f/registry.invalid/b.tgz"},
                             devDependencies={"z": "https://3405803783/z.tgz"}),
    "packages/web/package.json": manifest("web", optionalDependencies={"c": "git+http:\x2f/git.invalid/c.git"}),
    "node_modules/dep/package.json": manifest("dep", dependencies={"d": "https://[2001:db8::1]/d.tgz"},
                                              devDependencies={"e": "http:\x2f/dev.invalid/e.tgz"}),
    "node_modules/dep/test/package.json": manifest("fixture", dependencies={"f": "http:\x2f/fixture.invalid/f.tgz"}),
}


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class DepUrlParityTests(unittest.TestCase):
    maxDiff = None

    def test_the_tree_agrees(self):
        for deps in (False, True):
            with self.subTest(deps=deps), tempfile.TemporaryDirectory() as root:
                write_tree(root, TREE)
                (js_exit, js, js_err), (py_exit, py, py_err) = both(root, deps=deps)
                self.assertIsNotNone(js, f"JS wrote no report (exit {js_exit}): {js_err[-500:]}")
                self.assertIsNotNone(py, f"Python wrote no report (exit {py_exit}): {py_err[-500:]}")
                js_c = collections.Counter(issue_key(i) for i in js["issues"])
                py_c = collections.Counter(issue_key(i) for i in py["issues"])
                self.assertEqual(sorted((js_c - py_c).elements()), [], "only the JS engine reports")
                self.assertEqual(sorted((py_c - js_c).elements()), [], "only the Python engine reports")
                self.assertEqual(js["metrics"], py["metrics"])
                for field in DERIVED:
                    self.assertEqual(derived(js, field), derived(py, field), field)
                self.assertEqual(js_exit, py_exit)
                files = sorted(i["file"].replace("\\", "/") for i in py["issues"] if i["rule"] == "SC-DEP-URL")
                # the project's two and the workspace's; with --deps the dependency's root manifest (not its
                # devDependencies, nor its fixture's)
                want = ["package.json", "package.json", "packages/web/package.json"]
                self.assertEqual(files, sorted(want + (["node_modules/dep/package.json"] if deps else [])))


if __name__ == "__main__":
    unittest.main()
