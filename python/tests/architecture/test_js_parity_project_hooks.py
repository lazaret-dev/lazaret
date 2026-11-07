"""Engine parity for the follow of a project's own install hooks (SC-INSTALL-HOOK, 0.1.9): the Python CLI and the
npm CLI report the same findings (rule, file, line, severity, message), metrics, gate and exit code on the tree of
tests/scanner/test_review_project_hooks.py, with and without --deps. The expectations themselves are in that test
and its npm twin (js/test/review-project-hooks.test.js); this only holds the engines to each other. Inert content:
hosts are .invalid, nothing executed. Skipped where the npm engine is not built (node, and npm run build in js/).
"""
import collections
import tempfile
import unittest

from tests.architecture.test_js_parity import DERIVED, NPM_READY, NPM_SKIP, both, derived, issue_key
from tests.architecture.test_js_parity_lexing import write_tree
from tests.scanner.test_review_project_hooks import TREE


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class ProjectHookParityTests(unittest.TestCase):
    maxDiff = None

    def assert_same(self, deps, label):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, TREE)
            (js_exit, js, js_err), (py_exit, py, py_err) = both(root, deps=deps)
        self.assertIsNotNone(js, f"{label}: JS wrote no report (exit {js_exit}): {js_err[-500:]}")
        self.assertIsNotNone(py, f"{label}: Python wrote no report (exit {py_exit}): {py_err[-500:]}")
        js_c = collections.Counter(issue_key(i) for i in js["issues"])
        py_c = collections.Counter(issue_key(i) for i in py["issues"])
        self.assertEqual({"only the JS engine reports": sorted((js_c - py_c).elements()),
                          "only the Python engine reports": sorted((py_c - js_c).elements())},
                         {"only the JS engine reports": [], "only the Python engine reports": []},
                         f"{label}: the engines disagree")
        self.assertEqual(js["metrics"], py["metrics"], f"{label}: metrics")
        for field in DERIVED:
            self.assertEqual(derived(js, field), derived(py, field), f"{label}: {field}")
        self.assertEqual(js_exit, py_exit, f"{label}: exit code")
        return py

    def test_the_tree_agrees(self):
        for deps in (False, True):
            with self.subTest(deps=deps):
                report = self.assert_same(deps, "project hooks" + (" --deps" if deps else ""))
                followed = [i for i in report["issues"] if i["rule"] == "SC-INSTALL-HOOK" and i["sev"] == "CRITICAL"]
                # package.json, exfil, starter, both, shell, gen-other; with --deps viadep and node_modules/dep
                self.assertEqual(len(followed), 8 if deps else 6)


if __name__ == "__main__":
    unittest.main()
