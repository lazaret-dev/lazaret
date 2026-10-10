"""Engine parity for the CI files' hardening checks in project scans (S-4):
the Python CLI and the npm CLI report the same findings, metrics, gate and
exit code on a tree of GitHub workflows and GitLab CI files (the modules'
own parity, finding for finding, is test_js_parity_workflow_hardening.py
and test_js_parity_gitlabci.py; this holds the two scanners' wiring and the
gate's supply-chain condition to each other). Expectations are in
tests/scanner/test_ci_hardening_wired.py. Skipped where the npm engine is
not built.
"""
import collections
import tempfile
import unittest

from tests.architecture.test_js_parity import DERIVED, NPM_READY, NPM_SKIP, both, derived, issue_key
from tests.architecture.test_js_parity_lexing import write_tree
from tests.scanner.test_ci_hardening_wired import GITLAB, TREE, WORKFLOW


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class CiHardeningParityTests(unittest.TestCase):
    maxDiff = None

    def assert_same(self, tree, label):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, tree)
            (js_exit, js, js_err), (py_exit, py, py_err) = both(root)
        self.assertIsNotNone(js, f"{label}: JS wrote no report (exit {js_exit}): {js_err[-500:]}")
        self.assertIsNotNone(py, f"{label}: Python wrote no report (exit {py_exit}): {py_err[-500:]}")
        js_c = collections.Counter(issue_key(i) for i in js["issues"])
        py_c = collections.Counter(issue_key(i) for i in py["issues"])
        self.assertEqual(sorted((js_c - py_c).elements()), [], f"{label}: only the JS engine reports these")
        self.assertEqual(sorted((py_c - js_c).elements()), [], f"{label}: only the Python engine reports these")
        self.assertEqual(js["metrics"], py["metrics"], f"{label}: metrics")
        for field in DERIVED + ("supplyChain",):
            self.assertEqual(derived(js, field) if field in DERIVED else js[field],
                             derived(py, field) if field in DERIVED else py[field], f"{label}: {field}")
        self.assertEqual(js_exit, py_exit, f"{label}: exit code")
        return py

    def test_ci_files(self):
        report = self.assert_same(TREE, "ci files")
        self.assertEqual(report["supplyChain"], 1)

    def test_without_a_critical_one(self):
        tree = dict(TREE, **{".github/workflows/ci.yml": WORKFLOW.replace("pull_request_target", "pull_request"),
                             ".gitlab/ci/more.gitlab-ci.yml": GITLAB})
        report = self.assert_same(tree, "no critical")
        self.assertTrue(report["pass"])


if __name__ == "__main__":
    unittest.main()
