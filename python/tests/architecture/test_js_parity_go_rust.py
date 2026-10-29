"""Engine parity for a project's Go and Rust files (S-4): the Python CLI and
the npm CLI report the same findings (rule, file, line, severity, message),
metrics, gate and exit code on a tree of Go and Rust files (the curated Go
and Rust corpus, a project with markers, and a dependency tree whose Go and
Rust files neither reads yet), with and without --deps. The expectations
themselves are in tests/scanner/test_go_rust_sources.py; this only holds
the engines to each other. Inert content: fake credentials built by
concatenation, nothing executed. Skipped where the npm engine is not built
(node, and npm run build in js/).
"""
import collections
import json
import unittest

from tests.architecture.scanfile_corpus import GO_RS_CURATED
from tests.architecture.test_js_parity import DERIVED, NPM_READY, NPM_SKIP, both, derived, issue_key
from tests.architecture.test_js_parity_lexing import write_tree
from tests.scanner.test_go_rust_sources import AWS, TREE

DEPS = {"node_modules/dep/package.json": json.dumps({"name": "dep", "version": "1.0.0"}),
        "node_modules/dep/native/x.go": f"package x\nvar awsKey = \"{AWS}\"\n",
        "node_modules/dep/native/y.rs": f"let k = \"{AWS}\";\n"}


def go_rust_tree():
    tree = dict(TREE)
    for name, text in GO_RS_CURATED:
        tree["corpus/" + name] = text
    tree.update(DEPS)
    return tree


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class GoRustParityTests(unittest.TestCase):
    maxDiff = None

    def assert_same(self, tree, deps=False, label="go/rust"):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, tree)
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

    def test_go_and_rust_tree(self):
        report = self.assert_same(go_rust_tree())
        rules = {i["rule"] for i in report["issues"]}
        self.assertTrue({"S-SECRET", "S-TOKEN", "S-BIDI", "Q-TODO", "SC-HEXSTR", "SC-B64"} <= rules, rules)
        self.assertFalse([i for i in report["issues"] if "node_modules" in i["file"].replace("\\", "/")
                          and not i["rule"].startswith("Q-SKIPPED")])

    def test_with_deps(self):
        report = self.assert_same(go_rust_tree(), deps=True, label="go/rust --deps")
        self.assertFalse([i for i in report["issues"] if i["file"].replace("\\", "/").startswith("node_modules/dep/native")])


if __name__ == "__main__":
    unittest.main()
