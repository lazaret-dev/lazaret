"""Engine parity for compiled artifacts by their bytes (FP-BINARY-BY-NAME): the Python CLI and the npm CLI report the
same findings, metrics, gate and exit code on text named as compiled code (a Dockerfile named `.node`, a linker script
named `.so`) and compiled code's bytes under any name (an ELF, an ar archive whose first bytes read as text, a Mach-O
object named `.pcm`, a universal Mach-O, a Java class, a DEX), in the project and a dependency under --deps. The
expectations are in tests/scanner/test_review_binary_by_name.py. Inert. Skipped where the npm engine is not built.
"""
import collections
import os
import tempfile
import unittest

from tests.architecture.test_js_parity import DERIVED, NPM_READY, NPM_SKIP, both, derived, issue_key
from tests.scanner.test_review_binary_by_name import BINARY, TEXT


def names_tree():
    files = {"app.js": "require('pkg')\n", "package.json": '{"dependencies": {"pkg": "1.0.0"}}',
             "node_modules/pkg/package.json": '{"name": "pkg", "version": "1.0.0"}',
             "node_modules/pkg/index.js": "module.exports = 1\n", **TEXT, **BINARY}
    files.update({f"node_modules/pkg/{k}": v for k, v in {**TEXT, **BINARY}.items()})
    return files


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class BinaryNameParityTests(unittest.TestCase):
    maxDiff = None

    def assert_same(self, deps):
        with tempfile.TemporaryDirectory() as root:
            for rel, data in names_tree().items():
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
        return {i["file"].replace("\\", "/") for i in py["issues"] if i["rule"] == "SC-BINARY"}

    def test_names_and_bytes(self):
        self.assertEqual(self.assert_same(deps=False), set(BINARY))

    def test_names_and_bytes_with_deps(self):
        got = self.assert_same(deps=True)
        self.assertEqual({f for f in got if f.startswith("node_modules/")}, {f"node_modules/pkg/{k}" for k in BINARY})


if __name__ == "__main__":
    unittest.main()
