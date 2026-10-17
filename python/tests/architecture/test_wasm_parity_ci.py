"""The npm package's engine is the native engine (see test_wasm_parity): the
WebAssembly build against the native library on the CI files' readers, every
call of test_snapshot_ci's sets (the outlines, a workflow's findings, its
`uses:` and issues, a GitLab file's findings and issues, and the helpers).
Skipped where node, the WebAssembly build or the native library is missing.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_snapshot_ci import snapshot_sets
from tests.architecture.test_wasm_parity import both, differences


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmCiParityTests(unittest.TestCase):
    maxDiff = None

    def check(self, *names):
        calls = [[c, a, t] for name in names for c, a, t in snapshot_sets()[name]()]
        wasm, native = both(calls)
        self.assertEqual(len(wasm), len(calls))
        self.assertEqual(differences(calls, wasm, native), [])
        self.assertTrue(all(len(a) == 64 for a in wasm))                          # every call answered

    def test_outlines(self):
        self.check("ci_outline")

    def test_workflows_gitlab_files_and_helpers(self):
        self.check("ci_workflow", "ci_gitlab", "ci_helpers")


if __name__ == "__main__":
    unittest.main()
