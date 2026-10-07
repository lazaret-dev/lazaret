"""The npm package's engine is the native engine (see test_wasm_parity), for
project mode too (Q-1, 0.1.9: both packages ask the engine for the whole of
a project file's scan): the WebAssembly build against the native library on
test_snapshot_project's sets (scan_file in project mode, with and without a
taint configuration, and the function lists) and on the intra-file taint
alone (taint_scan, the npm package's taintScan). Skipped where node, the
WebAssembly build or the native library is missing.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture import project_corpus
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_snapshot_project import lang_of, snapshot_sets
from tests.architecture.test_wasm_parity import both, differences


def check(case, calls):
    wasm, native = both([list(c) for c in calls])
    case.assertEqual(len(wasm), len(calls))
    case.assertEqual(differences([list(c) for c in calls], wasm, native), [])
    case.assertTrue(all(len(a) == 64 for a in wasm))                              # every call answered
    return wasm


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmProjectParityTests(unittest.TestCase):
    maxDiff = None

    def test_project_scans(self):
        calls = snapshot_sets()["scan_project"]()
        wasm = check(self, calls)
        self.assertGreater(len(set(wasm)), len(calls) // 2)                       # findings, not only silence

    def test_with_a_taint_configuration_and_the_function_lists(self):
        sets = snapshot_sets()
        check(self, sets["scan_project_configured"]() + sets["functions"]())

    def test_the_taint_pass_alone(self):
        calls = [("taint_scan", {"lang": lang_of(p), "jsx": True, "redact": True}, t)
                 for p, t in project_corpus.corpus() if lang_of(p) in ("py", "js")]
        check(self, calls)


if __name__ == "__main__":
    unittest.main()
