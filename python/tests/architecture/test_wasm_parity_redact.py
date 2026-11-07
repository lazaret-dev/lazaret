"""The npm package's engine is the native engine (see test_wasm_parity): the
WebAssembly build against the native library on the one redactor, every call
of test_snapshot_redact's sets (a file's findings made and redacted, with its
entropy literals and without; results swept; a file's findings built outside
its scan given its redaction; free text and lines redacted, PEM blocks and
clipped lines). Skipped where node, the WebAssembly build or the native
library is missing.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_snapshot_redact import snapshot_sets
from tests.architecture.test_wasm_parity import both, differences


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmRedactParityTests(unittest.TestCase):
    maxDiff = None

    def test_every_set(self):
        calls = [[c, a, t] for make in snapshot_sets().values() for c, a, t in make()]
        wasm, native = both(calls)
        self.assertEqual(len(wasm), len(calls))
        self.assertEqual(differences(calls, wasm, native), [])
        self.assertTrue(all(len(a) == 64 for a in wasm))                          # every call answered


if __name__ == "__main__":
    unittest.main()
